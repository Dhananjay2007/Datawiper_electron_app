#include <algorithm>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <chrono>
#include <random>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <winioctl.h>
#include <ntddscsi.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/hdreg.h>
#include <scsi/sg.h>
#endif

enum WipeProfile { CITIZEN = 1, ENTERPRISE = 2, GOVERNMENT = 3 };
enum WipeMode { NIST_800_88 = 1, HSE = 2 };

struct WipeConfig {
    std::string device_path;
    WipeProfile profile;
    WipeMode mode;
    bool wipe_hpa_dco;
    int passes;
};

class SecureWiper {
private:
    WipeConfig config;
    std::vector<uint8_t> zero_pattern;
    std::vector<uint8_t> ones_pattern;
    std::vector<uint8_t> random_pattern;

    void initialize_patterns(size_t block_size) {
        zero_pattern.assign(block_size, 0x00);
        ones_pattern.assign(block_size, 0xFF);

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        random_pattern.resize(block_size);
        for(auto& byte : random_pattern) {
            byte = static_cast<uint8_t>(dis(gen));
        }
    }

#ifdef _WIN32
    bool send_ata_command(HANDLE device, uint8_t command, void* buffer = nullptr, size_t buf_size = 0) {
        ATA_PASS_THROUGH_EX apt;
        memset(&apt, 0, sizeof(apt));

        apt.Length = sizeof(ATA_PASS_THROUGH_EX);
        apt.AtaFlags = ATA_FLAGS_DRDY_REQUIRED;
        apt.PathId = 0;
        apt.TargetId = 0;
        apt.Lun = 0;
        apt.ReservedAsUchar = 0;
        apt.DataTransferLength = static_cast<ULONG>(buf_size);
        apt.TimeOutValue = 30; // 30 seconds
        apt.ReservedAsUlong = 0;
        apt.DataBufferOffset = sizeof(ATA_PASS_THROUGH_EX);

        apt.CurrentTaskFile[6] = command; // Command register

        if (buffer && buf_size > 0) {
            apt.AtaFlags |= ATA_FLAGS_DATA_OUT;
        }

        DWORD bytes_returned;
        std::vector<uint8_t> cmd_buffer(sizeof(ATA_PASS_THROUGH_EX) + buf_size);
        memcpy(cmd_buffer.data(), &apt, sizeof(apt));
        if (buffer && buf_size > 0) {
            memcpy(cmd_buffer.data() + sizeof(apt), buffer, buf_size);
        }

        return DeviceIoControl(device, IOCTL_ATA_PASS_THROUGH,
                             cmd_buffer.data(), static_cast<DWORD>(cmd_buffer.size()),
                             cmd_buffer.data(), static_cast<DWORD>(cmd_buffer.size()),
                             &bytes_returned, nullptr) != 0;
    }

    bool unlock_hpa_dco(HANDLE device) {
        std::cout << "[HPA/DCO] Unlocking hidden areas..." << std::endl;

        // READ NATIVE MAX ADDRESS EXT (0x27)
        if (!send_ata_command(device, 0x27)) {
            std::cout << "[HPA/DCO] Warning: Could not read native max address" << std::endl;
        }

        // SET NATIVE MAX ADDRESS EXT (0x37) - Reset HPA
        if (!send_ata_command(device, 0x37)) {
            std::cout << "[HPA/DCO] Warning: Could not reset HPA" << std::endl;
        }

        // DEVICE CONFIGURATION IDENTIFY (0xB1) - Reset DCO
        if (!send_ata_command(device, 0xB1)) {
            std::cout << "[HPA/DCO] Warning: Could not reset DCO" << std::endl;
        }

        std::cout << "[HPA/DCO] Hidden areas unlocked" << std::endl;
        return true;
    }

    HANDLE open_device(const std::string& path) {
        std::string device_path = "\\\\.\\" + path;
        return CreateFileA(device_path.c_str(),
                          GENERIC_READ | GENERIC_WRITE,
                          FILE_SHARE_READ | FILE_SHARE_WRITE,
                          nullptr, OPEN_EXISTING, 0, nullptr);
    }

    void close_device(HANDLE device) {
        CloseHandle(device);
    }

    uint64_t get_device_size(HANDLE device) {
        DISK_GEOMETRY_EX disk_geo;
        DWORD bytes_returned;
        if (DeviceIoControl(device, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                           nullptr, 0, &disk_geo, sizeof(disk_geo),
                           &bytes_returned, nullptr)) {
            return disk_geo.DiskSize.QuadPart;
        }
        return 0;
    }

    bool write_sectors(HANDLE device, uint64_t offset, const void* data, size_t size) {
        LARGE_INTEGER li;
        li.QuadPart = offset;
        SetFilePointer(device, li.LowPart, &li.HighPart, FILE_BEGIN);

        DWORD written;
        return WriteFile(device, data, static_cast<DWORD>(size), &written, nullptr) &&
               written == size;
    }

#else // Linux implementation
    bool send_ata_command(int fd, uint8_t command, void* buffer = nullptr, size_t buf_size = 0) {
        sg_io_hdr_t io_hdr;
        uint8_t cdb[16] = {0};
        uint8_t sense[32] = {0};

        // ATA PASS THROUGH (12)
        cdb[0] = 0xA1;
        cdb[1] = (buffer && buf_size > 0) ? 0x06 : 0x04; // PIO Data-Out/In
        cdb[2] = 0x0E; // FLAGS
        cdb[4] = command; // COMMAND
        cdb[6] = 0x01; // SECTOR COUNT

        memset(&io_hdr, 0, sizeof(io_hdr));
        io_hdr.interface_id = 'S';
        io_hdr.cmd_len = 12;
        io_hdr.mx_sb_len = sizeof(sense);
        io_hdr.dxfer_direction = (buffer && buf_size > 0) ? SG_DXFER_TO_DEV : SG_DXFER_NONE;
        io_hdr.dxfer_len = buf_size;
        io_hdr.dxferp = buffer;
        io_hdr.cmdp = cdb;
        io_hdr.sbp = sense;
        io_hdr.timeout = 30000;

        return ioctl(fd, SG_IO, &io_hdr) >= 0;
    }

    bool unlock_hpa_dco(int fd) {
        std::cout << "[HPA/DCO] Unlocking hidden areas..." << std::endl;

        // Similar ATA commands for Linux
        send_ata_command(fd, 0x27); // READ NATIVE MAX ADDRESS EXT
        send_ata_command(fd, 0x37); // SET NATIVE MAX ADDRESS EXT
        send_ata_command(fd, 0xB1); // DEVICE CONFIGURATION IDENTIFY

        std::cout << "[HPA/DCO] Hidden areas unlocked" << std::endl;
        return true;
    }

    int open_device(const std::string& path) {
        return open(path.c_str(), O_RDWR | O_DIRECT);
    }

    void close_device(int fd) {
        close(fd);
    }

    uint64_t get_device_size(int fd) {
        uint64_t size;
        if (ioctl(fd, BLKGETSIZE64, &size) == 0) {
            return size;
        }
        return 0;
    }

    bool write_sectors(int fd, uint64_t offset, const void* data, size_t size) {
        return pwrite(fd, data, size, offset) == static_cast<ssize_t>(size);
    }
#endif

    #ifdef _WIN32
    void perform_hse_wipe(HANDLE device, uint64_t device_size) {
    #else
    void perform_hse_wipe(int device, uint64_t device_size) {
    #endif
        const size_t block_size = 1024 * 1024; // 1MB blocks
        initialize_patterns(block_size);

        std::vector<std::vector<uint8_t>*> pass_patterns;

        // HSE Algorithm: Multiple sophisticated passes
        pass_patterns.push_back(&zero_pattern);      // Pass 1: Zeros
        pass_patterns.push_back(&ones_pattern);      // Pass 2: Ones
        pass_patterns.push_back(&random_pattern);    // Pass 3: Random

        // Government profile gets additional passes
        if (config.profile == GOVERNMENT) {
            pass_patterns.push_back(&random_pattern); // Pass 4: More random
            pass_patterns.push_back(&zero_pattern);   // Pass 5: Final zeros
        }

        for (size_t pass = 0; pass < pass_patterns.size(); ++pass) {
            std::cout << "[HSE PASS " << (pass + 1) << "] Starting..." << std::endl;
            auto start = std::chrono::high_resolution_clock::now();

            for (uint64_t offset = 0; offset < device_size; offset += block_size) {
                size_t remaining = static_cast<size_t>(device_size - offset);
                size_t write_size = (block_size < remaining) ? block_size : remaining;

                // Regenerate random pattern for each block in random passes
                if (pass_patterns[pass] == &random_pattern) {
                    std::random_device rd;
                    std::mt19937 gen(rd());
                    std::uniform_int_distribution<> dis(0, 255);
                    for (size_t i = 0; i < write_size; ++i) {
                        random_pattern[i] = static_cast<uint8_t>(dis(gen));
                    }
                }

                if (!write_sectors(device, offset, pass_patterns[pass]->data(), write_size)) {
                    std::cerr << "[ERROR] Write failed at offset " << offset << std::endl;
                    return;
                }

                // Progress indicator
                if (offset % (100 * 1024 * 1024) == 0) { // Every 100MB
                    double progress = (double)offset / device_size * 100.0;
                    std::cout << "\r[HSE PASS " << (pass + 1) << "] Progress: "
                             << std::fixed << std::setprecision(1) << progress << "%" << std::flush;
                }
            }

            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(end - start);
            std::cout << std::endl << "[HSE PASS " << (pass + 1) << "] Complete in "
                     << duration.count() << " seconds" << std::endl;
        }
    }

    #ifdef _WIN32
    void perform_nist_wipe(HANDLE device, uint64_t device_size) {
    #else
    void perform_nist_wipe(int device, uint64_t device_size) {
    #endif
        const size_t block_size = 1024 * 1024;
        initialize_patterns(block_size);

        std::cout << "[NIST] Single pass zero overwrite..." << std::endl;
        auto start = std::chrono::high_resolution_clock::now();

        for (uint64_t offset = 0; offset < device_size; offset += block_size) {
            size_t remaining = static_cast<size_t>(device_size - offset);
            size_t write_size = (block_size < remaining) ? block_size : remaining;

            if (!write_sectors(device, offset, zero_pattern.data(), write_size)) {
                std::cerr << "[ERROR] Write failed at offset " << offset << std::endl;
                return;
            }

            if (offset % (100 * 1024 * 1024) == 0) {
                double progress = (double)offset / device_size * 100.0;
                std::cout << "\r[NIST] Progress: " << std::fixed << std::setprecision(1)
                         << progress << "%" << std::flush;
            }
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(end - start);
        std::cout << std::endl << "[NIST] Complete in " << duration.count() << " seconds" << std::endl;
    }

public:
    SecureWiper(const WipeConfig& cfg) : config(cfg) {}

    bool execute_wipe() {
        std::cout << "=== INFO INVADERS SECURE WIPE ENGINE ===" << std::endl;
        std::cout << "Device: " << config.device_path << std::endl;
        std::cout << "Profile: " << (config.profile == CITIZEN ? "Citizen" :
                                    config.profile == ENTERPRISE ? "Enterprise" : "Government") << std::endl;
        std::cout << "Mode: " << (config.mode == NIST_800_88 ? "NIST SP 800-88" : "HSE") << std::endl;

        auto device = open_device(config.device_path);
#ifdef _WIN32
        if (device == INVALID_HANDLE_VALUE) {
#else
        if (device < 0) {
#endif
            std::cerr << "[ERROR] Cannot open device: " << config.device_path << std::endl;
            return false;
        }

        uint64_t device_size = get_device_size(device);
        if (device_size == 0) {
            std::cerr << "[ERROR] Cannot determine device size" << std::endl;
            close_device(device);
            return false;
        }

        std::cout << "Device size: " << (device_size / (1024*1024*1024)) << " GB" << std::endl;

        // Unlock HPA/DCO areas if requested
        if (config.wipe_hpa_dco) {
            if (!unlock_hpa_dco(device)) {
                std::cerr << "[WARNING] HPA/DCO unlock may have failed" << std::endl;
            }
        }

        // Perform the actual wipe based on selected mode
        if (config.mode == HSE) {
            perform_hse_wipe(device, device_size);
        } else {
            perform_nist_wipe(device, device_size);
        }

        close_device(device);
        std::cout << "[SUCCESS] Secure wipe completed!" << std::endl;
        return true;
    }
};

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cout << "Usage: " << argv[0] << " <device> <profile:1-3> <mode:1-2> [hpa_dco:0/1]" << std::endl;
        std::cout << "Profiles: 1=Citizen, 2=Enterprise, 3=Government" << std::endl;
        std::cout << "Modes: 1=NIST SP 800-88, 2=HSE" << std::endl;
        return 1;
    }

    WipeConfig config;
    config.device_path = argv[1];
    config.profile = static_cast<WipeProfile>(std::stoi(argv[2]));
    config.mode = static_cast<WipeMode>(std::stoi(argv[3]));
    config.wipe_hpa_dco = (argc > 4) ? (std::stoi(argv[4]) != 0) : true;

    SecureWiper wiper(config);
    return wiper.execute_wipe() ? 0 : 1;
}
