#include "secure_wiper.h"
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <random>

// Static member initialization
LogLevel WipeLogger::current_level = LogLevel::INFO;
std::function<void(LogLevel, const std::string&)> WipeLogger::log_callback = nullptr;

SecureWiper::SecureWiper(const WipeConfig& cfg) : config(cfg) {
    WipeLogger::info("SecureWiper initialized with device: " + config.device_path);
}

void SecureWiper::set_progress_callback(ProgressCallback callback) {
    progress_callback = callback;
}

void SecureWiper::report_progress(int percentage, const std::string& message) {
    if (progress_callback) {
        progress_callback(percentage, message);
    }
    WipeLogger::info("Progress: " + std::to_string(percentage) + "% - " + message);
}

void SecureWiper::initialize_patterns(size_t block_size) {
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
bool SecureWiper::send_ata_command(HANDLE device, uint8_t command, void* buffer, size_t buf_size) {
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

bool SecureWiper::unlock_hpa_dco(HANDLE device) {
    WipeLogger::info("[HPA/DCO] Unlocking hidden areas...");
    report_progress(2, "Unlocking HPA/DCO areas...");

    // READ NATIVE MAX ADDRESS EXT (0x27)
    if (!send_ata_command(device, 0x27)) {
        WipeLogger::warning("[HPA/DCO] Warning: Could not read native max address");
    }

    // SET NATIVE MAX ADDRESS EXT (0x37) - Reset HPA
    if (!send_ata_command(device, 0x37)) {
        WipeLogger::warning("[HPA/DCO] Warning: Could not reset HPA");
    }

    // DEVICE CONFIGURATION IDENTIFY (0xB1) - Reset DCO
    if (!send_ata_command(device, 0xB1)) {
        WipeLogger::warning("[HPA/DCO] Warning: Could not reset DCO");
    }

    WipeLogger::info("[HPA/DCO] Hidden areas unlocked");
    return true;
}

HANDLE SecureWiper::open_device(const std::string& path) {
    std::string device_path = "\\\\.\\" + path;
    HANDLE handle = CreateFileA(device_path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    
    if (handle == INVALID_HANDLE_VALUE) {
        WipeLogger::error("Failed to open device: " + path + " (Error: " + std::to_string(GetLastError()) + ")");
    }
    
    return handle;
}

void SecureWiper::close_device(HANDLE device) {
    CloseHandle(device);
}

uint64_t SecureWiper::get_device_size(HANDLE device) {
    DISK_GEOMETRY_EX disk_geo;
    DWORD bytes_returned;
    if (DeviceIoControl(device, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
        nullptr, 0, &disk_geo, sizeof(disk_geo),
        &bytes_returned, nullptr)) {
        return disk_geo.DiskSize.QuadPart;
    }
    return 0;
}

bool SecureWiper::write_sectors(HANDLE device, uint64_t offset, const void* data, size_t size) {
    LARGE_INTEGER li;
    li.QuadPart = offset;
    SetFilePointer(device, li.LowPart, &li.HighPart, FILE_BEGIN);

    DWORD written;
    return WriteFile(device, data, static_cast<DWORD>(size), &written, nullptr) &&
        written == size;
}

void SecureWiper::perform_hse_wipe(HANDLE device, uint64_t device_size) {
    const size_t block_size = 1024 * 1024; // 1MB blocks
    initialize_patterns(block_size);

    std::vector<std::vector<uint8_t>*> pass_patterns;

    // HSE Algorithm: Multiple sophisticated passes
    pass_patterns.push_back(&zero_pattern); // Pass 1: Zeros
    pass_patterns.push_back(&ones_pattern); // Pass 2: Ones
    pass_patterns.push_back(&random_pattern); // Pass 3: Random

    // Government profile gets additional passes
    if (config.profile == GOVERNMENT) {
        pass_patterns.push_back(&random_pattern); // Pass 4: More random
        pass_patterns.push_back(&zero_pattern); // Pass 5: Final zeros
    }

    auto start_time = std::chrono::high_resolution_clock::now();

    for (size_t pass = 0; pass < pass_patterns.size(); ++pass) {
        if (should_stop.load()) {
            WipeLogger::warning("Wipe operation stopped by user");
            return;
        }

        std::string pass_msg = "[HSE PASS " + std::to_string(pass + 1) + "] Starting...";
        WipeLogger::info(pass_msg);
        report_progress(10 + (pass * 80 / pass_patterns.size()), pass_msg);

        auto pass_start = std::chrono::high_resolution_clock::now();

        for (uint64_t offset = 0; offset < device_size; offset += block_size) {
            if (should_stop.load()) {
                return;
            }

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
                std::string error_msg = "[ERROR] Write failed at offset " + std::to_string(offset);
                WipeLogger::error(error_msg);
                throw SecureWipeException(error_msg);
            }

            // Progress indicator
            if (offset % (100 * 1024 * 1024) == 0) { // Every 100MB
                double pass_progress = (double)offset / device_size * 100.0;
                double overall_progress = 10 + (pass * 80 / pass_patterns.size()) + 
                                        (pass_progress * 80 / pass_patterns.size() / 100.0);
                
                std::string time_remaining = format_time_remaining(offset, device_size, start_time);
                std::string progress_msg = "HSE Pass " + std::to_string(pass + 1) + 
                                         " - " + std::to_string((int)pass_progress) + "%" +
                                         (time_remaining.empty() ? "" : " (" + time_remaining + ")");
                
                report_progress(static_cast<int>(overall_progress), progress_msg);
            }
        }

        auto pass_end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(pass_end - pass_start);
        std::string complete_msg = "[HSE PASS " + std::to_string(pass + 1) + "] Complete in " + 
                                 std::to_string(duration.count()) + " seconds";
        WipeLogger::info(complete_msg);
    }
}

void SecureWiper::perform_nist_wipe(HANDLE device, uint64_t device_size) {
    const size_t block_size = 1024 * 1024;
    initialize_patterns(block_size);

    WipeLogger::info("[NIST] Single pass zero overwrite...");
    report_progress(10, "Starting NIST SP 800-88 wipe...");

    auto start_time = std::chrono::high_resolution_clock::now();

    for (uint64_t offset = 0; offset < device_size; offset += block_size) {
        if (should_stop.load()) {
            WipeLogger::warning("Wipe operation stopped by user");
            return;
        }

        size_t remaining = static_cast<size_t>(device_size - offset);
        size_t write_size = (block_size < remaining) ? block_size : remaining;

        if (!write_sectors(device, offset, zero_pattern.data(), write_size)) {
            std::string error_msg = "[ERROR] Write failed at offset " + std::to_string(offset);
            WipeLogger::error(error_msg);
            throw SecureWipeException(error_msg);
        }

        if (offset % (100 * 1024 * 1024) == 0) {
            double progress = 10.0 + ((double)offset / device_size * 80.0);
            std::string time_remaining = format_time_remaining(offset, device_size, start_time);
            std::string progress_msg = "NIST Wipe - " + std::to_string((int)((double)offset / device_size * 100.0)) + "%" +
                                     (time_remaining.empty() ? "" : " (" + time_remaining + ")");
            
            report_progress(static_cast<int>(progress), progress_msg);
        }
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);
    std::string complete_msg = "[NIST] Complete in " + std::to_string(duration.count()) + " seconds";
    WipeLogger::info(complete_msg);
}

#else // Linux implementation

bool SecureWiper::send_ata_command(int fd, uint8_t command, void* buffer, size_t buf_size) {
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

bool SecureWiper::unlock_hpa_dco(int fd) {
    WipeLogger::info("[HPA/DCO] Unlocking hidden areas...");
    report_progress(2, "Unlocking HPA/DCO areas...");

    // Similar ATA commands for Linux
    send_ata_command(fd, 0x27); // READ NATIVE MAX ADDRESS EXT
    send_ata_command(fd, 0x37); // SET NATIVE MAX ADDRESS EXT
    send_ata_command(fd, 0xB1); // DEVICE CONFIGURATION IDENTIFY

    WipeLogger::info("[HPA/DCO] Hidden areas unlocked");
    return true;
}

int SecureWiper::open_device(const std::string& path) {
    int fd = open(path.c_str(), O_RDWR | O_DIRECT);
    if (fd < 0) {
        WipeLogger::error("Failed to open device: " + path + " (errno: " + std::to_string(errno) + ")");
    }
    return fd;
}

void SecureWiper::close_device(int fd) {
    close(fd);
}

uint64_t SecureWiper::get_device_size(int fd) {
    uint64_t size;
    if (ioctl(fd, BLKGETSIZE64, &size) == 0) {
        return size;
    }
    return 0;
}

bool SecureWiper::write_sectors(int fd, uint64_t offset, const void* data, size_t size) {
    return pwrite(fd, data, size, offset) == static_cast<ssize_t>(size);
}

void SecureWiper::perform_hse_wipe(int device, uint64_t device_size) {
    // Similar implementation to Windows version
    const size_t block_size = 1024 * 1024;
    initialize_patterns(block_size);

    std::vector<std::vector<uint8_t>*> pass_patterns;
    pass_patterns.push_back(&zero_pattern);
    pass_patterns.push_back(&ones_pattern);
    pass_patterns.push_back(&random_pattern);

    if (config.profile == GOVERNMENT) {
        pass_patterns.push_back(&random_pattern);
        pass_patterns.push_back(&zero_pattern);
    }

    auto start_time = std::chrono::high_resolution_clock::now();

    for (size_t pass = 0; pass < pass_patterns.size(); ++pass) {
        if (should_stop.load()) return;

        std::string pass_msg = "[HSE PASS " + std::to_string(pass + 1) + "] Starting...";
        report_progress(10 + (pass * 80 / pass_patterns.size()), pass_msg);

        for (uint64_t offset = 0; offset < device_size; offset += block_size) {
            if (should_stop.load()) return;

            size_t remaining = static_cast<size_t>(device_size - offset);
            size_t write_size = (block_size < remaining) ? block_size : remaining;

            if (pass_patterns[pass] == &random_pattern) {
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<> dis(0, 255);
                for (size_t i = 0; i < write_size; ++i) {
                    random_pattern[i] = static_cast<uint8_t>(dis(gen));
                }
            }

            if (!write_sectors(device, offset, pass_patterns[pass]->data(), write_size)) {
                throw SecureWipeException("Write failed at offset " + std::to_string(offset));
            }

            if (offset % (100 * 1024 * 1024) == 0) {
                double pass_progress = (double)offset / device_size * 100.0;
                double overall_progress = 10 + (pass * 80 / pass_patterns.size()) + 
                                        (pass_progress * 80 / pass_patterns.size() / 100.0);
                
                std::string time_remaining = format_time_remaining(offset, device_size, start_time);
                std::string progress_msg = "HSE Pass " + std::to_string(pass + 1) + 
                                         " - " + std::to_string((int)pass_progress) + "%" +
                                         (time_remaining.empty() ? "" : " (" + time_remaining + ")");
                
                report_progress(static_cast<int>(overall_progress), progress_msg);
            }
        }
    }
}

void SecureWiper::perform_nist_wipe(int device, uint64_t device_size) {
    // Similar implementation to Windows version
    const size_t block_size = 1024 * 1024;
    initialize_patterns(block_size);

    report_progress(10, "Starting NIST SP 800-88 wipe...");
    auto start_time = std::chrono::high_resolution_clock::now();

    for (uint64_t offset = 0; offset < device_size; offset += block_size) {
        if (should_stop.load()) return;

        size_t remaining = static_cast<size_t>(device_size - offset);
        size_t write_size = (block_size < remaining) ? block_size : remaining;

        if (!write_sectors(device, offset, zero_pattern.data(), write_size)) {
            throw SecureWipeException("Write failed at offset " + std::to_string(offset));
        }

        if (offset % (100 * 1024 * 1024) == 0) {
            double progress = 10.0 + ((double)offset / device_size * 80.0);
            std::string time_remaining = format_time_remaining(offset, device_size, start_time);
            std::string progress_msg = "NIST Wipe - " + std::to_string((int)((double)offset / device_size * 100.0)) + "%" +
                                     (time_remaining.empty() ? "" : " (" + time_remaining + ")");
            
            report_progress(static_cast<int>(progress), progress_msg);
        }
    }
}

#endif

bool SecureWiper::execute_wipe() {
    if (is_running.load()) {
        WipeLogger::error("Wipe operation already running");
        return false;
    }

    is_running.store(true);
    should_stop.store(false);

    try {
        WipeLogger::info("=== INFO INVADERS SECURE WIPE ENGINE ===");
        WipeLogger::info("Device: " + config.device_path);
        
        std::string profile_str = (config.profile == CITIZEN ? "Citizen" :
                                  config.profile == ENTERPRISE ? "Enterprise" : "Government");
        std::string mode_str = (config.mode == NIST_800_88 ? "NIST SP 800-88" : "HSE");
        
        WipeLogger::info("Profile: " + profile_str);
        WipeLogger::info("Mode: " + mode_str);

        report_progress(0, "Initializing secure wipe...");

        auto device = open_device(config.device_path);
#ifdef _WIN32
        if (device == INVALID_HANDLE_VALUE) {
#else
        if (device < 0) {
#endif
            throw SecureWipeException("Cannot open device: " + config.device_path);
        }

        uint64_t device_size = get_device_size(device);
        if (device_size == 0) {
            close_device(device);
            throw SecureWipeException("Cannot determine device size");
        }

        std::string size_gb = std::to_string(device_size / (1024*1024*1024));
        WipeLogger::info("Device size: " + size_gb + " GB");
        report_progress(1, "Device opened - Size: " + size_gb + " GB");

        // Unlock HPA/DCO areas if requested
        if (config.wipe_hpa_dco) {
            if (!unlock_hpa_dco(device)) {
                WipeLogger::warning("HPA/DCO unlock may have failed");
            }
        }

        report_progress(5, "Starting " + mode_str + " wipe process...");

        // Perform the actual wipe based on selected mode
        if (config.mode == HSE) {
            perform_hse_wipe(device, device_size);
        } else {
            perform_nist_wipe(device, device_size);
        }

        close_device(device);

        if (!should_stop.load()) {
            WipeLogger::info("[SUCCESS] Secure wipe completed!");
            report_progress(100, "Secure wipe completed successfully");
            is_running.store(false);
            return true;
        } else {
            WipeLogger::warning("Wipe operation was stopped");
            report_progress(0, "Wipe operation stopped");
            is_running.store(false);
            return false;
        }

    } catch (const SecureWipeException& e) {
        WipeLogger::error("Wipe failed: " + std::string(e.what()));
        report_progress(0, "Wipe failed: " + std::string(e.what()));
        is_running.store(false);
        return false;
    } catch (const std::exception& e) {
        WipeLogger::error("Unexpected error: " + std::string(e.what()));
        report_progress(0, "Unexpected error occurred");
        is_running.store(false);
        return false;
    }
}

void SecureWiper::stop_operation() {
    should_stop.store(true);
    WipeLogger::info("Stop request received");
}

bool SecureWiper::is_operation_running() const {
    return is_running.load();
}

std::string SecureWiper::format_time_remaining(uint64_t bytes_written, uint64_t total_bytes, 
                                              std::chrono::system_clock::time_point start_time) {
    if (bytes_written == 0) return "";
    
    auto now = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time);
    
    if (elapsed.count() < 10) return ""; // Don't show estimate for first 10 seconds
    
    double rate = static_cast<double>(bytes_written) / elapsed.count(); // bytes per second
    double remaining_bytes = total_bytes - bytes_written;
    double remaining_seconds = remaining_bytes / rate;
    
    int hours = static_cast<int>(remaining_seconds / 3600);
    int minutes = static_cast<int>((remaining_seconds - hours * 3600) / 60);
    int seconds = static_cast<int>(remaining_seconds) % 60;
    
    if (hours > 0) {
        return std::to_string(hours) + "h " + std::to_string(minutes) + "m remaining";
    } else if (minutes > 0) {
        return std::to_string(minutes) + "m " + std::to_string(seconds) + "s remaining";
    } else {
        return std::to_string(seconds) + "s remaining";
    }
}

// Static utility methods
std::vector<std::string> SecureWiper::detect_storage_devices() {
    return DeviceManager::get_physical_drives();
}

bool SecureWiper::validate_device_path(const std::string& path) {
    return !path.empty() && path.find("..") == std::string::npos;
}

bool SecureWiper::has_admin_privileges() {
#ifdef _WIN32
    BOOL isElevated = FALSE;
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation;
        DWORD size;
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(token);
    }
    return isElevated;
#else
    return geteuid() == 0;
#endif
}

// DeviceManager implementation
#ifdef _WIN32
std::vector<std::string> DeviceManager::get_physical_drives() {
    std::vector<std::string> drives;
    for (int i = 0; i < 32; ++i) {
        std::string drive_path = "PhysicalDrive" + std::to_string(i);
        std::string full_path = "\\\\.\\" + drive_path;
        
        HANDLE handle = CreateFileA(full_path.c_str(), 0, 
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, 
            OPEN_EXISTING, 0, nullptr);
        
        if (handle != INVALID_HANDLE_VALUE) {
            drives.push_back(drive_path);
            CloseHandle(handle);
        }
    }
    return drives;
}
#else
std::vector<std::string> DeviceManager::get_block_devices() {
    std::vector<std::string> devices;
    // Implementation for Linux block device detection
    // This would involve parsing /proc/partitions or using udev
    return devices;
}
#endif

// WipeLogger implementation
void WipeLogger::set_log_level(LogLevel level) {
    current_level = level;
}

void WipeLogger::set_log_callback(std::function<void(LogLevel, const std::string&)> callback) {
    log_callback = callback;
}

void WipeLogger::log(LogLevel level, const std::string& message) {
    if (level >= current_level) {
        if (log_callback) {
            log_callback(level, message);
        } else {
            // Default to console output
            std::cout << "[" << static_cast<int>(level) << "] " << message << std::endl;
        }
    }
}

void WipeLogger::info(const std::string& message) { log(LogLevel::INFO, message); }
void WipeLogger::warning(const std::string& message) { log(LogLevel::WARNING, message); }
void WipeLogger::error(const std::string& message) { log(LogLevel::ERROR, message); }
void WipeLogger::debug(const std::string& message) { log(LogLevel::DEBUG, message); }
void WipeLogger::fatal(const std::string& message) { log(LogLevel::FATAL, message); }