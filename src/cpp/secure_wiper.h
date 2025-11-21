#pragma once
#include "WipeLogger.h"
#include <string>
#include <vector>
#include <algorithm>
#include <initializer_list>
#include <iostream>
#include <fstream>
#include <chrono>
#include <cstring>
#include <random>
#include <system_error>
#include <sstream>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <fileapi.h>
#include <winioctl.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <linux/fs.h>
#include <linux/hdreg.h>
#endif


// --------------------- WipeLogger implementation ---------------------
LogLevel WipeLogger::current_level = LOG_INFO;
std::function<void(LogLevel, const std::string&)> WipeLogger::log_callback = nullptr;

void WipeLogger::set_log_level(LogLevel level) { current_level = level; }
void WipeLogger::set_log_callback(std::function<void(LogLevel, const std::string&)> callback) { log_callback = callback; }

static const char* level_to_label(LogLevel l) {
    switch (l) {
        case LOG_DEBUG: return "DEBUG";
        case LOG_INFO: return "INFO";
        case LOG_WARNING: return "WARNING";
        case LOG_ERROR: return "ERROR";
        case LOG_FATAL: return "FATAL";
        default: return "LOG";
    }
}

void WipeLogger::log(LogLevel level, const std::string& message) {
    if (level < current_level) return;
    if (log_callback) {
        log_callback(level, message);
        return;
    }
    std::cerr << "[" << level_to_label(level) << "] " << message << std::endl;
}
void WipeLogger::debug(const std::string& m) { log(LOG_DEBUG, m); }
void WipeLogger::info(const std::string& m) { log(LOG_INFO, m); }
void WipeLogger::warning(const std::string& m) { log(LOG_WARNING, m); }
void WipeLogger::error(const std::string& m) { log(LOG_ERROR, m); }
void WipeLogger::fatal(const std::string& m) { log(LOG_FATAL, m); }

// --------------------- Helpers ---------------------
static void fill_pattern(std::vector<uint8_t>& buf, uint8_t byte) {
    std::fill(buf.begin(), buf.end(), byte);
}
static void fill_random(std::vector<uint8_t>& buf) {
    static thread_local std::mt19937_64 rng((uint64_t)std::random_device{}());
    std::uniform_int_distribution<uint32_t> d(0, 0xFFFFFFFF);
    uint8_t *p = buf.data();
    size_t remaining = buf.size();
    while (remaining >= 4) {
        uint32_t v = d(rng);
        std::memcpy(p, &v, 4);
        p += 4; remaining -= 4;
    }
    for (size_t i = 0; i < remaining; ++i) p[i] = static_cast<uint8_t>(d(rng) & 0xFF);
}

static std::string human_readable_size(uint64_t s) {
    const char* units[] = {"B","KB","MB","GB","TB"};
    double size = (double)s;
    int unit = 0;
    while (size >= 1024.0 && unit < 4) { size /= 1024.0; ++unit; }
    char buf[64];
    snprintf(buf, sizeof(buf), "%.2f %s", size, units[unit]);
    return std::string(buf);
}

// --------------------- SecureWiper methods ---------------------
SecureWiper::SecureWiper(const WipeConfig& cfg) : config(cfg) {
    initialize_patterns(4 * 1024 * 1024); // 4MB buffer default
}

void SecureWiper::initialize_patterns(size_t block_size) {
    zero_pattern.assign(block_size, 0x00);
    ones_pattern.assign(block_size, 0xFF);
    random_pattern.assign(block_size, 0x00);
}

void SecureWiper::set_progress_callback(ProgressCallback callback) {
    progress_callback = callback;
}

void SecureWiper::report_progress(int percentage, const std::string& message) {
    if (progress_callback) progress_callback(percentage, message);
}

WipeProgress SecureWiper::get_current_progress() const {
    return {0, "N/A", "Not implemented", std::chrono::system_clock::now()};
}

void SecureWiper::stop_operation() {
    should_stop = true;
}

bool SecureWiper::is_operation_running() const {
    return is_running.load();
}

// Format ETA (system_clock used in header): returns string like "MM:SS remaining"
std::string SecureWiper::format_time_remaining(uint64_t bytes_written, uint64_t total_bytes,
                                               std::chrono::system_clock::time_point start_ts) {
    if (bytes_written == 0) return "Calculating...";
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_ts).count();
    if (elapsed <= 0) elapsed = 1;
    double rate = double(bytes_written) / double(elapsed); // bytes/sec
    double remaining_seconds = double(total_bytes - bytes_written) / std::max(1.0, rate);
    int mins = int(remaining_seconds) / 60;
    int secs = int(remaining_seconds) % 60;
    char buf[64];
    snprintf(buf, sizeof(buf), "%02d:%02d remaining", mins, secs);
    return std::string(buf);
}


// --------------------- Platform device helpers ---------------------
#ifdef _WIN32

static HANDLE open_raw_device_win(const std::string& path) {
    // path should be like "\\\\.\\PhysicalDrive0" or a volume path like "\\\\.\\C:"
    HANDLE h = CreateFileA(
        path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    return h;
}

static uint64_t get_device_size_win(HANDLE h) {
    // Use IOCTL_DISK_GET_LENGTH_INFO
    if (h == INVALID_HANDLE_VALUE) return 0;
    GET_LENGTH_INFORMATION lenInfo;
    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(h, IOCTL_DISK_GET_LENGTH_INFO, nullptr, 0, &lenInfo, sizeof(lenInfo), &bytes, nullptr);
    if (!ok) return 0;
    return static_cast<uint64_t>(lenInfo.Length.QuadPart);
}

static void flush_and_close_win(HANDLE h) {
    if (h == INVALID_HANDLE_VALUE) return;
    FlushFileBuffers(h);
    CloseHandle(h);
}

static bool raw_write_win(HANDLE h, uint64_t offset, const uint8_t* buf, size_t buf_size) {
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER li;
    li.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(h, li, nullptr, FILE_BEGIN)) return false;
    DWORD written = 0;
    BOOL ok = WriteFile(h, buf, static_cast<DWORD>(buf_size), &written, nullptr);
    if (!ok) return false;
    return written == buf_size;
}

#else // POSIX/Linux

static int open_raw_device_posix(const std::string& path) {
    int fd = ::open(path.c_str(), O_RDWR | O_SYNC | O_DIRECT);
    // If O_DIRECT fails (not supported on this FS), fallback
    if (fd < 0) {
        fd = ::open(path.c_str(), O_RDWR | O_SYNC);
    }
    return fd;
}

static uint64_t get_device_size_posix(int fd, const std::string& path) {
    if (fd < 0) return 0;
    uint64_t size = 0;
    // Try BLKGETSIZE64
    int r = ioctl(fd, BLKGETSIZE64, &size);
    if (r == 0) return size;
    // fallback: stat the device path (works for /dev/loop etc.)
    struct stat st;
    if (stat(path.c_str(), &st) == 0) {
        // if character/block device, size may not be available
        // return 0 in fallback
        (void)st;
    }
    return 0;
}

static void flush_and_close_posix(int fd) {
    if (fd >= 0) {
        fsync(fd);
        close(fd);
    }
}

static bool raw_write_posix(int fd, uint64_t offset, const uint8_t* buf, size_t buf_size) {
    if (fd < 0) return false;
    ssize_t w = pwrite(fd, buf, buf_size, offset);
    return (w == (ssize_t)buf_size);
}

#endif

// --------------------- High-level wipe execution ---------------------

static const size_t IO_CHUNK = 4 * 1024 * 1024; // 4MB

void SecureWiper::perform_nist_wipe(
#ifdef _WIN32
    HANDLE device,
#else
    int device,
#endif
    uint64_t device_size
) {
    // NIST 800-88: simple approach — single pass zero, then single pass random (commonly acceptable)
    // Implemented here: depending on config.passes we repeat patterns.
    const size_t chunk = std::min<size_t>(IO_CHUNK, zero_pattern.size());
    uint64_t total = device_size;
    uint64_t written = 0;

    auto start_ts = std::chrono::system_clock::now();
    is_running = true;
    should_stop = false;

    for (int pass = 0; pass < std::max(1, config.passes) && !should_stop; ++pass) {
        // Choose pattern: even pass -> zeros, odd -> random
        bool use_random = (pass % 2 == 1) || (config.mode == HSE && pass % 3 == 2);
        WipeLogger::info("Starting pass " + std::to_string(pass + 1) + (use_random ? " (random)" : " (zeros)"));
        // Prepare buffer per pass
        std::vector<uint8_t> buf(chunk);
        if (use_random) fill_random(buf);
        else fill_pattern(buf, 0x00);

        written = 0;
        uint64_t offset = 0;
        while (offset < total && !should_stop) {
            size_t to_write = static_cast<size_t>(std::min<uint64_t>(chunk, total - offset));
            // If random, refill for each chunk to increase randomness
            if (use_random) fill_random(buf);
#ifdef _WIN32
            bool ok = raw_write_win(device, offset, buf.data(), to_write);
#else
            bool ok = raw_write_posix(device, offset, buf.data(), to_write);
#endif
            if (!ok) {
                WipeLogger::error("Write failed at offset " + std::to_string(offset));
                throw SecureWipeException("Write failure during wipe");
            }
            offset += to_write;
            written = offset;
            int percent = static_cast<int>((written * 100) / total);
            std::string eta = format_time_remaining(written, total, start_ts);
            report_progress(percent, "Pass " + std::to_string(pass + 1) + " - " + eta);
        }

        // Flush after pass
#ifdef _WIN32
        FlushFileBuffers(device);
#else
        fsync(device);
#endif
        WipeLogger::info("Completed pass " + std::to_string(pass + 1) + " on device " + config.device_path);
    }

    is_running = false;
}

void SecureWiper::perform_hse_wipe(
#ifdef _WIN32
    HANDLE device,
#else
    int device,
#endif
    uint64_t device_size
) {
    // HSE mode — custom: alternate zeros, ones, random based on passes
    const size_t chunk = std::min<size_t>(IO_CHUNK, zero_pattern.size());
    uint64_t total = device_size;
    auto start_ts = std::chrono::system_clock::now();

    is_running = true;
    should_stop = false;

    for (int pass = 0; pass < std::max(1, config.passes) && !should_stop; ++pass) {
        std::vector<uint8_t> buf(chunk);
        int mod = pass % 3;
        if (mod == 0) fill_pattern(buf, 0x00);
        else if (mod == 1) fill_pattern(buf, 0xFF);
        else fill_random(buf);

        uint64_t offset = 0;
        while (offset < total && !should_stop) {
            size_t to_write = static_cast<size_t>(std::min<uint64_t>(chunk, total - offset));
#ifdef _WIN32
            bool ok = raw_write_win(device, offset, buf.data(), to_write);
#else
            bool ok = raw_write_posix(device, offset, buf.data(), to_write);
#endif
            if (!ok) {
                WipeLogger::error("Write failed at offset " + std::to_string(offset));
                throw SecureWipeException("Write failure during HSE wipe");
            }
            offset += to_write;
            int percent = static_cast<int>((offset * 100) / total);
            std::string eta = format_time_remaining(offset, total, start_ts);
            report_progress(percent, "Pass " + std::to_string(pass + 1) + " - " + eta);
        }
#ifdef _WIN32
        FlushFileBuffers(device);
#else
        fsync(device);
#endif
        WipeLogger::info("Completed HSE pass " + std::to_string(pass + 1));
    }

    is_running = false;
}

// Central execute - opens device & runs chosen routine
bool SecureWiper::execute_wipe() {
    should_stop = false;
    is_running = true;

    WipeLogger::info("execute_wipe: verifying device accessibility for " + config.device_path);

    // Validate device path & privileges
    if (!validate_device_path(config.device_path)) {
        WipeLogger::error("Invalid device path: " + config.device_path);
        is_running = false;
        throw SecureWipeException("Invalid device path");
    }
    if (!has_admin_privileges()) {
        WipeLogger::error("Insufficient privileges to open device: " + config.device_path);
        is_running = false;
        throw SecureWipeException("Administrator/root privileges required");
    }
    if (is_system_drive(config.device_path)) {
        WipeLogger::fatal("Attempt to wipe system drive blocked: " + config.device_path);
        is_running = false;
        throw SecureWipeException("Refusing to wipe system/boot drive");
    }

#ifdef _WIN32
    HANDLE dev = open_raw_device_win(config.device_path);
    if (dev == INVALID_HANDLE_VALUE) {
        WipeLogger::error("Failed to open device: " + config.device_path);
        is_running = false;
        throw SecureWipeException("Unable to open device");
    }
    uint64_t dev_size = get_device_size_win(dev);
    if (dev_size == 0) {
        flush_and_close_win(dev);
        is_running = false;
        throw SecureWipeException("Couldn't determine device size");
    }

    WipeLogger::info("Device size: " + human_readable_size(dev_size));

    try {
        if (config.mode == NIST_800_88) perform_nist_wipe(dev, dev_size);
        else perform_hse_wipe(dev, dev_size);
    } catch (...) {
        flush_and_close_win(dev);
        is_running = false;
        throw;
    }

    flush_and_close_win(dev);
#else
    int fd = open_raw_device_posix(config.device_path);
    if (fd < 0) {
        WipeLogger::error("Failed to open device (posix): " + config.device_path + " errno=" + std::to_string(errno));
        is_running = false;
        throw SecureWipeException("Unable to open device");
    }
    uint64_t dev_size = get_device_size_posix(fd, config.device_path);
    if (dev_size == 0) {
        flush_and_close_posix(fd);
        is_running = false;
        throw SecureWipeException("Couldn't determine device size");
    }
    WipeLogger::info("Device size: " + human_readable_size(dev_size));

    try {
        if (config.mode == NIST_800_88) perform_nist_wipe(fd, dev_size);
        else perform_hse_wipe(fd, dev_size);
    } catch (...) {
        flush_and_close_posix(fd);
        is_running = false;
        throw;
    }
    flush_and_close_posix(fd);
#endif

    is_running = false;
    WipeLogger::info("execute_wipe: completed for " + config.device_path);
    return !should_stop;
}

// --------------------- Static utility implementations ---------------------

std::vector<std::string> SecureWiper::detect_storage_devices() {
    std::vector<std::string> out;
#ifdef _WIN32
    // Enumerate PhysicalDrive0..64 - best-effort
    for (int i = 0; i < 64; ++i) {
        std::string path = "\\\\.\\PhysicalDrive" + std::to_string(i);
        HANDLE h = open_raw_device_win(path);
        if (h != INVALID_HANDLE_VALUE) {
            out.push_back(path);
            CloseHandle(h);
        }
    }
#else
    // Look for /dev/sd*, /dev/nvme*n* etc.
    // Simple approach: push common devices if they exist
    std::vector<std::string> candidates = {"/dev/sda", "/dev/sdb", "/dev/nvme0n1", "/dev/mmcblk0"};
    for (auto &p : candidates) {
        struct stat st;
        if (stat(p.c_str(), &st) == 0) out.push_back(p);
    }
    // Also try scanning /sys/block
    // (Keep simple for portability)
#endif
    return out;
}

bool SecureWiper::is_device_accessible(const std::string& device_path) {
#ifdef _WIN32
    HANDLE h = open_raw_device_win(device_path);
    if (h == INVALID_HANDLE_VALUE) return false;
    CloseHandle(h);
    return true;
#else
    int fd = open_raw_device_posix(device_path);
    if (fd < 0) return false;
    close(fd);
    return true;
#endif
}

std::string SecureWiper::get_device_info(const std::string& device_path) {
    DeviceInfo di;
    try {
        di = DeviceManager::get_device_info(device_path);
    } catch (...) {}
    std::ostringstream oss;
    oss << "Model: " << di.model << ", Serial: " << di.serial << ", Size: " << human_readable_size(di.size);
    return oss.str();
}

uint64_t SecureWiper::get_device_size_static(const std::string& device_path) {
#ifdef _WIN32
    HANDLE h = open_raw_device_win(device_path);
    if (h == INVALID_HANDLE_VALUE) return 0;
    uint64_t s = get_device_size_win(h);
    CloseHandle(h);
    return s;
#else
    int fd = open_raw_device_posix(device_path);
    if (fd < 0) return 0;
    uint64_t s = get_device_size_posix(fd, device_path);
    close(fd);
    return s;
#endif
}

bool SecureWiper::validate_device_path(const std::string& path) {
    // Basic validation: non-empty and device exists & accessible
    if (path.empty()) return false;
    return is_device_accessible(path);
}

bool SecureWiper::is_system_drive(const std::string& path) {
    // Best-effort checks:
#ifdef _WIN32
    // If path contains PhysicalDrive0 assume system in many PCs (best-effort)
    std::string lower = path;
    for (auto &c: lower) c = (char)tolower(c);
    if (lower.find("physicaldrive0") != std::string::npos) return true;

    // Also try to check system drive path
    char sysdir[MAX_PATH];
    if (GetSystemDirectoryA(sysdir, MAX_PATH)) {
        std::string sys(sysdir);
        // Get drive letter like "C:\\"
        if (sys.size() >= 2) {
            std::string drive = std::string(1, sys[0]) + ":";
            // QueryDosDevice to try to map drive to physical device path
            char target[1024];
            if (QueryDosDeviceA(drive.c_str(), target, sizeof(target))) {
                std::string targetS(target);
                // if the device path contains the physical device path
                std::string lower_target = targetS;
                for (auto &c: lower_target) c = (char)tolower(c);
                if (lower.find(lower_target) != std::string::npos) return true;
            }
        }
    }
    return false;
#else
    // On Linux: check /proc/mounts for '/' mount device
    std::ifstream f("/proc/mounts");
    std::string line;
    while (std::getline(f, line)) {
        std::istringstream iss(line);
        std::string dev, mnt;
        if (!(iss >> dev >> mnt)) continue;
        if (mnt == "/") {
            // If device_path matches dev exactly or dev is a partition of device_path
            if (dev == path) return true;
            // partition like /dev/sda1 and device_path /dev/sda
            if (dev.find(path) == 0) return true;
            // otherwise not system
            break;
        }
    }
    return false;
#endif
}

bool SecureWiper::has_admin_privileges() {
#ifdef _WIN32
    BOOL fAdmin = FALSE;
    PSID administratorsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2,
                                 SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS,
                                 0,0,0,0,0,0,
                                 &administratorsGroup)) {
        CheckTokenMembership(NULL, administratorsGroup, &fAdmin);
        FreeSid(administratorsGroup);
    }
    return fAdmin != FALSE;
#else
    return (geteuid() == 0);
#endif
}

// --------------------- DeviceManager implementations ---------------------
std::vector<DeviceInfo> DeviceManager::enumerate_devices() {
    std::vector<DeviceInfo> out;
    auto paths = SecureWiper::detect_storage_devices();
    for (auto &p : paths) {
        DeviceInfo di;
        di.path = p;
        di.model = get_device_model(p);
        di.serial = get_device_serial(p);
        di.size = SecureWiper::get_device_size_static(p);
        di.is_system_drive = SecureWiper::is_system_drive(p);
        di.is_removable = false; // best-effort default
        out.push_back(di);
    }
    return out;
}

DeviceInfo DeviceManager::get_device_info(const std::string& device_path) {
    DeviceInfo di;
    di.path = device_path;
    di.model = get_device_model(device_path);
    di.serial = get_device_serial(device_path);
    di.size = SecureWiper::get_device_size_static(device_path);
    di.is_system_drive = SecureWiper::is_system_drive(device_path);
    di.is_removable = false;
    return di;
}

bool DeviceManager::is_device_ready(const std::string& device_path) {
    return SecureWiper::is_device_accessible(device_path);
}

std::string DeviceManager::get_device_serial(const std::string& device_path) {
    // Best-effort: return empty if unavailable
#ifdef _WIN32
    return std::string("UNKNOWN_SERIAL");
#else
    return std::string("UNKNOWN_SERIAL");
#endif
}

std::string DeviceManager::get_device_model(const std::string& device_path) {
#ifdef _WIN32
    return std::string("UNKNOWN_MODEL");
#else
    return std::string("UNKNOWN_MODEL");
#endif
}

#ifdef _WIN32
std::vector<std::string> DeviceManager::get_physical_drives() {
    std::vector<std::string> out;
    for (int i = 0; i < 64; ++i) {
        std::string path = "\\\\.\\PhysicalDrive" + std::to_string(i);
        HANDLE h = open_raw_device_win(path);
        if (h != INVALID_HANDLE_VALUE) {
            out.push_back(path);
            CloseHandle(h);
        }
    }
    return out;
}

std::string DeviceManager::get_drive_letter_from_physical(const std::string& physical_path) {
    // Best-effort: return "C:" if physical_path contains "PhysicalDrive0"
    if (physical_path.find("PhysicalDrive0") != std::string::npos) return "C:";
    return std::string("");
}
#else
std::vector<std::string> DeviceManager::get_block_devices() {
    std::vector<std::string> out;
    // minimal scan of common devices
    std::vector<std::string> candidates = {"/dev/sda", "/dev/sdb", "/dev/nvme0n1", "/dev/mmcblk0"};
    for (auto &p : candidates) {
        struct stat st;
        if (stat(p.c_str(), &st) == 0) out.push_back(p);
    }
    return out;
}

bool DeviceManager::is_mounted(const std::string& device_path) {
    std::ifstream f("/proc/mounts");
    std::string line;
    while (std::getline(f, line)) {
        if (line.find(device_path) != std::string::npos) return true;
    }
    return false;
}
#endif

