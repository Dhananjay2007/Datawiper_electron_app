#pragma once
#include <string>
#include <functional>

enum class LogLevel { DEBUG, INFO, WARNING, ERROR, FATAL };

class WipeLogger {
public:
    LogLevel current_level;
    std::function<void(LogLevel, const std::string&)> log_callback;

    void set_log_level(LogLevel level) { current_level = level; }
    void set_log_callback(std::function<void(LogLevel, const std::string&)> cb) { log_callback = cb; }

    void log(LogLevel level, const std::string& msg) {
        if (log_callback) log_callback(level, msg);
    }

    void debug(const std::string& msg) { log(LogLevel::DEBUG, msg); }
    void info(const std::string& msg) { log(LogLevel::INFO, msg); }
    void warning(const std::string& msg) { log(LogLevel::WARNING, msg); }
    void error(const std::string& msg) { log(LogLevel::ERROR, msg); }
    void fatal(const std::string& msg) { log(LogLevel::FATAL, msg); }
};
