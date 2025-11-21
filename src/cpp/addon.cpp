#pragma once
#include <napi.h>
#include "secure_wiper.h"
#include "wiper_core.h"
#include "WipeLogger.h"
#include <memory>
#include <thread>
#include <string>
#include <vector>
#include <chrono>
#include <algorithm>
#include <initializer_list>
#include <map>
#include <mutex>
#include <chrono>
#include <atomic>
#include <ctime>

static std::map<std::string, std::shared_ptr<SecureWiper>> active_wipers;
static std::map<std::string, std::unique_ptr<std::thread>> active_threads;
static std::mutex wipers_mutex;

struct CallbackInfo {
    Napi::ThreadSafeFunction progress_callback;
    Napi::ThreadSafeFunction completion_callback;
};

static std::map<std::string, CallbackInfo> callbacks;
static std::mutex callbacks_mutex;

// Generate unique session IDs
std::string generate_session_id() {
    static std::atomic<int> counter{0};
    int id = ++counter;
    return "session_" + std::to_string(id) + "_" + std::to_string(time(nullptr));
}

// Convert C++ WipeConfig -> JS Object
Napi::Object WipeConfigToJS(Napi::Env env, const WipeConfig& config) {
    Napi::Object obj = Napi::Object::New(env);
    obj.Set("device_path", config.device_path);
    obj.Set("profile", static_cast<int>(config.profile));
    obj.Set("mode", static_cast<int>(config.mode));
    obj.Set("wipe_hpa_dco", config.wipe_hpa_dco);
    obj.Set("passes", config.passes);
    return obj;
}

// Convert JS Object -> C++ WipeConfig
WipeConfig JSToWipeConfig(Napi::Object obj) {
    WipeConfig config;
    config.device_path = obj.Get("device_path").As<Napi::String>().Utf8Value();
    config.profile = static_cast<WipeProfile>(obj.Get("profile").As<Napi::Number>().Int32Value());
    config.mode = static_cast<WipeMode>(obj.Get("mode").As<Napi::Number>().Int32Value());
    config.wipe_hpa_dco = obj.Get("wipe_hpa_dco").As<Napi::Boolean>().Value();
    config.passes = obj.Get("passes").As<Napi::Number>().Int32Value();
    if (config.passes <= 0) config.passes = 1;
    return config;
}

// Async worker for wiping
class WipeWorker : public Napi::AsyncWorker {
    std::string session_id;
    std::shared_ptr<SecureWiper> wiper;
    bool success;
    std::string error_message;

public:
    WipeWorker(Napi::Function& callback, const std::string& sid, std::shared_ptr<SecureWiper> w)
        : Napi::AsyncWorker(callback), session_id(sid), wiper(w), success(false) {}

    void Execute() override {
        try {
            success = wiper->execute_wipe();
        } catch (const std::exception& e) {
            success = false;
            error_message = e.what();
        } catch (...) {
            success = false;
            error_message = "Unknown error";
        }
    }

    void OnOK() override {
        std::lock_guard<std::mutex> lock(callbacks_mutex);
        auto it = callbacks.find(session_id);
        if (it != callbacks.end()) {
            it->second.completion_callback.NonBlockingCall([this](Napi::Env env, Napi::Function jsCb) {
                if (success) jsCb.Call({env.Null(), Napi::Boolean::New(env, true)});
                else jsCb.Call({Napi::String::New(env, error_message), env.Null()});
            });
        }

        std::lock_guard<std::mutex> lk(wipers_mutex);
        active_wipers.erase(session_id);
        active_threads.erase(session_id);

        callbacks.erase(session_id);
    }

    void OnError(const Napi::Error& e) override {
        std::lock_guard<std::mutex> lock(callbacks_mutex);
        auto it = callbacks.find(session_id);
        if (it != callbacks.end()) {
            it->second.completion_callback.NonBlockingCall([e](Napi::Env env, Napi::Function jsCb) {
                jsCb.Call({Napi::String::New(env, e.Message()), env.Null()});
            });
        }

        std::lock_guard<std::mutex> lk(wipers_mutex);
        active_wipers.erase(session_id);
        active_threads.erase(session_id);

        callbacks.erase(session_id);
    }
};

// Detect connected devices
Napi::Value DetectDevices(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    try {
        std::vector<std::string> devices;
#ifdef _WIN32
        devices = DeviceManager::get_physical_drives();
#else
        devices = DeviceManager::get_block_devices();
#endif
        Napi::Array arr = Napi::Array::New(env, devices.size());
        for (size_t i = 0; i < devices.size(); ++i) {
            Napi::Object o = Napi::Object::New(env);
            o.Set("path", devices[i]);
            try {
                o.Set("size", Napi::Number::New(env, static_cast<double>(SecureWiper::get_device_size_static(devices[i]))));
            } catch (...) {
                o.Set("size", Napi::Number::New(env, 0));
            }
            o.Set("accessible", SecureWiper::is_device_accessible(devices[i]));
            arr[i] = o;
        }
        return arr;
    } catch (const std::exception& e) {
        Napi::Error::New(env, std::string("DetectDevices failed: ") + e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

// Start a wipe
Napi::Value StartWipe(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 3 || !info[0].IsObject() || !info[1].IsFunction() || !info[2].IsFunction()) {
        Napi::TypeError::New(env, "Expected (config, progressCallback, completionCallback)").ThrowAsJavaScriptException();
        return env.Null();
    }

    try {
        WipeConfig cfg = JSToWipeConfig(info[0].As<Napi::Object>());
        if (!SecureWiper::validate_device_path(cfg.device_path)) {
            Napi::Error::New(env, "Invalid device path").ThrowAsJavaScriptException();
            return env.Null();
        }

        std::string session = generate_session_id();
        auto wiper = std::make_shared<SecureWiper>(cfg);

        // ThreadSafe callbacks
        Napi::ThreadSafeFunction progress_tsfn = Napi::ThreadSafeFunction::New(env, info[1].As<Napi::Function>(), "ProgressCallback", 0, 1);
        Napi::ThreadSafeFunction completion_tsfn = Napi::ThreadSafeFunction::New(env, info[2].As<Napi::Function>(), "CompletionCallback", 0, 1);

        {
            std::lock_guard<std::mutex> lk(callbacks_mutex);
            callbacks[session] = {progress_tsfn, completion_tsfn};
        }
        {
            std::lock_guard<std::mutex> lk(wipers_mutex);
            active_wipers[session] = wiper;
        }

        wiper->set_progress_callback([session](int percent, const std::string& msg) {
            std::lock_guard<std::mutex> lk(callbacks_mutex);
            auto it = callbacks.find(session);
            if (it == callbacks.end()) return;
            it->second.progress_callback.NonBlockingCall([percent, msg](Napi::Env env, Napi::Function jsCb) {
                jsCb.Call({Napi::Number::New(env, percent), Napi::String::New(env, msg)});
            });
        });

         auto dummy_cb = Napi::Function::New(env, [](const Napi::CallbackInfo&) {});
         auto worker = new WipeWorker(const_cast<Napi::Function&>(dummy_cb), session, wiper);
         worker->Queue();


        Napi::Object res = Napi::Object::New(env);
        res.Set("sessionId", session);
        res.Set("success", true);
        return res;

    } catch (const std::exception& e) {
        Napi::Error::New(env, std::string("StartWipe failed: ") + e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

// Stop a wipe
Napi::Value StopWipe(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected session ID").ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string sid = info[0].As<Napi::String>().Utf8Value();
    std::lock_guard<std::mutex> lk(wipers_mutex);
    auto it = active_wipers.find(sid);
    if (it != active_wipers.end()) {
        it->second->stop_operation();
        std::lock_guard<std::mutex> lk2(callbacks_mutex);
        callbacks.erase(sid);
        return Napi::Boolean::New(env, true);
    }
    return Napi::Boolean::New(env, false);
}

// Get wipe status
Napi::Value GetWipeStatus(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected session ID").ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string sid = info[0].As<Napi::String>().Utf8Value();
    Napi::Object res = Napi::Object::New(env);
    std::lock_guard<std::mutex> lk(wipers_mutex);
    auto it = active_wipers.find(sid);
    res.Set("running", it != active_wipers.end() && it->second->is_operation_running());
    res.Set("exists", it != active_wipers.end());
    return res;
}

// Validate device
Napi::Value ValidateDevice(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected device path").ThrowAsJavaScriptException();
        return env.Null();
    }
    std::string path = info[0].As<Napi::String>().Utf8Value();
    Napi::Object res = Napi::Object::New(env);
    res.Set("valid", SecureWiper::validate_device_path(path));
    res.Set("accessible", SecureWiper::is_device_accessible(path));
    res.Set("systemDrive", SecureWiper::is_system_drive(path));
    return res;
}

// Check admin privileges
Napi::Value HasAdminPrivileges(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    return Napi::Boolean::New(env, SecureWiper::has_admin_privileges());
}

// Get device info
Napi::Value GetDeviceInfo(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected device path").ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string path = info[0].As<Napi::String>().Utf8Value();
    try {
        Napi::Object res = Napi::Object::New(env);
        res.Set("size", Napi::Number::New(env, static_cast<double>(SecureWiper::get_device_size_static(path))));
        res.Set("info", SecureWiper::get_device_info(path));
        res.Set("accessible", SecureWiper::is_device_accessible(path));
        res.Set("systemDrive", SecureWiper::is_system_drive(path));
        return res;
    } catch (const std::exception& e) {
        Napi::Error::New(env, std::string("GetDeviceInfo failed: ") + e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

// Module initialization
Napi::Object Init(Napi::Env env, Napi::Object exports) {
    WipeLogger::set_log_callback([](LogLevel, const std::string& msg){ (void)msg; });

    exports.Set("detectDevices", Napi::Function::New(env, DetectDevices));
    exports.Set("startWipe", Napi::Function::New(env, StartWipe));
    exports.Set("stopWipe", Napi::Function::New(env, StopWipe));
    exports.Set("getWipeStatus", Napi::Function::New(env, GetWipeStatus));
    exports.Set("validateDevice", Napi::Function::New(env, ValidateDevice));
    exports.Set("hasAdminPrivileges", Napi::Function::New(env, HasAdminPrivileges));
    exports.Set("getDeviceInfo", Napi::Function::New(env, GetDeviceInfo));

    // Wipe profiles
    Napi::Object profiles = Napi::Object::New(env);
    profiles.Set("CITIZEN", Napi::Number::New(env, static_cast<int>(CITIZEN)));
    profiles.Set("ENTERPRISE", Napi::Number::New(env, static_cast<int>(ENTERPRISE)));
    profiles.Set("GOVERNMENT", Napi::Number::New(env, static_cast<int>(GOVERNMENT)));
    exports.Set("WipeProfile", profiles);

    // Wipe modes
    Napi::Object modes = Napi::Object::New(env);
    modes.Set("NIST_800_88", Napi::Number::New(env, static_cast<int>(NIST_800_88)));
    modes.Set("HSE", Napi::Number::New(env, static_cast<int>(HSE)));
    exports.Set("WipeMode", modes);

    return exports;
}

NODE_API_MODULE(secure_wiper, Init)
