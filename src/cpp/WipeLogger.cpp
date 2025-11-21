class SecureWiper {
public:
    bool is_running = false;
    bool should_stop = false;

    // Patterns
    std::string zero_pattern;
    std::string ones_pattern;
    std::string random_pattern;

    using ProgressCallback = std::function<void(int)>;
    ProgressCallback progress_callback;

    WipeLogger logger;

    SecureWiper(/* config struct or params */) {
        // initialize patterns and other members
    }

    void start() { is_running = true; }
    void stop() { should_stop = true; is_running = false; }
    int get_current_progress() { return 0; /* return actual progress */ }
};
