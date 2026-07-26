#ifndef OCELOT_LOGGING_HPP
#define OCELOT_LOGGING_HPP

#include <cstdio>
#include <mutex>
#include <string>

namespace ocelot_log {
    enum Level { kError = 0, kWarn = 1, kInfo = 2, kDebug = 3 };

    // Logging used to happen unconditionally on the data path (one line per
    // socket registration, per close, per destructor).  Every one of those took
    // the iostream lock on the epoll thread, which is the last place that should
    // be doing blocking I/O.  Everything below Warn is now compiled in but off by
    // default; set OCELOT_LOG=0..3 to raise it.
    inline Level &level() {
        static Level lvl = [] {
            if (const char *env = getenv("OCELOT_LOG")) {
                const int v = atoi(env);
                if (v >= kError && v <= kDebug)
                    return static_cast<Level>(v);
            }
            return kWarn;
        }();
        return lvl;
    }

    inline std::mutex &mutex() {
        static std::mutex m;
        return m;
    }
}

// stderr is unbuffered and does not fight with the iostream locks the proxy
// otherwise never touches.
#define OCELOT_LOG_AT(lvl, ...)                                                \
    do {                                                                       \
        if (ocelot_log::level() >= (lvl)) {                                    \
            std::lock_guard<std::mutex> _lk(ocelot_log::mutex());              \
            fprintf(stderr, __VA_ARGS__);                                      \
            fputc('\n', stderr);                                               \
        }                                                                      \
    } while (0)

#define LOG_ERROR(...) OCELOT_LOG_AT(ocelot_log::kError, __VA_ARGS__)
#define LOG_WARN(...) OCELOT_LOG_AT(ocelot_log::kWarn, __VA_ARGS__)
#define LOG_INFO(...) OCELOT_LOG_AT(ocelot_log::kInfo, __VA_ARGS__)
#define LOG_DEBUG(...) OCELOT_LOG_AT(ocelot_log::kDebug, __VA_ARGS__)

#endif
