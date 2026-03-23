#pragma once

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <format>
#include <print>
#include <string>
#include <string_view>
#include <utility>

namespace driver_loader::logging
{

enum class LogLevel : int
{
    Trace = 0,
    Info = 1,
    Warning = 2,
    Error = 3,
};

inline std::atomic<int> gLogLevel{ static_cast<int>(LogLevel::Error) };

inline const char *ToString(LogLevel level) noexcept
{
    switch (level)
    {
    case LogLevel::Trace:
        return "Trace";
    case LogLevel::Info:
        return "Info";
    case LogLevel::Warning:
        return "Warning";
    case LogLevel::Error:
    default:
        return "Error";
    }
}

inline std::string ToLower(std::string value)
{
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

inline LogLevel
ParseLogLevel(std::string_view levelText, LogLevel fallback = LogLevel::Error) noexcept
{
    const std::string level = ToLower(std::string(levelText));
    if (level == "trace")
    {
        return LogLevel::Trace;
    }
    if (level == "info")
    {
        return LogLevel::Info;
    }
    if (level == "warning" || level == "warn")
    {
        return LogLevel::Warning;
    }
    if (level == "error" || level == "err")
    {
        return LogLevel::Error;
    }
    return fallback;
}

inline void SetLogLevel(LogLevel level) noexcept
{
    gLogLevel.store(static_cast<int>(level), std::memory_order_relaxed);
}

inline LogLevel GetLogLevel() noexcept
{
    return static_cast<LogLevel>(gLogLevel.load(std::memory_order_relaxed));
}

inline bool ShouldLog(LogLevel level) noexcept
{
    return static_cast<int>(level) >= gLogLevel.load(std::memory_order_relaxed);
}

inline void InitLogLevelFromEnv(const char *envVarName = "BOOTSTRAP_PLAYGROUND_LOG_LEVEL") noexcept
{
    const char *levelText = std::getenv(envVarName);
    if (levelText == nullptr || levelText[0] == '\0')
    {
        return;
    }
    SetLogLevel(ParseLogLevel(levelText, GetLogLevel()));
}

template <typename... Args>
inline void Log(LogLevel level, const std::format_string<Args...>& fmt, Args &&...args)
{
    if (!ShouldLog(level))
    {
        return;
    }



    const std::string message = std::format(fmt, std::forward<Args&&>(args)...);
    std::println(stderr, "[{}] {}", ToString(level), message.c_str());
}

} // namespace driver_loader::logging

#define DL_LOG_TRACE(...)                                                                          \
    ::driver_loader::logging::Log(::driver_loader::logging::LogLevel::Trace, __VA_ARGS__)
#define DL_LOG_INFO(...)                                                                           \
    ::driver_loader::logging::Log(::driver_loader::logging::LogLevel::Info, __VA_ARGS__)
#define DL_LOG_WARNING(...)                                                                        \
    ::driver_loader::logging::Log(::driver_loader::logging::LogLevel::Warning, __VA_ARGS__)
#define DL_LOG_ERROR(...)                                                                          \
    ::driver_loader::logging::Log(::driver_loader::logging::LogLevel::Error, __VA_ARGS__)
