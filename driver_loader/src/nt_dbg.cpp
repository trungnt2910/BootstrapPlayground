// ---- Debug output ----------------------------------------------------------


#include "../include/wdm.hpp"
#include <iostream>
#include <print>

static ULONG impl_DbgPrint(const char *fmt, ...)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    std::va_list args;
    va_start(args, fmt);
    std::vfprintf(stderr, fmt, args);
    va_end(args);
    return 0;
}

static ULONG impl_DbgPrintEx(ULONG /*componentId*/, ULONG /*level*/, const char *fmt, ...)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    std::va_list args;
    va_start(args, fmt);
    std::vfprintf(stderr, fmt, args);
    va_end(args);
    return 0;
}
