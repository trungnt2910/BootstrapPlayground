// ---- Debug output ----------------------------------------------------------

#include <cstdio>

#include "nt_stubs_internal.hpp"

static ULONG impl_DbgPrint(PCCH fmt, ...)
{
    NT_STUB_REPORT();
    va_list args;
    va_start(args, fmt);
    std::vfprintf(stderr, fmt, args);
    std::fflush(stderr);
    va_end(args);
    return 0;
}

static ULONG impl_DbgPrintEx(ULONG /*componentId*/, ULONG /*level*/, PCCH fmt, ...)
{
    NT_STUB_REPORT();
    va_list args;
    va_start(args, fmt);
    std::vfprintf(stderr, fmt, args);
    std::fflush(stderr);
    va_end(args);
    return 0;
}
