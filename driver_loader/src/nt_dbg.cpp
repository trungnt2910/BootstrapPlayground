// ---- Debug output ----------------------------------------------------------

static ULONG impl_DbgPrint(const char* fmt, ...) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    std::va_list args;
    va_start(args, fmt);
    std::vfprintf(stderr, fmt, args);
    va_end(args);
    return 0;
}

static ULONG impl_DbgPrintEx(ULONG /*componentId*/, ULONG /*level*/,
                               const char* fmt, ...) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    std::va_list args;
    va_start(args, fmt);
    std::vfprintf(stderr, fmt, args);
    va_end(args);
    return 0;
}
