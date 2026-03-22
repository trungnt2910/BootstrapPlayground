// ---- CRT wrappers -----------------------------------------------------------

static std::size_t impl_strnlen(const char* s, std::size_t n) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (!s) return 0;
    const char* p = static_cast<const char*>(std::memchr(s, '\0', n));
    return p ? static_cast<std::size_t>(p - s) : n;
}

static int impl__stricmp(const char* s1, const char* s2) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (!s1 && !s2) return 0;
    if (!s1) return -1;
    if (!s2) return  1;
    while (*s1 && *s2) {
        const int c1 = std::tolower(static_cast<unsigned char>(*s1));
        const int c2 = std::tolower(static_cast<unsigned char>(*s2));
        if (c1 != c2) return c1 - c2;
        ++s1; ++s2;
    }
    return std::tolower(static_cast<unsigned char>(*s1)) -
           std::tolower(static_cast<unsigned char>(*s2));
}

static int impl_strncmp(const char* s1, const char* s2, std::size_t n) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return std::strncmp(s1, s2, n);
}

static int impl_strcmp(const char* s1, const char* s2) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return std::strcmp(s1, s2);
}

static char* impl_strcpy(char* dst, const char* src) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return std::strcpy(dst, src);
}

static char* impl_strncpy(char* dst, const char* src, std::size_t n) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return std::strncpy(dst, src, n);
}

static std::size_t impl_strlen(const char* s) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return s ? std::strlen(s) : 0;
}

static int impl_wcsncmp(const WCHAR* s1, const WCHAR* s2, std::size_t n) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return std::wcsncmp(s1, s2, n);
}

static std::size_t impl_wcslen(const WCHAR* s) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return s ? std::wcslen(s) : 0;
}

static int impl__wcsnicmp(const WCHAR* s1, const WCHAR* s2, std::size_t n) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return _wcsnicmp(s1, s2, n);
}

static WCHAR* impl_wcschr(const WCHAR* s, WCHAR c) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return const_cast<WCHAR*>(std::wcschr(s, c));
}

static void* impl_memset(void* s, int c, std::size_t n) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return std::memset(s, c, n);
}

static void* impl_memcpy(void* dst, const void* src, std::size_t n) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return std::memcpy(dst, src, n);
}

static int impl_isupper(int c) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return std::isupper(static_cast<unsigned char>(c));
}

static int impl_isdigit(int c) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return std::isdigit(static_cast<unsigned char>(c));
}

static int impl_iswspace(unsigned int c) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return std::iswspace(static_cast<wchar_t>(c));
}

static int impl_tolower(int c) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return std::tolower(static_cast<unsigned char>(c));
}

static int impl__snprintf(char* buf, std::size_t count, const char* fmt, ...) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    std::va_list args;
    va_start(args, fmt);
    const int ret = std::vsnprintf(buf, count, fmt, args);
    va_end(args);
    return ret;
}

static int impl__snwprintf(WCHAR* buf, std::size_t count, const WCHAR* fmt, ...) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    std::va_list args;
    va_start(args, fmt);
    const int ret = std::vswprintf(buf, count, fmt, args);
    va_end(args);
    return ret;
}
