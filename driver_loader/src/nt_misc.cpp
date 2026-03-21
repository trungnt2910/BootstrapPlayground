// ---- ETW -------------------------------------------------------------------

static NTSTATUS NTAPI impl_EtwRegister(PVOID /*providerId*/,
                                         PVOID /*callback*/,
                                         PVOID /*context*/,
                                         PVOID* regHandle) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    if (regHandle) *regHandle = nullptr;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_EtwSetInformation(PVOID /*regHandle*/,
                        ULONG /*infoClass*/, PVOID /*info*/,
                        ULONG /*infoLen*/) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_EtwWriteTransfer(PVOID /*regHandle*/,
                        PVOID /*eventDesc*/, PVOID* /*activityId*/,
                        PVOID* /*relatedId*/, ULONG /*userDataCount*/,
                        PVOID /*userData*/) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    return STATUS_SUCCESS;
}

// ---- Timing / interlock ----------------------------------------------------

static NTSTATUS NTAPI impl_KeDelayExecutionThread(ULONG /*mode*/,
                        BOOLEAN /*alertable*/, PVOID /*interval*/) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    return STATUS_SUCCESS;
}

static LONG NTAPI impl_InterlockedCompareExchange(volatile LONG* dest,
                                                    LONG exchange,
                                                    LONG comparand) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    return InterlockedCompareExchange(
        reinterpret_cast<volatile LONG*>(dest), exchange, comparand);
}

// ---- WDF (wdfldr.sys) ------------------------------------------------------

static NTSTATUS NTAPI impl_WdfVersionBind(PVOID /*driverObject*/,
                        PVOID /*registryPath*/, PVOID /*bindInfo*/,
                        PVOID* componentGlobals) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    if (componentGlobals) *componentGlobals = s_wdf_globals_buf;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_WdfVersionBindClass(PVOID /*context*/,
                        PVOID /*bindInfo*/, PVOID* componentGlobals) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    if (componentGlobals) *componentGlobals = s_wdf_globals_buf;
    return STATUS_SUCCESS;
}

static VOID NTAPI impl_WdfVersionUnbind(PVOID /*registryPath*/,
                                          PVOID /*bindInfo*/,
                                          PVOID /*componentGlobals*/) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
}

static VOID NTAPI impl_WdfVersionUnbindClass(PVOID /*context*/,
                                               PVOID /*bindInfo*/,
                                               PVOID /*componentGlobals*/) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
}

static NTSTATUS NTAPI impl_WdfLdrQueryInterface(PVOID /*iface*/) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    return STATUS_NOT_IMPLEMENTED;
}

// ---- BCrypt (cng.sys) ------------------------------------------------------

static NTSTATUS NTAPI impl_BCryptGenRandom(PVOID /*alg*/, UCHAR* buf,
                                            ULONG len, ULONG /*flags*/) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    if (!buf) return STATUS_INVALID_PARAMETER;
    for (ULONG i = 0; i < len; ++i)
        buf[i] = static_cast<UCHAR>(rand() & 0xFF);
    return STATUS_SUCCESS;
}

// ---- CRT wrappers ----------------------------------------------------------

static std::size_t impl_strnlen(const char* s, std::size_t n) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    if (!s) return 0;
    const char* p = static_cast<const char*>(std::memchr(s, '\0', n));
    return p ? static_cast<std::size_t>(p - s) : n;
}

static int impl__stricmp(const char* s1, const char* s2) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
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
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    return std::strncmp(s1, s2, n);
}

static int impl_strcmp(const char* s1, const char* s2) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    return std::strcmp(s1, s2);
}

static char* impl_strcpy(char* dst, const char* src) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    return std::strcpy(dst, src);
}

static char* impl_strncpy(char* dst, const char* src, std::size_t n) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    return std::strncpy(dst, src, n);
}

static std::size_t impl_strlen(const char* s) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    return s ? std::strlen(s) : 0;
}

static int impl_wcsncmp(const WCHAR* s1, const WCHAR* s2, std::size_t n) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    return std::wcsncmp(s1, s2, n);
}

static std::size_t impl_wcslen(const WCHAR* s) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    return s ? std::wcslen(s) : 0;
}

static int impl__wcsnicmp(const WCHAR* s1, const WCHAR* s2, std::size_t n) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    return _wcsnicmp(s1, s2, n);
}

static WCHAR* impl_wcschr(const WCHAR* s, WCHAR c) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    return const_cast<WCHAR*>(std::wcschr(s, c));
}

static void* impl_memset(void* s, int c, std::size_t n) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    return std::memset(s, c, n);
}

static void* impl_memcpy(void* dst, const void* src, std::size_t n) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    return std::memcpy(dst, src, n);
}

static int impl_isupper(int c) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    return std::isupper(static_cast<unsigned char>(c));
}

static int impl_isdigit(int c) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    return std::isdigit(static_cast<unsigned char>(c));
}

static int impl_iswspace(unsigned int c) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    return std::iswspace(static_cast<wchar_t>(c));
}

static int impl_tolower(int c) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    return std::tolower(static_cast<unsigned char>(c));
}

static int impl__snprintf(char* buf, std::size_t count, const char* fmt, ...) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    std::va_list args;
    va_start(args, fmt);
    const int ret = std::vsnprintf(buf, count, fmt, args);
    va_end(args);
    return ret;
}

static int impl__snwprintf(WCHAR* buf, std::size_t count, const WCHAR* fmt, ...) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    std::va_list args;
    va_start(args, fmt);
    const int ret = std::vswprintf(buf, count, fmt, args);
    va_end(args);
    return ret;
}
