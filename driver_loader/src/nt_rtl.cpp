// ---- Unicode string helpers ------------------------------------------------

static VOID NTAPI impl_RtlInitUnicodeString(UNICODE_STRING* dest,
                                             const WCHAR* src) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    if (!dest) return;
    if (!src) {
        dest->Length        = 0;
        dest->MaximumLength = 0;
        dest->Buffer        = nullptr;
        return;
    }
    const std::size_t raw_len = std::wcslen(src) * sizeof(WCHAR);
    constexpr std::size_t kMaxLen = 0xFFFEu;
    const auto len = static_cast<USHORT>(raw_len < kMaxLen ? raw_len : kMaxLen);
    dest->Buffer        = const_cast<WCHAR*>(src);
    dest->Length        = len;
    dest->MaximumLength = len + static_cast<USHORT>(sizeof(WCHAR));
}

static BOOLEAN NTAPI impl_RtlEqualUnicodeString(const UNICODE_STRING* s1,
                                                  const UNICODE_STRING* s2,
                                                  BOOLEAN caseInsensitive) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    if (!s1 || !s2) return FALSE;
    if (s1->Length != s2->Length) return FALSE;
    if (s1->Length == 0) return TRUE;
    const USHORT nChars = s1->Length / static_cast<USHORT>(sizeof(WCHAR));
    if (caseInsensitive)
        return _wcsnicmp(s1->Buffer, s2->Buffer, nChars) == 0 ? TRUE : FALSE;
    return std::wmemcmp(s1->Buffer, s2->Buffer, nChars) == 0 ? TRUE : FALSE;
}

static VOID NTAPI impl_RtlCopyUnicodeString(UNICODE_STRING* dest,
                                             const UNICODE_STRING* src) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    if (!dest) return;
    if (!src || !src->Buffer) { dest->Length = 0; return; }
    const USHORT copy = (src->Length < dest->MaximumLength)
                        ? src->Length : dest->MaximumLength;
    std::memcpy(dest->Buffer, src->Buffer, copy);
    dest->Length = copy;
    if (copy < dest->MaximumLength)
        dest->Buffer[copy / sizeof(WCHAR)] = L'\0';
}

static LONG NTAPI impl_RtlCompareUnicodeString(const UNICODE_STRING* s1,
                                                const UNICODE_STRING* s2,
                                                BOOLEAN caseInsensitive) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    if (!s1 || !s2) return 0;
    const USHORT minLen = (s1->Length < s2->Length) ? s1->Length : s2->Length;
    const USHORT nChars = minLen / static_cast<USHORT>(sizeof(WCHAR));
    int cmp = caseInsensitive
        ? _wcsnicmp(s1->Buffer, s2->Buffer, nChars)
        : std::wmemcmp(s1->Buffer, s2->Buffer, nChars);
    if (cmp != 0) return cmp;
    return static_cast<LONG>(s1->Length) - static_cast<LONG>(s2->Length);
}

static VOID NTAPI impl_RtlFreeUnicodeString(UNICODE_STRING* str) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    if (str && str->Buffer) {
        HeapFree(GetProcessHeap(), 0, str->Buffer);
        str->Buffer        = nullptr;
        str->Length        = 0;
        str->MaximumLength = 0;
    }
}

// ---- Memory / assert / system root -----------------------------------------

static SIZE_T NTAPI impl_RtlCompareMemory(const VOID* s1, const VOID* s2,
                                           SIZE_T len) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    const auto* a = static_cast<const unsigned char*>(s1);
    const auto* b = static_cast<const unsigned char*>(s2);
    SIZE_T i = 0;
    while (i < len && a[i] == b[i]) ++i;
    return i;
}

static VOID NTAPI impl_RtlAssert(PVOID assertion, PVOID fileName,
                                   ULONG line, char* message) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    std::fprintf(stderr, "[nt_stubs] RtlAssert: '%s' at %s:%lu%s%s\n",
        static_cast<const char*>(assertion),
        static_cast<const char*>(fileName),
        static_cast<unsigned long>(line),
        message ? ": " : "",
        message ? message : "");
}

static WCHAR* NTAPI impl_RtlGetNtSystemRoot(VOID) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    static WCHAR s_root[] = L"C:\\Windows";
    return s_root;
}

static NTSTATUS NTAPI impl_RtlUTF8ToUnicodeN(WCHAR* dest, ULONG destLen,
                                               ULONG* resultLen,
                                               const char* src,
                                               ULONG srcLen) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    if (!src) return STATUS_INVALID_PARAMETER;
    int n = MultiByteToWideChar(CP_UTF8, 0, src, static_cast<int>(srcLen),
                                 dest,
                                 dest ? static_cast<int>(destLen /
                                            static_cast<ULONG>(sizeof(WCHAR)))
                                      : 0);
    if (n == 0 && srcLen > 0) return STATUS_UNSUCCESSFUL;
    if (resultLen)
        *resultLen = static_cast<ULONG>(
            static_cast<unsigned>(n) * sizeof(WCHAR));
    return STATUS_SUCCESS;
}

// ---- Security descriptor helpers -------------------------------------------

static NTSTATUS NTAPI impl_RtlCreateSecurityDescriptor(PVOID sd,
                                                         ULONG /*revision*/) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    if (sd) std::memset(sd, 0, 20);
    return STATUS_SUCCESS;
}

static ULONG NTAPI impl_RtlLengthSecurityDescriptor(PVOID /*sd*/) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    return 0;
}

static NTSTATUS NTAPI impl_RtlGetDaclSecurityDescriptor(PVOID /*sd*/,
                        BOOLEAN* present, PVOID* dacl, BOOLEAN* defaulted) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    if (present)   *present   = FALSE;
    if (dacl)      *dacl      = nullptr;
    if (defaulted) *defaulted = FALSE;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_RtlGetGroupSecurityDescriptor(PVOID /*sd*/,
                        PVOID* group, BOOLEAN* defaulted) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    if (group)     *group     = nullptr;
    if (defaulted) *defaulted = FALSE;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_RtlGetOwnerSecurityDescriptor(PVOID /*sd*/,
                        PVOID* owner, BOOLEAN* defaulted) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    if (owner)     *owner     = nullptr;
    if (defaulted) *defaulted = FALSE;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_RtlGetSaclSecurityDescriptor(PVOID /*sd*/,
                        BOOLEAN* present, PVOID* sacl, BOOLEAN* defaulted) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    if (present)   *present   = FALSE;
    if (sacl)      *sacl      = nullptr;
    if (defaulted) *defaulted = FALSE;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_RtlSetDaclSecurityDescriptor(PVOID /*sd*/,
                        BOOLEAN /*present*/, PVOID /*dacl*/,
                        BOOLEAN /*defaulted*/) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_RtlAbsoluteToSelfRelativeSD(PVOID /*absoluteSD*/,
                        PVOID /*selfRelSD*/, ULONG* bufLen) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    if (bufLen) *bufLen = 0;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_RtlAddAccessAllowedAce(PVOID /*acl*/,
                        ULONG /*aceRev*/, ULONG /*access*/, PVOID /*sid*/) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    return STATUS_SUCCESS;
}

static ULONG NTAPI impl_RtlLengthSid(PVOID /*sid*/) { return 0; }

static NTSTATUS NTAPI impl_SeCaptureSecurityDescriptor(PVOID srcSD,
                        ULONG /*accessMode*/, ULONG /*poolType*/,
                        BOOLEAN /*captureIfKernel*/, PVOID* capturedSD) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    if (capturedSD) *capturedSD = srcSD;
    return STATUS_SUCCESS;
}

// ---- Memory allocation -----------------------------------------------------

static PVOID NTAPI impl_ExAllocatePoolWithTag(ULONG /*poolType*/,
                                               SIZE_T numberOfBytes,
                                               ULONG /*tag*/) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    return HeapAlloc(GetProcessHeap(), 0, numberOfBytes);
}

static PVOID NTAPI impl_ExAllocatePool2(ULONGLONG /*poolFlags*/,
                                         SIZE_T numberOfBytes,
                                         ULONG /*tag*/) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, numberOfBytes);
}

static VOID NTAPI impl_ExFreePool(PVOID p) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    if (p) HeapFree(GetProcessHeap(), 0, p);
}

static VOID NTAPI impl_ExFreePoolWithTag(PVOID p, ULONG /*tag*/) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    if (p) HeapFree(GetProcessHeap(), 0, p);
}

// ---- Mutex / event / spin-lock ---------------------------------------------

static VOID FASTCALL impl_ExAcquireFastMutex(FAST_MUTEX* mutex) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    if (mutex) InterlockedDecrement(&mutex->Count);
}

static VOID FASTCALL impl_ExReleaseFastMutex(FAST_MUTEX* mutex) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    if (mutex) InterlockedIncrement(&mutex->Count);
}

static VOID NTAPI impl_KeInitializeSpinLock(ULONG_PTR* spinLock) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    if (spinLock) *spinLock = 0;
}

static VOID NTAPI impl_KeInitializeEvent(KEVENT* event, ULONG /*type*/,
                                          BOOLEAN state) {
    std::fprintf(stderr, "[nt_stubs] call %s\n", __func__);
    std::fflush(stderr);
    if (event) event->Signaled = state ? 1 : 0;
}

// ---- IRQL ------------------------------------------------------------------

static KIRQL NTAPI impl_KeGetCurrentIrql(VOID) {
    return static_cast<KIRQL>(PASSIVE_LEVEL);
}

static KIRQL NTAPI impl_KeRaiseIrqlToDpcLevel(VOID) {
    std::fprintf(stderr,
        "[nt_stubs] call KeRaiseIrqlToDpcLevel -> PASSIVE_LEVEL\n");
    std::fflush(stderr);
    return static_cast<KIRQL>(PASSIVE_LEVEL);
}

static KIRQL FASTCALL impl_KfRaiseIrql(KIRQL /*newIrql*/) {
    return static_cast<KIRQL>(PASSIVE_LEVEL);
}

static VOID NTAPI impl_RtlFailFast(ULONG_PTR code) {
    std::fprintf(stderr,
        "[nt_stubs] call RtlFailFast(code=0x%llX)\n",
        static_cast<unsigned long long>(code));
    std::fflush(stderr);
    std::abort();
}
