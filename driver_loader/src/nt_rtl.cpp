// ---- Unicode string helpers ------------------------------------------------


#include "../include/wdm.hpp"
#include <iostream>
#include <print>

static VOID NTAPI impl_RtlInitUnicodeString(UNICODE_STRING *dest, const WCHAR *src)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (!dest)
        return;
    if (!src)
    {
        dest->Length = 0;
        dest->MaximumLength = 0;
        dest->Buffer = nullptr;
        return;
    }
    const std::size_t raw_len = std::wcslen(src) * sizeof(WCHAR);
    constexpr std::size_t kMaxLen = 0xFFFEu;
    const auto len = static_cast<USHORT>(raw_len < kMaxLen ? raw_len : kMaxLen);
    dest->Buffer = const_cast<WCHAR *>(src);
    dest->Length = len;
    dest->MaximumLength = len + static_cast<USHORT>(sizeof(WCHAR));
}

static BOOLEAN NTAPI impl_RtlEqualUnicodeString(const UNICODE_STRING *s1, const UNICODE_STRING *s2,
                                                BOOLEAN caseInsensitive)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (!s1 || !s2)
        return FALSE;
    if (s1->Length != s2->Length)
        return FALSE;
    if (s1->Length == 0)
        return TRUE;
    const USHORT nChars = s1->Length / static_cast<USHORT>(sizeof(WCHAR));
    if (caseInsensitive)
        return _wcsnicmp(s1->Buffer, s2->Buffer, nChars) == 0 ? TRUE : FALSE;
    return std::wmemcmp(s1->Buffer, s2->Buffer, nChars) == 0 ? TRUE : FALSE;
}

static VOID NTAPI impl_RtlCopyUnicodeString(UNICODE_STRING *dest, const UNICODE_STRING *src)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (!dest)
        return;
    if (!src || !src->Buffer)
    {
        dest->Length = 0;
        return;
    }
    const USHORT copy = (src->Length < dest->MaximumLength) ? src->Length : dest->MaximumLength;
    std::memcpy(dest->Buffer, src->Buffer, copy);
    dest->Length = copy;
    if (copy < dest->MaximumLength)
        dest->Buffer[copy / sizeof(WCHAR)] = L'\0';
}

static LONG NTAPI impl_RtlCompareUnicodeString(const UNICODE_STRING *s1, const UNICODE_STRING *s2,
                                               BOOLEAN caseInsensitive)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (!s1 || !s2)
        return 0;
    const USHORT minLen = (s1->Length < s2->Length) ? s1->Length : s2->Length;
    const USHORT nChars = minLen / static_cast<USHORT>(sizeof(WCHAR));
    int cmp = caseInsensitive ? _wcsnicmp(s1->Buffer, s2->Buffer, nChars)
                              : std::wmemcmp(s1->Buffer, s2->Buffer, nChars);
    if (cmp != 0)
        return cmp;
    return static_cast<LONG>(s1->Length) - static_cast<LONG>(s2->Length);
}

static VOID NTAPI impl_RtlFreeUnicodeString(UNICODE_STRING *str)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (str && str->Buffer)
    {
        HeapFree(GetProcessHeap(), 0, str->Buffer);
        str->Buffer = nullptr;
        str->Length = 0;
        str->MaximumLength = 0;
    }
}

// ---- Memory / assert / system root -----------------------------------------

static SIZE_T NTAPI impl_RtlCompareMemory(const VOID *s1, const VOID *s2, SIZE_T len)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    const auto *a = static_cast<const unsigned char *>(s1);
    const auto *b = static_cast<const unsigned char *>(s2);
    SIZE_T i = 0;
    while (i < len && a[i] == b[i])
        ++i;
    return i;
}

static VOID NTAPI impl_RtlAssert(PVOID assertion, PVOID fileName, ULONG line, char *message)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    std::println(stderr, "[nt_stubs] RtlAssert: '{}' at {}:{}{}{}",
                 static_cast<const char *>(assertion), static_cast<const char *>(fileName),
                 static_cast<unsigned long>(line), message ? ": " : "", message ? message : "");
    std::flush(std::cerr);
}

static WCHAR *NTAPI impl_RtlGetNtSystemRoot(VOID)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    static WCHAR s_root[] = L"C:\\Windows";
    return s_root;
}

static NTSTATUS NTAPI impl_RtlUTF8ToUnicodeN(WCHAR *dest, ULONG destLen, ULONG *resultLen,
                                             const char *src, ULONG srcLen)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (!src)
        return STATUS_INVALID_PARAMETER;
    int n = MultiByteToWideChar(CP_UTF8, 0, src, static_cast<int>(srcLen), dest,
                                dest ? static_cast<int>(destLen / static_cast<ULONG>(sizeof(WCHAR)))
                                     : 0);
    if (n == 0 && srcLen > 0)
        return STATUS_UNSUCCESSFUL;
    if (resultLen)
        *resultLen = static_cast<ULONG>(static_cast<unsigned>(n) * sizeof(WCHAR));
    return STATUS_SUCCESS;
}

// ---- Security descriptor helpers -------------------------------------------

static NTSTATUS NTAPI impl_RtlCreateSecurityDescriptor(PVOID sd, ULONG /*revision*/)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (sd)
        std::memset(sd, 0, 20);
    return STATUS_SUCCESS;
}

static ULONG NTAPI impl_RtlLengthSecurityDescriptor(PVOID /*sd*/)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return 0;
}

static NTSTATUS NTAPI impl_RtlGetDaclSecurityDescriptor(PVOID /*sd*/, BOOLEAN *present, PVOID *dacl,
                                                        BOOLEAN *defaulted)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (present)
        *present = FALSE;
    if (dacl)
        *dacl = nullptr;
    if (defaulted)
        *defaulted = FALSE;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_RtlGetGroupSecurityDescriptor(PVOID /*sd*/, PVOID *group,
                                                         BOOLEAN *defaulted)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (group)
        *group = nullptr;
    if (defaulted)
        *defaulted = FALSE;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_RtlGetOwnerSecurityDescriptor(PVOID /*sd*/, PVOID *owner,
                                                         BOOLEAN *defaulted)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (owner)
        *owner = nullptr;
    if (defaulted)
        *defaulted = FALSE;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_RtlGetSaclSecurityDescriptor(PVOID /*sd*/, BOOLEAN *present, PVOID *sacl,
                                                        BOOLEAN *defaulted)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (present)
        *present = FALSE;
    if (sacl)
        *sacl = nullptr;
    if (defaulted)
        *defaulted = FALSE;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_RtlSetDaclSecurityDescriptor(PVOID /*sd*/, BOOLEAN /*present*/,
                                                        PVOID /*dacl*/, BOOLEAN /*defaulted*/)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_RtlAbsoluteToSelfRelativeSD(PVOID /*absoluteSD*/, PVOID /*selfRelSD*/,
                                                       ULONG *bufLen)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (bufLen)
        *bufLen = 0;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_RtlAddAccessAllowedAce(PVOID /*acl*/, ULONG /*aceRev*/, ULONG /*access*/,
                                                  PVOID /*sid*/)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return STATUS_SUCCESS;
}

static ULONG NTAPI impl_RtlLengthSid(PVOID /*sid*/)
{
    return 0;
}

static NTSTATUS NTAPI impl_SeCaptureSecurityDescriptor(PVOID srcSD, ULONG /*accessMode*/,
                                                       ULONG /*poolType*/,
                                                       BOOLEAN /*captureIfKernel*/,
                                                       PVOID *capturedSD)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (capturedSD)
        *capturedSD = srcSD;
    return STATUS_SUCCESS;
}

static VOID NTAPI impl_RtlFailFast(ULONG_PTR code)
{
    std::println(stderr, "[nt_stubs] call RtlFailFast(code=0x{:X})",
                 static_cast<unsigned long long>(code));
    std::flush(std::cerr);
    std::abort();
}
