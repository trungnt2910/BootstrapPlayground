// nt_stubs.cpp – Stub infrastructure + implementations of ntoskrnl.exe exports.
//
// The 256 numbered "abort" stubs are generated at configure-time into
// nt_stubs_generated.cpp by CMakeLists.txt.  This file provides:
//   • The shared state (name_table, next_index, handle_call).
//   • The public helper used by DriverLoader to allocate a stub slot.
//   • Implementations of common ntoskrnl.exe functions.

#include "nt_stubs_internal.hpp"
#include "../include/wdm.hpp"   // includes <windows.h> and <winternl.h>

#include <array>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>

// ---------------------------------------------------------------------------
// Shared stub state
// ---------------------------------------------------------------------------

namespace nt_stubs_internal {

std::array<const char*, 256> name_table = {};
int next_index = 0;

[[noreturn]] void handle_call(int idx) noexcept {
    const char* name =
        (idx >= 0 && idx < 256 && name_table[static_cast<std::size_t>(idx)])
        ? name_table[static_cast<std::size_t>(idx)]
        : "<unknown>";
    std::fprintf(stderr,
        "[nt_stubs] Unimplemented ntoskrnl function called: %s (stub #%d)\n",
        name, idx);
    std::fflush(stderr);
    std::abort();
}

} // namespace nt_stubs_internal

// ---------------------------------------------------------------------------
// Fallback stub – used when all 256 numbered slots are exhausted.
// ---------------------------------------------------------------------------

static void* fallback_stub() noexcept {
    std::fprintf(stderr,
        "[nt_stubs] An ntoskrnl stub was called but all 256 stub slots are "
        "exhausted.\n");
    std::fflush(stderr);
    std::abort();
}

// ---------------------------------------------------------------------------
// Public helper: allocate a numbered stub slot for 'name'.
// Returns the stub function pointer, or the fallback stub pointer if all
// 256 slots are taken.
// ---------------------------------------------------------------------------

void* nt_stubs_allocate(const char* name) noexcept {
    using namespace nt_stubs_internal;
    if (next_index >= 256) {
        std::fprintf(stderr,
            "[nt_stubs] Warning: more than 256 stubs requested; "
            "'%s' will use the fallback stub.\n", name ? name : "<null>");
        return reinterpret_cast<void*>(&fallback_stub);
    }
    name_table[static_cast<std::size_t>(next_index)] = name;
    void* ptr = reinterpret_cast<void*>(
        nt_stubs_internal::get_stub_table()[next_index]);
    ++next_index;
    return ptr;
}

// ---------------------------------------------------------------------------
// Built-in ntoskrnl.exe symbol table
//
// The table maps function names to their implementations.
// DriverLoader consults this table before falling back to the numbered stubs.
// ---------------------------------------------------------------------------

// Forward declarations of every implementation below.
extern "C" {

// Debug output – variadic, always __cdecl (no NTAPI).
static ULONG impl_DbgPrint(const char* format, ...);
static ULONG impl_DbgPrintEx(ULONG componentId, ULONG level,
                              const char* format, ...);

// String helpers
static VOID NTAPI impl_RtlInitUnicodeString(UNICODE_STRING* dest, const WCHAR* src);
static BOOLEAN NTAPI impl_RtlEqualUnicodeString(const UNICODE_STRING* s1,
                                                  const UNICODE_STRING* s2,
                                                  BOOLEAN caseInsensitive);
static VOID NTAPI impl_RtlCopyUnicodeString(UNICODE_STRING* dest,
                                             const UNICODE_STRING* src);
static LONG NTAPI impl_RtlCompareUnicodeString(const UNICODE_STRING* s1,
                                                const UNICODE_STRING* s2,
                                                BOOLEAN caseInsensitive);

// Memory allocation
static PVOID NTAPI impl_ExAllocatePoolWithTag(ULONG poolType, SIZE_T numberOfBytes,
                                               ULONG tag);
static PVOID NTAPI impl_ExAllocatePool2(ULONGLONG poolFlags, SIZE_T numberOfBytes,
                                         ULONG tag);
static VOID NTAPI impl_ExFreePool(PVOID p);
static VOID NTAPI impl_ExFreePoolWithTag(PVOID p, ULONG tag);

// Spin-lock (no-op in user mode)
static VOID NTAPI impl_KeInitializeSpinLock(ULONG_PTR* spinLock);

// Reference counting (no-op in user mode)
static LONG_PTR FASTCALL impl_ObfReferenceObject(PVOID object);
static LONG_PTR FASTCALL impl_ObfDereferenceObject(PVOID object);

// System routine address lookup
static PVOID NTAPI impl_MmGetSystemRoutineAddress(UNICODE_STRING* routineName);

// Device I/O
static NTSTATUS NTAPI impl_IoCreateDevice(PDRIVER_OBJECT driverObject,
                                           ULONG deviceExtensionSize,
                                           UNICODE_STRING* deviceName,
                                           ULONG deviceType,
                                           ULONG deviceCharacteristics,
                                           BOOLEAN exclusive,
                                           PDEVICE_OBJECT* deviceObject);
static NTSTATUS NTAPI impl_IoCreateSymbolicLink(UNICODE_STRING* symLinkName,
                                                  UNICODE_STRING* deviceName);
static VOID     NTAPI impl_IoDeleteDevice(PDEVICE_OBJECT deviceObject);
static NTSTATUS NTAPI impl_IoDeleteSymbolicLink(UNICODE_STRING* symLinkName);

// InterlockedXxx wrappers
static LONG NTAPI impl_InterlockedCompareExchange(volatile LONG* dest,
                                                   LONG exchange, LONG comparand);

} // extern "C"

// ---------------------------------------------------------------------------
// Symbol-name → address table
// ---------------------------------------------------------------------------

struct NtSymbol {
    const char* name;
    void*       address;
};

// Helper macro to shorten the table entries.
#define NT_SYM(fn) { #fn, reinterpret_cast<void*>(&impl_##fn) }

static const NtSymbol s_nt_symbols[] = {
    NT_SYM(DbgPrint),
    NT_SYM(DbgPrintEx),
    NT_SYM(RtlInitUnicodeString),
    NT_SYM(RtlEqualUnicodeString),
    NT_SYM(RtlCopyUnicodeString),
    NT_SYM(RtlCompareUnicodeString),
    NT_SYM(ExAllocatePoolWithTag),
    NT_SYM(ExAllocatePool2),
    NT_SYM(ExFreePool),
    NT_SYM(ExFreePoolWithTag),
    NT_SYM(KeInitializeSpinLock),
    NT_SYM(ObfReferenceObject),
    NT_SYM(ObfDereferenceObject),
    NT_SYM(MmGetSystemRoutineAddress),
    NT_SYM(IoCreateDevice),
    NT_SYM(IoCreateSymbolicLink),
    NT_SYM(IoDeleteDevice),
    NT_SYM(IoDeleteSymbolicLink),
    NT_SYM(InterlockedCompareExchange),
};

#undef NT_SYM

void* nt_stubs_lookup_ntoskrnl(const char* name) noexcept {
    for (const auto& sym : s_nt_symbols) {
        if (std::strcmp(sym.name, name) == 0) return sym.address;
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// Implementations
// ---------------------------------------------------------------------------

static ULONG impl_DbgPrint(const char* format, ...) {
    std::va_list args;
    va_start(args, format);
    std::vfprintf(stderr, format, args);
    va_end(args);
    return 0;
}

static ULONG impl_DbgPrintEx(ULONG /*componentId*/, ULONG /*level*/,
                              const char* format, ...) {
    std::va_list args;
    va_start(args, format);
    std::vfprintf(stderr, format, args);
    va_end(args);
    return 0;
}

static VOID NTAPI impl_RtlInitUnicodeString(UNICODE_STRING* dest,
                                             const WCHAR* src) {
    if (!dest) return;
    if (!src) {
        dest->Length        = 0;
        dest->MaximumLength = 0;
        dest->Buffer        = nullptr;
        return;
    }
    const std::size_t raw_len = std::wcslen(src) * sizeof(WCHAR);
    // UNICODE_STRING.Length is USHORT; clamp to avoid overflow.
    constexpr std::size_t kMaxLen = 0xFFFEu;  // leave room for the NUL terminator
    const auto len = static_cast<USHORT>(raw_len < kMaxLen ? raw_len : kMaxLen);
    dest->Buffer        = const_cast<WCHAR*>(src);
    dest->Length        = len;
    dest->MaximumLength = len + static_cast<USHORT>(sizeof(WCHAR));
}

static BOOLEAN NTAPI impl_RtlEqualUnicodeString(const UNICODE_STRING* s1,
                                                  const UNICODE_STRING* s2,
                                                  BOOLEAN caseInsensitive) {
    if (!s1 || !s2) return FALSE;
    if (s1->Length != s2->Length) return FALSE;
    if (s1->Length == 0) return TRUE;
    const USHORT nChars = s1->Length / static_cast<USHORT>(sizeof(WCHAR));
    if (caseInsensitive) {
        return _wcsnicmp(s1->Buffer, s2->Buffer, nChars) == 0 ? TRUE : FALSE;
    }
    return std::wmemcmp(s1->Buffer, s2->Buffer, nChars) == 0 ? TRUE : FALSE;
}

static VOID NTAPI impl_RtlCopyUnicodeString(UNICODE_STRING* dest,
                                             const UNICODE_STRING* src) {
    if (!dest) return;
    if (!src || !src->Buffer) {
        dest->Length = 0;
        return;
    }
    const USHORT copy = (src->Length < dest->MaximumLength)
                        ? src->Length
                        : dest->MaximumLength;
    std::memcpy(dest->Buffer, src->Buffer, copy);
    dest->Length = copy;
    // Null-terminate if there is room.
    if (copy < dest->MaximumLength)
        dest->Buffer[copy / sizeof(WCHAR)] = L'\0';
}

static LONG NTAPI impl_RtlCompareUnicodeString(const UNICODE_STRING* s1,
                                                const UNICODE_STRING* s2,
                                                BOOLEAN caseInsensitive) {
    if (!s1 || !s2) return 0;
    const USHORT minLen = (s1->Length < s2->Length) ? s1->Length : s2->Length;
    const USHORT nChars = minLen / static_cast<USHORT>(sizeof(WCHAR));
    int cmp = caseInsensitive
        ? _wcsnicmp(s1->Buffer, s2->Buffer, nChars)
        : std::wmemcmp(s1->Buffer, s2->Buffer, nChars);
    if (cmp != 0) return cmp;
    return static_cast<LONG>(s1->Length) - static_cast<LONG>(s2->Length);
}

static PVOID NTAPI impl_ExAllocatePoolWithTag(ULONG /*poolType*/,
                                               SIZE_T numberOfBytes,
                                               ULONG /*tag*/) {
    return HeapAlloc(GetProcessHeap(), 0, numberOfBytes);
}

static PVOID NTAPI impl_ExAllocatePool2(ULONGLONG /*poolFlags*/,
                                         SIZE_T numberOfBytes,
                                         ULONG /*tag*/) {
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, numberOfBytes);
}

static VOID NTAPI impl_ExFreePool(PVOID p) {
    if (p) HeapFree(GetProcessHeap(), 0, p);
}

static VOID NTAPI impl_ExFreePoolWithTag(PVOID p, ULONG /*tag*/) {
    if (p) HeapFree(GetProcessHeap(), 0, p);
}

static VOID NTAPI impl_KeInitializeSpinLock(ULONG_PTR* spinLock) {
    if (spinLock) *spinLock = 0;
}

static LONG_PTR FASTCALL impl_ObfReferenceObject(PVOID /*object*/) {
    return 1;
}

static LONG_PTR FASTCALL impl_ObfDereferenceObject(PVOID /*object*/) {
    return 0;
}

static PVOID NTAPI impl_MmGetSystemRoutineAddress(UNICODE_STRING* routineName) {
    if (!routineName || !routineName->Buffer) return nullptr;
    // Convert to narrow string for the symbol table lookup.
    char narrow[256] = {};
    const int len = WideCharToMultiByte(CP_ACP, 0,
        routineName->Buffer,
        routineName->Length / static_cast<int>(sizeof(WCHAR)),
        narrow, static_cast<int>(sizeof(narrow)) - 1, nullptr, nullptr);
    if (len <= 0) return nullptr;
    narrow[len] = '\0';
    return nt_stubs_lookup_ntoskrnl(narrow);
}

static NTSTATUS NTAPI impl_IoCreateDevice(PDRIVER_OBJECT driverObject,
                                           ULONG deviceExtensionSize,
                                           UNICODE_STRING* /*deviceName*/,
                                           ULONG /*deviceType*/,
                                           ULONG /*deviceCharacteristics*/,
                                           BOOLEAN /*exclusive*/,
                                           PDEVICE_OBJECT* deviceObject) {
    if (!deviceObject) return STATUS_INVALID_PARAMETER;
    const SIZE_T total = sizeof(DEVICE_OBJECT) + deviceExtensionSize;
    auto* dev = static_cast<DEVICE_OBJECT*>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, total));
    if (!dev) return STATUS_INSUFFICIENT_RESOURCES;
    dev->Type         = 3; // IO_TYPE_DEVICE
    dev->Size         = static_cast<USHORT>(total);
    dev->DriverObject = driverObject;
    if (deviceExtensionSize > 0)
        dev->DeviceExtension = reinterpret_cast<UCHAR*>(dev) + sizeof(DEVICE_OBJECT);
    // Link into the driver's device list (prepend).
    if (driverObject) {
        dev->NextDevice            = driverObject->DeviceObject;
        driverObject->DeviceObject = dev;
    }
    *deviceObject = dev;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_IoCreateSymbolicLink(UNICODE_STRING* /*symLinkName*/,
                                                  UNICODE_STRING* /*deviceName*/) {
    // No-op in user mode – always succeed.
    return STATUS_SUCCESS;
}

static VOID NTAPI impl_IoDeleteDevice(PDEVICE_OBJECT deviceObject) {
    if (!deviceObject) return;
    // Unlink from the driver's device list.
    PDRIVER_OBJECT drv = deviceObject->DriverObject;
    if (drv) {
        PDEVICE_OBJECT* pp = &drv->DeviceObject;
        while (*pp && *pp != deviceObject)
            pp = &(*pp)->NextDevice;
        if (*pp) *pp = deviceObject->NextDevice;
    }
    HeapFree(GetProcessHeap(), 0, deviceObject);
}

static NTSTATUS NTAPI impl_IoDeleteSymbolicLink(UNICODE_STRING* /*symLinkName*/) {
    return STATUS_SUCCESS;
}

static LONG NTAPI impl_InterlockedCompareExchange(volatile LONG* dest,
                                                   LONG exchange,
                                                   LONG comparand) {
    return InterlockedCompareExchange(
        reinterpret_cast<volatile LONG*>(dest), exchange, comparand);
}
