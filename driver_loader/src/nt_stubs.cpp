// nt_stubs.cpp – Stub infrastructure + implementations of ntoskrnl.exe exports.
//
// The numbered "abort" stubs are generated at configure-time into
// nt_stubs_generated.cpp by CMakeLists.txt.  This file provides:
//   • The shared state (name_table, next_index, handle_call).
//   • The public helper used by DriverLoader to allocate a stub slot.
//   • Implementations of common ntoskrnl.exe functions.
//   • Implementations of HAL, WDF, CNG and CRT functions (same symbol table).

// <windows.h> must come before wdm.hpp to establish scalar type definitions.
#include <windows.h>

#include "../include/driver_loader.hpp"
#include "../include/wdf.hpp"
#include "../include/wdm.hpp"
#include "nt_stubs_internal.hpp"

#include <array>
#include <cctype>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <format>
#include <iostream>
#include <limits>
#include <print>
#include <string>
#include <utility>

// ---------------------------------------------------------------------------
// Shared stub state
// ---------------------------------------------------------------------------

namespace nt_stubs_internal
{

std::array<const char *, 256> name_table = {};
int next_index = 0;

[[noreturn]] static void ReportAndAbort(const char *msg) noexcept
{
    if (!msg)
        msg = "[nt_stubs] <null message>\n";
    OutputDebugStringA(msg);
    HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
    if (h && h != INVALID_HANDLE_VALUE)
    {
        DWORD written = 0;
        const DWORD len = static_cast<DWORD>(std::strlen(msg));
        (void)WriteFile(h, msg, len, &written, nullptr);
    }
    std::print(std::cerr, "{}", msg);
    std::flush(std::cerr);
    std::abort();
}

[[noreturn]] void HandleCall(int idx) noexcept
{
    const char *name = (idx >= 0 && idx < 256 && name_table[static_cast<std::size_t>(idx)])
                           ? name_table[static_cast<std::size_t>(idx)]
                           : "<unknown>";
    {
        const std::string enter_buf =
            std::format("[nt_stubs] handle_call-enter #{} name={}", idx, name);
        OutputDebugStringA(enter_buf.c_str());
        std::println(std::cerr, "{}", enter_buf);
        std::flush(std::cerr);
    }
    const std::string buf = std::format(
        "[nt_stubs] handle_call-exit  #{} result=<abort> reason=unimplemented symbol={}\n"
        "[nt_stubs] Unimplemented ntoskrnl function called: {} (stub #{})",
        idx, name, name, idx);
    ReportAndAbort(buf.c_str());
}

} // namespace nt_stubs_internal

// ---------------------------------------------------------------------------
// Fallback stub – used when all 256 numbered slots are exhausted.
// ---------------------------------------------------------------------------

static void *FallbackStub() noexcept
{
    nt_stubs_internal::ReportAndAbort(
        "[nt_stubs] An ntoskrnl stub was called but all 256 stub slots are "
        "exhausted.\n");
}

// ---------------------------------------------------------------------------
// Public helper: allocate a numbered stub slot for 'name'.
// Returns the stub function pointer, or the fallback stub pointer if all
// 256 slots are taken.
// ---------------------------------------------------------------------------

void *NtStubsAllocate(const char *name) noexcept
{
    using namespace nt_stubs_internal;
    if (next_index >= 256)
    {
        std::println(
            stderr,
            "[nt_stubs] Warning: more than 256 stubs requested; '{}' will use the fallback stub.",
            name ? name : "<null>");
        return reinterpret_cast<void *>(&FallbackStub);
    }
    name_table[static_cast<std::size_t>(next_index)] = name;
    void *ptr = reinterpret_cast<void *>(nt_stubs_internal::GetStubTable()[next_index]);
    ++next_index;
    return ptr;
}

// ---------------------------------------------------------------------------
// Global variable stubs
//
// For kernel data exports (PsProcessType, SeExports, etc.) the IAT entry
// must hold the ADDRESS of the variable, not its value.  We return &var from
// the symbol table so the driver's *__imp_Var dereference gives our value.
// ---------------------------------------------------------------------------

static ULONG_PTR s_fakeObjectTypeProc = 1;
static ULONG_PTR s_fakeObjectTypeThr = 1;
static ULONG_PTR s_fakeObjectTypeDev = 1;
static PVOID s_psProcessType = &s_fakeObjectTypeProc;
static PVOID s_psThreadType = &s_fakeObjectTypeThr;
static PVOID s_ioDeviceObjectType = &s_fakeObjectTypeDev;
static EPROCESS s_fakeEprocess = {};
static PEPROCESS s_psInitialSystemProcess = &s_fakeEprocess;
static SE_EXPORTS s_seExportsBuf = {};
static PSE_EXPORTS s_seExports = &s_seExportsBuf;

// ---------------------------------------------------------------------------
// Built-in symbol table
//
// Consulted by NtStubsLookup() for ALL imported DLLs (ntoskrnl, hal,
// wdfldr, cng, etc.).  Function names are unique across kernel DLLs so a
// single flat table is safe.
// ---------------------------------------------------------------------------

// Forward declarations of every implementation below.
extern "C"
{

    // ---- Debug output ----------------------------------------------------------
    static ULONG impl_DbgPrint(const char *fmt, ...);
    static ULONG impl_DbgPrintEx(ULONG componentId, ULONG level, const char *fmt, ...);

    // ---- Unicode string helpers ------------------------------------------------
    static VOID NTAPI impl_RtlInitUnicodeString(UNICODE_STRING *dest, const WCHAR *src);
    static BOOLEAN NTAPI impl_RtlEqualUnicodeString(const UNICODE_STRING *s1,
                                                    const UNICODE_STRING *s2,
                                                    BOOLEAN caseInsensitive);
    static VOID NTAPI impl_RtlCopyUnicodeString(UNICODE_STRING *dest, const UNICODE_STRING *src);
    static LONG NTAPI impl_RtlCompareUnicodeString(const UNICODE_STRING *s1,
                                                   const UNICODE_STRING *s2,
                                                   BOOLEAN caseInsensitive);
    static VOID NTAPI impl_RtlFreeUnicodeString(UNICODE_STRING *str);

    // ---- RtlCompareMemory / Assert / SystemRoot --------------------------------
    static SIZE_T NTAPI impl_RtlCompareMemory(const VOID *s1, const VOID *s2, SIZE_T len);
    static VOID NTAPI impl_RtlAssert(PVOID assertion, PVOID fileName, ULONG line, char *message);
    static WCHAR *NTAPI impl_RtlGetNtSystemRoot(VOID);
    static NTSTATUS NTAPI impl_RtlUTF8ToUnicodeN(WCHAR *dest, ULONG destLen, ULONG *resultLen,
                                                 const char *src, ULONG srcLen);

    // ---- Security descriptor helpers -------------------------------------------
    static NTSTATUS NTAPI impl_RtlCreateSecurityDescriptor(PVOID sd, ULONG revision);
    static ULONG NTAPI impl_RtlLengthSecurityDescriptor(PVOID sd);
    static NTSTATUS NTAPI impl_RtlGetDaclSecurityDescriptor(PVOID sd, BOOLEAN *present, PVOID *dacl,
                                                            BOOLEAN *defaulted);
    static NTSTATUS NTAPI impl_RtlGetGroupSecurityDescriptor(PVOID sd, PVOID *group,
                                                             BOOLEAN *defaulted);
    static NTSTATUS NTAPI impl_RtlGetOwnerSecurityDescriptor(PVOID sd, PVOID *owner,
                                                             BOOLEAN *defaulted);
    static NTSTATUS NTAPI impl_RtlGetSaclSecurityDescriptor(PVOID sd, BOOLEAN *present, PVOID *sacl,
                                                            BOOLEAN *defaulted);
    static NTSTATUS NTAPI impl_RtlSetDaclSecurityDescriptor(PVOID sd, BOOLEAN present, PVOID dacl,
                                                            BOOLEAN defaulted);
    static NTSTATUS NTAPI impl_RtlAbsoluteToSelfRelativeSD(PVOID absoluteSD, PVOID selfRelSD,
                                                           ULONG *bufLen);
    static NTSTATUS NTAPI impl_RtlAddAccessAllowedAce(PVOID acl, ULONG aceRev, ULONG accessMask,
                                                      PVOID sid);
    static ULONG NTAPI impl_RtlLengthSid(PVOID sid);
    static NTSTATUS NTAPI impl_SeCaptureSecurityDescriptor(PVOID srcSD, ULONG accessMode,
                                                           ULONG poolType, BOOLEAN captureIfKernel,
                                                           PVOID *capturedSD);

    // ---- Memory allocation -----------------------------------------------------
    static PVOID NTAPI impl_ExAllocatePoolWithTag(ULONG poolType, SIZE_T numberOfBytes, ULONG tag);
    static PVOID NTAPI impl_ExAllocatePool2(ULONGLONG poolFlags, SIZE_T numberOfBytes, ULONG tag);
    static VOID NTAPI impl_ExFreePool(PVOID p);
    static VOID NTAPI impl_ExFreePoolWithTag(PVOID p, ULONG tag);

    // ---- Mutex / event ---------------------------------------------------------
    static VOID FASTCALL impl_ExAcquireFastMutex(FAST_MUTEX *mutex);
    static VOID FASTCALL impl_ExReleaseFastMutex(FAST_MUTEX *mutex);
    static VOID NTAPI impl_KeInitializeSpinLock(ULONG_PTR *spinLock);
    static VOID NTAPI impl_KeInitializeEvent(KEVENT *event, ULONG type, BOOLEAN state);

    // ---- IRQL ------------------------------------------------------------------
    static KIRQL NTAPI impl_KeGetCurrentIrql(VOID);
    static KIRQL NTAPI impl_KeRaiseIrqlToDpcLevel(VOID);
    static KIRQL FASTCALL impl_KfRaiseIrql(KIRQL newIrql);
    static VOID NTAPI impl_RtlFailFast(ULONG_PTR code);

    // ---- Reference counting ----------------------------------------------------
    static LONG_PTR FASTCALL impl_ObfReferenceObject(PVOID object);
    static LONG_PTR FASTCALL impl_ObfDereferenceObject(PVOID object);
    static NTSTATUS NTAPI impl_ObReferenceObjectByHandle(HANDLE handle, ULONG access,
                                                         PVOID objectType, UCHAR accessMode,
                                                         PVOID *object, PVOID handleInfo);
    static NTSTATUS NTAPI impl_ObOpenObjectByPointer(PVOID object, ULONG attrs, PVOID accessState,
                                                     ULONG access, PVOID objectType,
                                                     UCHAR accessMode, HANDLE *handle);
    static NTSTATUS NTAPI impl_ObQueryNameString(PVOID object, PVOID nameInfo, ULONG length,
                                                 ULONG *returnLength);

    // ---- System routine lookup -------------------------------------------------
    static PVOID NTAPI impl_MmGetSystemRoutineAddress(UNICODE_STRING *routineName);

    // ---- Memory descriptor list ------------------------------------------------
    static PMDL NTAPI impl_IoAllocateMdl(PVOID va, ULONG byteCount, BOOLEAN secondary,
                                         BOOLEAN chargeQuota, PIRP irp);
    static VOID NTAPI impl_IoFreeMdl(PMDL mdl);
    static VOID NTAPI impl_MmProbeAndLockPages(PMDL mdl, UCHAR accessMode, ULONG operation);
    static VOID NTAPI impl_MmUnlockPages(PMDL mdl);
    static PVOID NTAPI impl_MmMapLockedPagesSpecifyCache(PMDL mdl, UCHAR accessMode,
                                                         ULONG cacheType, PVOID baseAddr,
                                                         ULONG zeroBits, ULONG priority);
    static VOID NTAPI impl_MmUnmapLockedPages(PVOID baseAddr, PMDL mdl);
    static NTSTATUS NTAPI impl_MmProtectMdlSystemAddress(PMDL mdl, ULONG newProtect);
    static BOOLEAN NTAPI impl_MmIsAddressValid(PVOID addr);

    // ---- Device I/O ------------------------------------------------------------
    static NTSTATUS NTAPI impl_IoCreateDevice(PDRIVER_OBJECT driverObject, ULONG extSize,
                                              UNICODE_STRING *devName, ULONG devType,
                                              ULONG devChars, BOOLEAN exclusive,
                                              PDEVICE_OBJECT *deviceObject);
    static NTSTATUS NTAPI impl_IoCreateSymbolicLink(UNICODE_STRING *symLink,
                                                    UNICODE_STRING *devName);
    static VOID NTAPI impl_IoDeleteDevice(PDEVICE_OBJECT deviceObject);
    static NTSTATUS NTAPI impl_IoDeleteSymbolicLink(UNICODE_STRING *symLink);
    static VOID FASTCALL impl_IofCompleteRequest(PIRP irp, char priorityBoost);
    static BOOLEAN NTAPI impl_IoIsWdmVersionAvailable(UCHAR major, UCHAR minor);

    // ---- Process / thread ------------------------------------------------------
    static NTSTATUS NTAPI impl_PsRegisterPicoProvider(PVOID provider, PVOID routines);
    static PEPROCESS NTAPI impl_IoGetCurrentProcess(VOID);
    static PVOID NTAPI impl_PsGetCurrentProcessId(VOID);
    static PVOID NTAPI impl_PsGetProcessId(PEPROCESS process);
    static PKTHREAD NTAPI impl_KeGetCurrentThread(VOID);

    // ---- Zw* (registry / object / memory) -------------------------------------
    static NTSTATUS NTAPI impl_ZwClose(HANDLE handle);
    static NTSTATUS NTAPI impl_ZwOpenKey(HANDLE *key, ULONG access, PVOID attrs);
    static NTSTATUS NTAPI impl_ZwCreateKey(HANDLE *key, ULONG access, PVOID attrs, ULONG titleIdx,
                                           PVOID cls, ULONG options, ULONG *disposition);
    static NTSTATUS NTAPI impl_ZwQueryValueKey(HANDLE key, PVOID name, ULONG keyClass, PVOID info,
                                               ULONG infoLen, ULONG *resultLen);
    static NTSTATUS NTAPI impl_ZwSetValueKey(HANDLE key, PVOID name, ULONG titleIdx, ULONG type,
                                             PVOID data, ULONG len);
    static NTSTATUS NTAPI impl_ZwSetSecurityObject(HANDLE handle, ULONG secInfo, PVOID sd);
    static NTSTATUS NTAPI impl_ZwQuerySystemInformation(ULONG infoClass, PVOID info, ULONG infoLen,
                                                        ULONG *returnLen);
    static NTSTATUS NTAPI impl_ZwFlushInstructionCache(HANDLE process, PVOID baseAddr, SIZE_T len);
    static NTSTATUS NTAPI impl_ZwDuplicateObject(HANDLE srcProcess, HANDLE srcHandle,
                                                 HANDLE dstProcess, HANDLE *dstHandle, ULONG access,
                                                 ULONG attrs, ULONG opts);
    static NTSTATUS NTAPI impl_ZwTerminateProcess(HANDLE process, NTSTATUS exitStatus);
    static NTSTATUS NTAPI impl_ZwAllocateVirtualMemory(HANDLE process, PVOID *baseAddr,
                                                       ULONG_PTR zeroBits, SIZE_T *regionSize,
                                                       ULONG allocType, ULONG protect);
    static NTSTATUS NTAPI impl_ZwFreeVirtualMemory(HANDLE process, PVOID *baseAddr,
                                                   SIZE_T *regionSize, ULONG freeType);
    static NTSTATUS NTAPI impl_ZwCreateFile(HANDLE *fileHandle, ULONG access, PVOID attrs,
                                            PVOID ioStatus, PVOID allocSize, ULONG fileAttrs,
                                            ULONG shareAccess, ULONG createDisp, ULONG createOpts,
                                            PVOID eaBuffer, ULONG eaLength);
    static LONG impl___C_specific_handler_fallback(...);
    static VOID NTAPI impl__local_unwind_fallback(PVOID frame, PVOID targetIp);
    static VOID NTAPI impl___jump_unwind_fallback(PVOID frame, PVOID targetIp);
    static VOID NTAPI impl_RtlUnwind_fallback(PVOID targetFrame, PVOID targetIp,
                                              PVOID exceptionRecord, PVOID returnValue);

    // ---- ETW -------------------------------------------------------------------
    static NTSTATUS NTAPI impl_EtwRegister(PVOID providerId, PVOID callback, PVOID context,
                                           PVOID *regHandle);
    static NTSTATUS NTAPI impl_EtwSetInformation(PVOID regHandle, ULONG infoClass, PVOID info,
                                                 ULONG infoLen);
    static NTSTATUS NTAPI impl_EtwWriteTransfer(PVOID regHandle, PVOID eventDesc, PVOID *activityId,
                                                PVOID *relatedId, ULONG userDataCount,
                                                PVOID userData);

    // ---- Timing ----------------------------------------------------------------
    static NTSTATUS NTAPI impl_KeDelayExecutionThread(ULONG mode, BOOLEAN alertable,
                                                      PVOID interval);

    // ---- Interlock -------------------------------------------------------------
    static LONG NTAPI impl_InterlockedCompareExchange(volatile LONG *dest, LONG exchange,
                                                      LONG comparand);

    // ---- WDF (wdfldr.sys) ------------------------------------------------------
    static NTSTATUS NTAPI impl_WdfVersionBind(PDRIVER_OBJECT driverObject,
                                              PUNICODE_STRING registryPath, PWDF_BIND_INFO bindInfo,
                                              PWDF_COMPONENT_GLOBALS *componentGlobals);
    static NTSTATUS NTAPI impl_WdfVersionBindClass(PVOID context, PWDF_BIND_INFO bindInfo,
                                                   PWDF_COMPONENT_GLOBALS *componentGlobals);
    static VOID NTAPI impl_WdfVersionUnbind(PUNICODE_STRING registryPath, PWDF_BIND_INFO bindInfo,
                                            PWDF_COMPONENT_GLOBALS componentGlobals);
    static VOID NTAPI impl_WdfVersionUnbindClass(PVOID context, PWDF_BIND_INFO bindInfo,
                                                 PWDF_COMPONENT_GLOBALS componentGlobals);
    static NTSTATUS NTAPI impl_WdfLdrQueryInterface(PVOID iface);

    // ---- BCrypt (cng.sys) ------------------------------------------------------
    static NTSTATUS NTAPI impl_BCryptGenRandom(PVOID alg, UCHAR *buf, ULONG len, ULONG flags);

    // ---- CRT wrappers (ntoskrnl re-exports) ------------------------------------
    // No calling-convention attribute: default is __cdecl on all arches, matching
    // how kernel CRT exports are generated by MSVC.
    static std::size_t impl_strnlen(const char *s, std::size_t n);
    static int impl__stricmp(const char *s1, const char *s2);
    static int impl_strncmp(const char *s1, const char *s2, std::size_t n);
    static int impl_strcmp(const char *s1, const char *s2);
    static char *impl_strcpy(char *dst, const char *src);
    static char *impl_strncpy(char *dst, const char *src, std::size_t n);
    static std::size_t impl_strlen(const char *s);
    static int impl_wcsncmp(const WCHAR *s1, const WCHAR *s2, std::size_t n);
    static std::size_t impl_wcslen(const WCHAR *s);
    static int impl__wcsnicmp(const WCHAR *s1, const WCHAR *s2, std::size_t n);
    static WCHAR *impl_wcschr(const WCHAR *s, WCHAR c);
    static void *impl_memset(void *s, int c, std::size_t n);
    static void *impl_memcpy(void *dst, const void *src, std::size_t n);
    static int impl_isupper(int c);
    static int impl_isdigit(int c);
    static int impl_iswspace(unsigned int c);
    static int impl_tolower(int c);
    static int impl__snprintf(char *buf, std::size_t count, const char *fmt, ...);
    static int impl__snwprintf(WCHAR *buf, std::size_t count, const WCHAR *fmt, ...);

} // extern "C"

// ---------------------------------------------------------------------------
// Symbol-name → address table
// ---------------------------------------------------------------------------

struct NtSymbol
{
    const char *name;
    void *address;
};

#define NT_SYM(fn)                                                                                 \
    {                                                                                              \
        #fn, reinterpret_cast<void *>(&impl_##fn)                                                  \
    }
#define NT_VAR(sym)                                                                                \
    {                                                                                              \
        #sym, reinterpret_cast<void *>(&s_##sym)                                                   \
    }

static const NtSymbol s_ntSymbols[] = {
    // ---- Debug output -------------------------------------------------------
    NT_SYM(DbgPrint),
    NT_SYM(DbgPrintEx),

    // ---- Unicode string helpers ---------------------------------------------
    NT_SYM(RtlInitUnicodeString),
    NT_SYM(RtlEqualUnicodeString),
    NT_SYM(RtlCopyUnicodeString),
    NT_SYM(RtlCompareUnicodeString),
    NT_SYM(RtlFreeUnicodeString),
    NT_SYM(RtlFailFast),
    NT_SYM(RtlCompareMemory),
    NT_SYM(RtlAssert),
    NT_SYM(RtlGetNtSystemRoot),
    NT_SYM(RtlUTF8ToUnicodeN),

    // ---- Security descriptor helpers ----------------------------------------
    NT_SYM(RtlCreateSecurityDescriptor),
    NT_SYM(RtlLengthSecurityDescriptor),
    NT_SYM(RtlGetDaclSecurityDescriptor),
    NT_SYM(RtlGetGroupSecurityDescriptor),
    NT_SYM(RtlGetOwnerSecurityDescriptor),
    NT_SYM(RtlGetSaclSecurityDescriptor),
    NT_SYM(RtlSetDaclSecurityDescriptor),
    NT_SYM(RtlAbsoluteToSelfRelativeSD),
    NT_SYM(RtlAddAccessAllowedAce),
    NT_SYM(RtlLengthSid),
    NT_SYM(SeCaptureSecurityDescriptor),

    // ---- Global kernel variables (DATA imports) -----------------------------
    NT_VAR(PsProcessType),
    NT_VAR(PsThreadType),
    NT_VAR(IoDeviceObjectType),
    NT_VAR(PsInitialSystemProcess),
    NT_VAR(SeExports),

    // ---- Memory allocation --------------------------------------------------
    NT_SYM(ExAllocatePoolWithTag),
    NT_SYM(ExAllocatePool2),
    NT_SYM(ExFreePool),
    NT_SYM(ExFreePoolWithTag),

    // ---- Mutex / event / spin-lock ------------------------------------------
    NT_SYM(ExAcquireFastMutex),
    NT_SYM(ExReleaseFastMutex),
    NT_SYM(KeInitializeSpinLock),
    NT_SYM(KeInitializeEvent),

    // ---- IRQL ---------------------------------------------------------------
    NT_SYM(KeGetCurrentIrql),
    NT_SYM(KeRaiseIrqlToDpcLevel),
    NT_SYM(KfRaiseIrql),

    // ---- Reference counting -------------------------------------------------
    NT_SYM(ObfReferenceObject),
    NT_SYM(ObfDereferenceObject),
    NT_SYM(ObReferenceObjectByHandle),
    NT_SYM(ObOpenObjectByPointer),
    NT_SYM(ObQueryNameString),

    // ---- System routine lookup ----------------------------------------------
    NT_SYM(MmGetSystemRoutineAddress),

    // ---- MDL operations -----------------------------------------------------
    NT_SYM(IoAllocateMdl),
    NT_SYM(IoFreeMdl),
    NT_SYM(MmProbeAndLockPages),
    NT_SYM(MmUnlockPages),
    NT_SYM(MmMapLockedPagesSpecifyCache),
    NT_SYM(MmUnmapLockedPages),
    NT_SYM(MmProtectMdlSystemAddress),
    NT_SYM(MmIsAddressValid),

    // ---- Device I/O ---------------------------------------------------------
    NT_SYM(IoCreateDevice),
    NT_SYM(IoCreateSymbolicLink),
    NT_SYM(IoDeleteDevice),
    NT_SYM(IoDeleteSymbolicLink),
    NT_SYM(IofCompleteRequest),
    NT_SYM(IoIsWdmVersionAvailable),

    // ---- Process / thread ---------------------------------------------------
    NT_SYM(PsRegisterPicoProvider),
    NT_SYM(IoGetCurrentProcess),
    NT_SYM(PsGetCurrentProcessId),
    NT_SYM(PsGetProcessId),
    NT_SYM(KeGetCurrentThread),

    // ---- Zw* ----------------------------------------------------------------
    NT_SYM(ZwClose),
    NT_SYM(ZwOpenKey),
    NT_SYM(ZwCreateKey),
    NT_SYM(ZwQueryValueKey),
    NT_SYM(ZwSetValueKey),
    NT_SYM(ZwSetSecurityObject),
    NT_SYM(ZwQuerySystemInformation),
    NT_SYM(ZwFlushInstructionCache),
    NT_SYM(ZwDuplicateObject),
    NT_SYM(ZwTerminateProcess),
    NT_SYM(ZwAllocateVirtualMemory),
    NT_SYM(ZwFreeVirtualMemory),
    NT_SYM(ZwCreateFile),

    // ---- ETW ----------------------------------------------------------------
    NT_SYM(EtwRegister),
    NT_SYM(EtwSetInformation),
    NT_SYM(EtwWriteTransfer),

    // ---- Timing / interlock -------------------------------------------------
    NT_SYM(KeDelayExecutionThread),
    NT_SYM(InterlockedCompareExchange),

    // ---- WDF (wdfldr.sys) ---------------------------------------------------
    NT_SYM(WdfVersionBind),
    NT_SYM(WdfVersionBindClass),
    NT_SYM(WdfVersionUnbind),
    NT_SYM(WdfVersionUnbindClass),
    NT_SYM(WdfLdrQueryInterface),

    // ---- BCrypt (cng.sys) ---------------------------------------------------
    NT_SYM(BCryptGenRandom),

    // ---- CRT wrappers -------------------------------------------------------
    NT_SYM(strnlen),
    {"_stricmp", reinterpret_cast<void *>(&impl__stricmp)},
    NT_SYM(strncmp),
    NT_SYM(strcmp),
    NT_SYM(strcpy),
    NT_SYM(strncpy),
    NT_SYM(strlen),
    NT_SYM(wcsncmp),
    NT_SYM(wcslen),
    {"_wcsnicmp", reinterpret_cast<void *>(&impl__wcsnicmp)},
    NT_SYM(wcschr),
    NT_SYM(memset),
    NT_SYM(memcpy),
    NT_SYM(isupper),
    NT_SYM(isdigit),
    NT_SYM(iswspace),
    NT_SYM(tolower),
    {"_snprintf", reinterpret_cast<void *>(&impl__snprintf)},
    {"_snwprintf", reinterpret_cast<void *>(&impl__snwprintf)},
};

#undef NT_SYM
#undef NT_VAR

// ---------------------------------------------------------------------------
// NtStubsLookup – consulted for ALL imported DLLs.
// Special-cases a few SEH/unwind helpers that must resolve to the real
// implementations in ntdll.dll / msvcrt.dll.
// ---------------------------------------------------------------------------

void *NtStubsLookup(const char *name) noexcept
{
    if (!name)
        return nullptr;

    // SEH / unwind helpers: look up from the host DLLs at runtime.
    // These must be the genuine implementations for SEH to work.
    {
        static const char *const seh_names[] = {
            "__C_specific_handler",
            "_local_unwind",
            "RtlUnwind",
            "__jump_unwind",
        };
        for (const char *sn : seh_names)
        {
            if (std::strcmp(name, sn) == 0)
            {
#if defined(_M_IX86) || defined(__i386__)
                // On 32-bit x86, forwarding kernel unwind helpers to ntdll's
                // user-mode implementations can terminate the process when
                // unwind metadata/context differs. Prefer local fallbacks.
                std::println(stderr, "[nt_stubs] lookup {} -> x86 fallback", name);
                if (std::strcmp(sn, "__C_specific_handler") == 0)
                    return reinterpret_cast<void *>(&impl___C_specific_handler_fallback);
                if (std::strcmp(sn, "_local_unwind") == 0)
                    return reinterpret_cast<void *>(&impl__local_unwind_fallback);
                if (std::strcmp(sn, "__jump_unwind") == 0)
                    return reinterpret_cast<void *>(&impl___jump_unwind_fallback);
                if (std::strcmp(sn, "RtlUnwind") == 0)
                    return reinterpret_cast<void *>(&impl_RtlUnwind_fallback);
#endif
                HMODULE m = GetModuleHandleA("ntdll.dll");
                if (m)
                {
                    void *p = reinterpret_cast<void *>(GetProcAddress(m, sn));
                    if (p)
                    {
                        std::println(stderr, "[nt_stubs] lookup {} -> ntdll @ {:p}", name, p);
                        return p;
                    }
                }
                // _local_unwind / __jump_unwind may be in msvcrt.dll.
                m = GetModuleHandleA("msvcrt.dll");
                if (!m)
                    m = LoadLibraryA("msvcrt.dll");
                if (m)
                {
                    void *p = reinterpret_cast<void *>(GetProcAddress(m, sn));
                    if (p)
                    {
                        std::println(stderr, "[nt_stubs] lookup {} -> msvcrt @ {:p}", name, p);
                        return p;
                    }
                }
                // Fallback to no-op helpers so DriverEntry can continue on
                // runtimes where these exports are absent.
                const std::string msg =
                    std::format("[nt_stubs] Warning: {} not found in ntdll/msvcrt; using fallback "
                                "implementation.\n",
                                sn);
                OutputDebugStringA(msg.c_str());
                std::print(std::cerr, "{}", msg);
                std::flush(std::cerr);
                if (std::strcmp(sn, "__C_specific_handler") == 0)
                    return reinterpret_cast<void *>(&impl___C_specific_handler_fallback);
                if (std::strcmp(sn, "_local_unwind") == 0)
                    return reinterpret_cast<void *>(&impl__local_unwind_fallback);
                if (std::strcmp(sn, "__jump_unwind") == 0)
                    return reinterpret_cast<void *>(&impl___jump_unwind_fallback);
                if (std::strcmp(sn, "RtlUnwind") == 0)
                    return reinterpret_cast<void *>(&impl_RtlUnwind_fallback);
                return nullptr;
            }
        }
    }

    for (const auto &sym : s_ntSymbols)
    {
        if (std::strcmp(sym.name, name) == 0)
        {
            std::println(stderr, "[nt_stubs] lookup {} -> builtin @ {:p}", name, sym.address);
            return sym.address;
        }
    }
    std::println(stderr, "[nt_stubs] lookup {} -> <unresolved>", name);
    return nullptr;
}

// Backward-compatibility alias (used internally by MmGetSystemRoutineAddress).
void *NtStubsLookupNtoskrnl(const char *name) noexcept
{
    return NtStubsLookup(name);
}

// ---------------------------------------------------------------------------
// Implementations
// ---------------------------------------------------------------------------

// Stub implementations are grouped by family for maintainability.
#include "nt_cng.cpp"
#include "nt_crt.cpp"
#include "nt_dbg.cpp"
#include "nt_etw.cpp"
#include "nt_ex.cpp"
#include "nt_io.cpp"
#include "nt_ke.cpp"
#include "nt_misc.cpp"
#include "nt_mm.cpp"
#include "nt_ob.cpp"
#include "nt_ps.cpp"
#include "nt_rtl.cpp"
#include "nt_wdf.cpp"
#include "nt_zw.cpp"
