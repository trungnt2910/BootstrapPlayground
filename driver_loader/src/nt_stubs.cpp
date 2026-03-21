// nt_stubs.cpp – Stub infrastructure + implementations of ntoskrnl.exe exports.
//
// The 256 numbered "abort" stubs are generated at configure-time into
// nt_stubs_generated.cpp by CMakeLists.txt.  This file provides:
//   • The shared state (name_table, next_index, handle_call).
//   • The public helper used by DriverLoader to allocate a stub slot.
//   • Implementations of common ntoskrnl.exe functions.
//   • Implementations of HAL, WDF, CNG and CRT functions (same symbol table).

// <windows.h> must come before wdm.hpp to establish scalar type definitions.
#include <windows.h>

#include "nt_stubs_internal.hpp"
#include "../include/wdm.hpp"

#include <array>
#include <cctype>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <cwctype>

// ---------------------------------------------------------------------------
// Shared stub state
// ---------------------------------------------------------------------------

namespace nt_stubs_internal {

std::array<const char*, 256> name_table = {};
int next_index = 0;

[[noreturn]] static void report_and_abort(const char* msg) noexcept {
    if (!msg) msg = "[nt_stubs] <null message>\n";
    OutputDebugStringA(msg);
    HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
    if (h && h != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        const DWORD len = static_cast<DWORD>(std::strlen(msg));
        (void)WriteFile(h, msg, len, &written, nullptr);
    }
    std::fputs(msg, stderr);
    std::fflush(stderr);
    std::abort();
}

[[noreturn]] void handle_call(int idx) noexcept {
    const char* name =
        (idx >= 0 && idx < 256 && name_table[static_cast<std::size_t>(idx)])
        ? name_table[static_cast<std::size_t>(idx)]
        : "<unknown>";
    char buf[320];
    std::snprintf(buf, sizeof(buf),
                  "[nt_stubs] Unimplemented ntoskrnl function called: %s (stub #%d)\n",
                  name, idx);
    report_and_abort(buf);
}

} // namespace nt_stubs_internal

// ---------------------------------------------------------------------------
// Fallback stub – used when all 256 numbered slots are exhausted.
// ---------------------------------------------------------------------------

static void* fallback_stub() noexcept {
    nt_stubs_internal::report_and_abort(
        "[nt_stubs] An ntoskrnl stub was called but all 256 stub slots are "
        "exhausted.\n");
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
// Global variable stubs
//
// For kernel data exports (PsProcessType, SeExports, etc.) the IAT entry
// must hold the ADDRESS of the variable, not its value.  We return &var from
// the symbol table so the driver's *__imp_Var dereference gives our value.
// ---------------------------------------------------------------------------

static PVOID        s_PsProcessType          = nullptr;
static PVOID        s_PsThreadType           = nullptr;
static PVOID        s_IoDeviceObjectType     = nullptr;
static EPROCESS     s_fake_eprocess          = {};
static PEPROCESS    s_PsInitialSystemProcess = &s_fake_eprocess;
static SE_EXPORTS   s_se_exports_buf         = {};
static PSE_EXPORTS  s_SeExports              = &s_se_exports_buf;

// Fake WDF component globals buffer (zeroed; used by WdfVersionBind stubs).
static UCHAR        s_wdf_globals_buf[1024]  = {};

// ---------------------------------------------------------------------------
// Built-in symbol table
//
// Consulted by nt_stubs_lookup() for ALL imported DLLs (ntoskrnl, hal,
// wdfldr, cng, etc.).  Function names are unique across kernel DLLs so a
// single flat table is safe.
// ---------------------------------------------------------------------------

// Forward declarations of every implementation below.
extern "C" {

// ---- Debug output ----------------------------------------------------------
static ULONG impl_DbgPrint(const char* fmt, ...);
static ULONG impl_DbgPrintEx(ULONG componentId, ULONG level,
                              const char* fmt, ...);

// ---- Unicode string helpers ------------------------------------------------
static VOID   NTAPI impl_RtlInitUnicodeString(UNICODE_STRING* dest,
                                               const WCHAR* src);
static BOOLEAN NTAPI impl_RtlEqualUnicodeString(const UNICODE_STRING* s1,
                                                 const UNICODE_STRING* s2,
                                                 BOOLEAN caseInsensitive);
static VOID   NTAPI impl_RtlCopyUnicodeString(UNICODE_STRING* dest,
                                               const UNICODE_STRING* src);
static LONG   NTAPI impl_RtlCompareUnicodeString(const UNICODE_STRING* s1,
                                                  const UNICODE_STRING* s2,
                                                  BOOLEAN caseInsensitive);
static VOID   NTAPI impl_RtlFreeUnicodeString(UNICODE_STRING* str);

// ---- RtlCompareMemory / Assert / SystemRoot --------------------------------
static SIZE_T NTAPI impl_RtlCompareMemory(const VOID* s1, const VOID* s2,
                                           SIZE_T len);
static VOID   NTAPI impl_RtlAssert(PVOID assertion, PVOID fileName,
                                    ULONG line, char* message);
static WCHAR* NTAPI impl_RtlGetNtSystemRoot(VOID);
static NTSTATUS NTAPI impl_RtlUTF8ToUnicodeN(WCHAR* dest, ULONG destLen,
                                              ULONG* resultLen,
                                              const char* src, ULONG srcLen);

// ---- Security descriptor helpers -------------------------------------------
static NTSTATUS NTAPI impl_RtlCreateSecurityDescriptor(PVOID sd,
                                                        ULONG revision);
static ULONG    NTAPI impl_RtlLengthSecurityDescriptor(PVOID sd);
static NTSTATUS NTAPI impl_RtlGetDaclSecurityDescriptor(PVOID sd,
                        BOOLEAN* present, PVOID* dacl, BOOLEAN* defaulted);
static NTSTATUS NTAPI impl_RtlGetGroupSecurityDescriptor(PVOID sd,
                        PVOID* group, BOOLEAN* defaulted);
static NTSTATUS NTAPI impl_RtlGetOwnerSecurityDescriptor(PVOID sd,
                        PVOID* owner, BOOLEAN* defaulted);
static NTSTATUS NTAPI impl_RtlGetSaclSecurityDescriptor(PVOID sd,
                        BOOLEAN* present, PVOID* sacl, BOOLEAN* defaulted);
static NTSTATUS NTAPI impl_RtlSetDaclSecurityDescriptor(PVOID sd,
                        BOOLEAN present, PVOID dacl, BOOLEAN defaulted);
static NTSTATUS NTAPI impl_RtlAbsoluteToSelfRelativeSD(PVOID absoluteSD,
                        PVOID selfRelSD, ULONG* bufLen);
static NTSTATUS NTAPI impl_RtlAddAccessAllowedAce(PVOID acl, ULONG aceRev,
                        ULONG accessMask, PVOID sid);
static ULONG    NTAPI impl_RtlLengthSid(PVOID sid);
static NTSTATUS NTAPI impl_SeCaptureSecurityDescriptor(PVOID srcSD,
                        ULONG accessMode, ULONG poolType,
                        BOOLEAN captureIfKernel, PVOID* capturedSD);

// ---- Memory allocation -----------------------------------------------------
static PVOID NTAPI impl_ExAllocatePoolWithTag(ULONG poolType,
                                               SIZE_T numberOfBytes,
                                               ULONG tag);
static PVOID NTAPI impl_ExAllocatePool2(ULONGLONG poolFlags,
                                         SIZE_T numberOfBytes,
                                         ULONG tag);
static VOID  NTAPI impl_ExFreePool(PVOID p);
static VOID  NTAPI impl_ExFreePoolWithTag(PVOID p, ULONG tag);

// ---- Mutex / event ---------------------------------------------------------
static VOID FASTCALL impl_ExAcquireFastMutex(FAST_MUTEX* mutex);
static VOID FASTCALL impl_ExReleaseFastMutex(FAST_MUTEX* mutex);
static VOID   NTAPI impl_KeInitializeSpinLock(ULONG_PTR* spinLock);
static VOID   NTAPI impl_KeInitializeEvent(KEVENT* event, ULONG type,
                                            BOOLEAN state);

// ---- IRQL ------------------------------------------------------------------
static KIRQL  NTAPI  impl_KeGetCurrentIrql(VOID);
static KIRQL  NTAPI  impl_KeRaiseIrqlToDpcLevel(VOID);
static KIRQL  FASTCALL impl_KfRaiseIrql(KIRQL newIrql);

// ---- Reference counting ----------------------------------------------------
static LONG_PTR FASTCALL impl_ObfReferenceObject(PVOID object);
static LONG_PTR FASTCALL impl_ObfDereferenceObject(PVOID object);
static NTSTATUS NTAPI impl_ObReferenceObjectByHandle(HANDLE handle,
                        ULONG access, PVOID objectType, UCHAR accessMode,
                        PVOID* object, PVOID handleInfo);
static NTSTATUS NTAPI impl_ObOpenObjectByPointer(PVOID object, ULONG attrs,
                        PVOID accessState, ULONG access, PVOID objectType,
                        UCHAR accessMode, HANDLE* handle);
static NTSTATUS NTAPI impl_ObQueryNameString(PVOID object, PVOID nameInfo,
                        ULONG length, ULONG* returnLength);

// ---- System routine lookup -------------------------------------------------
static PVOID NTAPI impl_MmGetSystemRoutineAddress(UNICODE_STRING* routineName);

// ---- Memory descriptor list ------------------------------------------------
static PMDL  NTAPI impl_IoAllocateMdl(PVOID va, ULONG byteCount,
                        BOOLEAN secondary, BOOLEAN chargeQuota, PIRP irp);
static VOID  NTAPI impl_IoFreeMdl(PMDL mdl);
static VOID  NTAPI impl_MmProbeAndLockPages(PMDL mdl, UCHAR accessMode,
                        ULONG operation);
static VOID  NTAPI impl_MmUnlockPages(PMDL mdl);
static PVOID NTAPI impl_MmMapLockedPagesSpecifyCache(PMDL mdl,
                        UCHAR accessMode, ULONG cacheType,
                        PVOID baseAddr, ULONG zeroBits, ULONG priority);
static VOID  NTAPI impl_MmUnmapLockedPages(PVOID baseAddr, PMDL mdl);
static NTSTATUS NTAPI impl_MmProtectMdlSystemAddress(PMDL mdl,
                        ULONG newProtect);
static BOOLEAN NTAPI impl_MmIsAddressValid(PVOID addr);

// ---- Device I/O ------------------------------------------------------------
static NTSTATUS NTAPI impl_IoCreateDevice(PDRIVER_OBJECT driverObject,
                        ULONG extSize, UNICODE_STRING* devName,
                        ULONG devType, ULONG devChars,
                        BOOLEAN exclusive, PDEVICE_OBJECT* deviceObject);
static NTSTATUS NTAPI impl_IoCreateSymbolicLink(UNICODE_STRING* symLink,
                                                  UNICODE_STRING* devName);
static VOID     NTAPI impl_IoDeleteDevice(PDEVICE_OBJECT deviceObject);
static NTSTATUS NTAPI impl_IoDeleteSymbolicLink(UNICODE_STRING* symLink);
static VOID   FASTCALL impl_IofCompleteRequest(PIRP irp, char priorityBoost);
static BOOLEAN  NTAPI impl_IoIsWdmVersionAvailable(UCHAR major, UCHAR minor);

// ---- Process / thread ------------------------------------------------------
static NTSTATUS NTAPI impl_PsRegisterPicoProvider(PVOID provider,
                                                    PVOID routines);
static PEPROCESS NTAPI impl_IoGetCurrentProcess(VOID);
static PVOID    NTAPI impl_PsGetCurrentProcessId(VOID);
static PVOID    NTAPI impl_PsGetProcessId(PEPROCESS process);
static PKTHREAD NTAPI impl_KeGetCurrentThread(VOID);

// ---- Zw* (registry / object / memory) -------------------------------------
static NTSTATUS NTAPI impl_ZwClose(HANDLE handle);
static NTSTATUS NTAPI impl_ZwOpenKey(HANDLE* key, ULONG access, PVOID attrs);
static NTSTATUS NTAPI impl_ZwCreateKey(HANDLE* key, ULONG access, PVOID attrs,
                        ULONG titleIdx, PVOID cls, ULONG options,
                        ULONG* disposition);
static NTSTATUS NTAPI impl_ZwQueryValueKey(HANDLE key, PVOID name,
                        ULONG keyClass, PVOID info, ULONG infoLen,
                        ULONG* resultLen);
static NTSTATUS NTAPI impl_ZwSetValueKey(HANDLE key, PVOID name,
                        ULONG titleIdx, ULONG type, PVOID data, ULONG len);
static NTSTATUS NTAPI impl_ZwSetSecurityObject(HANDLE handle, ULONG secInfo,
                                                PVOID sd);
static NTSTATUS NTAPI impl_ZwQuerySystemInformation(ULONG infoClass,
                        PVOID info, ULONG infoLen, ULONG* returnLen);
static NTSTATUS NTAPI impl_ZwFlushInstructionCache(HANDLE process,
                        PVOID baseAddr, SIZE_T len);
static NTSTATUS NTAPI impl_ZwDuplicateObject(HANDLE srcProcess,
                        HANDLE srcHandle, HANDLE dstProcess,
                        HANDLE* dstHandle, ULONG access, ULONG attrs,
                        ULONG opts);
static NTSTATUS NTAPI impl_ZwTerminateProcess(HANDLE process,
                                               NTSTATUS exitStatus);
static NTSTATUS NTAPI impl_ZwAllocateVirtualMemory(HANDLE process,
                        PVOID* baseAddr, ULONG_PTR zeroBits,
                        SIZE_T* regionSize, ULONG allocType, ULONG protect);
static NTSTATUS NTAPI impl_ZwFreeVirtualMemory(HANDLE process,
                        PVOID* baseAddr, SIZE_T* regionSize, ULONG freeType);
static NTSTATUS NTAPI impl_ZwCreateFile(HANDLE* fileHandle, ULONG access,
                        PVOID attrs, PVOID ioStatus, PVOID allocSize,
                        ULONG fileAttrs, ULONG shareAccess,
                        ULONG createDisp, ULONG createOpts,
                        PVOID eaBuffer, ULONG eaLength);
static LONG  NTAPI impl___C_specific_handler_fallback(...);
static VOID  NTAPI impl__local_unwind_fallback(PVOID frame, PVOID targetIp);
static VOID  NTAPI impl___jump_unwind_fallback(PVOID frame, PVOID targetIp);
static VOID  NTAPI impl_RtlUnwind_fallback(PVOID targetFrame, PVOID targetIp,
                                           PVOID exceptionRecord,
                                           PVOID returnValue);

// ---- ETW -------------------------------------------------------------------
static NTSTATUS NTAPI impl_EtwRegister(PVOID providerId, PVOID callback,
                                        PVOID context, PVOID* regHandle);
static NTSTATUS NTAPI impl_EtwSetInformation(PVOID regHandle, ULONG infoClass,
                                               PVOID info, ULONG infoLen);
static NTSTATUS NTAPI impl_EtwWriteTransfer(PVOID regHandle, PVOID eventDesc,
                        PVOID* activityId, PVOID* relatedId,
                        ULONG userDataCount, PVOID userData);

// ---- Timing ----------------------------------------------------------------
static NTSTATUS NTAPI impl_KeDelayExecutionThread(ULONG mode, BOOLEAN alertable,
                                                    PVOID interval);

// ---- Interlock -------------------------------------------------------------
static LONG NTAPI impl_InterlockedCompareExchange(volatile LONG* dest,
                                                    LONG exchange,
                                                    LONG comparand);

// ---- WDF (wdfldr.sys) ------------------------------------------------------
static NTSTATUS NTAPI impl_WdfVersionBind(PVOID driverObject,
                        PVOID registryPath, PVOID bindInfo,
                        PVOID* componentGlobals);
static NTSTATUS NTAPI impl_WdfVersionBindClass(PVOID context,
                        PVOID bindInfo, PVOID* componentGlobals);
static VOID NTAPI impl_WdfVersionUnbind(PVOID registryPath, PVOID bindInfo,
                                         PVOID componentGlobals);
static VOID NTAPI impl_WdfVersionUnbindClass(PVOID context, PVOID bindInfo,
                                               PVOID componentGlobals);
static NTSTATUS NTAPI impl_WdfLdrQueryInterface(PVOID iface);

// ---- BCrypt (cng.sys) ------------------------------------------------------
static NTSTATUS NTAPI impl_BCryptGenRandom(PVOID alg, UCHAR* buf,
                                            ULONG len, ULONG flags);

// ---- CRT wrappers (ntoskrnl re-exports) ------------------------------------
// No calling-convention attribute: default is __cdecl on all arches, matching
// how kernel CRT exports are generated by MSVC.
static std::size_t impl_strnlen(const char* s, std::size_t n);
static int    impl__stricmp(const char* s1, const char* s2);
static int    impl_strncmp(const char* s1, const char* s2, std::size_t n);
static int    impl_strcmp(const char* s1, const char* s2);
static char*  impl_strcpy(char* dst, const char* src);
static char*  impl_strncpy(char* dst, const char* src, std::size_t n);
static std::size_t impl_strlen(const char* s);
static int    impl_wcsncmp(const WCHAR* s1, const WCHAR* s2, std::size_t n);
static std::size_t impl_wcslen(const WCHAR* s);
static int    impl__wcsnicmp(const WCHAR* s1, const WCHAR* s2, std::size_t n);
static WCHAR* impl_wcschr(const WCHAR* s, WCHAR c);
static void*  impl_memset(void* s, int c, std::size_t n);
static void*  impl_memcpy(void* dst, const void* src, std::size_t n);
static int    impl_isupper(int c);
static int    impl_isdigit(int c);
static int    impl_iswspace(unsigned int c);
static int    impl_tolower(int c);
static int    impl__snprintf(char* buf, std::size_t count,
                              const char* fmt, ...);
static int    impl__snwprintf(WCHAR* buf, std::size_t count,
                               const WCHAR* fmt, ...);

} // extern "C"

// ---------------------------------------------------------------------------
// Symbol-name → address table
// ---------------------------------------------------------------------------

struct NtSymbol {
    const char* name;
    void*       address;
};

#define NT_SYM(fn)  { #fn, reinterpret_cast<void*>(&impl_##fn) }
#define NT_VAR(sym) { #sym, reinterpret_cast<void*>(&s_##sym)  }

static const NtSymbol s_nt_symbols[] = {
    // ---- Debug output -------------------------------------------------------
    NT_SYM(DbgPrint),
    NT_SYM(DbgPrintEx),

    // ---- Unicode string helpers ---------------------------------------------
    NT_SYM(RtlInitUnicodeString),
    NT_SYM(RtlEqualUnicodeString),
    NT_SYM(RtlCopyUnicodeString),
    NT_SYM(RtlCompareUnicodeString),
    NT_SYM(RtlFreeUnicodeString),
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
    { "_stricmp",   reinterpret_cast<void*>(&impl__stricmp)   },
    NT_SYM(strncmp),
    NT_SYM(strcmp),
    NT_SYM(strcpy),
    NT_SYM(strncpy),
    NT_SYM(strlen),
    NT_SYM(wcsncmp),
    NT_SYM(wcslen),
    { "_wcsnicmp",  reinterpret_cast<void*>(&impl__wcsnicmp)  },
    NT_SYM(wcschr),
    NT_SYM(memset),
    NT_SYM(memcpy),
    NT_SYM(isupper),
    NT_SYM(isdigit),
    NT_SYM(iswspace),
    NT_SYM(tolower),
    { "_snprintf",  reinterpret_cast<void*>(&impl__snprintf)  },
    { "_snwprintf", reinterpret_cast<void*>(&impl__snwprintf) },
};

#undef NT_SYM
#undef NT_VAR

// ---------------------------------------------------------------------------
// nt_stubs_lookup – consulted for ALL imported DLLs.
// Special-cases a few SEH/unwind helpers that must resolve to the real
// implementations in ntdll.dll / msvcrt.dll.
// ---------------------------------------------------------------------------

void* nt_stubs_lookup(const char* name) noexcept {
    if (!name) return nullptr;

    // SEH / unwind helpers: look up from the host DLLs at runtime.
    // These must be the genuine implementations for SEH to work.
    {
        static const char* const seh_names[] = {
            "__C_specific_handler",
            "_local_unwind",
            "RtlUnwind",
            "__jump_unwind",
        };
        for (const char* sn : seh_names) {
            if (std::strcmp(name, sn) == 0) {
                HMODULE m = GetModuleHandleA("ntdll.dll");
                if (m) {
                    void* p = reinterpret_cast<void*>(GetProcAddress(m, sn));
                    if (p) return p;
                }
                // _local_unwind / __jump_unwind may be in msvcrt.dll.
                m = GetModuleHandleA("msvcrt.dll");
                if (!m) m = LoadLibraryA("msvcrt.dll");
                if (m) {
                    void* p = reinterpret_cast<void*>(GetProcAddress(m, sn));
                    if (p) return p;
                }
                // Fallback to no-op helpers so DriverEntry can continue on
                // runtimes where these exports are absent.
                char msg[256];
                std::snprintf(msg, sizeof(msg),
                              "[nt_stubs] Warning: %s not found in ntdll/msvcrt; using fallback implementation.\n",
                              sn);
                OutputDebugStringA(msg);
                std::fputs(msg, stderr);
                std::fflush(stderr);
                if (std::strcmp(sn, "__C_specific_handler") == 0)
                    return reinterpret_cast<void*>(&impl___C_specific_handler_fallback);
                if (std::strcmp(sn, "_local_unwind") == 0)
                    return reinterpret_cast<void*>(&impl__local_unwind_fallback);
                if (std::strcmp(sn, "__jump_unwind") == 0)
                    return reinterpret_cast<void*>(&impl___jump_unwind_fallback);
                if (std::strcmp(sn, "RtlUnwind") == 0)
                    return reinterpret_cast<void*>(&impl_RtlUnwind_fallback);
                return nullptr;
            }
        }
    }

    for (const auto& sym : s_nt_symbols) {
        if (std::strcmp(sym.name, name) == 0) return sym.address;
    }
    return nullptr;
}

// Backward-compatibility alias (used internally by MmGetSystemRoutineAddress).
void* nt_stubs_lookup_ntoskrnl(const char* name) noexcept {
    return nt_stubs_lookup(name);
}

// ---------------------------------------------------------------------------
// Implementations
// ---------------------------------------------------------------------------

// ---- Debug output ----------------------------------------------------------

static ULONG impl_DbgPrint(const char* fmt, ...) {
    std::va_list args;
    va_start(args, fmt);
    std::vfprintf(stderr, fmt, args);
    va_end(args);
    return 0;
}

static ULONG impl_DbgPrintEx(ULONG /*componentId*/, ULONG /*level*/,
                               const char* fmt, ...) {
    std::va_list args;
    va_start(args, fmt);
    std::vfprintf(stderr, fmt, args);
    va_end(args);
    return 0;
}

// ---- Unicode string helpers ------------------------------------------------

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
    constexpr std::size_t kMaxLen = 0xFFFEu;
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
    if (caseInsensitive)
        return _wcsnicmp(s1->Buffer, s2->Buffer, nChars) == 0 ? TRUE : FALSE;
    return std::wmemcmp(s1->Buffer, s2->Buffer, nChars) == 0 ? TRUE : FALSE;
}

static VOID NTAPI impl_RtlCopyUnicodeString(UNICODE_STRING* dest,
                                             const UNICODE_STRING* src) {
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
    const auto* a = static_cast<const unsigned char*>(s1);
    const auto* b = static_cast<const unsigned char*>(s2);
    SIZE_T i = 0;
    while (i < len && a[i] == b[i]) ++i;
    return i;
}

static VOID NTAPI impl_RtlAssert(PVOID assertion, PVOID fileName,
                                   ULONG line, char* message) {
    std::fprintf(stderr, "[nt_stubs] RtlAssert: '%s' at %s:%lu%s%s\n",
        static_cast<const char*>(assertion),
        static_cast<const char*>(fileName),
        static_cast<unsigned long>(line),
        message ? ": " : "",
        message ? message : "");
}

static WCHAR* NTAPI impl_RtlGetNtSystemRoot(VOID) {
    static WCHAR s_root[] = L"C:\\Windows";
    return s_root;
}

static NTSTATUS NTAPI impl_RtlUTF8ToUnicodeN(WCHAR* dest, ULONG destLen,
                                               ULONG* resultLen,
                                               const char* src,
                                               ULONG srcLen) {
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
    if (sd) std::memset(sd, 0, 20);
    return STATUS_SUCCESS;
}

static ULONG NTAPI impl_RtlLengthSecurityDescriptor(PVOID /*sd*/) {
    return 0;
}

static NTSTATUS NTAPI impl_RtlGetDaclSecurityDescriptor(PVOID /*sd*/,
                        BOOLEAN* present, PVOID* dacl, BOOLEAN* defaulted) {
    if (present)   *present   = FALSE;
    if (dacl)      *dacl      = nullptr;
    if (defaulted) *defaulted = FALSE;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_RtlGetGroupSecurityDescriptor(PVOID /*sd*/,
                        PVOID* group, BOOLEAN* defaulted) {
    if (group)     *group     = nullptr;
    if (defaulted) *defaulted = FALSE;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_RtlGetOwnerSecurityDescriptor(PVOID /*sd*/,
                        PVOID* owner, BOOLEAN* defaulted) {
    if (owner)     *owner     = nullptr;
    if (defaulted) *defaulted = FALSE;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_RtlGetSaclSecurityDescriptor(PVOID /*sd*/,
                        BOOLEAN* present, PVOID* sacl, BOOLEAN* defaulted) {
    if (present)   *present   = FALSE;
    if (sacl)      *sacl      = nullptr;
    if (defaulted) *defaulted = FALSE;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_RtlSetDaclSecurityDescriptor(PVOID /*sd*/,
                        BOOLEAN /*present*/, PVOID /*dacl*/,
                        BOOLEAN /*defaulted*/) {
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_RtlAbsoluteToSelfRelativeSD(PVOID /*absoluteSD*/,
                        PVOID /*selfRelSD*/, ULONG* bufLen) {
    if (bufLen) *bufLen = 0;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_RtlAddAccessAllowedAce(PVOID /*acl*/,
                        ULONG /*aceRev*/, ULONG /*access*/, PVOID /*sid*/) {
    return STATUS_SUCCESS;
}

static ULONG NTAPI impl_RtlLengthSid(PVOID /*sid*/) { return 0; }

static NTSTATUS NTAPI impl_SeCaptureSecurityDescriptor(PVOID srcSD,
                        ULONG /*accessMode*/, ULONG /*poolType*/,
                        BOOLEAN /*captureIfKernel*/, PVOID* capturedSD) {
    if (capturedSD) *capturedSD = srcSD;
    return STATUS_SUCCESS;
}

// ---- Memory allocation -----------------------------------------------------

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

// ---- Mutex / event / spin-lock ---------------------------------------------

static VOID FASTCALL impl_ExAcquireFastMutex(FAST_MUTEX* mutex) {
    if (mutex) InterlockedDecrement(&mutex->Count);
}

static VOID FASTCALL impl_ExReleaseFastMutex(FAST_MUTEX* mutex) {
    if (mutex) InterlockedIncrement(&mutex->Count);
}

static VOID NTAPI impl_KeInitializeSpinLock(ULONG_PTR* spinLock) {
    if (spinLock) *spinLock = 0;
}

static VOID NTAPI impl_KeInitializeEvent(KEVENT* event, ULONG /*type*/,
                                          BOOLEAN state) {
    if (event) event->Signaled = state ? 1 : 0;
}

// ---- IRQL ------------------------------------------------------------------

static KIRQL NTAPI impl_KeGetCurrentIrql(VOID) {
    return static_cast<KIRQL>(PASSIVE_LEVEL);
}

static KIRQL NTAPI impl_KeRaiseIrqlToDpcLevel(VOID) {
    return static_cast<KIRQL>(PASSIVE_LEVEL);
}

static KIRQL FASTCALL impl_KfRaiseIrql(KIRQL /*newIrql*/) {
    return static_cast<KIRQL>(PASSIVE_LEVEL);
}

// ---- Reference counting ----------------------------------------------------

static LONG_PTR FASTCALL impl_ObfReferenceObject(PVOID /*object*/) {
    return 1;
}

static LONG_PTR FASTCALL impl_ObfDereferenceObject(PVOID /*object*/) {
    return 0;
}

static NTSTATUS NTAPI impl_ObReferenceObjectByHandle(HANDLE /*handle*/,
                        ULONG /*access*/, PVOID /*objectType*/,
                        UCHAR /*accessMode*/, PVOID* object,
                        PVOID /*handleInfo*/) {
    if (object) *object = nullptr;
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS NTAPI impl_ObOpenObjectByPointer(PVOID /*object*/,
                        ULONG /*attrs*/, PVOID /*accessState*/,
                        ULONG /*access*/, PVOID /*objectType*/,
                        UCHAR /*accessMode*/, HANDLE* handle) {
    if (handle) *handle = nullptr;
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS NTAPI impl_ObQueryNameString(PVOID /*object*/,
                        PVOID nameInfo, ULONG length, ULONG* returnLength) {
    if (returnLength) *returnLength = 0;
    if (nameInfo && length > 0)
        static_cast<char*>(nameInfo)[0] = '\0';
    return STATUS_SUCCESS;
}

// ---- System routine lookup -------------------------------------------------

static PVOID NTAPI impl_MmGetSystemRoutineAddress(UNICODE_STRING* routineName) {
    if (!routineName || !routineName->Buffer) return nullptr;
    char narrow[256] = {};
    const int len = WideCharToMultiByte(CP_ACP, 0,
        routineName->Buffer,
        routineName->Length / static_cast<int>(sizeof(WCHAR)),
        narrow, static_cast<int>(sizeof(narrow)) - 1, nullptr, nullptr);
    if (len <= 0) return nullptr;
    narrow[len] = '\0';
    return nt_stubs_lookup(narrow);
}

// ---- MDL operations --------------------------------------------------------

static PMDL NTAPI impl_IoAllocateMdl(PVOID /*va*/, ULONG /*byteCount*/,
                        BOOLEAN /*secondary*/, BOOLEAN /*chargeQuota*/,
                        PIRP /*irp*/) {
    return static_cast<PMDL>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 64));
}

static VOID NTAPI impl_IoFreeMdl(PMDL mdl) {
    HeapFree(GetProcessHeap(), 0, mdl);
}

static VOID NTAPI impl_MmProbeAndLockPages(PMDL /*mdl*/, UCHAR /*accessMode*/,
                                             ULONG /*operation*/) {}

static VOID NTAPI impl_MmUnlockPages(PMDL /*mdl*/) {}

static PVOID NTAPI impl_MmMapLockedPagesSpecifyCache(PMDL /*mdl*/,
                        UCHAR /*accessMode*/, ULONG /*cacheType*/,
                        PVOID /*baseAddr*/, ULONG /*zeroBits*/,
                        ULONG /*priority*/) {
    return nullptr;
}

static VOID NTAPI impl_MmUnmapLockedPages(PVOID /*baseAddr*/,
                                            PMDL /*mdl*/) {}

static NTSTATUS NTAPI impl_MmProtectMdlSystemAddress(PMDL /*mdl*/,
                                                       ULONG /*newProtect*/) {
    return STATUS_SUCCESS;
}

static BOOLEAN NTAPI impl_MmIsAddressValid(PVOID addr) {
    return (addr != nullptr) ? TRUE : FALSE;
}

// ---- Device I/O ------------------------------------------------------------

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
    dev->Type         = 3;
    dev->Size         = static_cast<USHORT>(total);
    dev->DriverObject = driverObject;
    if (deviceExtensionSize > 0)
        dev->DeviceExtension =
            reinterpret_cast<UCHAR*>(dev) + sizeof(DEVICE_OBJECT);
    if (driverObject) {
        dev->NextDevice            = driverObject->DeviceObject;
        driverObject->DeviceObject = dev;
    }
    *deviceObject = dev;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_IoCreateSymbolicLink(UNICODE_STRING* /*symLink*/,
                                                  UNICODE_STRING* /*devName*/) {
    return STATUS_SUCCESS;
}

static VOID NTAPI impl_IoDeleteDevice(PDEVICE_OBJECT deviceObject) {
    if (!deviceObject) return;
    PDRIVER_OBJECT drv = deviceObject->DriverObject;
    if (drv) {
        PDEVICE_OBJECT* pp = &drv->DeviceObject;
        while (*pp && *pp != deviceObject)
            pp = &(*pp)->NextDevice;
        if (*pp) *pp = deviceObject->NextDevice;
    }
    HeapFree(GetProcessHeap(), 0, deviceObject);
}

static NTSTATUS NTAPI impl_IoDeleteSymbolicLink(UNICODE_STRING* /*symLink*/) {
    return STATUS_SUCCESS;
}

static VOID FASTCALL impl_IofCompleteRequest(PIRP /*irp*/,
                                               char /*priorityBoost*/) {}

static BOOLEAN NTAPI impl_IoIsWdmVersionAvailable(UCHAR major, UCHAR minor) {
    // Report WDM 1.10 (Windows 7 kernel) as the supported version.
    if (major < 1) return TRUE;
    if (major == 1 && minor <= 0x10u) return TRUE;
    return FALSE;
}

// ---- Process / thread ------------------------------------------------------

static NTSTATUS NTAPI impl_PsRegisterPicoProvider(PVOID /*provider*/,
                                                    PVOID /*routines*/) {
    return STATUS_SUCCESS;
}

static PEPROCESS NTAPI impl_IoGetCurrentProcess(VOID) {
    return &s_fake_eprocess;
}

static PVOID NTAPI impl_PsGetCurrentProcessId(VOID) {
    return reinterpret_cast<PVOID>(
        static_cast<ULONG_PTR>(GetCurrentProcessId()));
}

static PVOID NTAPI impl_PsGetProcessId(PEPROCESS /*process*/) {
    return nullptr;
}

static PKTHREAD NTAPI impl_KeGetCurrentThread(VOID) {
    return nullptr;
}

// ---- Zw* -------------------------------------------------------------------

static NTSTATUS NTAPI impl_ZwClose(HANDLE /*handle*/) {
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_ZwOpenKey(HANDLE* key, ULONG /*access*/,
                                      PVOID /*attrs*/) {
    if (key) *key = nullptr;
    return STATUS_OBJECT_NAME_NOT_FOUND;
}

static NTSTATUS NTAPI impl_ZwCreateKey(HANDLE* key, ULONG /*access*/,
                        PVOID /*attrs*/, ULONG /*titleIdx*/, PVOID /*cls*/,
                        ULONG /*options*/, ULONG* disposition) {
    if (key)         *key         = nullptr;
    if (disposition) *disposition = 1u; // REG_CREATED_NEW_KEY
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_ZwQueryValueKey(HANDLE /*key*/, PVOID /*name*/,
                        ULONG /*keyClass*/, PVOID /*info*/, ULONG /*infoLen*/,
                        ULONG* resultLen) {
    if (resultLen) *resultLen = 0;
    return STATUS_OBJECT_NAME_NOT_FOUND;
}

static NTSTATUS NTAPI impl_ZwSetValueKey(HANDLE /*key*/, PVOID /*name*/,
                        ULONG /*titleIdx*/, ULONG /*type*/, PVOID /*data*/,
                        ULONG /*len*/) {
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_ZwSetSecurityObject(HANDLE /*handle*/,
                                                 ULONG /*secInfo*/,
                                                 PVOID /*sd*/) {
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_ZwQuerySystemInformation(ULONG /*infoClass*/,
                        PVOID /*info*/, ULONG /*infoLen*/,
                        ULONG* returnLen) {
    if (returnLen) *returnLen = 0;
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS NTAPI impl_ZwFlushInstructionCache(HANDLE /*process*/,
                        PVOID /*baseAddr*/, SIZE_T /*len*/) {
    FlushInstructionCache(GetCurrentProcess(), nullptr, 0);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_ZwDuplicateObject(HANDLE /*srcProcess*/,
                        HANDLE /*srcHandle*/, HANDLE /*dstProcess*/,
                        HANDLE* dstHandle, ULONG /*access*/,
                        ULONG /*attrs*/, ULONG /*opts*/) {
    if (dstHandle) *dstHandle = nullptr;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_ZwTerminateProcess(HANDLE /*process*/,
                                                NTSTATUS /*exitStatus*/) {
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_ZwAllocateVirtualMemory(HANDLE /*process*/,
                        PVOID* baseAddr, ULONG_PTR /*zeroBits*/,
                        SIZE_T* regionSize, ULONG allocType, ULONG protect) {
    if (!baseAddr || !regionSize || *regionSize == 0)
        return STATUS_INVALID_PARAMETER;
    const DWORD type = allocType ? static_cast<DWORD>(allocType)
                                 : static_cast<DWORD>(MEM_COMMIT | MEM_RESERVE);
    const DWORD prot = protect   ? static_cast<DWORD>(protect)
                                 : static_cast<DWORD>(PAGE_READWRITE);
    PVOID mem = VirtualAlloc(*baseAddr, *regionSize, type, prot);
    if (!mem) return STATUS_NO_MEMORY;
    *baseAddr = mem;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_ZwFreeVirtualMemory(HANDLE /*process*/,
                        PVOID* baseAddr, SIZE_T* regionSize, ULONG freeType) {
    if (!baseAddr || !*baseAddr) return STATUS_INVALID_PARAMETER;
    const SIZE_T sz = regionSize ? *regionSize : 0;
    const DWORD ft  = freeType   ? static_cast<DWORD>(freeType)
                                 : static_cast<DWORD>(MEM_RELEASE);
    VirtualFree(*baseAddr, sz, ft);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_ZwCreateFile(HANDLE* fileHandle, ULONG /*access*/,
                        PVOID /*attrs*/, PVOID /*ioStatus*/,
                        PVOID /*allocSize*/, ULONG /*fileAttrs*/,
                        ULONG /*shareAccess*/, ULONG /*createDisp*/,
                        ULONG /*createOpts*/, PVOID /*eaBuffer*/,
                        ULONG /*eaLength*/) {
    if (fileHandle) *fileHandle = nullptr;
    return STATUS_NOT_IMPLEMENTED;
}

static LONG NTAPI impl___C_specific_handler_fallback(...) {
    return 0;
}

static VOID NTAPI impl__local_unwind_fallback(PVOID /*frame*/,
                                               PVOID /*targetIp*/) {}

static VOID NTAPI impl___jump_unwind_fallback(PVOID /*frame*/,
                                               PVOID /*targetIp*/) {}

static VOID NTAPI impl_RtlUnwind_fallback(PVOID /*targetFrame*/,
                                           PVOID /*targetIp*/,
                                           PVOID /*exceptionRecord*/,
                                           PVOID /*returnValue*/) {}

// ---- ETW -------------------------------------------------------------------

static NTSTATUS NTAPI impl_EtwRegister(PVOID /*providerId*/,
                                         PVOID /*callback*/,
                                         PVOID /*context*/,
                                         PVOID* regHandle) {
    if (regHandle) *regHandle = nullptr;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_EtwSetInformation(PVOID /*regHandle*/,
                        ULONG /*infoClass*/, PVOID /*info*/,
                        ULONG /*infoLen*/) {
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_EtwWriteTransfer(PVOID /*regHandle*/,
                        PVOID /*eventDesc*/, PVOID* /*activityId*/,
                        PVOID* /*relatedId*/, ULONG /*userDataCount*/,
                        PVOID /*userData*/) {
    return STATUS_SUCCESS;
}

// ---- Timing / interlock ----------------------------------------------------

static NTSTATUS NTAPI impl_KeDelayExecutionThread(ULONG /*mode*/,
                        BOOLEAN /*alertable*/, PVOID /*interval*/) {
    return STATUS_SUCCESS;
}

static LONG NTAPI impl_InterlockedCompareExchange(volatile LONG* dest,
                                                    LONG exchange,
                                                    LONG comparand) {
    return InterlockedCompareExchange(
        reinterpret_cast<volatile LONG*>(dest), exchange, comparand);
}

// ---- WDF (wdfldr.sys) ------------------------------------------------------

static NTSTATUS NTAPI impl_WdfVersionBind(PVOID /*driverObject*/,
                        PVOID /*registryPath*/, PVOID /*bindInfo*/,
                        PVOID* componentGlobals) {
    if (componentGlobals) *componentGlobals = s_wdf_globals_buf;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_WdfVersionBindClass(PVOID /*context*/,
                        PVOID /*bindInfo*/, PVOID* componentGlobals) {
    if (componentGlobals) *componentGlobals = s_wdf_globals_buf;
    return STATUS_SUCCESS;
}

static VOID NTAPI impl_WdfVersionUnbind(PVOID /*registryPath*/,
                                          PVOID /*bindInfo*/,
                                          PVOID /*componentGlobals*/) {}

static VOID NTAPI impl_WdfVersionUnbindClass(PVOID /*context*/,
                                               PVOID /*bindInfo*/,
                                               PVOID /*componentGlobals*/) {}

static NTSTATUS NTAPI impl_WdfLdrQueryInterface(PVOID /*iface*/) {
    return STATUS_NOT_IMPLEMENTED;
}

// ---- BCrypt (cng.sys) ------------------------------------------------------

static NTSTATUS NTAPI impl_BCryptGenRandom(PVOID /*alg*/, UCHAR* buf,
                                            ULONG len, ULONG /*flags*/) {
    if (!buf) return STATUS_INVALID_PARAMETER;
    for (ULONG i = 0; i < len; ++i)
        buf[i] = static_cast<UCHAR>(rand() & 0xFF);
    return STATUS_SUCCESS;
}

// ---- CRT wrappers ----------------------------------------------------------

static std::size_t impl_strnlen(const char* s, std::size_t n) {
    if (!s) return 0;
    const char* p = static_cast<const char*>(std::memchr(s, '\0', n));
    return p ? static_cast<std::size_t>(p - s) : n;
}

static int impl__stricmp(const char* s1, const char* s2) {
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
    return std::strncmp(s1, s2, n);
}

static int impl_strcmp(const char* s1, const char* s2) {
    return std::strcmp(s1, s2);
}

static char* impl_strcpy(char* dst, const char* src) {
    return std::strcpy(dst, src);
}

static char* impl_strncpy(char* dst, const char* src, std::size_t n) {
    return std::strncpy(dst, src, n);
}

static std::size_t impl_strlen(const char* s) {
    return s ? std::strlen(s) : 0;
}

static int impl_wcsncmp(const WCHAR* s1, const WCHAR* s2, std::size_t n) {
    return std::wcsncmp(s1, s2, n);
}

static std::size_t impl_wcslen(const WCHAR* s) {
    return s ? std::wcslen(s) : 0;
}

static int impl__wcsnicmp(const WCHAR* s1, const WCHAR* s2, std::size_t n) {
    return _wcsnicmp(s1, s2, n);
}

static WCHAR* impl_wcschr(const WCHAR* s, WCHAR c) {
    return const_cast<WCHAR*>(std::wcschr(s, c));
}

static void* impl_memset(void* s, int c, std::size_t n) {
    return std::memset(s, c, n);
}

static void* impl_memcpy(void* dst, const void* src, std::size_t n) {
    return std::memcpy(dst, src, n);
}

static int impl_isupper(int c) {
    return std::isupper(static_cast<unsigned char>(c));
}

static int impl_isdigit(int c) {
    return std::isdigit(static_cast<unsigned char>(c));
}

static int impl_iswspace(unsigned int c) {
    return std::iswspace(static_cast<wchar_t>(c));
}

static int impl_tolower(int c) {
    return std::tolower(static_cast<unsigned char>(c));
}

static int impl__snprintf(char* buf, std::size_t count, const char* fmt, ...) {
    std::va_list args;
    va_start(args, fmt);
    const int ret = std::vsnprintf(buf, count, fmt, args);
    va_end(args);
    return ret;
}

static int impl__snwprintf(WCHAR* buf, std::size_t count, const WCHAR* fmt, ...) {
    std::va_list args;
    va_start(args, fmt);
    const int ret = std::vswprintf(buf, count, fmt, args);
    va_end(args);
    return ret;
}
