// ---- Mm* --------------------------------------------------------------------

#include <windows.h>

#include "wdm.hpp"

#include "nt_stubs_internal.hpp"

static PVOID NTAPI impl_MmGetSystemRoutineAddress(UNICODE_STRING *routineName)
{
    NT_STUB_REPORT();
    if (!routineName || !routineName->Buffer)
    {
        return nullptr;
    }
    char narrow[256] = {};
    const int len = WideCharToMultiByte(
        CP_ACP,
        0,
        routineName->Buffer,
        routineName->Length / static_cast<int>(sizeof(WCHAR)),
        narrow,
        static_cast<int>(sizeof(narrow)) - 1,
        nullptr,
        nullptr);
    if (len <= 0)
    {
        return nullptr;
    }
    narrow[len] = '\0';
    void *sym = NtStubsLookup(narrow);
    if (sym)
    {
        std::println(stderr, "[nt_stubs] MmGetSystemRoutineAddress({}) -> {:p}", narrow, sym);
        return sym;
    }
    void *stub = NtStubsAllocate(narrow);
    std::println(
        stderr,
        "[nt_stubs] MmGetSystemRoutineAddress({}) unresolved; using stub @ {:p}",
        narrow,
        stub);
    return stub;
}

static VOID NTAPI impl_MmProbeAndLockPages(PMDL /*mdl*/, UCHAR /*accessMode*/, ULONG /*operation*/)
{
    NT_STUB_REPORT();
}

static VOID NTAPI impl_MmUnlockPages(PMDL /*mdl*/)
{
    NT_STUB_REPORT();
}

static PVOID NTAPI impl_MmMapLockedPagesSpecifyCache(
    PMDL /*mdl*/,
    UCHAR /*accessMode*/,
    ULONG /*cacheType*/,
    PVOID /*baseAddr*/,
    ULONG /*zeroBits*/,
    ULONG /*priority*/)
{
    NT_STUB_REPORT();
    return nullptr;
}

static VOID NTAPI impl_MmUnmapLockedPages(PVOID /*baseAddr*/, PMDL /*mdl*/)
{
    NT_STUB_REPORT();
}

static NTSTATUS NTAPI impl_MmProtectMdlSystemAddress(PMDL /*mdl*/, ULONG /*newProtect*/)
{
    NT_STUB_REPORT();
    return STATUS_SUCCESS;
}

static BOOLEAN NTAPI impl_MmIsAddressValid(PVOID addr)
{
    NT_STUB_REPORT();
    return (addr != nullptr) ? TRUE : FALSE;
}
