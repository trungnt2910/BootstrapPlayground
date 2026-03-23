// ---- Ex* --------------------------------------------------------------------

#include <iostream>
#include <print>

#include <Windows.h>

#include "wdm.hpp"

static PVOID NTAPI
impl_ExAllocatePoolWithTag(ULONG /*poolType*/, SIZE_T numberOfBytes, ULONG /*tag*/)
{
    NT_STUB_REPORT();
    return HeapAlloc(GetProcessHeap(), 0, numberOfBytes);
}

static PVOID NTAPI
impl_ExAllocatePool2(ULONGLONG /*poolFlags*/, SIZE_T numberOfBytes, ULONG /*tag*/)
{
    NT_STUB_REPORT();
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, numberOfBytes);
}

static VOID NTAPI impl_ExFreePool(PVOID p)
{
    NT_STUB_REPORT();
    if (p)
    {
        HeapFree(GetProcessHeap(), 0, p);
    }
}

static VOID NTAPI impl_ExFreePoolWithTag(PVOID p, ULONG /*tag*/)
{
    NT_STUB_REPORT();
    if (p)
    {
        HeapFree(GetProcessHeap(), 0, p);
    }
}

static VOID FASTCALL impl_ExAcquireFastMutex(FAST_MUTEX *mutex)
{
    NT_STUB_REPORT();
    if (mutex)
    {
        InterlockedDecrement(&mutex->Count);
    }
}

static VOID FASTCALL impl_ExReleaseFastMutex(FAST_MUTEX *mutex)
{
    NT_STUB_REPORT();
    if (mutex)
    {
        InterlockedIncrement(&mutex->Count);
    }
}
