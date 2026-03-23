// ---- Ex* --------------------------------------------------------------------

static PVOID NTAPI impl_ExAllocatePoolWithTag(ULONG /*poolType*/, SIZE_T numberOfBytes,
                                              ULONG /*tag*/)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return HeapAlloc(GetProcessHeap(), 0, numberOfBytes);
}

static PVOID NTAPI impl_ExAllocatePool2(ULONGLONG /*poolFlags*/, SIZE_T numberOfBytes,
                                        ULONG /*tag*/)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, numberOfBytes);
}

static VOID NTAPI impl_ExFreePool(PVOID p)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (p)
        HeapFree(GetProcessHeap(), 0, p);
}

static VOID NTAPI impl_ExFreePoolWithTag(PVOID p, ULONG /*tag*/)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (p)
        HeapFree(GetProcessHeap(), 0, p);
}

static VOID FASTCALL impl_ExAcquireFastMutex(FAST_MUTEX *mutex)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (mutex)
        InterlockedDecrement(&mutex->Count);
}

static VOID FASTCALL impl_ExReleaseFastMutex(FAST_MUTEX *mutex)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (mutex)
        InterlockedIncrement(&mutex->Count);
}
