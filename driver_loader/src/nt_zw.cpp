// ---- Zw* --------------------------------------------------------------------

static NTSTATUS NTAPI impl_ZwClose(HANDLE /*handle*/)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_ZwOpenKey(HANDLE *key, ULONG /*access*/, PVOID /*attrs*/)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (key)
        *key = nullptr;
    return STATUS_OBJECT_NAME_NOT_FOUND;
}

static NTSTATUS NTAPI impl_ZwCreateKey(HANDLE *key, ULONG /*access*/, PVOID /*attrs*/,
                                       ULONG /*titleIdx*/, PVOID /*cls*/, ULONG /*options*/,
                                       ULONG *disposition)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (key)
        *key = nullptr;
    if (disposition)
        *disposition = 1u; // REG_CREATED_NEW_KEY
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_ZwQueryValueKey(HANDLE /*key*/, PVOID /*name*/, ULONG /*keyClass*/,
                                           PVOID /*info*/, ULONG /*infoLen*/, ULONG *resultLen)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (resultLen)
        *resultLen = 0;
    return STATUS_OBJECT_NAME_NOT_FOUND;
}

static NTSTATUS NTAPI impl_ZwSetValueKey(HANDLE /*key*/, PVOID /*name*/, ULONG /*titleIdx*/,
                                         ULONG /*type*/, PVOID /*data*/, ULONG /*len*/)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_ZwSetSecurityObject(HANDLE /*handle*/, ULONG /*secInfo*/, PVOID /*sd*/)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_ZwQuerySystemInformation(ULONG /*infoClass*/, PVOID /*info*/,
                                                    ULONG /*infoLen*/, ULONG *returnLen)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (returnLen)
        *returnLen = 0;
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS NTAPI impl_ZwFlushInstructionCache(HANDLE /*process*/, PVOID /*baseAddr*/,
                                                   SIZE_T /*len*/)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    FlushInstructionCache(GetCurrentProcess(), nullptr, 0);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_ZwDuplicateObject(HANDLE /*srcProcess*/, HANDLE /*srcHandle*/,
                                             HANDLE /*dstProcess*/, HANDLE *dstHandle,
                                             ULONG /*access*/, ULONG /*attrs*/, ULONG /*opts*/)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (dstHandle)
        *dstHandle = nullptr;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_ZwTerminateProcess(HANDLE /*process*/, NTSTATUS /*exitStatus*/)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_ZwAllocateVirtualMemory(HANDLE /*process*/, PVOID *baseAddr,
                                                   ULONG_PTR /*zeroBits*/, SIZE_T *regionSize,
                                                   ULONG allocType, ULONG protect)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (!baseAddr || !regionSize || *regionSize == 0)
        return STATUS_INVALID_PARAMETER;
    const DWORD type =
        allocType ? static_cast<DWORD>(allocType) : static_cast<DWORD>(MEM_COMMIT | MEM_RESERVE);
    const DWORD prot = protect ? static_cast<DWORD>(protect) : static_cast<DWORD>(PAGE_READWRITE);
    PVOID mem = VirtualAlloc(*baseAddr, *regionSize, type, prot);
    if (!mem)
        return STATUS_NO_MEMORY;
    *baseAddr = mem;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_ZwFreeVirtualMemory(HANDLE /*process*/, PVOID *baseAddr,
                                               SIZE_T *regionSize, ULONG freeType)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (!baseAddr || !*baseAddr)
        return STATUS_INVALID_PARAMETER;
    const SIZE_T sz = regionSize ? *regionSize : 0;
    const DWORD ft = freeType ? static_cast<DWORD>(freeType) : static_cast<DWORD>(MEM_RELEASE);
    VirtualFree(*baseAddr, sz, ft);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_ZwCreateFile(HANDLE *fileHandle, ULONG /*access*/, PVOID /*attrs*/,
                                        PVOID /*ioStatus*/, PVOID /*allocSize*/,
                                        ULONG /*fileAttrs*/, ULONG /*shareAccess*/,
                                        ULONG /*createDisp*/, ULONG /*createOpts*/,
                                        PVOID /*eaBuffer*/, ULONG /*eaLength*/)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (fileHandle)
        *fileHandle = nullptr;
    return STATUS_NOT_IMPLEMENTED;
}
