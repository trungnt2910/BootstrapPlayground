// ---- MDL operations --------------------------------------------------------

#include <limits>

static PMDL NTAPI impl_IoAllocateMdl(PVOID /*va*/, ULONG byteCount,
                        BOOLEAN /*secondary*/, BOOLEAN /*chargeQuota*/,
                        PIRP /*irp*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    constexpr SIZE_T kHeaderBytes = sizeof(MDL);
    constexpr SIZE_T kPageSize = 0x1000u;
    const SIZE_T page_count =
        (static_cast<SIZE_T>(byteCount) + kPageSize - 1u) / kPageSize;
    const SIZE_T max_size = (std::numeric_limits<SIZE_T>::max)();
    if (page_count > (max_size - kHeaderBytes) / sizeof(ULONG_PTR))
        return nullptr;
    const SIZE_T total_bytes = kHeaderBytes + page_count * sizeof(ULONG_PTR);
    return static_cast<PMDL>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, total_bytes));
}

static VOID NTAPI impl_IoFreeMdl(PMDL mdl) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    HeapFree(GetProcessHeap(), 0, mdl);
}

static VOID NTAPI impl_MmProbeAndLockPages(PMDL /*mdl*/, UCHAR /*accessMode*/,
                                             ULONG /*operation*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
}

static VOID NTAPI impl_MmUnlockPages(PMDL /*mdl*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
}

static PVOID NTAPI impl_MmMapLockedPagesSpecifyCache(PMDL /*mdl*/,
                        UCHAR /*accessMode*/, ULONG /*cacheType*/,
                        PVOID /*baseAddr*/, ULONG /*zeroBits*/,
                        ULONG /*priority*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return nullptr;
}

static VOID NTAPI impl_MmUnmapLockedPages(PVOID /*baseAddr*/,
                                            PMDL /*mdl*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
}

static NTSTATUS NTAPI impl_MmProtectMdlSystemAddress(PMDL /*mdl*/,
                                                       ULONG /*newProtect*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return STATUS_SUCCESS;
}

static BOOLEAN NTAPI impl_MmIsAddressValid(PVOID addr) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
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
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
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
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return STATUS_SUCCESS;
}

static VOID NTAPI impl_IoDeleteDevice(PDEVICE_OBJECT deviceObject) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
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
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return STATUS_SUCCESS;
}

static VOID FASTCALL impl_IofCompleteRequest(PIRP /*irp*/,
                                               char /*priorityBoost*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
}

static BOOLEAN NTAPI impl_IoIsWdmVersionAvailable(UCHAR major, UCHAR minor) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    // Report WDM 1.10 (Windows 7 kernel) as the supported version.
    if (major < 1) return TRUE;
    if (major == 1 && minor <= 0x10u) return TRUE;
    return FALSE;
}

// ---- Process / thread ------------------------------------------------------

static NTSTATUS NTAPI impl_PsRegisterPicoProvider(PVOID /*provider*/,
                                                    PVOID /*routines*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return STATUS_SUCCESS;
}

static PEPROCESS NTAPI impl_IoGetCurrentProcess(VOID) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return &s_fake_eprocess;
}

static PVOID NTAPI impl_PsGetCurrentProcessId(VOID) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return reinterpret_cast<PVOID>(
        static_cast<ULONG_PTR>(GetCurrentProcessId()));
}

static PVOID NTAPI impl_PsGetProcessId(PEPROCESS /*process*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return nullptr;
}

static PKTHREAD NTAPI impl_KeGetCurrentThread(VOID) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return nullptr;
}

// ---- Zw* -------------------------------------------------------------------

static NTSTATUS NTAPI impl_ZwClose(HANDLE /*handle*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_ZwOpenKey(HANDLE* key, ULONG /*access*/,
                                      PVOID /*attrs*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (key) *key = nullptr;
    return STATUS_OBJECT_NAME_NOT_FOUND;
}

static NTSTATUS NTAPI impl_ZwCreateKey(HANDLE* key, ULONG /*access*/,
                        PVOID /*attrs*/, ULONG /*titleIdx*/, PVOID /*cls*/,
                        ULONG /*options*/, ULONG* disposition) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (key)         *key         = nullptr;
    if (disposition) *disposition = 1u; // REG_CREATED_NEW_KEY
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_ZwQueryValueKey(HANDLE /*key*/, PVOID /*name*/,
                        ULONG /*keyClass*/, PVOID /*info*/, ULONG /*infoLen*/,
                        ULONG* resultLen) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (resultLen) *resultLen = 0;
    return STATUS_OBJECT_NAME_NOT_FOUND;
}

static NTSTATUS NTAPI impl_ZwSetValueKey(HANDLE /*key*/, PVOID /*name*/,
                        ULONG /*titleIdx*/, ULONG /*type*/, PVOID /*data*/,
                        ULONG /*len*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_ZwSetSecurityObject(HANDLE /*handle*/,
                                                 ULONG /*secInfo*/,
                                                 PVOID /*sd*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_ZwQuerySystemInformation(ULONG /*infoClass*/,
                        PVOID /*info*/, ULONG /*infoLen*/,
                        ULONG* returnLen) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (returnLen) *returnLen = 0;
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS NTAPI impl_ZwFlushInstructionCache(HANDLE /*process*/,
                        PVOID /*baseAddr*/, SIZE_T /*len*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    FlushInstructionCache(GetCurrentProcess(), nullptr, 0);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_ZwDuplicateObject(HANDLE /*srcProcess*/,
                        HANDLE /*srcHandle*/, HANDLE /*dstProcess*/,
                        HANDLE* dstHandle, ULONG /*access*/,
                        ULONG /*attrs*/, ULONG /*opts*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (dstHandle) *dstHandle = nullptr;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_ZwTerminateProcess(HANDLE /*process*/,
                                                NTSTATUS /*exitStatus*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_ZwAllocateVirtualMemory(HANDLE /*process*/,
                        PVOID* baseAddr, ULONG_PTR /*zeroBits*/,
                        SIZE_T* regionSize, ULONG allocType, ULONG protect) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
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
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
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
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (fileHandle) *fileHandle = nullptr;
    return STATUS_NOT_IMPLEMENTED;
}

static LONG impl___C_specific_handler_fallback(...) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return 0;
}

static VOID NTAPI impl__local_unwind_fallback(PVOID /*frame*/,
                                               PVOID /*targetIp*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
}

static VOID NTAPI impl___jump_unwind_fallback(PVOID /*frame*/,
                                               PVOID /*targetIp*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
}

static VOID NTAPI impl_RtlUnwind_fallback(PVOID /*targetFrame*/,
                                           PVOID /*targetIp*/,
                                           PVOID /*exceptionRecord*/,
                                           PVOID /*returnValue*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
}
