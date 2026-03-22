// ---- Wdf* -------------------------------------------------------------------

static VOID NTAPI impl_WdfStubTableEntry0() {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
}

static VOID NTAPI impl_WdfStubTableEntry1() {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
}

static VOID NTAPI impl_WdfStubTableEntry2() {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
}

static PVOID s_wdf_function_table_stub[] = {
    &impl_WdfStubTableEntry0,
    &impl_WdfStubTableEntry1,
    &impl_WdfStubTableEntry2,
};

static NTSTATUS NTAPI impl_WdfVersionBind(PDRIVER_OBJECT driverObject,
                        PUNICODE_STRING /*registryPath*/, PWDF_BIND_INFO bindInfo,
                        PWDF_COMPONENT_GLOBALS* componentGlobals) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (!bindInfo || !componentGlobals) {
        return STATUS_INVALID_PARAMETER;
    }
    if (bindInfo->Size < sizeof(WDF_BIND_INFO)) {
        return STATUS_INVALID_PARAMETER;
    }

    DriverLoader* loader = DriverLoader::FromDriverObject(driverObject);
    if (!loader) {
        return STATUS_INVALID_PARAMETER;
    }

    bindInfo->FuncCount = static_cast<ULONG>(std::size(s_wdf_function_table_stub));
    bindInfo->Module = driverObject;
    if (bindInfo->FuncTable == nullptr) {
        bindInfo->FuncTable = reinterpret_cast<PVOID>(s_wdf_function_table_stub);
    }

    auto& globals = loader->WdfComponentGlobals();
    auto& driver_globals = loader->WdfDriverGlobals();
    driver_globals.Driver = driverObject;
    driver_globals.DriverFlags = 0;
    driver_globals.DisplaceDriverUnload = 0;

    globals.Size = sizeof(WDF_COMPONENT_GLOBALS);
    globals.DriverGlobals = &driver_globals;
    globals.FuncTable = bindInfo->FuncTable;
    globals.FuncCount = bindInfo->FuncCount;
    *componentGlobals = &globals;
    std::println(stderr,
        "[nt_stubs] {}: FuncTable={:p} FuncCount={} Globals={:p}",
        __func__,
        bindInfo->FuncTable,
        static_cast<unsigned long>(bindInfo->FuncCount),
        static_cast<void*>(&globals));
    std::flush(std::cerr);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_WdfVersionBindClass(PVOID context,
                        PWDF_BIND_INFO bindInfo, PWDF_COMPONENT_GLOBALS* componentGlobals) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (!context) {
        return STATUS_INVALID_PARAMETER;
    }
    auto* driverObject = static_cast<PDRIVER_OBJECT>(context);
    return impl_WdfVersionBind(driverObject, nullptr, bindInfo, componentGlobals);
}

static VOID NTAPI impl_WdfVersionUnbind(PUNICODE_STRING /*registryPath*/,
                                          PWDF_BIND_INFO /*bindInfo*/,
                                          PWDF_COMPONENT_GLOBALS componentGlobals) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (componentGlobals) {
        if (componentGlobals->DriverGlobals) {
            componentGlobals->DriverGlobals->Driver = nullptr;
        }
        componentGlobals->DriverGlobals = nullptr;
        componentGlobals->FuncTable = nullptr;
        componentGlobals->FuncCount = 0;
    }
}

static VOID NTAPI impl_WdfVersionUnbindClass(PVOID /*context*/,
                                               PWDF_BIND_INFO bindInfo,
                                               PWDF_COMPONENT_GLOBALS componentGlobals) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    impl_WdfVersionUnbind(nullptr, bindInfo, componentGlobals);
}

static NTSTATUS NTAPI impl_WdfLdrQueryInterface(PVOID /*iface*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return STATUS_SUCCESS;
}
