// ---- Wdf* -------------------------------------------------------------------

template<std::size_t Index>
static VOID NTAPI impl_WdfStubTableEntry() {
    std::println(stderr, "[nt_stubs] call impl_WdfStubTableEntry{}", Index);
    std::flush(std::cerr);
}

template<std::size_t... Indices>
static auto MakeWdfFunctionTable(std::index_sequence<Indices...>) {
    return std::array<WDFFUNC, sizeof...(Indices)>{
        &impl_WdfStubTableEntry<Indices>...
    };
}

static constexpr ULONG kWdfFunctionTableStubCount = 0x1BC;
static auto s_wdf_function_table_stub =
    MakeWdfFunctionTable(std::make_index_sequence<kWdfFunctionTableStubCount>{});

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

    bindInfo->FuncCount = kWdfFunctionTableStubCount;
    bindInfo->Module = driverObject;
    if (bindInfo->FuncTable == nullptr) {
        bindInfo->FuncTable = s_wdf_function_table_stub.data();
    }

    auto& driver_globals = loader->WdfDriverGlobals();
    driver_globals.Driver = driverObject;
    driver_globals.DriverFlags = 0;
    driver_globals.DisplaceDriverUnload = 0;

    *componentGlobals = nullptr;
    std::println(stderr,
        "[nt_stubs] {}: FuncTable={:p} FuncCount={} ComponentGlobals={:p}",
        __func__,
        static_cast<void*>(bindInfo->FuncTable),
        static_cast<unsigned long>(bindInfo->FuncCount),
        static_cast<void*>(*componentGlobals));
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
    (void)componentGlobals;
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
