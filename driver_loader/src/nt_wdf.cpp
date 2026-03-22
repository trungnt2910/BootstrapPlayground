// ---- Wdf* -------------------------------------------------------------------

static UCHAR s_wdf_function_table_stub[1024] = {};

struct WDF_BIND_INFO_STUB {
    ULONG Size;
    ULONG Component;
    ULONG VersionMajor;
    ULONG VersionMinor;
    PVOID FuncTable;
    PVOID Module;
};

struct WDF_COMPONENT_GLOBALS_STUB {
    ULONG Size;
    PVOID Driver;
    ULONG Reserved[6];
};

static WDF_COMPONENT_GLOBALS_STUB s_wdf_component_globals = {
    sizeof(WDF_COMPONENT_GLOBALS_STUB), nullptr, {0, 0, 0, 0, 0, 0},
};

static NTSTATUS NTAPI impl_WdfVersionBind(PVOID driverObject,
                        PVOID /*registryPath*/, PVOID bindInfo,
                        PVOID* componentGlobals) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (!bindInfo || !componentGlobals) {
        return STATUS_INVALID_PARAMETER;
    }
    auto* info = static_cast<WDF_BIND_INFO_STUB*>(bindInfo);
    if (info->Size >= sizeof(WDF_BIND_INFO_STUB)) {
        info->FuncTable = s_wdf_function_table_stub;
    }
    s_wdf_component_globals.Driver = driverObject;
    *componentGlobals = &s_wdf_component_globals;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_WdfVersionBindClass(PVOID context,
                        PVOID bindInfo, PVOID* componentGlobals) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return impl_WdfVersionBind(context, nullptr, bindInfo, componentGlobals);
}

static VOID NTAPI impl_WdfVersionUnbind(PVOID /*registryPath*/,
                                          PVOID /*bindInfo*/,
                                          PVOID /*componentGlobals*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    s_wdf_component_globals.Driver = nullptr;
}

static VOID NTAPI impl_WdfVersionUnbindClass(PVOID /*context*/,
                                               PVOID /*bindInfo*/,
                                               PVOID /*componentGlobals*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    s_wdf_component_globals.Driver = nullptr;
}

static NTSTATUS NTAPI impl_WdfLdrQueryInterface(PVOID /*iface*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return STATUS_NOT_IMPLEMENTED;
}
