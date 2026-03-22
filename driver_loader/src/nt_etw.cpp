// ---- Etw* -------------------------------------------------------------------

static NTSTATUS NTAPI impl_EtwRegister(PVOID /*providerId*/,
                                         PVOID /*callback*/,
                                         PVOID /*context*/,
                                         PVOID* regHandle) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (regHandle) *regHandle = nullptr;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_EtwSetInformation(PVOID /*regHandle*/,
                        ULONG /*infoClass*/, PVOID /*info*/,
                        ULONG /*infoLen*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_EtwWriteTransfer(PVOID /*regHandle*/,
                        PVOID /*eventDesc*/, PVOID* /*activityId*/,
                        PVOID* /*relatedId*/, ULONG /*userDataCount*/,
                        PVOID /*userData*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return STATUS_SUCCESS;
}
