// ---- Ps* --------------------------------------------------------------------

static NTSTATUS NTAPI impl_PsRegisterPicoProvider(PVOID /*provider*/, PVOID /*routines*/)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return STATUS_TOO_LATE;
}

static PVOID NTAPI impl_PsGetCurrentProcessId(VOID)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(GetCurrentProcessId()));
}

static PVOID NTAPI impl_PsGetProcessId(PEPROCESS /*process*/)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return nullptr;
}
