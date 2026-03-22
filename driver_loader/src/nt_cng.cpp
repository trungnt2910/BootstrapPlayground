// ---- BCrypt* ----------------------------------------------------------------

static NTSTATUS NTAPI impl_BCryptGenRandom(PVOID /*alg*/, UCHAR* buf,
                                            ULONG len, ULONG /*flags*/) {
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (!buf) return STATUS_INVALID_PARAMETER;
    for (ULONG i = 0; i < len; ++i)
        buf[i] = static_cast<UCHAR>(rand() & 0xFF);
    return STATUS_SUCCESS;
}
