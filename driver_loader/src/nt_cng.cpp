// ---- BCrypt* ----------------------------------------------------------------

#include <cstdlib>
#include <iostream>
#include <print>

#ifndef NT_STUB_REPORT
#define NT_STUB_REPORT()                                                                           \
    do                                                                                             \
    {                                                                                              \
        std::println(stderr, "[nt_stubs] call {}", __func__);                                      \
        std::flush(std::cerr);                                                                     \
    } while (0)
#endif

static NTSTATUS NTAPI impl_BCryptGenRandom(PVOID alg, UCHAR *buf, ULONG len, ULONG flags)
{
    NT_STUB_REPORT();
    UNREFERENCED_PARAMETER(alg);
    UNREFERENCED_PARAMETER(flags);

    if (buf == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    for (ULONG i = 0; i < len; ++i)
    {
        buf[i] = static_cast<UCHAR>(std::rand() & 0xFF);
    }

    return STATUS_SUCCESS;
}
