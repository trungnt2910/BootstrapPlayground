// ---- BCrypt* ----------------------------------------------------------------


#include "../include/wdm.hpp"
#include <iostream>
#include <print>

#include <cstdlib>

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
