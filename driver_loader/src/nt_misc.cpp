// Intentionally keep truly uncategorized stubs in this file.


#include "../include/wdm.hpp"
#include <iostream>
#include <print>

static LONG NTAPI impl_InterlockedCompareExchange(volatile LONG *dest, LONG exchange,
                                                  LONG comparand)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return InterlockedCompareExchange(reinterpret_cast<volatile LONG *>(dest), exchange, comparand);
}
