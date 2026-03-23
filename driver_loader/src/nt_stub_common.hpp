#pragma once

#include "../include/wdm.hpp"

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
