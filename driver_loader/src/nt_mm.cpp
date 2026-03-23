// ---- Mm* --------------------------------------------------------------------


#include "../include/wdm.hpp"
#include <iostream>
#include <print>

static PVOID NTAPI impl_MmGetSystemRoutineAddress(UNICODE_STRING *routineName)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (!routineName || !routineName->Buffer)
        return nullptr;
    char narrow[256] = {};
    const int len = WideCharToMultiByte(
        CP_ACP, 0, routineName->Buffer, routineName->Length / static_cast<int>(sizeof(WCHAR)),
        narrow, static_cast<int>(sizeof(narrow)) - 1, nullptr, nullptr);
    if (len <= 0)
        return nullptr;
    narrow[len] = '\0';
    void *sym = NtStubsLookup(narrow);
    if (sym)
    {
        std::println(stderr, "[nt_stubs] MmGetSystemRoutineAddress({}) -> {:p}", narrow, sym);
        std::flush(std::cerr);
        return sym;
    }
    void *stub = NtStubsAllocate(narrow);
    std::println(stderr, "[nt_stubs] MmGetSystemRoutineAddress({}) unresolved; using stub @ {:p}",
                 narrow, stub);
    std::flush(std::cerr);
    return stub;
}
