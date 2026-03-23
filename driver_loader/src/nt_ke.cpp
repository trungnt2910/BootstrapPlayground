// ---- Ke* / Kf* --------------------------------------------------------------


#include "../include/wdm.hpp"
#include <iostream>
#include <print>

static VOID NTAPI impl_KeInitializeSpinLock(ULONG_PTR *spinLock)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (spinLock)
        *spinLock = 0;
}

static VOID NTAPI impl_KeInitializeEvent(KEVENT *event, ULONG /*type*/, BOOLEAN state)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    if (event)
        event->Signaled = state ? 1 : 0;
}

static KIRQL NTAPI impl_KeGetCurrentIrql(VOID)
{
    std::println(stderr, "[nt_stubs] call {} -> PASSIVE_LEVEL", __func__);
    std::flush(std::cerr);
    return static_cast<KIRQL>(PASSIVE_LEVEL);
}

static KIRQL NTAPI impl_KeRaiseIrqlToDpcLevel(VOID)
{
    std::println(stderr, "[nt_stubs] call KeRaiseIrqlToDpcLevel -> PASSIVE_LEVEL");
    std::flush(std::cerr);
    return static_cast<KIRQL>(PASSIVE_LEVEL);
}

static KIRQL FASTCALL impl_KfRaiseIrql(KIRQL /*newIrql*/)
{
    return static_cast<KIRQL>(PASSIVE_LEVEL);
}

static NTSTATUS NTAPI impl_KeDelayExecutionThread(ULONG /*mode*/, BOOLEAN /*alertable*/,
                                                  PVOID /*interval*/)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return STATUS_SUCCESS;
}

static PKTHREAD NTAPI impl_KeGetCurrentThread(VOID)
{
    std::println(stderr, "[nt_stubs] call {}", __func__);
    std::flush(std::cerr);
    return nullptr;
}
