// ---- Ke* / Kf* --------------------------------------------------------------

#include "logger.hpp"

#include "nt_stubs_internal.hpp"

static VOID NTAPI impl_KeInitializeSpinLock(ULONG_PTR *spinLock)
{
    NT_STUB_REPORT();
    if (spinLock)
        *spinLock = 0;
}

static VOID NTAPI impl_KeInitializeEvent(KEVENT *event, ULONG /*type*/, BOOLEAN state)
{
    NT_STUB_REPORT();
    if (event)
        event->Signaled = state ? 1 : 0;
}

static KIRQL NTAPI impl_KeGetCurrentIrql(VOID)
{
    DL_LOG_TRACE("[nt_stubs] call {} -> PASSIVE_LEVEL", __func__);
    return static_cast<KIRQL>(PASSIVE_LEVEL);
}

static KIRQL NTAPI impl_KeRaiseIrqlToDpcLevel(VOID)
{
    DL_LOG_TRACE("[nt_stubs] call {} -> PASSIVE_LEVEL", __func__);
    return static_cast<KIRQL>(PASSIVE_LEVEL);
}

static KIRQL FASTCALL impl_KfRaiseIrql(KIRQL /*newIrql*/)
{
    return static_cast<KIRQL>(PASSIVE_LEVEL);
}

static NTSTATUS NTAPI
impl_KeDelayExecutionThread(ULONG /*mode*/, BOOLEAN /*alertable*/, PVOID /*interval*/)
{
    NT_STUB_REPORT();
    return STATUS_SUCCESS;
}

static PKTHREAD NTAPI impl_KeGetCurrentThread(VOID)
{
    NT_STUB_REPORT();
    return nullptr;
}
