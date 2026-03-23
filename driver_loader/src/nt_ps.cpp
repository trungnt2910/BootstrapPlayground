// ---- Ps* --------------------------------------------------------------------

#include <Windows.h>

#include "nt_stubs_internal.hpp"

struct _PS_FAKE_PROCESS_TYPE {} PsFakeProcessType;
struct _PS_FAKE_THREAD_TYPE {} PsFakeThreadType;
struct EPROCESS PsFakeSystemProcess;

PVOID impl_PsProcessType = &PsFakeProcessType;
PVOID impl_PsThreadType = &PsFakeThreadType;
PEPROCESS impl_PsInitialSystemProcess = &PsFakeSystemProcess;

static NTSTATUS NTAPI impl_PsRegisterPicoProvider(PVOID /*provider*/, PVOID /*routines*/)
{
    NT_STUB_REPORT();
    return STATUS_TOO_LATE;
}

static PVOID NTAPI impl_PsGetCurrentProcessId(VOID)
{
    NT_STUB_REPORT();
    return reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(GetCurrentProcessId()));
}

static PVOID NTAPI impl_PsGetProcessId(PEPROCESS /*process*/)
{
    NT_STUB_REPORT();
    return nullptr;
}
