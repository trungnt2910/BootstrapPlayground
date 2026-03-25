// ---- Etw* -------------------------------------------------------------------

#include "../include/wdm.hpp"
#include <iostream>
#include <print>

static NTSTATUS NTAPI
impl_EtwRegister(PVOID /*providerId*/, PVOID /*callback*/, PVOID /*context*/, PVOID *regHandle)
{
    NT_STUB_REPORT();
    std::flush(std::cerr);
    if (regHandle)
        *regHandle = nullptr;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI
impl_EtwSetInformation(PVOID /*regHandle*/, ULONG /*infoClass*/, PVOID /*info*/, ULONG /*infoLen*/)
{
    NT_STUB_REPORT();
    std::flush(std::cerr);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI impl_EtwWriteTransfer(
    PVOID /*regHandle*/,
    PVOID /*eventDesc*/,
    PVOID * /*activityId*/,
    PVOID * /*relatedId*/,
    ULONG /*userDataCount*/,
    PVOID /*userData*/)
{
    NT_STUB_REPORT();
    std::flush(std::cerr);
    return STATUS_SUCCESS;
}
