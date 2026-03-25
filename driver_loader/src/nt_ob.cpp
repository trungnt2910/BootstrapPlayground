// ---- Reference counting ----------------------------------------------------

#include "../include/wdm.hpp"
#include <iostream>
#include <print>

static LONG_PTR FASTCALL impl_ObfReferenceObject(PVOID /*object*/)
{
    NT_STUB_REPORT();
    std::flush(std::cerr);
    return 1;
}

static LONG_PTR FASTCALL impl_ObfDereferenceObject(PVOID /*object*/)
{
    NT_STUB_REPORT();
    std::flush(std::cerr);
    return 0;
}

static NTSTATUS NTAPI impl_ObReferenceObjectByHandle(
    HANDLE /*handle*/,
    ULONG /*access*/,
    PVOID /*objectType*/,
    UCHAR /*accessMode*/,
    PVOID *object,
    PVOID /*handleInfo*/)
{
    NT_STUB_REPORT();
    std::flush(std::cerr);
    if (object)
        *object = nullptr;
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS NTAPI impl_ObOpenObjectByPointer(
    PVOID /*object*/,
    ULONG /*attrs*/,
    PVOID /*accessState*/,
    ULONG /*access*/,
    PVOID /*objectType*/,
    UCHAR /*accessMode*/,
    HANDLE *handle)
{
    NT_STUB_REPORT();
    std::flush(std::cerr);
    if (handle)
        *handle = nullptr;
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS NTAPI
impl_ObQueryNameString(PVOID /*object*/, PVOID nameInfo, ULONG length, ULONG *returnLength)
{
    NT_STUB_REPORT();
    std::flush(std::cerr);
    if (returnLength)
        *returnLength = 0;
    if (nameInfo && length > 0)
        static_cast<char *>(nameInfo)[0] = '\0';
    return STATUS_SUCCESS;
}
