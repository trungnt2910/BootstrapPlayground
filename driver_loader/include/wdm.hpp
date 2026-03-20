#pragma once
// wdm.hpp – Minimal ABI-compatible replications of Windows Driver Kit structures.
//
// Pull in <windows.h> and <winternl.h> first so that all standard scalar
// types (NTSTATUS, LONG, ULONG, PVOID, UNICODE_STRING, LIST_ENTRY, …) come
// from the system headers.  We only define driver-specific types that are NOT
// exported by those headers.

#include <windows.h>
#include <winternl.h>

// PUNICODE_STRING / PCUNICODE_STRING are typedef'd in winternl.h on most
// MinGW builds.  Provide them only if they are missing.
#ifndef _PUNICODE_STRING_DEFINED
#define _PUNICODE_STRING_DEFINED
typedef UNICODE_STRING* PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;
#endif

// ---------------------------------------------------------------------------
// Calling convention
// ---------------------------------------------------------------------------

// On x86, most kernel functions use __stdcall (callee cleans the stack).
// On every other architecture there is a single calling convention.
#if defined(_M_IX86) || defined(__i386__)
#  ifndef NTAPI
#    define NTAPI __stdcall
#  endif
#  ifndef FASTCALL
#    define FASTCALL __fastcall
#  endif
#else
#  ifndef NTAPI
#    define NTAPI
#  endif
#  ifndef FASTCALL
#    define FASTCALL
#  endif
#endif

// ---------------------------------------------------------------------------
// Common NT status codes – guarded so we don't conflict with windows.h
// ---------------------------------------------------------------------------

#ifndef STATUS_SUCCESS
#  define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_UNSUCCESSFUL
#  define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif
#ifndef STATUS_NOT_IMPLEMENTED
#  define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)
#endif
#ifndef STATUS_INVALID_PARAMETER
#  define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif
#ifndef STATUS_NOT_SUPPORTED
#  define STATUS_NOT_SUPPORTED ((NTSTATUS)0xC00000BBL)
#endif
#ifndef STATUS_INSUFFICIENT_RESOURCES
#  define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AL)
#endif
#ifndef STATUS_OBJECT_NAME_EXISTS
#  define STATUS_OBJECT_NAME_EXISTS ((NTSTATUS)0x40000000L)
#endif
#ifndef STATUS_OBJECT_NAME_COLLISION
#  define STATUS_OBJECT_NAME_COLLISION ((NTSTATUS)0xC0000035L)
#endif
#ifndef STATUS_NO_MEMORY
#  define STATUS_NO_MEMORY ((NTSTATUS)0xC0000017L)
#endif

// NT_SUCCESS evaluates true for informational and success codes.
inline bool NT_SUCCESS(NTSTATUS st) noexcept {
    return st >= 0;
}

// ---------------------------------------------------------------------------
// IRP major-function codes.
// Define with #ifndef guards in case <winternl.h> or other Windows headers
// already provide them (they are present in DDK / Driver Kit headers).
// ---------------------------------------------------------------------------

#ifndef IRP_MJ_CREATE
#  define IRP_MJ_CREATE                   0
#  define IRP_MJ_CREATE_NAMED_PIPE        1
#  define IRP_MJ_CLOSE                    2
#  define IRP_MJ_READ                     3
#  define IRP_MJ_WRITE                    4
#  define IRP_MJ_QUERY_INFORMATION        5
#  define IRP_MJ_SET_INFORMATION          6
#  define IRP_MJ_QUERY_EA                 7
#  define IRP_MJ_SET_EA                   8
#  define IRP_MJ_FLUSH_BUFFERS            9
#  define IRP_MJ_QUERY_VOLUME_INFORMATION 10
#  define IRP_MJ_SET_VOLUME_INFORMATION   11
#  define IRP_MJ_DIRECTORY_CONTROL        12
#  define IRP_MJ_FILE_SYSTEM_CONTROL      13
#  define IRP_MJ_DEVICE_CONTROL           14
#  define IRP_MJ_INTERNAL_DEVICE_CONTROL  15
#  define IRP_MJ_SHUTDOWN                 16
#  define IRP_MJ_LOCK_CONTROL             17
#  define IRP_MJ_CLEANUP                  18
#  define IRP_MJ_CREATE_MAILSLOT          19
#  define IRP_MJ_QUERY_SECURITY           20
#  define IRP_MJ_SET_SECURITY             21
#  define IRP_MJ_POWER                    22
#  define IRP_MJ_SYSTEM_CONTROL           23
#  define IRP_MJ_DEVICE_CHANGE            24
#  define IRP_MJ_QUERY_QUOTA              25
#  define IRP_MJ_SET_QUOTA                26
#  define IRP_MJ_PNP                      27
#  define IRP_MJ_MAXIMUM_FUNCTION         27
#endif

// Number of MajorFunction[] entries: IRP_MJ_MAXIMUM_FUNCTION + 1 = 28.
// Use a literal constant to avoid any dependency on the name defined above.
#define IRP_MJ_COUNT 28

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------

struct _DRIVER_OBJECT;
using  DRIVER_OBJECT  = _DRIVER_OBJECT;
using  PDRIVER_OBJECT = _DRIVER_OBJECT*;

struct _DEVICE_OBJECT;
using  DEVICE_OBJECT  = _DEVICE_OBJECT;
using  PDEVICE_OBJECT = _DEVICE_OBJECT*;

struct _IRP;
using  IRP  = _IRP;
using  PIRP = _IRP*;

// ---------------------------------------------------------------------------
// Function-pointer typedefs
// ---------------------------------------------------------------------------

using PDRIVER_UNLOAD     = void (NTAPI*)(_DRIVER_OBJECT* DriverObject);
using PDRIVER_DISPATCH   = NTSTATUS (NTAPI*)(_DEVICE_OBJECT* DeviceObject, _IRP* Irp);
using PDRIVER_INITIALIZE = NTSTATUS (NTAPI*)(_DRIVER_OBJECT* DriverObject,
                                              UNICODE_STRING* RegistryPath);

// ---------------------------------------------------------------------------
// DRIVER_EXTENSION
// ---------------------------------------------------------------------------

struct _DRIVER_EXTENSION {
    _DRIVER_OBJECT*    DriverObject;
    void*              AddDevice;       // PDRIVER_ADD_DEVICE
    ULONG              Count;
    UNICODE_STRING     ServiceKeyName;
};
using DRIVER_EXTENSION  = _DRIVER_EXTENSION;
using PDRIVER_EXTENSION = _DRIVER_EXTENSION*;

// ---------------------------------------------------------------------------
// DRIVER_OBJECT
// ---------------------------------------------------------------------------

struct _DRIVER_OBJECT {
    SHORT              Type;            // = 4 (IO_TYPE_DRIVER)
    SHORT              Size;            // = sizeof(DRIVER_OBJECT)
    PDEVICE_OBJECT     DeviceObject;    // head of the device-object list
    ULONG              Flags;
    PVOID              DriverStart;     // base address of the driver image
    ULONG              DriverSize;      // size of the driver image in bytes
    PVOID              DriverSection;   // LDR_DATA_TABLE_ENTRY (unused)
    PDRIVER_EXTENSION  DriverExtension;
    UNICODE_STRING     DriverName;
    PUNICODE_STRING    HardwareDatabase;
    PVOID              FastIoDispatch;  // PFAST_IO_DISPATCH (unused)
    PDRIVER_INITIALIZE DriverInit;
    PVOID              DriverStartIo;   // PDRIVER_STARTIO (unused)
    PDRIVER_UNLOAD     DriverUnload;
    PDRIVER_DISPATCH   MajorFunction[IRP_MJ_COUNT];
};

// ---------------------------------------------------------------------------
// DEVICE_OBJECT (minimal subset used by the test framework)
// ---------------------------------------------------------------------------

struct _DEVICE_OBJECT {
    SHORT              Type;            // = 3 (IO_TYPE_DEVICE)
    USHORT             Size;
    LONG               ReferenceCount;
    PDRIVER_OBJECT     DriverObject;
    PDEVICE_OBJECT     NextDevice;
    PDEVICE_OBJECT     AttachedDevice;
    PIRP               CurrentIrp;
    PVOID              Timer;
    ULONG              Flags;
    ULONG              Characteristics;
    PVOID              Vpb;             // PVPB
    PVOID              DeviceExtension;
    ULONG              DeviceType;
    UCHAR              StackSize;
};

// ---------------------------------------------------------------------------
// Pool flags (POOL_FLAGS = ULONGLONG in the Windows SDK)
// ---------------------------------------------------------------------------

inline constexpr ULONGLONG POOL_FLAG_NON_PAGED          = 0x0000000000000004ULL;
inline constexpr ULONGLONG POOL_FLAG_PAGED               = 0x0000000000000008ULL;
inline constexpr ULONGLONG POOL_FLAG_NON_PAGED_EXECUTE   = 0x0000000000000010ULL;
