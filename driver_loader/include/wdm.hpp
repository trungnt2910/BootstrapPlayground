#pragma once
// wdm.hpp – Minimal ABI-compatible replications of Windows Driver Kit structures.
//
// This header intentionally does NOT include <windows.h> or <winternl.h>.
// Those headers must be included BEFORE this header in translation units that
// need both (e.g., driver_loader.cpp, nt_stubs.cpp, test_host.cpp).
//
// The reason is that <windows.h> / <winternl.h> from some llvm-mingw builds
// define macros with the same names as our kernel types (PDRIVER_OBJECT, etc.),
// which would corrupt our C++ 'using' declarations.  By including wdm.hpp
// AFTER <windows.h>, any such macros are already defined and we test for them
// with #ifdef guards rather than letting them silently corrupt our code.
//
// Scalar types (NTSTATUS, ULONG, …) are defined here using C++ primitive types
// guarded with the same macros Windows SDK uses, so the definitions are
// compatible when windows.h is included in the same TU.

// ---------------------------------------------------------------------------
// Scalar types (guarded for compatibility with windows.h)
// ---------------------------------------------------------------------------

#ifndef _NTSTATUS_
#define _NTSTATUS_
typedef long NTSTATUS;
#endif
#ifndef __NTSTATUS_DEFINED
#define __NTSTATUS_DEFINED
#endif

#ifndef _WINNT_
// Only define if windows.h hasn't been included yet.
typedef long                LONG;
typedef unsigned long       ULONG;
typedef unsigned short      USHORT;
typedef short               SHORT;
typedef unsigned char       UCHAR;
typedef wchar_t             WCHAR;
typedef unsigned char       BOOLEAN;
typedef long long           LONGLONG;
typedef unsigned long long  ULONGLONG;
typedef void*               PVOID;
typedef void*               HANDLE;
#if defined(_WIN64)
typedef unsigned long long  ULONG_PTR;
typedef long long           LONG_PTR;
typedef unsigned long long  SIZE_T;
#else
typedef unsigned long       ULONG_PTR;
typedef long                LONG_PTR;
typedef unsigned long       SIZE_T;
#endif
typedef unsigned short      WORD;
typedef unsigned long       DWORD;
typedef int                 BOOL;
typedef unsigned char       BYTE;
#endif // _WINNT_

// ---------------------------------------------------------------------------
// UNICODE_STRING – must match Windows ABI exactly
// ---------------------------------------------------------------------------

#ifndef _UNICODE_STRING_DEFINED
#define _UNICODE_STRING_DEFINED
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    WCHAR* Buffer;
} UNICODE_STRING;
#endif

typedef UNICODE_STRING* PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

// ---------------------------------------------------------------------------
// Calling convention
// ---------------------------------------------------------------------------

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
// Common NT status codes
// ---------------------------------------------------------------------------

#ifndef STATUS_SUCCESS
#  define STATUS_SUCCESS           ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_UNSUCCESSFUL
#  define STATUS_UNSUCCESSFUL      ((NTSTATUS)0xC0000001L)
#endif
#ifndef STATUS_NOT_IMPLEMENTED
#  define STATUS_NOT_IMPLEMENTED   ((NTSTATUS)0xC0000002L)
#endif
#ifndef STATUS_INVALID_PARAMETER
#  define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif
#ifndef STATUS_NOT_SUPPORTED
#  define STATUS_NOT_SUPPORTED     ((NTSTATUS)0xC00000BBL)
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
#  define STATUS_NO_MEMORY         ((NTSTATUS)0xC0000017L)
#endif
#ifndef STATUS_OBJECT_NAME_NOT_FOUND
#  define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#  define STATUS_BUFFER_TOO_SMALL  ((NTSTATUS)0xC0000023L)
#endif
#ifndef STATUS_ACCESS_DENIED
#  define STATUS_ACCESS_DENIED     ((NTSTATUS)0xC0000022L)
#endif

inline bool NT_SUCCESS(NTSTATUS st) noexcept { return st >= 0; }

// ---------------------------------------------------------------------------
// IRP major-function codes
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

// Literal constant – does not rely on any macro name.
#define IRP_MJ_COUNT 28

// ---------------------------------------------------------------------------
// Forward declarations for kernel object types
// ---------------------------------------------------------------------------

#ifndef _DRIVER_OBJECT_DEFINED
#define _DRIVER_OBJECT_DEFINED
struct _DRIVER_OBJECT;
#endif

#ifndef _DEVICE_OBJECT_DEFINED
#define _DEVICE_OBJECT_DEFINED
struct _DEVICE_OBJECT;
#endif

#ifndef _IRP_DEFINED
#define _IRP_DEFINED
struct _IRP;
#endif

typedef struct _DRIVER_OBJECT  DRIVER_OBJECT;
typedef struct _DRIVER_OBJECT* PDRIVER_OBJECT;
typedef struct _DEVICE_OBJECT  DEVICE_OBJECT;
typedef struct _DEVICE_OBJECT* PDEVICE_OBJECT;
typedef struct _IRP            IRP;
typedef struct _IRP*           PIRP;

// ---------------------------------------------------------------------------
// Function-pointer typedefs
// ---------------------------------------------------------------------------

typedef void  (NTAPI* PDRIVER_UNLOAD    )(DRIVER_OBJECT* DriverObject);
typedef NTSTATUS (NTAPI* PDRIVER_DISPATCH)(DEVICE_OBJECT* DeviceObject, IRP* Irp);
typedef NTSTATUS (NTAPI* PDRIVER_INITIALIZE)(DRIVER_OBJECT* DriverObject,
                                             UNICODE_STRING* RegistryPath);

// ---------------------------------------------------------------------------
// DRIVER_EXTENSION
// ---------------------------------------------------------------------------

typedef struct _DRIVER_EXTENSION {
    DRIVER_OBJECT*     DriverObject;
    void*              AddDevice;       // PDRIVER_ADD_DEVICE
    ULONG              Count;
    UNICODE_STRING     ServiceKeyName;
} DRIVER_EXTENSION, *PDRIVER_EXTENSION;

// ---------------------------------------------------------------------------
// DRIVER_OBJECT  (full definition)
// ---------------------------------------------------------------------------

struct _DRIVER_OBJECT {
    SHORT              Type;            // = 4 (IO_TYPE_DRIVER)
    SHORT              Size;            // = sizeof(DRIVER_OBJECT)
    PDEVICE_OBJECT     DeviceObject;
    ULONG              Flags;
    PVOID              DriverStart;
    ULONG              DriverSize;
    PVOID              DriverSection;
    PDRIVER_EXTENSION  DriverExtension;
    UNICODE_STRING     DriverName;
    PUNICODE_STRING    HardwareDatabase;
    PVOID              FastIoDispatch;
    PDRIVER_INITIALIZE DriverInit;
    PVOID              DriverStartIo;
    PDRIVER_UNLOAD     DriverUnload;
    PDRIVER_DISPATCH   MajorFunction[IRP_MJ_COUNT];
};

// ---------------------------------------------------------------------------
// DEVICE_OBJECT  (minimal subset)
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
    PVOID              Vpb;
    PVOID              DeviceExtension;
    ULONG              DeviceType;
    UCHAR              StackSize;
};

// ---------------------------------------------------------------------------
// Pool flags (POOL_FLAGS = ULONGLONG in the Windows SDK)
// ---------------------------------------------------------------------------

#define POOL_FLAG_NON_PAGED         ((ULONGLONG)0x0000000000000004ULL)
#define POOL_FLAG_PAGED             ((ULONGLONG)0x0000000000000008ULL)
#define POOL_FLAG_NON_PAGED_EXECUTE ((ULONGLONG)0x0000000000000010ULL)

// ---------------------------------------------------------------------------
// IRQL
// ---------------------------------------------------------------------------

#ifndef _IRQL_DEFINED
#define _IRQL_DEFINED
typedef UCHAR KIRQL;
typedef KIRQL* PKIRQL;
#endif

#define PASSIVE_LEVEL  0
#define APC_LEVEL      1
#define DISPATCH_LEVEL 2

// ---------------------------------------------------------------------------
// Opaque kernel object types (forward declarations)
// ---------------------------------------------------------------------------

#ifndef _EPROCESS_DEFINED
#define _EPROCESS_DEFINED
struct _EPROCESS { ULONG_PTR Reserved; };
typedef struct _EPROCESS  EPROCESS;
typedef struct _EPROCESS* PEPROCESS;
#endif

#ifndef _ETHREAD_DEFINED
#define _ETHREAD_DEFINED
struct _ETHREAD  { ULONG_PTR Reserved; };
typedef struct _ETHREAD  ETHREAD;
typedef struct _ETHREAD* PETHREAD;
#endif

#ifndef _KTHREAD_DEFINED
#define _KTHREAD_DEFINED
struct _KTHREAD  { ULONG_PTR Reserved; };
typedef struct _KTHREAD  KTHREAD;
typedef struct _KTHREAD* PKTHREAD;
#endif

// ---------------------------------------------------------------------------
// MDL (minimal definition)
// ---------------------------------------------------------------------------

#ifndef _MDL_DEFINED
#define _MDL_DEFINED
typedef struct _MDL {
    struct _MDL* Next;
    CSHORT       Size;
    CSHORT       MdlFlags;
    PVOID        Process;
    PVOID        MappedSystemVa;
    PVOID        StartVa;
    ULONG        ByteCount;
    ULONG        ByteOffset;
} MDL, *PMDL;
#endif

// ---------------------------------------------------------------------------
// KEVENT (minimal signaled-state tracker)
// ---------------------------------------------------------------------------

#ifndef _KEVENT_DEFINED
#define _KEVENT_DEFINED
typedef struct _KEVENT {
    LONG Signaled;
} KEVENT, *PKEVENT;
#endif

// ---------------------------------------------------------------------------
// FAST_MUTEX (minimal stub; real kernel struct is larger)
// ---------------------------------------------------------------------------

#ifndef _FAST_MUTEX_DEFINED
#define _FAST_MUTEX_DEFINED
typedef struct _FAST_MUTEX {
    LONG Count;
    PVOID Owner;
    ULONG Contention;
    ULONG OldIrql;
} FAST_MUTEX, *PFAST_MUTEX;
#endif

// ---------------------------------------------------------------------------
// SE_EXPORTS – large opaque blob; we zero-initialise it in our stubs.
// The real WDK definition lists many privilege LUIDs and SID pointers.
// ---------------------------------------------------------------------------

#ifndef _SE_EXPORTS_DEFINED
#define _SE_EXPORTS_DEFINED
typedef struct _SE_EXPORTS {
    UCHAR _opaque[1024];
} SE_EXPORTS, *PSE_EXPORTS;
#endif
