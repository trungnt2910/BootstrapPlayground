// test_driver.cpp – Minimal Windows kernel-mode driver used as the test target.
//
// This file intentionally avoids all system headers so it can be compiled
// with -nostdinc++ / -nostdlib against synthetic import libraries.
// It imports:
//   ntoskrnl.exe  →  DbgPrintEx
//   lxcore.sys    →  LxInitialize  (supplied by the test host)

// ---- Minimal type definitions (no system headers) -----------------------

typedef long NTSTATUS;
typedef unsigned long ULONG;
typedef unsigned short USHORT;
typedef wchar_t WCHAR;
typedef void* PVOID;

// On x86 Windows the kernel ABI uses __stdcall (callee-cleans-stack).
// On every other architecture it is a no-op.
#if defined(_M_IX86) || defined(__i386__)
#  define NTAPI __stdcall
#else
#  define NTAPI
#endif

// Minimal UNICODE_STRING matching Windows ABI.
struct UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    WCHAR* Buffer;
};

// Opaque forward declarations.
typedef struct _DRIVER_OBJECT DRIVER_OBJECT, *PDRIVER_OBJECT;
typedef UNICODE_STRING* PUNICODE_STRING;

// ---- Imported kernel functions ------------------------------------------

// DbgPrintEx is variadic – variadic functions cannot use NTAPI (__stdcall).
extern "C" ULONG DbgPrintEx(ULONG ComponentId, ULONG Level,
                              const char* Format, ...);

extern "C" NTSTATUS NTAPI LxInitialize(PDRIVER_OBJECT DriverObject,
                                        PVOID Subsystem);

// ---- DriverEntry --------------------------------------------------------

extern "C" NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT DriverObject,
                                       PUNICODE_STRING RegistryPath) {
    // Suppress unused-parameter warnings.
    (void)RegistryPath;

    // Call LxInitialize (provided by the consumer of DriverLoader).
    // The test host supplies a stub that returns STATUS_SUCCESS (0).
    NTSTATUS status = LxInitialize(DriverObject, nullptr);
    (void)status;

    // Log via DbgPrintEx (provided by our ntoskrnl stub table).
    // 77 = DPFLTR_IHVDRIVER_ID, 0 = DPFLTR_ERROR_LEVEL.
    DbgPrintEx(77, 0, "test_driver: DriverEntry called successfully.\n");

    return 0; // STATUS_SUCCESS
}
