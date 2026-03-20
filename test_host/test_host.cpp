// test_host.cpp – Test host for the Windows driver testing framework.
//
// Usage:  test_host.exe  [path/to/driver.sys]
//
// Default driver path: test_driver.sys (same directory as the executable).
//
// The host:
//   1. Registers a LxInitialize consumer symbol (stub returning STATUS_SUCCESS).
//   2. Loads the driver through DriverLoader.
//   3. Calls the driver's DriverEntry.
//   4. Asserts that DriverEntry returned STATUS_SUCCESS.
//   5. Prints a success message and exits with code 0.

#include "driver_loader.hpp"
#include "wdm.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>

#include <windows.h>

// ---------------------------------------------------------------------------
// Consumer-supplied stub: LxInitialize (normally exported by lxcore.sys).
// ---------------------------------------------------------------------------

extern "C" NTSTATUS NTAPI LxInitialize(PDRIVER_OBJECT /*driverObject*/,
                                        PVOID          /*subsystem*/) {
    std::fprintf(stderr, "[test_host] LxInitialize stub called.\n");
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    // Build the driver path using only C-style string operations so that
    // no heap allocation (std::string) is needed before the try block.
    // On some Wine+QEMU configurations (e.g. ARM64 under Debian bookworm),
    // heap allocation can silently fail before the runtime is fully set up.
    static char default_path[MAX_PATH + 32];
    const char* path_cstr = nullptr;

    if (argc >= 2 && argv[1] != nullptr && argv[1][0] != '\0') {
        path_cstr = argv[1];
    } else {
        DWORD n = GetModuleFileNameA(nullptr, default_path, MAX_PATH);
        if (n > 0) {
            // Truncate at the last directory separator.
            char* sep1 = std::strrchr(default_path, '\\');
            char* sep2 = std::strrchr(default_path, '/');
            char* last_sep = (sep1 > sep2) ? sep1 : sep2;
            if (last_sep) {
                *(last_sep + 1) = '\0';  // keep the separator, clear after it
            } else {
                default_path[0] = '\0';  // no separator – use cwd
            }
        } else {
            default_path[0] = '\0';
        }
        std::strncat(default_path, "test_driver.sys",
                     sizeof(default_path) - std::strlen(default_path) - 1);
        path_cstr = default_path;
    }

    std::fprintf(stderr, "[test_host] Loading driver: %s\n", path_cstr);

    try {
        // DriverLoader constructor accepts std::string; construct it here
        // inside the try block so any allocation failure is caught.
        DriverLoader loader(path_cstr);

        // Supply the LxInitialize symbol so the driver's import from lxcore.sys
        // resolves to our stub above.
        loader.add_symbol("LxInitialize",
                          reinterpret_cast<void*>(&LxInitialize));

        loader.load();
        std::fprintf(stderr, "[test_host] Driver mapped successfully.\n");

        const NTSTATUS status = loader.call_driver_entry();

        if (!NT_SUCCESS(status)) {
            std::fprintf(stderr,
                "[test_host] FAIL: DriverEntry returned 0x%08lX\n",
                static_cast<unsigned long>(status));
            return EXIT_FAILURE;
        }

        std::fprintf(stderr,
            "[test_host] DriverEntry returned STATUS_SUCCESS (0x%08lX).\n",
            static_cast<unsigned long>(status));

        // --- Driver property queries ------------------------------------

        const DRIVER_OBJECT& drv = loader.driver_object();
        std::fprintf(stderr,
            "[test_host] DriverObject.DriverName = %.*ls\n",
            static_cast<int>(drv.DriverName.Length / sizeof(wchar_t)),
            drv.DriverName.Buffer);

        if (drv.DeviceObject) {
            std::fprintf(stderr, "[test_host] DeviceObject registered at %p\n",
                static_cast<void*>(drv.DeviceObject));
        } else {
            std::fprintf(stderr, "[test_host] No device objects registered.\n");
        }

        if (drv.DriverUnload) {
            std::fprintf(stderr, "[test_host] DriverUnload registered at %p\n",
                reinterpret_cast<void*>(drv.DriverUnload));
        } else {
            std::fprintf(stderr, "[test_host] No DriverUnload callback.\n");
        }

        std::fprintf(stdout, "[test_host] PASS\n");
        return EXIT_SUCCESS;

    } catch (const std::exception& ex) {
        std::fprintf(stderr, "[test_host] Exception: %s\n", ex.what());
        return EXIT_FAILURE;
    }
}

