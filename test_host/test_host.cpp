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
//
// lxmonika and similar drivers call LxInitialize to register themselves with
// the Pico subsystem.  In a usermode test environment we simply return
// STATUS_SUCCESS so that DriverEntry can proceed.
// ---------------------------------------------------------------------------

extern "C" NTSTATUS NTAPI LxInitialize(PDRIVER_OBJECT /*driverObject*/,
                                        PVOID          /*subsystem*/) {
    std::fprintf(stderr, "[test_host] LxInitialize stub called – returning STATUS_SUCCESS.\n");
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    // Resolve the driver path without returning std::string from a helper.
    // Returning a non-trivially-copyable type like std::string by value from
    // a separate function involves a hidden-pointer ABI that can be
    // unreliable under Wine/QEMU on some architectures.  Building the path
    // directly inside main avoids the issue entirely.
    char default_exe_path[MAX_PATH] = {};
    std::string driver_path;
    if (argc >= 2) {
        driver_path = argv[1];
    } else {
        GetModuleFileNameA(nullptr, default_exe_path, MAX_PATH);
        driver_path = default_exe_path;
        const auto slash = driver_path.find_last_of("/\\");
        if (slash != std::string::npos)
            driver_path.resize(slash + 1);
        else
            driver_path.clear();
        driver_path += "test_driver.sys";
    }

    std::fprintf(stderr, "[test_host] Loading driver: %s\n", driver_path.c_str());

    try {
        DriverLoader loader(driver_path);

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
