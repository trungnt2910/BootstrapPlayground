// test_host.cpp – Test host for the Windows driver testing framework.
//
// Usage:  test_host.exe  [path/to/driver.sys]
//
// Default driver path: the architecture-appropriate lxmonika_*.sys located
// in the same directory as the executable.
//
// The host:
//   1. Registers a LxInitialize consumer symbol (stub returning STATUS_SUCCESS).
//   2. Loads the driver through DriverLoader.
//   3. Calls the driver's DllInitialize export.
//   4. Asserts that DllInitialize returned STATUS_SUCCESS.
//   5. Prints a success message and exits with code 0.

#include "driver_loader.hpp"
#include "wdm.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>

#include <windows.h>

// Select the architecture-appropriate lxmonika driver filename.
#if defined(__x86_64__) || defined(_M_AMD64)
#  define LXMONIKA_SYS "lxmonika_x64.sys"
#elif defined(__i386__) || defined(_M_IX86)
#  define LXMONIKA_SYS "lxmonika_x86.sys"
#elif defined(__aarch64__) || defined(_M_ARM64)
#  define LXMONIKA_SYS "lxmonika_arm64.sys"
#elif defined(__arm__) || defined(_M_ARM)
#  define LXMONIKA_SYS "lxmonika_arm.sys"
#else
#  error "Unknown target architecture – cannot select lxmonika driver"
#endif

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
        std::strncat(default_path, LXMONIKA_SYS,
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

        const NTSTATUS status = loader.call_dll_initialize();

        if (!NT_SUCCESS(status)) {
            std::fprintf(stderr,
                "[test_host] FAIL: DllInitialize returned 0x%08lX\n",
                static_cast<unsigned long>(status));
            return EXIT_FAILURE;
        }

        std::fprintf(stderr,
            "[test_host] DllInitialize returned STATUS_SUCCESS (0x%08lX).\n",
            static_cast<unsigned long>(status));

        std::fprintf(stdout, "[test_host] PASS\n");
        return EXIT_SUCCESS;

    } catch (const std::exception& ex) {
        std::fprintf(stderr, "[test_host] Exception: %s\n", ex.what());
        return EXIT_FAILURE;
    }
}

