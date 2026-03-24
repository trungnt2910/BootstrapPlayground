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
//   3. Calls the driver's DriverEntry (via the PE entry point).
//   4. Asserts that DriverEntry returned STATUS_SUCCESS.
//   5. Prints a success message and exits with code 0.

#include "driver_loader.hpp"
#include "wdm.hpp"

#include <cstdlib>
#include <cstring>
#include <optional>
#include <print>
#include <stdexcept>
#include <string>

#include <windows.h>

static std::optional<driver_loader::logging::LogLevel> ParseLogLevelArg(const char *arg)
{
    if (arg == nullptr)
    {
        return std::nullopt;
    }

    constexpr const char *kPrefix = "--log-level=";
    if (std::strncmp(arg, kPrefix, std::strlen(kPrefix)) != 0)
    {
        return std::nullopt;
    }

    const char *value = arg + std::strlen(kPrefix);
    if (value[0] == '\0')
    {
        return std::nullopt;
    }

    return driver_loader::logging::ParseLogLevel(value, driver_loader::logging::LogLevel::Error);
}

static LONG WINAPI TopLevelExceptionFilter(EXCEPTION_POINTERS *ep)
{
    if (!ep || !ep->ExceptionRecord)
        return EXCEPTION_CONTINUE_SEARCH;

    const EXCEPTION_RECORD *er = ep->ExceptionRecord;
    ULONG_PTR access_type = 0;
    ULONG_PTR access_addr = 0;
    if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er->NumberParameters >= 2)
    {
        access_type = er->ExceptionInformation[0];
        access_addr = er->ExceptionInformation[1];
    }

    std::println(
        stderr,
        "[test_host] SEH: code=0x{:08X} address={:p} flags=0x{:08X} "
        "access_type={} access_addr={:p}",
        static_cast<unsigned long>(er->ExceptionCode),
        er->ExceptionAddress,
        static_cast<unsigned long>(er->ExceptionFlags),
        static_cast<unsigned long long>(access_type),
        reinterpret_cast<void *>(access_addr));
    return EXCEPTION_CONTINUE_SEARCH;
}

#define LXMONIKA_SYS "lxmonika.sys"

// ---------------------------------------------------------------------------
// Consumer-supplied stub: LxInitialize (normally exported by lxcore.sys).
// ---------------------------------------------------------------------------

extern "C" NTSTATUS NTAPI LxInitialize(PDRIVER_OBJECT /*driverObject*/, PVOID /*subsystem*/)
{
    std::println(stderr, "[test_host] LxInitialize stub called.");
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char *argv[])
{
    SetUnhandledExceptionFilter(&TopLevelExceptionFilter);
    constexpr std::size_t kDriverPathExtraCapacity = 32;

    DriverLoader::InitLogLevelFromEnv();
    for (int i = 1; i < argc; ++i)
    {
        const auto level = ParseLogLevelArg(argv[i]);
        if (level.has_value())
        {
            DriverLoader::SetLogLevel(*level);
        }
    }

    // Build the driver path using only C-style string operations so that
    // no heap allocation (std::string) is needed before the try block.
    // On some Wine+QEMU configurations (e.g. ARM64 under Debian bookworm),
    // heap allocation can silently fail before the runtime is fully set up.
    static char default_path[MAX_PATH + 32];
    const char *pathCStr = nullptr;

    for (int i = 1; i < argc; ++i)
    {
        if (argv[i] == nullptr || argv[i][0] == '\0')
        {
            continue;
        }
        if (std::strncmp(argv[i], "--log-level=", std::strlen("--log-level=")) == 0)
        {
            continue;
        }
        pathCStr = argv[i];
        break;
    }

    if (pathCStr == nullptr)
    {
        DWORD n = GetModuleFileNameA(nullptr, default_path, MAX_PATH);
        if (n > 0)
        {
            // Truncate at the last directory separator.
            char *sep1 = std::strrchr(default_path, '\\');
            char *sep2 = std::strrchr(default_path, '/');
            char *last_sep = (sep1 > sep2) ? sep1 : sep2;
            if (last_sep)
            {
                *(last_sep + 1) = '\0'; // keep the separator, clear after it
            }
            else
            {
                default_path[0] = '\0'; // no separator – use cwd
            }
        }
        else
        {
            default_path[0] = '\0';
        }
        std::strncat(
            default_path, LXMONIKA_SYS, sizeof(default_path) - std::strlen(default_path) - 1);
        pathCStr = default_path;
    }

    std::println(stderr, "[test_host] Loading driver: {}", pathCStr);

    static char pdbPath[MAX_PATH + kDriverPathExtraCapacity];
    std::strncpy(pdbPath, pathCStr, sizeof(pdbPath) - 1);
    pdbPath[sizeof(pdbPath) - 1] = '\0';
    char *pdb_ext = std::strrchr(pdbPath, '.');
    if (pdb_ext != nullptr)
    {
        if (static_cast<std::size_t>(&pdbPath[sizeof(pdbPath)] - pdb_ext) >= 5)
        {
            std::memcpy(pdb_ext, ".pdb", 5);
        }
    }

    try
    {
        // DriverLoader constructor accepts std::string; construct it here
        // inside the try block so any allocation failure is caught.
        DriverLoader loader(pathCStr);

        // Supply the LxInitialize symbol so the driver's import from lxcore.sys
        // resolves to our stub above.
        loader.SetDriverName(L"lxmonika");
        loader.AddSymbol("LxInitialize", reinterpret_cast<void *>(&LxInitialize));

        loader.Load();
        std::println(stderr, "[test_host] Driver loaded at {}.", loader.GetBase());
        if (GetFileAttributesA(pdbPath) == INVALID_FILE_ATTRIBUTES)
        {
            std::println(stderr, "[test_host] FAIL: Required PDB not found: {}", pdbPath);
            return EXIT_FAILURE;
        }
        loader.LoadPdb(pdbPath);
        std::println(stderr, "[test_host] Loaded PDB: {}", pdbPath);

        const NTSTATUS status = loader.CallDriverEntry(std::nullopt);

        if (status != STATUS_NOT_SUPPORTED)
        {
            std::println(
                stderr,
                "[test_host] FAIL: DriverEntry returned 0x{:08X}, expected "
                "STATUS_NOT_SUPPORTED (0x{:08X})",
                static_cast<unsigned long>(status),
                static_cast<unsigned long>(STATUS_NOT_SUPPORTED));
            return EXIT_FAILURE;
        }

        std::println(
            stderr,
            "[test_host] DriverEntry returned STATUS_NOT_SUPPORTED (0x{:08X}) as expected.",
            static_cast<unsigned long>(status));

        std::println("[test_host] PASS");
        return EXIT_SUCCESS;
    }
    catch (const std::exception &ex)
    {
        std::println(stderr, "[test_host] Exception: {}", ex.what());
        return EXIT_FAILURE;
    }
}
