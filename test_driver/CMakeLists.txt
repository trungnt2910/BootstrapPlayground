cmake_minimum_required(VERSION 3.24)

# ---------------------------------------------------------------------------
# Build the test driver (.sys) using explicit compiler/linker invocations.
#
# We cannot use add_executable/add_library here because:
#   • The driver must be built with -nostdlib / -nostdinc++ (no C++ runtime).
#   • The driver must have /subsystem:native and a custom entry point.
#   • The driver requires synthetic import libraries for ntoskrnl.exe and
#     lxcore.sys, which are created from hand-written DEF files.
# ---------------------------------------------------------------------------

# Locate the compiler and dlltool from the toolchain.
if(NOT CMAKE_CXX_COMPILER)
    message(FATAL_ERROR "CMAKE_CXX_COMPILER is not set – run CMake with the toolchain file.")
endif()

if(NOT CMAKE_DLLTOOL)
    set(CMAKE_DLLTOOL "${CMAKE_SYSTEM_PROCESSOR}-w64-mingw32-dlltool")
endif()

# ---------------------------------------------------------------------------
# Map CMAKE_SYSTEM_PROCESSOR → dlltool machine name
# ---------------------------------------------------------------------------
if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    set(_DLL_MACHINE "i386:x86-64")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "i686")
    set(_DLL_MACHINE "i386")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
    set(_DLL_MACHINE "arm64")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "armv7")
    set(_DLL_MACHINE "arm")
else()
    message(FATAL_ERROR "Unsupported CMAKE_SYSTEM_PROCESSOR: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

# ---------------------------------------------------------------------------
# Generate DEF files and import libraries
# ---------------------------------------------------------------------------

set(_OUTDIR "${CMAKE_CURRENT_BINARY_DIR}")

# ntoskrnl.exe import library
set(_NTOSKRNL_DEF "${_OUTDIR}/ntoskrnl.def")
set(_NTOSKRNL_LIB "${_OUTDIR}/ntoskrnl.lib")
file(WRITE "${_NTOSKRNL_DEF}"
"LIBRARY ntoskrnl.exe\n"
"EXPORTS\n"
"\tDbgPrintEx\n"
)

add_custom_command(
    OUTPUT  "${_NTOSKRNL_LIB}"
    COMMAND "${CMAKE_DLLTOOL}"
            -m "${_DLL_MACHINE}"
            -D "ntoskrnl.exe"
            -d "${_NTOSKRNL_DEF}"
            -l "${_NTOSKRNL_LIB}"
    DEPENDS "${_NTOSKRNL_DEF}"
    COMMENT "Creating ntoskrnl.lib import library"
    VERBATIM
)

# lxcore.sys import library
set(_LXCORE_DEF "${_OUTDIR}/lxcore.def")
set(_LXCORE_LIB "${_OUTDIR}/lxcore.lib")
file(WRITE "${_LXCORE_DEF}"
"LIBRARY lxcore.sys\n"
"EXPORTS\n"
"\tLxInitialize\n"
)

add_custom_command(
    OUTPUT  "${_LXCORE_LIB}"
    COMMAND "${CMAKE_DLLTOOL}"
            -m "${_DLL_MACHINE}"
            -D "lxcore.sys"
            -d "${_LXCORE_DEF}"
            -l "${_LXCORE_LIB}"
    DEPENDS "${_LXCORE_DEF}"
    COMMENT "Creating lxcore.lib import library"
    VERBATIM
)

# ---------------------------------------------------------------------------
# Compiler/linker flags for the kernel driver
# ---------------------------------------------------------------------------

# Extra flags for x86: use __cdecl to be consistent across all functions in
# this minimal driver (no stdcall/fastcall confusion without the CRT).
if(CMAKE_SYSTEM_PROCESSOR STREQUAL "i686")
    set(_ARCH_FLAGS "-m32")
else()
    set(_ARCH_FLAGS "")
endif()

# Sanitizer flags should NOT propagate to the driver – it is a standalone
# kernel-format binary built with -nostdlib.
# We intentionally omit ENABLE_ASAN / ENABLE_UBSAN here.

set(_DRIVER_SRC "${CMAKE_CURRENT_SOURCE_DIR}/test_driver.cpp")
set(_DRIVER_SYS "${_OUTDIR}/test_driver.sys")

add_custom_command(
    OUTPUT "${_DRIVER_SYS}"
    COMMAND "${CMAKE_CXX_COMPILER}"
            ${_ARCH_FLAGS}
            -std=c++26
            -nostdlib
            -nostdinc++
            -fms-extensions
            # Override the PE entry point to DriverEntry (no CRT startup).
            -Wl,-e,DriverEntry
            # Suppress warnings that arise from the kernel-mode -nostdlib build.
            -Wno-unused-command-line-argument
            -o "${_DRIVER_SYS}"
            "${_DRIVER_SRC}"
            "${_NTOSKRNL_LIB}"
            "${_LXCORE_LIB}"
    DEPENDS "${_DRIVER_SRC}" "${_NTOSKRNL_LIB}" "${_LXCORE_LIB}"
    COMMENT "Building test_driver.sys"
    VERBATIM
)

add_custom_target(test_driver ALL
    DEPENDS "${_DRIVER_SYS}"
)

# Export the path to the .sys file so test_host can reference it.
set(TEST_DRIVER_SYS_PATH "${_DRIVER_SYS}" CACHE INTERNAL
    "Absolute path to the compiled test_driver.sys")
