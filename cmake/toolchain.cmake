# cmake/toolchain.cmake
# Cross-compilation toolchain for llvm-mingw targeting Windows.
#
# MINGW_ARCH must be set before including this file.  It can be passed
# either as a CMake cache variable (-DMINGW_ARCH=…) or as the
# environment variable MINGW_ARCH.  The environment variable is consulted
# first so that it works during the toolchain-bootstrap phase, when CMake
# cache variables set via -D may not yet be available.
#
# Supported values: x86_64, i686, armv7, aarch64

# NOTE: cmake_minimum_required() must NOT be called from a toolchain file.

# Resolve MINGW_ARCH: prefer the env-var because it is visible during the
# early toolchain-bootstrap pass that runs before -D values are cached.
if(NOT DEFINED MINGW_ARCH OR MINGW_ARCH STREQUAL "")
    set(MINGW_ARCH "$ENV{MINGW_ARCH}")
endif()

if(NOT MINGW_ARCH)
    message(FATAL_ERROR
        "MINGW_ARCH must be set to one of: x86_64, i686, armv7, aarch64.  "
        "Pass it as -DMINGW_ARCH=… on the cmake command line, or set the "
        "MINGW_ARCH environment variable before running cmake.")
endif()

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR "${MINGW_ARCH}")

set(_TRIPLE "${MINGW_ARCH}-w64-mingw32")

set(CMAKE_C_COMPILER   "${_TRIPLE}-clang")
set(CMAKE_CXX_COMPILER "${_TRIPLE}-clang++")
set(CMAKE_RC_COMPILER  "${_TRIPLE}-windres")

# llvm-mingw bundles llvm-ar / llvm-ranlib under the arch-prefixed names.
set(CMAKE_AR     "${_TRIPLE}-ar")
set(CMAKE_RANLIB "${_TRIPLE}-ranlib")
set(CMAKE_DLLTOOL "${_TRIPLE}-dlltool")

# Static linking is required by the spec.  Applied globally; the flag is
# silently ignored by the linker for static library (.a) targets.
add_link_options(-static)

# Don't try to run test executables on the build host (cross-build).
set(CMAKE_CROSSCOMPILING_EMULATOR "")
