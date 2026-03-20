# cmake/toolchain.cmake
# Cross-compilation toolchain for llvm-mingw targeting Windows.
#
# Usage (from the build root):
#   cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain.cmake \
#         -DMINGW_ARCH=x86_64   # or i686 / armv7 / aarch64

cmake_minimum_required(VERSION 3.24)

if(NOT DEFINED MINGW_ARCH)
    message(FATAL_ERROR
        "MINGW_ARCH must be set to one of: x86_64, i686, armv7, aarch64")
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

# Static linking is required by the spec – applied to executables only.
# (We use add_link_options here; individual library targets should not
# be affected since this flag is ignored for static libraries by the linker.)
add_link_options(-static)

# Don't try to run test executables on the build host (cross-build).
set(CMAKE_CROSSCOMPILING_EMULATOR "")
