cmake_minimum_required(VERSION 3.24)
project(DriverTestFramework CXX)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Required warning flags.
add_compile_options(-Wall -Wextra -Wpedantic -Werror)

# Sanitizer support (optional, controlled by -DENABLE_ASAN=ON / -DENABLE_UBSAN=ON).
include(${CMAKE_SOURCE_DIR}/cmake/Sanitizers.cmake)

# Keep the original hello world binary for backward compatibility.
add_executable(hello hello.cpp)
target_link_options(hello PRIVATE -static)

add_subdirectory(driver_loader)
add_subdirectory(test_driver)
add_subdirectory(test_host)

# Copy lxmonika driver binaries into the build directory so that test_host
# and the CI workflow can find them at runtime.
if(EXISTS "${CMAKE_SOURCE_DIR}/drivers")
    file(GLOB _lxmonika_drivers "${CMAKE_SOURCE_DIR}/drivers/lxmonika_*.sys")
    foreach(_drv IN LISTS _lxmonika_drivers)
        get_filename_component(_drv_name "${_drv}" NAME)
        configure_file("${_drv}" "${CMAKE_BINARY_DIR}/${_drv_name}" COPYONLY)
    endforeach()
endif()
