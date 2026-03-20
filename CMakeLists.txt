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
