cmake_minimum_required(VERSION 3.24)

add_executable(test_host test_host.cpp)

target_include_directories(test_host PRIVATE
    ${CMAKE_SOURCE_DIR}/driver_loader/include
)

target_link_libraries(test_host PRIVATE driver_loader)

# Static link against the C++ standard library and runtime so the
# executable is self-contained (runs without a separate libc++.dll).
target_link_options(test_host PRIVATE -static)
