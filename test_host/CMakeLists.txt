cmake_minimum_required(VERSION 3.24)

add_executable(test_host test_host.cpp)

target_include_directories(test_host PRIVATE
    ${CMAKE_SOURCE_DIR}/driver_loader/include
)

target_link_libraries(test_host PRIVATE driver_loader)

# Static link against the C++ standard library and runtime so the
# executable is self-contained (runs without a separate libc++.dll).
target_link_options(test_host PRIVATE -static)

if(${MINGW_ARCH} STREQUAL "x86_64")
    set(DRIVER_ARCH "x64")
elseif(${MINGW_ARCH} STREQUAL "i686")
    set(DRIVER_ARCH "x86")
elseif(${MINGW_ARCH} STREQUAL "armv7")
    set(DRIVER_ARCH "arm")
elseif(${MINGW_ARCH} STREQUAL "aarch64")
    set(DRIVER_ARCH "arm64")
endif()

add_custom_command(TARGET test_host POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/drivers/lxmonika_${DRIVER_ARCH}.sys"
        "$<TARGET_FILE_DIR:test_host>/lxmonika.sys"
)

add_custom_command(TARGET test_host POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/drivers/lxmonika_${DRIVER_ARCH}.pdb"
        "$<TARGET_FILE_DIR:test_host>/lxmonika.pdb"
)

target_compile_options(test_host PRIVATE -gcodeview -O0)
target_link_options(test_host PRIVATE -Wl,--pdb=)
