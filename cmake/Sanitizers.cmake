# cmake/Sanitizers.cmake
# Opt-in sanitizer support.
#
# Variables consumed:
#   ENABLE_ASAN  (ON/OFF)  – AddressSanitizer.  Not supported on ARM / ARM64.
#   ENABLE_UBSAN (ON/OFF)  – UndefinedBehaviorSanitizer.

option(ENABLE_ASAN  "Enable AddressSanitizer"            OFF)
option(ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer"  OFF)

if(ENABLE_ASAN)
    # ASAN is only available for x86 and x86_64 with llvm-mingw.
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(i686|x86_64)$")
        add_compile_options(-fsanitize=address)
        add_link_options(-fsanitize=address)
    else()
        message(WARNING
            "ENABLE_ASAN=ON ignored: AddressSanitizer is not supported "
            "on ${CMAKE_SYSTEM_PROCESSOR} with llvm-mingw.")
    endif()
endif()

if(ENABLE_UBSAN)
    add_compile_options(-fsanitize=undefined)
    add_link_options(-fsanitize=undefined)
endif()
