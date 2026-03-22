#pragma once

#include "wdm.hpp"

#include <cstddef>

// Minimal KMDF-compatible declarations used by wdfldr stubs.
// These are replicated because WDF headers are not available in usermode MinGW.

using WDFDRIVER = PVOID;

constexpr std::size_t WDF_DRIVER_GLOBALS_NAME_LEN = 32;

typedef struct _WDF_DRIVER_GLOBALS {
    WDFDRIVER Driver;
    ULONG DriverFlags;
    ULONG DriverTag;
    CHAR DriverName[WDF_DRIVER_GLOBALS_NAME_LEN];
    BOOLEAN DisplaceDriverUnload;
} WDF_DRIVER_GLOBALS, *PWDF_DRIVER_GLOBALS;

typedef struct _WDF_COMPONENT_GLOBALS {
    ULONG Size;
    PWDF_DRIVER_GLOBALS DriverGlobals;
    PVOID FuncTable;
    ULONG FuncCount;
} WDF_COMPONENT_GLOBALS, *PWDF_COMPONENT_GLOBALS;

typedef struct _WDF_BIND_INFO {
    ULONG Size;
    PVOID Component;
    ULONG VersionMajor;
    ULONG VersionMinor;
    ULONG FuncCount;
    PVOID FuncTable;
    PVOID Module;
} WDF_BIND_INFO, *PWDF_BIND_INFO;
