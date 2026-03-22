#pragma once

#include "wdm.hpp"

// Minimal WDF declarations used by wdfldr-related stubs.
// These are replicated because WDF headers are not available in usermode MinGW.

using WDFDRIVER = PVOID;
constexpr ULONG WDF_DRIVER_GLOBALS_NAME_LEN = 32;

typedef ULONG WDF_MAJOR_VERSION;
typedef ULONG WDF_MINOR_VERSION;
typedef ULONG WDF_BUILD_NUMBER;

typedef
VOID
(*WDFFUNC)(
    VOID
    );

typedef struct _WDF_VERSION {
    WDF_MAJOR_VERSION  Major;
    WDF_MINOR_VERSION  Minor;
    WDF_BUILD_NUMBER   Build;
} WDF_VERSION;

typedef struct _WDF_BIND_INFO {
    ULONG              Size;
    PWCHAR             Component;
    WDF_VERSION        Version;
    ULONG              FuncCount;
    WDFFUNC*           FuncTable;
    PVOID              Module;
} WDF_BIND_INFO, *PWDF_BIND_INFO;

typedef struct _WDF_COMPONENT_GLOBALS WDF_COMPONENT_GLOBALS, *PWDF_COMPONENT_GLOBALS;

typedef struct _WDF_DRIVER_GLOBALS {
    WDFDRIVER Driver;
    ULONG DriverFlags;
    ULONG DriverTag;
    CHAR DriverName[WDF_DRIVER_GLOBALS_NAME_LEN];
    BOOLEAN DisplaceDriverUnload;
} WDF_DRIVER_GLOBALS, *PWDF_DRIVER_GLOBALS;
