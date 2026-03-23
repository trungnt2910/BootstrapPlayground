#pragma once
// nt_stubs_internal.hpp – Internal interface between the generated stub file
// and the stub-management code in nt_stubs.cpp.
//
// NOT part of the public API.

#include <array>
#include <cstddef>
#include <string>

#include <Windows.h>

#include "logger.hpp"
#include "wdm.hpp"

// Function pointer type for the generated stubs.
using STUB_FUNCTION = void *(*)() noexcept;

// Per-stub name storage (populated at load time by DriverLoader).
extern std::array<std::string, 256> NtStubNameTable;

// Next available stub index.
extern int NtStubNextIndex;

// Called by every generated stub.  Prints an error and aborts.
// Marked [[noreturn]] so callers do not need a return statement.
[[noreturn]] void NtStubCall(int idx) noexcept;

// Returns a pointer to the table of generated stub function pointers.
// The table is defined in the generated source file.
const STUB_FUNCTION *NtStubGetTable() noexcept;

#define NT_STUB_REPORT() DL_LOG_TRACE("[nt_stubs] call {}", __func__)

// ---------------------------------------------------------------------------
// Global variable stubs
//
// For kernel data exports (PsProcessType, SeExports, etc.) the IAT entry
// must hold the ADDRESS of the variable, not its value.  We return &var from
// the symbol table so the driver's *__imp_Var dereference gives our value.
// ---------------------------------------------------------------------------
extern PEPROCESS impl_PsInitialSystemProcess;

extern PVOID impl_PsProcessType;
extern PVOID impl_PsThreadType;
extern PVOID impl_IoDeviceObjectType;

extern PSE_EXPORTS impl_SeExports;
