#pragma once
// nt_stubs_internal.hpp – Internal interface between the generated stub file
// and the stub-management code in nt_stubs.cpp.
//
// NOT part of the public API.

#include <array>
#include <cstddef>

namespace nt_stubs_internal {

// Function pointer type for the generated stubs.
using stub_fn_t = void* (*)() noexcept;

// Per-stub name storage (populated at load time by DriverLoader).
extern std::array<const char*, 256> name_table;

// Next available stub index.
extern int next_index;

// Called by every generated stub.  Prints an error and aborts.
// Marked [[noreturn]] so callers do not need a return statement.
[[noreturn]] void handle_call(int idx) noexcept;

// Returns a pointer to the table of 256 stub function pointers.
// The table is defined in the generated source file.
const stub_fn_t* get_stub_table() noexcept;

} // namespace nt_stubs_internal
