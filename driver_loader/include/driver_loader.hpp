#pragma once
// driver_loader.hpp – Public API of the Windows kernel-driver PE loader.
//
// <windows.h> must be included BEFORE this header so that Windows scalar types
// are established before wdm.hpp's type guards kick in.
#include <windows.h>

#include "wdm.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>

// ---------------------------------------------------------------------------
// DriverLoader
// ---------------------------------------------------------------------------

class DriverLoader {
public:
    // Construct a loader for the given .sys file path.
    // The file is not read until load() is called.
    explicit DriverLoader(std::string path);

    ~DriverLoader();

    // Non-copyable, movable.
    DriverLoader(const DriverLoader&)            = delete;
    DriverLoader& operator=(const DriverLoader&) = delete;
    DriverLoader(DriverLoader&&)                 = default;
    DriverLoader& operator=(DriverLoader&&)      = default;

    // -----------------------------------------------------------------------
    // Symbol overrides
    // -----------------------------------------------------------------------

    // Register a symbol that will be used when the driver imports a function by
    // that name from ANY DLL.  Consumer-supplied symbols take precedence over
    // the default ntoskrnl stubs.
    //
    // Call before load().
    void add_symbol(std::string name, void* address);

    // -----------------------------------------------------------------------
    // Loading
    // -----------------------------------------------------------------------

    // Parse the PE file, map sections into virtual memory with the correct
    // alignment and protections, apply base relocations, and resolve all
    // imports.
    //
    // Throws std::runtime_error on any failure.
    void load();

    // Returns true if load() has been called successfully.
    [[nodiscard]] bool is_loaded() const noexcept { return m_base != nullptr; }

    // Load debug symbols for the currently loaded driver image using DbgHelp.
    // If pdb_path is non-empty, its directory is added to the symbol search
    // path before loading symbols for this module.
    //
    // Requires: is_loaded() == true.
    // Throws std::runtime_error on failure.
    void load_pdb(std::string pdb_path);

    // -----------------------------------------------------------------------
    // Execution
    // -----------------------------------------------------------------------

    // Invoke the driver's DriverEntry entry point with a synthetic DRIVER_OBJECT
    // and the provided registry path.
    //
    // Requires: is_loaded() == true.
    NTSTATUS call_driver_entry(
        std::wstring_view registry_path =
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\TestDriver");

    // -----------------------------------------------------------------------
    // Driver-object accessors (valid after a successful call_driver_entry)
    // -----------------------------------------------------------------------

    // Returns a reference to the synthetic DRIVER_OBJECT passed to DriverEntry.
    [[nodiscard]] DRIVER_OBJECT&       driver_object()       noexcept { return m_driver_object; }
    [[nodiscard]] const DRIVER_OBJECT& driver_object() const noexcept { return m_driver_object; }

    // Convenience: first registered device object (may be null).
    [[nodiscard]] PDEVICE_OBJECT device_object() const noexcept {
        return m_driver_object.DeviceObject;
    }

    // Convenience: the driver's unload callback (may be null).
    [[nodiscard]] PDRIVER_UNLOAD driver_unload() const noexcept {
        return m_driver_object.DriverUnload;
    }

    // Convenience: one of the driver's IRP dispatch routines.
    // index must be in [0, IRP_MJ_MAXIMUM_FUNCTION].
    [[nodiscard]] PDRIVER_DISPATCH major_function(int index) const noexcept {
        if (index < 0 || index > IRP_MJ_MAXIMUM_FUNCTION) return nullptr;
        return m_driver_object.MajorFunction[index];
    }

    // -----------------------------------------------------------------------
    // Export lookup
    // -----------------------------------------------------------------------

    // Find an exported symbol by name.  Returns nullptr if not found.
    // Requires: is_loaded() == true.
    [[nodiscard]] void* get_export(std::string_view name)  const;

    // Find an exported symbol by ordinal.  Returns nullptr if not found.
    [[nodiscard]] void* get_export(std::uint16_t ordinal)  const;

private:
    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    // Resolve a single import.  Checks (in order):
    //   1. Consumer-supplied overrides (m_extra_symbols).
    //   2. Built-in ntoskrnl implementations.
    //   3. Next available numbered stub (recorded in the stub table).
    // For non-ntoskrnl DLLs the built-in table is not consulted, so the
    // result will be a stub unless the consumer supplied the symbol.
    [[nodiscard]] void* resolve_import(std::string_view dll_name,
                                       std::string_view func_name);

    void map_sections  (const std::byte* file_data, std::size_t file_size);
    void apply_relocations();
    void resolve_imports(const std::byte* file_data);

    // ------------------------------------------------------------------
    // State
    // ------------------------------------------------------------------

    std::string m_path;

    // Consumer-supplied symbol overrides.
    std::unordered_map<std::string, void*> m_extra_symbols;

    // Mapped image.
    void*       m_base = nullptr;
    std::size_t m_image_size = 0;

    // Synthetic driver state.
    DRIVER_OBJECT   m_driver_object     = {};
    DRIVER_EXTENSION m_driver_extension = {};
    UNICODE_STRING  m_driver_name_str   = {};
    UNICODE_STRING  m_registry_path_str = {};

    // Storage for the driver-name wide string.
    std::wstring m_driver_name_buf;
    // Storage for the registry-path wide string (set at call_driver_entry time).
    std::wstring m_registry_path_buf;

    // Per-instance DbgHelp symbol state (managed by load_pdb/destructor).
    bool         m_dbghelp_attached   = false;
    std::uint64_t m_dbghelp_module_base = 0;
};
