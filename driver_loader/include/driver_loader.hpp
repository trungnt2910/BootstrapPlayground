#pragma once
// driver_loader.hpp – Public API of the Windows kernel-driver PE loader.
//
// <windows.h> must be included BEFORE this header so that Windows scalar types
// are established before wdm.hpp's type guards kick in.
#include <windows.h>

#include "logger.hpp"
#include "wdf.hpp"
#include "wdm.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <type_traits>
#include <unordered_map>

// ---------------------------------------------------------------------------
// DriverLoader
// ---------------------------------------------------------------------------

class DriverLoader
{
  public:
    // Configure framework logging.
    static void SetLogLevel(driver_loader::logging::LogLevel level) noexcept
    {
        driver_loader::logging::SetLogLevel(level);
    }
    static void SetLogLevelFromString(std::string_view level) noexcept
    {
        driver_loader::logging::SetLogLevel(
            driver_loader::logging::ParseLogLevel(level, driver_loader::logging::GetLogLevel()));
    }
    static void
    InitLogLevelFromEnv(const char *envVarName = "BOOTSTRAP_PLAYGROUND_LOG_LEVEL") noexcept
    {
        driver_loader::logging::InitLogLevelFromEnv(envVarName);
    }
    [[nodiscard]] static driver_loader::logging::LogLevel GetLogLevel() noexcept
    {
        return driver_loader::logging::GetLogLevel();
    }

    // Construct a loader for the given .sys file path.
    // The file is not read until Load() is called.
    explicit DriverLoader(std::string path);

    ~DriverLoader();

    // Non-copyable, movable.
    DriverLoader(const DriverLoader &) = delete;
    DriverLoader &operator=(const DriverLoader &) = delete;
    DriverLoader(DriverLoader &&) = default;
    DriverLoader &operator=(DriverLoader &&) = default;

    // -----------------------------------------------------------------------
    // Symbol overrides
    // -----------------------------------------------------------------------

    // Register a symbol that will be used when the driver imports a function by
    // that name from ANY DLL.  Consumer-supplied symbols take precedence over
    // the default ntoskrnl stubs.
    //
    // Call before Load().
    void AddSymbol(std::string name, void *address);

    // -----------------------------------------------------------------------
    // Loading
    // -----------------------------------------------------------------------

    // Parse the PE file, map sections into virtual memory with the correct
    // alignment and protections, apply base relocations, and resolve all
    // imports.
    //
    // Throws std::runtime_error on any failure.
    void Load();

    // Returns true if Load() has been called successfully.
    [[nodiscard]] bool IsLoaded() const noexcept
    {
        return m_base != nullptr;
    }

    // Load debug symbols for the currently loaded driver image using DbgHelp.
    // If pdb_path is non-empty, its directory is added to the symbol search
    // path before loading symbols for this module.
    //
    // Requires: IsLoaded() == true.
    // Throws std::runtime_error on failure.
    void LoadPdb(const std::string &pdbPath);

    // -----------------------------------------------------------------------
    // Execution
    // -----------------------------------------------------------------------

    // Invoke the driver's DriverEntry entry point with a synthetic DRIVER_OBJECT
    // and the provided registry path.
    //
    // Requires: IsLoaded() == true.
    NTSTATUS CallDriverEntry(const std::optional<std::wstring> &registry_path = std::nullopt);

    // Driver service name. Used for DRIVER_OBJECT.DriverName and for deriving
    // the default registry path when CallDriverEntry is invoked with std::nullopt.
    // Default: derived from the loaded .sys file stem (without extension).
    [[nodiscard]] const std::wstring &GetDriverName() const noexcept
    {
        return m_driver_name;
    }
    void SetDriverName(std::wstring name);

    // -----------------------------------------------------------------------
    // Driver-object accessors (valid after a successful CallDriverEntry)
    // -----------------------------------------------------------------------

    // Returns a reference to the synthetic DRIVER_OBJECT passed to DriverEntry.
    [[nodiscard]] DRIVER_OBJECT &DriverObject() noexcept
    {
        return m_driver_object;
    }
    [[nodiscard]] const DRIVER_OBJECT &DriverObject() const noexcept
    {
        return m_driver_object;
    }

    // Convenience: first registered device object (may be null).
    [[nodiscard]] PDEVICE_OBJECT DeviceObject() const noexcept
    {
        return m_driver_object.DeviceObject;
    }

    // Convenience: the driver's unload callback (may be null).
    [[nodiscard]] PDRIVER_UNLOAD DriverUnload() const noexcept
    {
        return m_driver_object.DriverUnload;
    }

    // Convenience: one of the driver's IRP dispatch routines.
    // index must be in [0, IRP_MJ_MAXIMUM_FUNCTION].
    [[nodiscard]] PDRIVER_DISPATCH MajorFunction(int index) const noexcept
    {
        if (index < 0 || index > IRP_MJ_MAXIMUM_FUNCTION)
            return nullptr;
        return m_driver_object.MajorFunction[index];
    }

    // -----------------------------------------------------------------------
    // Export lookup
    // -----------------------------------------------------------------------

    // Find an exported symbol by name.  Returns nullptr if not found.
    // Requires: IsLoaded() == true.
    [[nodiscard]] void *GetExport(const std::string &name) const;

    // Find an exported symbol by ordinal.  Returns nullptr if not found.
    [[nodiscard]] void *GetExport(std::uint16_t ordinal) const;

    template <typename T> [[nodiscard]] T *GetExport(const std::string &name) const
    {
        static_assert(!std::is_void_v<T>);
        return reinterpret_cast<T *>(GetExport(name));
    }

    template <typename T> [[nodiscard]] T *GetExport(std::uint16_t ordinal) const
    {
        static_assert(!std::is_void_v<T>);
        return reinterpret_cast<T *>(GetExport(ordinal));
    }

    // Find a loaded debug symbol by name from DbgHelp.
    // Returns nullptr if symbols are not loaded or the symbol is not found.
    [[nodiscard]] void *GetDebugSymbol(const std::string &name) const;
    // Find a loaded debug symbol range [start, end) from DbgHelp.
    // Returns true when a valid range is found. On failure, returns false and
    // zeroes both output values.
    [[nodiscard]] bool GetDebugSymbolRange(const std::string &name, std::uintptr_t &start,
                                           std::uintptr_t &endExclusive) const;
    [[nodiscard]] std::optional<std::pair<std::uintptr_t, std::uintptr_t>>
    TryGetDebugSymbolRange(const std::string &name) const;

    template <typename T> [[nodiscard]] T *GetDebugSymbol(const std::string &name) const
    {
        static_assert(!std::is_void_v<T>);
        return reinterpret_cast<T *>(GetDebugSymbol(name));
    }

    [[nodiscard]] void *GetBase() const noexcept
    {
        return m_base;
    }
    [[nodiscard]] std::size_t GetImageSize() const noexcept
    {
        return m_image_size;
    }
    [[nodiscard]] bool HasLoadedDebugSymbols() const noexcept
    {
        return m_dbghelp_attached && m_dbghelp_module_base != 0;
    }
    [[nodiscard]] WDF_DRIVER_GLOBALS &WdfDriverGlobals() noexcept
    {
        return m_wdf_driver_globals;
    }
    [[nodiscard]] static DriverLoader *
    FromDriverObject(const DRIVER_OBJECT *driver_object) noexcept;

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
    [[nodiscard]] void *ResolveImport(std::string_view dll_name, std::string_view func_name);

    void MapSections(const std::byte *file_data, std::size_t file_size);
    void ApplyRelocations();
    void ResolveImports(const std::byte *file_data);
    void InitializeSecurityCookie();
    [[nodiscard]] std::wstring BuildDefaultRegistryPath() const;
    [[nodiscard]] static std::wstring DeriveDriverNameFromPath(std::string_view path);

    // ------------------------------------------------------------------
    // State
    // ------------------------------------------------------------------

    std::string m_path;

    // Consumer-supplied symbol overrides.
    std::unordered_map<std::string, void *> m_extra_symbols;

    // Mapped image.
    void *m_base = nullptr;
    std::size_t m_image_size = 0;

    // Synthetic driver state.
    DRIVER_OBJECT m_driver_object = {};
    DRIVER_EXTENSION m_driver_extension = {};
    UNICODE_STRING m_driver_name_str = {};
    UNICODE_STRING m_registry_path_str = {};

    // Driver service name storage.
    std::wstring m_driver_name;
    std::wstring m_driver_name_nt_buf;
    // Storage for the registry-path wide string (set at CallDriverEntry time).
    std::wstring m_registry_path_buf;

    // Per-instance DbgHelp symbol state (managed by LoadPdb/destructor).
    bool m_dbghelp_attached = false;
    std::uint64_t m_dbghelp_module_base = 0;

    WDF_DRIVER_GLOBALS m_wdf_driver_globals = {};

    static std::unordered_map<const DRIVER_OBJECT *, DriverLoader *> s_driver_object_map;
    static std::mutex s_driver_object_map_mutex;
};
