// driver_loader.cpp – PE loader implementation.

// <windows.h> must come first (it's already included transitively via
// driver_loader.hpp → <windows.h>, but make the dependency explicit here).
#include "../include/driver_loader.hpp"
#include "nt_stubs_internal.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <ios>
#include <iterator>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

// Forward declarations from nt_stubs.cpp.
void* nt_stubs_allocate(const char* name) noexcept;
void* nt_stubs_lookup(const char* name) noexcept;

// ---------------------------------------------------------------------------
// Windows PE headers (from <windows.h>).
// ---------------------------------------------------------------------------
#include <windows.h>

// ---------------------------------------------------------------------------
// ARM / ARM64 relocation types that may be absent from older MinGW headers.
// ---------------------------------------------------------------------------

#ifndef IMAGE_REL_BASED_THUMB_MOV32
#  define IMAGE_REL_BASED_THUMB_MOV32 7
#endif

// On 32-bit ARM Windows, drivers use IMAGE_FILE_MACHINE_ARMNT (Thumb-2).
// Older MinGW headers may only define IMAGE_FILE_MACHINE_ARM (old ARM).
#ifndef IMAGE_FILE_MACHINE_ARMNT
#  define IMAGE_FILE_MACHINE_ARMNT 0x01c4
#endif

// ---------------------------------------------------------------------------
// Default IRP dispatch handler used to fill DRIVER_OBJECT.MajorFunction[].
// ---------------------------------------------------------------------------

static NTSTATUS NTAPI default_dispatch_fn(DEVICE_OBJECT* /*dev*/,
                                           IRP* /*irp*/) noexcept {
    return STATUS_NOT_SUPPORTED;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

namespace {

// Return the optional-header data directory for the given index.
// base is the mapped image base address.
inline const IMAGE_DATA_DIRECTORY*
get_data_dir(const void* base, int index) noexcept {
    const auto* dos  = static_cast<const IMAGE_DOS_HEADER*>(base);
    const auto* nth  =
        reinterpret_cast<const IMAGE_NT_HEADERS*>(
            static_cast<const char*>(base) + dos->e_lfanew);
    if (static_cast<DWORD>(index) >= nth->OptionalHeader.NumberOfRvaAndSizes) return nullptr;
    const auto& dir = nth->OptionalHeader.DataDirectory[index];
    if (dir.VirtualAddress == 0) return nullptr;
    return &dir;
}

// RVA → host pointer within a mapped image.
inline void* rva_to_ptr(void* base, DWORD rva) noexcept {
    return static_cast<char*>(base) + rva;
}

// Convert PE section characteristics to VirtualProtect page-protection flags.
DWORD section_prot(DWORD chars) noexcept {
    const bool exec  = (chars & IMAGE_SCN_MEM_EXECUTE) != 0;
    const bool read  = (chars & IMAGE_SCN_MEM_READ)    != 0;
    const bool write = (chars & IMAGE_SCN_MEM_WRITE)   != 0;

    if (exec && write) return PAGE_EXECUTE_READWRITE;
    if (exec && read)  return PAGE_EXECUTE_READ;
    if (exec)          return PAGE_EXECUTE;
    if (write)         return PAGE_READWRITE;
    if (read)          return PAGE_READONLY;
    return PAGE_NOACCESS;
}

// Case-insensitive ASCII comparison for DLL names.
bool iequal(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// DriverLoader constructor / destructor
// ---------------------------------------------------------------------------

DriverLoader::DriverLoader(std::string path)
    : m_path(std::move(path))
{}

DriverLoader::~DriverLoader() {
    if (m_base) {
        VirtualFree(m_base, 0, MEM_RELEASE);
        m_base = nullptr;
    }
}

// ---------------------------------------------------------------------------
// add_symbol
// ---------------------------------------------------------------------------

void DriverLoader::add_symbol(std::string name, void* address) {
    m_extra_symbols.insert_or_assign(std::move(name), address);
}

// ---------------------------------------------------------------------------
// load
// ---------------------------------------------------------------------------

void DriverLoader::load() {
    if (m_base)
        throw std::runtime_error("DriverLoader::load() called more than once");

    // ---- Read the file --------------------------------------------------
    std::ifstream ifs(m_path, std::ios::binary);
    if (!ifs)
        throw std::runtime_error("Cannot open driver file: " + m_path);

    // Read into a char buffer; reinterpret as bytes where needed.
    std::vector<char> file_chars(
        (std::istreambuf_iterator<char>(ifs)),
        std::istreambuf_iterator<char>());
    if (file_chars.empty())
        throw std::runtime_error("Driver file is empty: " + m_path);

    const auto* file_data = reinterpret_cast<const std::byte*>(file_chars.data());
    const std::size_t file_size = file_chars.size();

    // ---- Validate headers -----------------------------------------------
    if (file_size < sizeof(IMAGE_DOS_HEADER))
        throw std::runtime_error("File too small for DOS header");

    const auto* dos =
        reinterpret_cast<const IMAGE_DOS_HEADER*>(file_data);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)  // 'MZ'
        throw std::runtime_error("Not a valid PE file (bad MZ signature)");

    if (file_size < static_cast<std::size_t>(dos->e_lfanew) +
                           sizeof(IMAGE_NT_HEADERS))
        throw std::runtime_error("File too small for NT headers");

    const auto* nth =
        reinterpret_cast<const IMAGE_NT_HEADERS*>(
            reinterpret_cast<const char*>(file_data) + dos->e_lfanew);

    if (nth->Signature != IMAGE_NT_SIGNATURE)  // 'PE\0\0'
        throw std::runtime_error("Not a valid PE file (bad NT signature)");

    // Architecture check: the loaded driver must match the host process.
#if defined(_M_AMD64) || defined(__x86_64__)
    constexpr WORD expected_machine = IMAGE_FILE_MACHINE_AMD64;
#elif defined(_M_IX86) || defined(__i386__)
    constexpr WORD expected_machine = IMAGE_FILE_MACHINE_I386;
#elif defined(_M_ARM64) || defined(__aarch64__)
    constexpr WORD expected_machine = IMAGE_FILE_MACHINE_ARM64;
#elif defined(_M_ARM) || defined(__arm__)
    constexpr WORD expected_machine = IMAGE_FILE_MACHINE_ARMNT;
#else
#  error "Unknown target architecture"
#endif
    if (nth->FileHeader.Machine != expected_machine)
        throw std::runtime_error("PE machine type does not match host architecture");

    // ---- Map sections ---------------------------------------------------
    map_sections(file_data, file_size);

    // ---- Relocate -------------------------------------------------------
    apply_relocations();

    // ---- Resolve imports ------------------------------------------------
    resolve_imports(file_data);

    // ---- Set per-section memory protections ----------------------------
    const auto* nth_mapped =
        reinterpret_cast<const IMAGE_NT_HEADERS*>(
            static_cast<const char*>(m_base) + dos->e_lfanew);
    const IMAGE_SECTION_HEADER* sections =
        IMAGE_FIRST_SECTION(nth_mapped);

    for (WORD i = 0; i < nth_mapped->FileHeader.NumberOfSections; ++i) {
        const auto& sec = sections[i];
        if (sec.VirtualAddress == 0 || sec.Misc.VirtualSize == 0) continue;
        DWORD prot = section_prot(sec.Characteristics);
        DWORD old  = 0;
        VirtualProtect(rva_to_ptr(m_base, sec.VirtualAddress),
                       sec.Misc.VirtualSize, prot, &old);
    }

    // Flush CPU instruction cache so newly-mapped code is visible.
    FlushInstructionCache(GetCurrentProcess(), m_base, m_image_size);
}

// ---------------------------------------------------------------------------
// map_sections
// ---------------------------------------------------------------------------

void DriverLoader::map_sections(const std::byte* file_data,
                                 std::size_t /*file_size*/) {
    const auto* dos =
        reinterpret_cast<const IMAGE_DOS_HEADER*>(file_data);
    const auto* nth =
        reinterpret_cast<const IMAGE_NT_HEADERS*>(
            reinterpret_cast<const char*>(file_data) + dos->e_lfanew);

    m_image_size = nth->OptionalHeader.SizeOfImage;

    // Allocate a contiguous region large enough for the entire image.
    // Use PAGE_EXECUTE_READWRITE initially; per-section protections are
    // applied after imports are resolved.
    m_base = VirtualAlloc(nullptr, m_image_size,
                          MEM_COMMIT | MEM_RESERVE,
                          PAGE_EXECUTE_READWRITE);
    if (!m_base)
        throw std::runtime_error("VirtualAlloc failed for driver image");

    // Copy the PE headers.
    std::memcpy(m_base, file_data, nth->OptionalHeader.SizeOfHeaders);

    // Copy each section.
    const IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nth);
    for (WORD i = 0; i < nth->FileHeader.NumberOfSections; ++i) {
        const auto& sec = sections[i];
        if (sec.SizeOfRawData == 0) continue;
        void* dst = rva_to_ptr(m_base, sec.VirtualAddress);
        const void* src = file_data + sec.PointerToRawData;
        const std::size_t copy_size =
            std::min<std::size_t>(sec.SizeOfRawData, sec.Misc.VirtualSize);
        std::memcpy(dst, src, copy_size);
    }
}

// ---------------------------------------------------------------------------
// apply_relocations
// ---------------------------------------------------------------------------

void DriverLoader::apply_relocations() {
    const auto* dos =
        static_cast<const IMAGE_DOS_HEADER*>(m_base);
    const auto* nth =
        reinterpret_cast<const IMAGE_NT_HEADERS*>(
            static_cast<const char*>(m_base) + dos->e_lfanew);

    const std::uintptr_t image_base_preferred =
        static_cast<std::uintptr_t>(nth->OptionalHeader.ImageBase);
    const std::uintptr_t image_base_actual =
        reinterpret_cast<std::uintptr_t>(m_base);
    const std::intptr_t delta =
        static_cast<std::intptr_t>(image_base_actual - image_base_preferred);

    if (delta == 0) return;  // No relocation needed.

    const IMAGE_DATA_DIRECTORY* reloc_dir =
        get_data_dir(m_base, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (!reloc_dir) return;  // No relocation table.

    const auto* block =
        static_cast<const IMAGE_BASE_RELOCATION*>(
            rva_to_ptr(m_base, reloc_dir->VirtualAddress));
    const auto* block_end =
        reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
            reinterpret_cast<const char*>(block) + reloc_dir->Size);

    while (block < block_end && block->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
        void* page_base = rva_to_ptr(m_base, block->VirtualAddress);
        const WORD* entry = reinterpret_cast<const WORD*>(block + 1);
        const int count =
            static_cast<int>(
                (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD));

        for (int i = 0; i < count; ++i) {
            const int type   = entry[i] >> 12;
            const int offset = entry[i] & 0x0FFF;

            switch (type) {
            case IMAGE_REL_BASED_ABSOLUTE:
                // Padding entry – skip.
                break;
            case IMAGE_REL_BASED_HIGHLOW: {
                // 32-bit absolute relocation (x86).
                auto* p = reinterpret_cast<DWORD*>(
                    static_cast<char*>(page_base) + offset);
                *p = static_cast<DWORD>(*p + static_cast<DWORD>(delta));
                break;
            }
            case IMAGE_REL_BASED_DIR64: {
                // 64-bit absolute relocation (x64, ARM64).
                auto* p = reinterpret_cast<std::uint64_t*>(
                    static_cast<char*>(page_base) + offset);
                *p = static_cast<std::uint64_t>(
                    static_cast<std::int64_t>(*p) + delta);
                break;
            }
            case IMAGE_REL_BASED_THUMB_MOV32: {
                // ARM Thumb-2 MOV32 relocation: a MOVW/MOVT pair that together
                // encode a 32-bit absolute address.
                //
                // Each 32-bit Thumb-2 instruction is stored in memory as two
                // consecutive little-endian 16-bit halfwords.  When read as a
                // DWORD the first halfword occupies bits [15:0] and the second
                // halfword occupies bits [31:16].
                //
                // For MOVW/MOVT (T3 encoding per ARM DDI 0406):
                //   first halfword:  1111 0i10 0100 imm4  (bits [15:0] of DWORD)
                //   second halfword: 0 imm3 Rd imm8       (bits [31:16] of DWORD)
                //
                // imm16 bit positions inside the DWORD:
                //   imm4 → DWORD bits  [3:0]
                //   i    → DWORD bit  [10]
                //   imm3 → DWORD bits [30:28]
                //   imm8 → DWORD bits [23:16]
                //   imm16 = (imm4<<12) | (i<<11) | (imm3<<8) | imm8
                auto* p = reinterpret_cast<DWORD*>(
                    static_cast<char*>(page_base) + offset);
                auto decode_thumb_imm16 = [](DWORD insn) -> WORD {
                    const WORD imm4 = static_cast<WORD>( insn        & 0x000FU);
                    const WORD i    = static_cast<WORD>((insn >> 10) & 0x0001U);
                    const WORD imm3 = static_cast<WORD>((insn >> 28) & 0x0007U);
                    const WORD imm8 = static_cast<WORD>((insn >> 16) & 0x00FFU);
                    return static_cast<WORD>((imm4 << 12) | (i << 11) |
                                             (imm3 <<  8) |  imm8);
                };
                auto encode_thumb_imm16 = [](DWORD insn, WORD imm16) -> DWORD {
                    // Clear the four bit-fields that carry imm16.
                    const DWORD mask =
                        0x000FU            |   // imm4  → bits  [3:0]
                        (0x0001U << 10)    |   // i     → bit  [10]
                        (0x0007U << 28)    |   // imm3  → bits [30:28]
                        (0x00FFU << 16);       // imm8  → bits [23:16]
                    insn &= ~mask;
                    insn |= static_cast<DWORD>( (imm16 >> 12) & 0xFU);
                    insn |= static_cast<DWORD>(((imm16 >> 11) & 0x1U) << 10);
                    insn |= static_cast<DWORD>(((imm16 >>  8) & 0x7U) << 28);
                    insn |= static_cast<DWORD>(  (imm16       & 0xFFU) << 16);
                    return insn;
                };
                WORD lo = decode_thumb_imm16(p[0]);
                WORD hi = decode_thumb_imm16(p[1]);
                DWORD val = static_cast<DWORD>(
                    (static_cast<DWORD>(hi) << 16) | static_cast<DWORD>(lo));
                val = static_cast<DWORD>(val + static_cast<DWORD>(delta));
                p[0] = encode_thumb_imm16(p[0], static_cast<WORD>(val & 0xFFFF));
                p[1] = encode_thumb_imm16(p[1], static_cast<WORD>(val >> 16));
                break;
            }
            default:
                // Unknown relocation type – log a warning but continue.
                std::fprintf(stderr,
                    "[driver_loader] Unknown relocation type %d at offset %d\n",
                    type, offset);
                break;
            }
        }

        block = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
            reinterpret_cast<const char*>(block) + block->SizeOfBlock);
    }
}

// ---------------------------------------------------------------------------
// resolve_imports
// ---------------------------------------------------------------------------

void DriverLoader::resolve_imports(const std::byte* /*file_data*/) {
    const IMAGE_DATA_DIRECTORY* import_dir =
        get_data_dir(m_base, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (!import_dir) return;

    auto* desc = static_cast<IMAGE_IMPORT_DESCRIPTOR*>(
        rva_to_ptr(m_base, import_dir->VirtualAddress));

    while (desc->Name != 0) {
        const char* dll_name =
            static_cast<const char*>(rva_to_ptr(m_base, desc->Name));

        // OriginalFirstThunk holds the name table; FirstThunk is the IAT.
        // If OriginalFirstThunk is 0, fall back to FirstThunk for both.
        const DWORD name_thunk_rva = desc->OriginalFirstThunk
                                     ? desc->OriginalFirstThunk
                                     : desc->FirstThunk;

        auto* name_thunk =
            static_cast<IMAGE_THUNK_DATA*>(
                rva_to_ptr(m_base, name_thunk_rva));
        auto* iat =
            static_cast<IMAGE_THUNK_DATA*>(
                rva_to_ptr(m_base, desc->FirstThunk));

        while (name_thunk->u1.AddressOfData != 0) {
            void* func_addr = nullptr;

            if (IMAGE_SNAP_BY_ORDINAL(name_thunk->u1.Ordinal)) {
                // Import by ordinal.
                const WORD ordinal =
                    static_cast<WORD>(IMAGE_ORDINAL(name_thunk->u1.Ordinal));
                char ordinal_name[32];
                std::snprintf(ordinal_name, sizeof(ordinal_name),
                              "#%u", static_cast<unsigned>(ordinal));
                func_addr = resolve_import(dll_name, ordinal_name);
            } else {
                // Import by name.
                const auto* ibn =
                    static_cast<const IMAGE_IMPORT_BY_NAME*>(
                        rva_to_ptr(m_base,
                            static_cast<DWORD>(name_thunk->u1.AddressOfData)));
                func_addr = resolve_import(dll_name, ibn->Name);
            }

            iat->u1.Function = reinterpret_cast<ULONG_PTR>(func_addr);

            ++name_thunk;
            ++iat;
        }

        ++desc;
    }
}

// ---------------------------------------------------------------------------
// resolve_import
// ---------------------------------------------------------------------------

void* DriverLoader::resolve_import(std::string_view dll_name,
                                    std::string_view func_name) {
    // 1. Consumer-supplied override (highest priority).
    {
        auto it = m_extra_symbols.find(std::string(func_name));
        if (it != m_extra_symbols.end()) return it->second;
    }

    // 2. Built-in symbol table – checked for ALL DLLs.
    //    Kernel DLL function names are globally unique, so a single flat
    //    table covers ntoskrnl, hal, wdfldr, cng, etc.
    {
        std::string name_str(func_name);
        void* addr = nt_stubs_lookup(name_str.c_str());
        if (addr) return addr;

        // 3. Numbered stub for any unrecognised import.
        const bool is_ntoskrnl_dll =
            iequal(dll_name, "ntoskrnl.exe") ||
            iequal(dll_name, "ntkrnlpa.exe") ||
            iequal(dll_name, "ntkrnlmp.exe") ||
            iequal(dll_name, "ntkrpamp.exe");

        if (!is_ntoskrnl_dll) {
            std::fprintf(stderr,
                "[driver_loader] Warning: no symbol provided for "
                "%.*s!%s; using stub.\n",
                static_cast<int>(dll_name.size()), dll_name.data(),
                name_str.c_str());
        }
        return nt_stubs_allocate(name_str.c_str());
    }
}

// ---------------------------------------------------------------------------
// call_driver_entry
// ---------------------------------------------------------------------------

NTSTATUS DriverLoader::call_driver_entry(std::wstring_view registry_path) {
    if (!m_base)
        throw std::runtime_error(
            "DriverLoader::call_driver_entry() called before load()");

    const auto* dos =
        static_cast<const IMAGE_DOS_HEADER*>(m_base);
    const auto* nth =
        reinterpret_cast<const IMAGE_NT_HEADERS*>(
            static_cast<const char*>(m_base) + dos->e_lfanew);

    if (nth->OptionalHeader.AddressOfEntryPoint == 0)
        throw std::runtime_error("Driver PE has no entry point");

    // ---- Initialise DRIVER_EXTENSION ------------------------------------
    m_driver_extension          = {};
    m_driver_extension.DriverObject = &m_driver_object;

    // ---- Initialise DRIVER_OBJECT ---------------------------------------
    m_driver_name_buf = L"\\Driver\\TestDriver";
    m_driver_name_str.Buffer        =
        const_cast<WCHAR*>(m_driver_name_buf.c_str());
    m_driver_name_str.Length        =
        static_cast<USHORT>(m_driver_name_buf.size() * sizeof(WCHAR));
    m_driver_name_str.MaximumLength = m_driver_name_str.Length;

    m_driver_object                 = {};
    m_driver_object.Type            = 4;   // IO_TYPE_DRIVER
    m_driver_object.Size            = sizeof(DRIVER_OBJECT);
    m_driver_object.DriverExtension = &m_driver_extension;
    m_driver_object.DriverName      = m_driver_name_str;
    m_driver_object.DriverStart     = m_base;
    m_driver_object.DriverSize      =
        static_cast<ULONG>(nth->OptionalHeader.SizeOfImage);

    // Default dispatch: a do-nothing handler that returns STATUS_NOT_SUPPORTED.
    for (auto& fn : m_driver_object.MajorFunction)
        fn = default_dispatch_fn;

    // ---- Initialise registry path UNICODE_STRING -----------------------
    m_registry_path_buf.assign(registry_path.begin(), registry_path.end());
    m_registry_path_str.Buffer        =
        const_cast<WCHAR*>(m_registry_path_buf.c_str());
    m_registry_path_str.Length        =
        static_cast<USHORT>(m_registry_path_buf.size() * sizeof(WCHAR));
    m_registry_path_str.MaximumLength = m_registry_path_str.Length;

    // ---- Call DriverEntry ----------------------------------------------
    // Build the entry-point address.  On ARM32 (Thumb-2) the PE entry-point
    // RVA addresses the actual code but does NOT include the Thumb
    // interworking bit (bit 0).  We must set it so that an indirect branch
    // (BLX Rx) will switch the CPU to Thumb mode before executing the code.
    using DriverEntryFn = NTSTATUS (NTAPI*)(PDRIVER_OBJECT, PUNICODE_STRING);
    auto entry_addr = reinterpret_cast<ULONG_PTR>(
        static_cast<char*>(m_base) +
        nth->OptionalHeader.AddressOfEntryPoint);
#if defined(_M_ARM) || defined(__arm__)
    entry_addr |= 1U;  // set Thumb interworking bit
#endif
    auto* entry = reinterpret_cast<DriverEntryFn>(entry_addr);

    return entry(&m_driver_object, &m_registry_path_str);
}

// ---------------------------------------------------------------------------
// get_export  (by name)
// ---------------------------------------------------------------------------

void* DriverLoader::get_export(std::string_view name) const {
    if (!m_base) return nullptr;

    const IMAGE_DATA_DIRECTORY* export_dir =
        get_data_dir(m_base, IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (!export_dir) return nullptr;

    const auto* ied = static_cast<const IMAGE_EXPORT_DIRECTORY*>(
        rva_to_ptr(m_base, export_dir->VirtualAddress));

    const DWORD* name_ptrs =
        static_cast<const DWORD*>(rva_to_ptr(m_base, ied->AddressOfNames));
    const WORD* ordinals =
        static_cast<const WORD*>(
            rva_to_ptr(m_base, ied->AddressOfNameOrdinals));
    const DWORD* funcs =
        static_cast<const DWORD*>(rva_to_ptr(m_base, ied->AddressOfFunctions));

    for (DWORD i = 0; i < ied->NumberOfNames; ++i) {
        const char* export_name =
            static_cast<const char*>(rva_to_ptr(m_base, name_ptrs[i]));
        if (name == export_name) {
            const DWORD rva = funcs[ordinals[i]];
            // Check for forwarded export (RVA inside the export directory).
            if (rva >= export_dir->VirtualAddress &&
                rva <  export_dir->VirtualAddress + export_dir->Size)
                return nullptr;  // Forwarded exports not resolved here.
            return rva_to_ptr(m_base, rva);
        }
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// get_export  (by ordinal)
// ---------------------------------------------------------------------------

void* DriverLoader::get_export(std::uint16_t ordinal) const {
    if (!m_base) return nullptr;

    const IMAGE_DATA_DIRECTORY* export_dir =
        get_data_dir(m_base, IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (!export_dir) return nullptr;

    const auto* ied = static_cast<const IMAGE_EXPORT_DIRECTORY*>(
        rva_to_ptr(m_base, export_dir->VirtualAddress));

    if (ordinal < ied->Base ||
        static_cast<DWORD>(ordinal - ied->Base) >= ied->NumberOfFunctions)
        return nullptr;

    const DWORD* funcs =
        static_cast<const DWORD*>(rva_to_ptr(m_base, ied->AddressOfFunctions));

    const DWORD rva = funcs[ordinal - ied->Base];
    if (rva == 0) return nullptr;
    // Check for forwarded export (RVA falls inside the export directory).
    if (rva >= export_dir->VirtualAddress &&
        rva < export_dir->VirtualAddress + export_dir->Size)
        return nullptr;  // Forwarded exports not resolved here.
    return rva_to_ptr(m_base, rva);
}

// ---------------------------------------------------------------------------
// call_dll_initialize
// ---------------------------------------------------------------------------

NTSTATUS DriverLoader::call_dll_initialize(std::wstring_view registry_path) {
    if (!m_base)
        throw std::runtime_error(
            "DriverLoader::call_dll_initialize() called before load()");

    void* fn = get_export("DllInitialize");
    if (!fn)
        throw std::runtime_error(
            "Driver does not export DllInitialize");

    // Initialise registry path UNICODE_STRING.
    m_registry_path_buf.assign(registry_path.begin(), registry_path.end());
    m_registry_path_str.Buffer        =
        const_cast<WCHAR*>(m_registry_path_buf.c_str());
    m_registry_path_str.Length        =
        static_cast<USHORT>(m_registry_path_buf.size() * sizeof(WCHAR));
    m_registry_path_str.MaximumLength = m_registry_path_str.Length;

    // On ARM32 (Thumb-2) set the interworking bit so an indirect BLX
    // transitions to Thumb mode before executing the function.
    using DllInitializeFn = NTSTATUS (NTAPI*)(PUNICODE_STRING);
    auto entry_addr = reinterpret_cast<ULONG_PTR>(fn);
#if defined(_M_ARM) || defined(__arm__)
    entry_addr |= 1U;
#endif
    auto* entry = reinterpret_cast<DllInitializeFn>(entry_addr);

    return entry(&m_registry_path_str);
}