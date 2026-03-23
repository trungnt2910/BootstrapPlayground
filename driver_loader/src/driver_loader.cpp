// driver_loader.cpp – PE loader implementation.

// <windows.h> must come first (it's already included transitively via
// driver_loader.hpp → <windows.h>, but make the dependency explicit here).
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <format>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <mutex>
#include <optional>
#include <print>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "driver_loader.hpp"
#include "logger.hpp"
#include "nt_stubs_internal.hpp"

// Forward declarations from nt_stubs.cpp.
void *NtStubsAllocate(const char *name) noexcept;
void *NtStubsLookup(const char *name) noexcept;

// ---------------------------------------------------------------------------
// Windows PE headers (from <windows.h>).
// ---------------------------------------------------------------------------
#include <bcrypt.h>
#include <dbghelp.h>
#include <windows.h>

// ---------------------------------------------------------------------------
// ARM / ARM64 relocation types that may be absent from older MinGW headers.
// ---------------------------------------------------------------------------

#ifndef IMAGE_REL_BASED_THUMB_MOV32
#define IMAGE_REL_BASED_THUMB_MOV32 7
#endif

// On 32-bit ARM Windows, drivers use IMAGE_FILE_MACHINE_ARMNT (Thumb-2).
// Older MinGW headers may only define IMAGE_FILE_MACHINE_ARM (old ARM).
#ifndef IMAGE_FILE_MACHINE_ARMNT
#define IMAGE_FILE_MACHINE_ARMNT 0x01c4
#endif

// ---------------------------------------------------------------------------
// Default IRP dispatch handler used to fill DRIVER_OBJECT.MajorFunction[].
// ---------------------------------------------------------------------------

static NTSTATUS NTAPI DefaultDispatchFn(DEVICE_OBJECT * /*dev*/, IRP * /*irp*/) noexcept
{
    return STATUS_NOT_SUPPORTED;
}

namespace
{
thread_local DriverLoader *gActiveEntryLoader = nullptr;

static void PrintDbghelpStackTrace(EXCEPTION_POINTERS *ep)
{
    if (!ep || !ep->ContextRecord)
        return;

    const HANDLE process = GetCurrentProcess();
    const HANDLE thread = GetCurrentThread();

    CONTEXT context = *ep->ContextRecord;
    STACKFRAME64 frame = {};
    DWORD machine = 0;

#if defined(_M_X64) || defined(__x86_64__)
    machine = IMAGE_FILE_MACHINE_AMD64;
    frame.AddrPC.Offset = context.Rip;
    frame.AddrPC.Mode = AddrModeFlat;
    frame.AddrFrame.Offset = context.Rbp;
    frame.AddrFrame.Mode = AddrModeFlat;
    frame.AddrStack.Offset = context.Rsp;
    frame.AddrStack.Mode = AddrModeFlat;
#elif defined(_M_IX86) || defined(__i386__)
    machine = IMAGE_FILE_MACHINE_I386;
    frame.AddrPC.Offset = context.Eip;
    frame.AddrPC.Mode = AddrModeFlat;
    frame.AddrFrame.Offset = context.Ebp;
    frame.AddrFrame.Mode = AddrModeFlat;
    frame.AddrStack.Offset = context.Esp;
    frame.AddrStack.Mode = AddrModeFlat;
#elif defined(_M_ARM64) || defined(__aarch64__)
    machine = IMAGE_FILE_MACHINE_ARM64;
    frame.AddrPC.Offset = context.Pc;
    frame.AddrPC.Mode = AddrModeFlat;
    frame.AddrFrame.Offset = context.Fp;
    frame.AddrFrame.Mode = AddrModeFlat;
    frame.AddrStack.Offset = context.Sp;
    frame.AddrStack.Mode = AddrModeFlat;
#elif defined(_M_ARM) || defined(__arm__)
    machine = IMAGE_FILE_MACHINE_ARMNT;
    frame.AddrPC.Offset = context.Pc;
    frame.AddrPC.Mode = AddrModeFlat;
    frame.AddrFrame.Offset = context.R11;
    frame.AddrFrame.Mode = AddrModeFlat;
    frame.AddrStack.Offset = context.Sp;
    frame.AddrStack.Mode = AddrModeFlat;
#else
    DL_LOG_ERROR("stack trace not implemented on this architecture");
    return;
#endif

    DL_LOG_ERROR("Stack trace:");
    for (int i = 0; i < 64; ++i)
    {
        const BOOL ok = StackWalk64(
            machine,
            process,
            thread,
            &frame,
            &context,
            nullptr,
            SymFunctionTableAccess64,
            SymGetModuleBase64,
            nullptr);
        if (!ok || frame.AddrPC.Offset == 0)
            break;

        char symbolBuf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = {};
        auto *symbol = reinterpret_cast<SYMBOL_INFO *>(symbolBuf);
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol->MaxNameLen = MAX_SYM_NAME;

        DWORD64 displacement = 0;
        const bool haveSymbol =
            SymFromAddr(process, frame.AddrPC.Offset, &displacement, symbol) == TRUE;
#ifndef NDEBUG
        const DWORD symbolLookupError = have_symbol ? 0 : GetLastError();
#endif

        IMAGEHLP_LINE64 line = {};
        line.SizeOfStruct = sizeof(line);
        DWORD lineDisplacement = 0;
        const bool haveLine =
            SymGetLineFromAddr64(process, frame.AddrPC.Offset, &lineDisplacement, &line) == TRUE;

        std::ostringstream lineStream;

        if (haveSymbol && haveLine)
        {
            lineStream << "  #"
                       << std::setw(2) << std::setfill('0') << i << ' '
                       << "0x" << reinterpret_cast<void *>(frame.AddrPC.Offset) << ' '
                       << symbol->Name << "+0x"
                       << static_cast<intptr_t>(displacement) << ' '
                       << '(' << line.FileName << ':' << line.LineNumber << ')';
            DL_LOG_ERROR("{}", lineStream.str().c_str());
        }
        else if (haveSymbol)
        {
            lineStream << "  #"
                       << std::setw(2) << std::setfill('0') << i << ' '
                       << "0x" << reinterpret_cast<void *>(frame.AddrPC.Offset) << ' '
                       << symbol->Name << "+0x"
                       << static_cast<intptr_t>(displacement);
            DL_LOG_ERROR("{}", lineStream.str().c_str());
        }
        else
        {
            DL_LOG_ERROR("  #{:02} {:p}", i, reinterpret_cast<void *>(frame.AddrPC.Offset));
        }
#ifndef NDEBUG
        if (!have_symbol && gActiveEntryLoader != nullptr &&
            gActiveEntryLoader->HasLoadedDebugSymbols())
        {
            const std::uintptr_t image_start =
                reinterpret_cast<std::uintptr_t>(gActiveEntryLoader->GetBase());
            const std::size_t image_size = gActiveEntryLoader->GetImageSize();
            const std::uintptr_t image_end = image_start + image_size;
            const std::uintptr_t current_pc = static_cast<std::uintptr_t>(frame.AddrPC.Offset);
            if (image_size > 0 && current_pc >= image_start && current_pc < image_end)
            {
                DL_LOG_ERROR(
                    "SymFromAddr(0x{:X}) lookup failed: GetLastError()={}",
                    static_cast<unsigned long long>(current_pc),
                    static_cast<unsigned long>(symbolLookupError));
            }
        }
#endif
    }
}
} // namespace

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

namespace
{

// Return the optional-header data directory for the given index.
// base is the mapped image base address.
inline const IMAGE_DATA_DIRECTORY *GetDataDir(const void *base, int index) noexcept
{
    const auto *dos = static_cast<const IMAGE_DOS_HEADER *>(base);
    const auto *nth =
        reinterpret_cast<const IMAGE_NT_HEADERS *>(static_cast<const char *>(base) + dos->e_lfanew);
    if (static_cast<DWORD>(index) >= nth->OptionalHeader.NumberOfRvaAndSizes)
        return nullptr;
    const auto &dir = nth->OptionalHeader.DataDirectory[index];
    if (dir.VirtualAddress == 0)
        return nullptr;
    return &dir;
}

// RVA → host pointer within a mapped image.
inline void *RvaToPtr(void *base, DWORD rva) noexcept
{
    return static_cast<char *>(base) + rva;
}

// Convert PE section characteristics to VirtualProtect page-protection flags.
DWORD SectionProt(DWORD chars) noexcept
{
    const bool exec = (chars & IMAGE_SCN_MEM_EXECUTE) != 0;
    const bool read = (chars & IMAGE_SCN_MEM_READ) != 0;
    const bool write = (chars & IMAGE_SCN_MEM_WRITE) != 0;

    if (exec && write)
        return PAGE_EXECUTE_READWRITE;
    if (exec && read)
        return PAGE_EXECUTE_READ;
    if (exec)
        return PAGE_EXECUTE;
    if (write)
        return PAGE_READWRITE;
    if (read)
        return PAGE_READONLY;
    return PAGE_NOACCESS;
}

// Case-insensitive ASCII comparison for DLL names.
bool IEqual(std::string_view a, std::string_view b) noexcept
{
    if (a.size() != b.size())
        return false;
    for (std::size_t i = 0; i < a.size(); ++i)
    {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}

std::mutex s_dbghelpMutex;
std::atomic<int> s_dbghelpRefcount{ 0 };
bool s_dbghelpInitialized = false;

struct DebugSymbolRange final
{
    std::uintptr_t start = 0;
    std::uintptr_t endExclusive = 0;
};

[[nodiscard]] bool TryResolveSymbolRange(
    DriverLoader *loader, const char *symbolName, DebugSymbolRange &range) noexcept
{
    range = {};
    if (!loader || !symbolName)
        return false;
    return loader->GetDebugSymbolRange(symbolName, range.start, range.endExclusive);
}

[[nodiscard]] bool TryRedirectPrivilegedInstruction(
    EXCEPTION_POINTERS *ep, const DebugSymbolRange &range, const void *targetFunction) noexcept
{
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord || !targetFunction)
    {
        return false;
    }
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_PRIV_INSTRUCTION)
    {
        return false;
    }
    const std::uintptr_t fault_ip =
        reinterpret_cast<std::uintptr_t>(ep->ExceptionRecord->ExceptionAddress);
    if (fault_ip < range.start || fault_ip >= range.endExclusive)
    {
        return false;
    }
#if defined(_M_X64) || defined(__x86_64__)
    ep->ContextRecord->Rip = reinterpret_cast<DWORD64>(targetFunction);
#elif defined(_M_IX86) || defined(__i386__)
    ep->ContextRecord->Eip = reinterpret_cast<DWORD>(targetFunction);
#elif defined(_M_ARM64) || defined(__aarch64__) || defined(_M_ARM) || defined(__arm__)
    ep->ContextRecord->Pc = reinterpret_cast<DWORD64>(targetFunction);
#else
    return false;
#endif
    return true;
}

LONG WINAPI EntryExceptionDiagnostics(EXCEPTION_POINTERS *ep)
{
    if (!ep || !ep->ExceptionRecord)
        return EXCEPTION_CONTINUE_SEARCH;
    DebugSymbolRange keGetCurrentIrqlRange{};
    if (TryResolveSymbolRange(gActiveEntryLoader, "KeGetCurrentIrql", keGetCurrentIrqlRange))
    {
        const void *keGetCurrentIrqlStub = NtStubsLookup("KeGetCurrentIrql");
        if (keGetCurrentIrqlStub != nullptr &&
            TryRedirectPrivilegedInstruction(ep, keGetCurrentIrqlRange, keGetCurrentIrqlStub))
        {
            DL_LOG_WARNING(
                "redirected privileged instruction at {:p} to KeGetCurrentIrql stub {:p}",
                ep->ExceptionRecord->ExceptionAddress,
                keGetCurrentIrqlStub);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    {
        std::lock_guard<std::mutex> lock(s_dbghelpMutex);
        if (s_dbghelpInitialized && gActiveEntryLoader != nullptr)
        {
            PrintDbghelpStackTrace(ep);
        }
    }
    const EXCEPTION_RECORD *er = ep->ExceptionRecord;
    ULONG_PTR access_type = 0;
    ULONG_PTR access_addr = 0;
    if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er->NumberParameters >= 2)
    {
        access_type = er->ExceptionInformation[0];
        access_addr = er->ExceptionInformation[1];
    }
    DL_LOG_ERROR(
        "SEH: code=0x{:08X} addr={:p} flags=0x{:08X} access_type={} access_addr={:p}",
        static_cast<unsigned long>(er->ExceptionCode),
        er->ExceptionAddress,
        static_cast<unsigned long>(er->ExceptionFlags),
        static_cast<unsigned long long>(access_type),
        reinterpret_cast<void *>(access_addr));
    return EXCEPTION_CONTINUE_SEARCH;
}

struct NextSymbolSearch
{
    DWORD64 start;
    DWORD64 next;
};

static BOOL CALLBACK
FindNextSymbolCb(PSYMBOL_INFO symbol_info, ULONG /*symbol_size*/, PVOID user_context)
{
    if (!symbol_info || !user_context)
        return FALSE;
    auto *search = static_cast<NextSymbolSearch *>(user_context);
    if (symbol_info->Address > search->start &&
        (search->next == 0 || symbol_info->Address < search->next))
    {
        search->next = symbol_info->Address;
    }
    return TRUE;
}

constexpr ULONG kWdfDriverTag =
    (static_cast<ULONG>('W') << 16) | (static_cast<ULONG>('D') << 8) | static_cast<ULONG>('F');

void CopyDriverNameToWdfGlobals(
    const std::wstring &source, CHAR (&dest)[WDF_DRIVER_GLOBALS_NAME_LEN])
{
    std::memset(dest, 0, sizeof(dest));
    if (source.empty())
    {
        return;
    }

    const int written = WideCharToMultiByte(
        CP_UTF8,
        0,
        source.c_str(),
        -1,
        dest,
        static_cast<int>(WDF_DRIVER_GLOBALS_NAME_LEN),
        nullptr,
        nullptr);
    if (written > 0)
    {
        return;
    }

    const char *fallback = "driver";
    std::strncpy(dest, fallback, WDF_DRIVER_GLOBALS_NAME_LEN - 1);
    dest[WDF_DRIVER_GLOBALS_NAME_LEN - 1] = '\0';
}

} // anonymous namespace

std::unordered_map<const DRIVER_OBJECT *, DriverLoader *> DriverLoader::s_driverObjectMap = {};
std::mutex DriverLoader::s_driverObjectMapMutex;

// ---------------------------------------------------------------------------
// DriverLoader constructor / destructor
// ---------------------------------------------------------------------------

DriverLoader::DriverLoader(std::string path)
    : m_path(std::move(path)), m_driverName(DeriveDriverNameFromPath(m_path))
{
    if (m_driverName.empty())
    {
        m_driverName = L"TestDriver";
    }
}

DriverLoader::~DriverLoader()
{
    {
        std::lock_guard<std::mutex> lock(s_driverObjectMapMutex);
        s_driverObjectMap.erase(&m_driverObject);
    }
    {
        std::lock_guard<std::mutex> lock(s_dbghelpMutex);
        if (m_dbghelpAttached)
        {
            const HANDLE proc = GetCurrentProcess();
            if (m_dbghelpModuleBase != 0)
            {
                (void)SymUnloadModule64(proc, m_dbghelpModuleBase);
                m_dbghelpModuleBase = 0;
            }
            const int refs = --s_dbghelpRefcount;
            m_dbghelpAttached = false;
            if (refs <= 0 && s_dbghelpInitialized)
            {
                (void)SymCleanup(proc);
                s_dbghelpInitialized = false;
                s_dbghelpRefcount = 0;
            }
        }
    }
    if (m_base)
    {
        VirtualFree(m_base, 0, MEM_RELEASE);
        m_base = nullptr;
    }
}

// ---------------------------------------------------------------------------
// AddSymbol
// ---------------------------------------------------------------------------

void DriverLoader::AddSymbol(std::string name, void *address)
{
    m_extraSymbols.insert_or_assign(std::move(name), address);
}

// ---------------------------------------------------------------------------
// Load
// ---------------------------------------------------------------------------

void DriverLoader::Load()
{
    InitLogLevelFromEnv();
    if (m_base)
        throw std::runtime_error("DriverLoader::Load() called more than once");

    // ---- Read the file --------------------------------------------------
    std::ifstream ifs(m_path, std::ios::binary);
    if (!ifs)
        throw std::runtime_error("Cannot open driver file: " + m_path);

    // Read into a char buffer; reinterpret as bytes where needed.
    std::vector<char> file_chars(
        (std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    if (file_chars.empty())
        throw std::runtime_error("Driver file is empty: " + m_path);

    const auto *file_data = reinterpret_cast<const std::byte *>(file_chars.data());
    const std::size_t file_size = file_chars.size();

    // ---- Validate headers -----------------------------------------------
    if (file_size < sizeof(IMAGE_DOS_HEADER))
        throw std::runtime_error("File too small for DOS header");

    const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(file_data);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) // 'MZ'
        throw std::runtime_error("Not a valid PE file (bad MZ signature)");

    if (file_size < static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS))
        throw std::runtime_error("File too small for NT headers");

    const auto *nth = reinterpret_cast<const IMAGE_NT_HEADERS *>(
        reinterpret_cast<const char *>(file_data) + dos->e_lfanew);

    if (nth->Signature != IMAGE_NT_SIGNATURE) // 'PE\0\0'
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
#error "Unknown target architecture"
#endif
    if (nth->FileHeader.Machine != expected_machine)
        throw std::runtime_error("PE machine type does not match host architecture");

    // ---- Map sections ---------------------------------------------------
    MapSections(file_data, file_size);

    // ---- Relocate -------------------------------------------------------
    ApplyRelocations();

    // ---- Resolve imports ------------------------------------------------
    ResolveImports(file_data);

    // ---- Initialize /GS security cookie --------------------------------
    // Some drivers (e.g. KMDF-linked) call __security_init_cookie during
    // early entry and fast-fail if the cookie still equals the default
    // placeholder. Initialize it from IMAGE_LOAD_CONFIG_DIRECTORY.
    InitializeSecurityCookie();

    // ---- Set per-section memory protections ----------------------------
    const auto *nth_mapped = reinterpret_cast<const IMAGE_NT_HEADERS *>(
        static_cast<const char *>(m_base) + dos->e_lfanew);
    const IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(nth_mapped);

    for (WORD i = 0; i < nth_mapped->FileHeader.NumberOfSections; ++i)
    {
        const auto &sec = sections[i];
        if (sec.VirtualAddress == 0 || sec.Misc.VirtualSize == 0)
            continue;
        DWORD prot = SectionProt(sec.Characteristics);
        DWORD old = 0;
        VirtualProtect(RvaToPtr(m_base, sec.VirtualAddress), sec.Misc.VirtualSize, prot, &old);
    }

    // Flush CPU instruction cache so newly mapped code is visible.
    FlushInstructionCache(GetCurrentProcess(), m_base, m_imageSize);
}

void DriverLoader::InitializeSecurityCookie()
{
    const auto *dos = static_cast<const IMAGE_DOS_HEADER *>(m_base);
    const auto *nth = reinterpret_cast<const IMAGE_NT_HEADERS *>(
        static_cast<const char *>(m_base) + dos->e_lfanew);

    const IMAGE_DATA_DIRECTORY *loadcfg_dir = GetDataDir(m_base, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
    if (!loadcfg_dir || loadcfg_dir->Size == 0)
    {
        return;
    }

    constexpr std::size_t kSecurityCookieFieldEnd =
        offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, SecurityCookie) +
        sizeof(decltype(IMAGE_LOAD_CONFIG_DIRECTORY::SecurityCookie));
    if (loadcfg_dir->Size < kSecurityCookieFieldEnd)
    {
        return;
    }

    const auto *loadcfg = static_cast<const IMAGE_LOAD_CONFIG_DIRECTORY *>(
        RvaToPtr(m_base, loadcfg_dir->VirtualAddress));
    const std::uintptr_t cookie_va = static_cast<std::uintptr_t>(loadcfg->SecurityCookie);
    if (cookie_va == 0)
    {
        return;
    }

    const std::uintptr_t image_start = reinterpret_cast<std::uintptr_t>(m_base);
    const std::size_t image_size = nth->OptionalHeader.SizeOfImage;
    const std::uintptr_t cookie_addr = static_cast<std::uintptr_t>(cookie_va);
    if (image_size < sizeof(std::uintptr_t) || cookie_addr < image_start)
    {
        return;
    }
    if ((cookie_addr - image_start) > (image_size - sizeof(std::uintptr_t)))
    {
        return;
    }
    if ((cookie_addr % alignof(std::uintptr_t)) != 0)
    {
        return;
    }

    auto *cookie_ptr = reinterpret_cast<std::uintptr_t *>(cookie_addr);

#if defined(_WIN64)
    // MSVC/GS default placeholder cookie on 64-bit targets.
    constexpr std::uintptr_t kDefaultCookie = 0x00002B992DDFA232ULL;
    constexpr std::uintptr_t kCookieHighMask = 0xFFFF000000000000ULL;
    constexpr std::uintptr_t kFallbackCookieXorMask = 0x4711A55A3C6DEB1FULL;
#else
    // MSVC/GS default placeholder cookie on 32-bit targets.
    constexpr std::uintptr_t kDefaultCookie = 0xBB40E64EU;
    constexpr std::uintptr_t kFallbackCookieXorMask = 0xA55A4711U;
#endif
    std::uint64_t seed = 0;
    if (BCryptGenRandom(
            nullptr,
            reinterpret_cast<PUCHAR>(&seed),
            static_cast<ULONG>(sizeof(seed)),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS)
    {
        seed = 0;
    }
    seed ^= static_cast<std::uint64_t>(GetCurrentProcessId()) << 16;
    seed ^= static_cast<std::uint64_t>(GetCurrentThreadId());
    seed ^= static_cast<std::uint64_t>(GetTickCount64());
    seed ^= reinterpret_cast<std::uintptr_t>(m_base);
    seed ^= reinterpret_cast<std::uintptr_t>(&seed);
    seed ^= static_cast<std::uint64_t>(nth->OptionalHeader.AddressOfEntryPoint);
    LARGE_INTEGER qpc = {};
    if (QueryPerformanceCounter(&qpc) != 0)
    {
        seed ^= static_cast<std::uint64_t>(qpc.QuadPart);
    }
    else
    {
        // Mix in FILETIME entropy if high-resolution performance counter
        // sampling is unavailable.
        FILETIME ft = {};
        GetSystemTimeAsFileTime(&ft);
        const std::uint64_t filetime_ticks = (static_cast<std::uint64_t>(ft.dwHighDateTime) << 32) |
                                             static_cast<std::uint64_t>(ft.dwLowDateTime);
        seed ^= reinterpret_cast<std::uintptr_t>(cookie_ptr);
        seed ^= filetime_ticks;
    }

    const auto normalize_cookie = [](std::uintptr_t value) -> std::uintptr_t
    {
#if defined(_WIN64)
        return (value & ~kCookieHighMask);
#else
        return value;
#endif
    };

    std::uintptr_t cookie = normalize_cookie(static_cast<std::uintptr_t>(seed));
    if (cookie == 0 || cookie == kDefaultCookie)
    {
        cookie = normalize_cookie(cookie ^ kFallbackCookieXorMask);
        if (cookie == 0 || cookie == kDefaultCookie)
        {
            cookie += 1;
        }
    }

    *cookie_ptr = cookie;
}

void DriverLoader::LoadPdb(const std::string &pdbPath)
{
    DL_LOG_TRACE("Loading PDB at: {}", pdbPath);

    if (!m_base)
    {
        throw std::runtime_error("DriverLoader::LoadPdb() called before Load()");
    }

    const HANDLE proc = GetCurrentProcess();
    std::lock_guard<std::mutex> lock(s_dbghelpMutex);

    if (!s_dbghelpInitialized)
    {
        SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME);
        if (!SymInitialize(proc, nullptr, FALSE))
        {
            throw std::runtime_error("SymInitialize failed");
        }
        s_dbghelpInitialized = true;
    }

    if (!m_dbghelpAttached)
    {
        ++s_dbghelpRefcount;
        m_dbghelpAttached = true;
    }

    const auto has_pdb_extension = [](const std::string &path) -> bool
    {
        if (path.size() < 4)
            return false;
        const std::string_view ext(path.c_str() + (path.size() - 4), 4);
        return IEqual(ext, ".pdb");
    };

    if (!pdbPath.empty())
    {
        const DWORD attributes = GetFileAttributesA(pdbPath.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES)
        {
            const DWORD attribute_error = GetLastError();
            throw std::runtime_error(
                std::format(
                    "PDB path is invalid or inaccessible: {} (GetLastError={})",
                    pdbPath,
                    static_cast<unsigned long>(attribute_error)));
        }
        if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        {
            throw std::runtime_error("PDB path is a directory, not a file: " + pdbPath);
        }

        std::string search_path = pdbPath;
        if (has_pdb_extension(pdbPath))
        {
            const std::size_t sep = pdbPath.find_last_of("/\\");
            if (sep == std::string::npos)
            {
                search_path = ".";
            }
            else if (sep == 0)
            {
                search_path = pdbPath.substr(0, 1);
            }
            else
            {
                search_path = pdbPath.substr(0, sep);
            }
        }
        if (!search_path.empty() && !SymSetSearchPath(proc, search_path.c_str()))
        {
            throw std::runtime_error("SymSetSearchPath failed for pdb path: " + pdbPath);
        }
    }

    if (m_dbghelpModuleBase != 0)
    {
        (void)SymUnloadModule64(proc, m_dbghelpModuleBase);
        m_dbghelpModuleBase = 0;
    }

    DWORD64 mod_base = SymLoadModuleEx(
        proc,
        nullptr,
        pdbPath.c_str(),
        nullptr,
        reinterpret_cast<DWORD64>(m_base),
        static_cast<DWORD>(m_imageSize),
        nullptr,
        0);
    if (mod_base == 0)
    {
        DWORD error = GetLastError();
        throw std::runtime_error(
            "SymLoadModuleEx failed for image: " + m_path + ", error=" + std::to_string(error)
        );
    }
    m_dbghelpModuleBase = static_cast<std::uint64_t>(mod_base);

    // Touch symbol loading so failures surface immediately.
    IMAGEHLP_MODULEW64 modinfo = {};
    modinfo.SizeOfStruct = sizeof(modinfo);
    if (!SymGetModuleInfoW64(proc, mod_base, &modinfo))
    {
        throw std::runtime_error("SymGetModuleInfoW64 failed after SymLoadModuleEx");
    }
}

// ---------------------------------------------------------------------------
// MapSections
// ---------------------------------------------------------------------------

void DriverLoader::MapSections(const std::byte *file_data, std::size_t /*file_size*/)
{
    const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(file_data);
    const auto *nth = reinterpret_cast<const IMAGE_NT_HEADERS *>(
        reinterpret_cast<const char *>(file_data) + dos->e_lfanew);

    m_imageSize = nth->OptionalHeader.SizeOfImage;

    // Allocate a contiguous region large enough for the entire image.
    // Use PAGE_EXECUTE_READWRITE initially; per-section protections are
    // applied after imports are resolved.
    m_base = VirtualAlloc(nullptr, m_imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!m_base)
        throw std::runtime_error("VirtualAlloc failed for driver image");

    // Copy the PE headers.
    std::memcpy(m_base, file_data, nth->OptionalHeader.SizeOfHeaders);

    // Copy each section.
    const IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(nth);
    for (WORD i = 0; i < nth->FileHeader.NumberOfSections; ++i)
    {
        const auto &sec = sections[i];
        if (sec.SizeOfRawData == 0)
            continue;
        void *dst = RvaToPtr(m_base, sec.VirtualAddress);
        const void *src = file_data + sec.PointerToRawData;
        const std::size_t copy_size =
            std::min<std::size_t>(sec.SizeOfRawData, sec.Misc.VirtualSize);
        std::memcpy(dst, src, copy_size);
    }
}

// ---------------------------------------------------------------------------
// ApplyRelocations
// ---------------------------------------------------------------------------

void DriverLoader::ApplyRelocations()
{
    const auto *dos = static_cast<const IMAGE_DOS_HEADER *>(m_base);
    const auto *nth = reinterpret_cast<const IMAGE_NT_HEADERS *>(
        static_cast<const char *>(m_base) + dos->e_lfanew);

    const std::uintptr_t image_base_preferred =
        static_cast<std::uintptr_t>(nth->OptionalHeader.ImageBase);
    const std::uintptr_t image_base_actual = reinterpret_cast<std::uintptr_t>(m_base);
    const std::intptr_t delta =
        static_cast<std::intptr_t>(image_base_actual - image_base_preferred);

    if (delta == 0)
        return; // No relocation needed.

    const IMAGE_DATA_DIRECTORY *reloc_dir = GetDataDir(m_base, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (!reloc_dir)
        return; // No relocation table.

    const auto *block =
        static_cast<const IMAGE_BASE_RELOCATION *>(RvaToPtr(m_base, reloc_dir->VirtualAddress));
    const auto *block_end = reinterpret_cast<const IMAGE_BASE_RELOCATION *>(
        reinterpret_cast<const char *>(block) + reloc_dir->Size);

    while (block < block_end && block->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
    {
        void *page_base = RvaToPtr(m_base, block->VirtualAddress);
        const WORD *entry = reinterpret_cast<const WORD *>(block + 1);
        const int count =
            static_cast<int>((block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD));

        for (int i = 0; i < count; ++i)
        {
            const int type = entry[i] >> 12;
            const int offset = entry[i] & 0x0FFF;

            switch (type)
            {
            case IMAGE_REL_BASED_ABSOLUTE:
                // Padding entry – skip.
                break;
            case IMAGE_REL_BASED_HIGHLOW:
            {
                // 32-bit absolute relocation (x86).
                auto *p = reinterpret_cast<DWORD *>(static_cast<char *>(page_base) + offset);
                *p = static_cast<DWORD>(*p + static_cast<DWORD>(delta));
                break;
            }
            case IMAGE_REL_BASED_DIR64:
            {
                // 64-bit absolute relocation (x64, ARM64).
                auto *p =
                    reinterpret_cast<std::uint64_t *>(static_cast<char *>(page_base) + offset);
                *p = static_cast<std::uint64_t>(static_cast<std::int64_t>(*p) + delta);
                break;
            }
            case IMAGE_REL_BASED_THUMB_MOV32:
            {
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
                auto *p = reinterpret_cast<DWORD *>(static_cast<char *>(page_base) + offset);
                constexpr auto decode_thumb_imm16 = [](DWORD insn) -> WORD
                {
                    const WORD imm4 = static_cast<WORD>(insn & 0x000FU);
                    const WORD i = static_cast<WORD>((insn >> 10) & 0x0001U);
                    const WORD imm3 = static_cast<WORD>((insn >> 28) & 0x0007U);
                    const WORD imm8 = static_cast<WORD>((insn >> 16) & 0x00FFU);
                    return static_cast<WORD>((imm4 << 12) | (i << 11) | (imm3 << 8) | imm8);
                };
                constexpr auto encode_thumb_imm16 = [](DWORD insn, WORD imm16) -> DWORD
                {
                    // Clear the four bit-fields that carry imm16.
                    const DWORD mask = 0x000FU |         // imm4  → bits  [3:0]
                                       (0x0001U << 10) | // i     → bit  [10]
                                       (0x0007U << 28) | // imm3  → bits [30:28]
                                       (0x00FFU << 16);  // imm8  → bits [23:16]
                    insn &= ~mask;
                    insn |= static_cast<DWORD>((imm16 >> 12) & 0xFU);
                    insn |= static_cast<DWORD>(((imm16 >> 11) & 0x1U) << 10);
                    insn |= static_cast<DWORD>(((imm16 >> 8) & 0x7U) << 28);
                    insn |= static_cast<DWORD>((imm16 & 0xFFU) << 16);
                    return insn;
                };
                WORD lo = decode_thumb_imm16(p[0]);
                WORD hi = decode_thumb_imm16(p[1]);
                DWORD val =
                    static_cast<DWORD>((static_cast<DWORD>(hi) << 16) | static_cast<DWORD>(lo));
                val = static_cast<DWORD>(val + static_cast<DWORD>(delta));
                p[0] = encode_thumb_imm16(p[0], static_cast<WORD>(val & 0xFFFF));
                p[1] = encode_thumb_imm16(p[1], static_cast<WORD>(val >> 16));
                break;
            }
            default:
                // Unknown relocation type – log a warning but continue.
                DL_LOG_WARNING("Unknown relocation type {} at offset {}", type, offset);
                break;
            }
        }

        block = reinterpret_cast<const IMAGE_BASE_RELOCATION *>(
            reinterpret_cast<const char *>(block) + block->SizeOfBlock);
    }
}

// ---------------------------------------------------------------------------
// ResolveImports
// ---------------------------------------------------------------------------

void DriverLoader::ResolveImports(const std::byte * /*file_data*/)
{
    const IMAGE_DATA_DIRECTORY *import_dir = GetDataDir(m_base, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (!import_dir)
        return;

    auto *desc =
        static_cast<IMAGE_IMPORT_DESCRIPTOR *>(RvaToPtr(m_base, import_dir->VirtualAddress));

    while (desc->Name != 0)
    {
        const char *dll_name = static_cast<const char *>(RvaToPtr(m_base, desc->Name));

        // OriginalFirstThunk holds the name table; FirstThunk is the IAT.
        // If OriginalFirstThunk is 0, fall back to FirstThunk for both.
        const DWORD name_thunk_rva =
            desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;

        auto *name_thunk = static_cast<IMAGE_THUNK_DATA *>(RvaToPtr(m_base, name_thunk_rva));
        auto *iat = static_cast<IMAGE_THUNK_DATA *>(RvaToPtr(m_base, desc->FirstThunk));

        while (name_thunk->u1.AddressOfData != 0)
        {
            void *func_addr = nullptr;

            if (IMAGE_SNAP_BY_ORDINAL(name_thunk->u1.Ordinal))
            {
                // Import by ordinal.
                const WORD ordinal = static_cast<WORD>(IMAGE_ORDINAL(name_thunk->u1.Ordinal));
                func_addr =
                    ResolveImport(dll_name, std::format("#{}", static_cast<unsigned>(ordinal)));
            }
            else
            {
                // Import by name.
                const auto *ibn = static_cast<const IMAGE_IMPORT_BY_NAME *>(
                    RvaToPtr(m_base, static_cast<DWORD>(name_thunk->u1.AddressOfData)));
                func_addr = ResolveImport(dll_name, ibn->Name);
            }

            iat->u1.Function = reinterpret_cast<ULONG_PTR>(func_addr);

            ++name_thunk;
            ++iat;
        }

        ++desc;
    }
}

// ---------------------------------------------------------------------------
// ResolveImport
// ---------------------------------------------------------------------------

void *DriverLoader::ResolveImport(std::string_view dll_name, std::string_view func_name)
{
    std::string name_str(func_name);

    // 1. Consumer-supplied override (highest priority).
    {
        auto it = m_extraSymbols.find(name_str);
        if (it != m_extraSymbols.end())
        {
            DL_LOG_TRACE("import {}!{} -> consumer symbol @ {:p}", dll_name, name_str, it->second);
            return it->second;
        }
    }

    // 2. Built-in symbol table – checked for ALL DLLs.
    //    Kernel DLL function names are globally unique, so a single flat
    //    table covers ntoskrnl, hal, wdfldr, cng, etc.
    {
        void *addr = NtStubsLookup(name_str.c_str());
        if (addr)
        {
            DL_LOG_TRACE("import {}!{} -> builtin symbol @ {:p}", dll_name, name_str, addr);
            return addr;
        }

        // 3. Numbered stub for any unrecognized import.
        const bool is_ntoskrnl_dll =
            IEqual(dll_name, "ntoskrnl.exe") || IEqual(dll_name, "ntkrnlpa.exe") ||
            IEqual(dll_name, "ntkrnlmp.exe") || IEqual(dll_name, "ntkrpamp.exe");

        void *stub = NtStubsAllocate(name_str.c_str());
        if (!is_ntoskrnl_dll)
        {
            DL_LOG_WARNING(
                "no symbol provided for {}!{}; using stub @ {:p}.", dll_name, name_str, stub);
        }
        else
        {
            DL_LOG_TRACE("import {}!{} -> numbered stub @ {:p}", dll_name, name_str, stub);
        }
        return stub;
    }
}

// ---------------------------------------------------------------------------
// CallDriverEntry
// ---------------------------------------------------------------------------

NTSTATUS DriverLoader::CallDriverEntry(const std::optional<std::wstring> &registry_path)
{
    if (!m_base)
        throw std::runtime_error("DriverLoader::CallDriverEntry() called before Load()");

    const auto *dos = static_cast<const IMAGE_DOS_HEADER *>(m_base);
    const auto *nth = reinterpret_cast<const IMAGE_NT_HEADERS *>(
        static_cast<const char *>(m_base) + dos->e_lfanew);

    if (nth->OptionalHeader.AddressOfEntryPoint == 0)
        throw std::runtime_error("Driver PE has no entry point");

    // ---- Initialize DRIVER_EXTENSION ------------------------------------
    m_driverExtension = {};
    m_driverExtension.DriverObject = &m_driverObject;

    // ---- Initialize DRIVER_OBJECT ---------------------------------------
    m_driverNameNtBuf = L"\\Driver\\";
    m_driverNameNtBuf += m_driverName;
    m_driverNameStr.Buffer = const_cast<WCHAR *>(m_driverNameNtBuf.c_str());
    m_driverNameStr.Length = static_cast<USHORT>(m_driverNameNtBuf.size() * sizeof(WCHAR));
    m_driverNameStr.MaximumLength = m_driverNameStr.Length;

    m_driverObject = {};
    m_driverObject.Type = 4; // IO_TYPE_DRIVER
    m_driverObject.Size = sizeof(DRIVER_OBJECT);
    m_driverObject.DriverExtension = &m_driverExtension;
    m_driverObject.DriverName = m_driverNameStr;
    m_driverObject.DriverStart = m_base;
    m_driverObject.DriverSize = static_cast<ULONG>(nth->OptionalHeader.SizeOfImage);

    // Default dispatch: a do-nothing handler that returns STATUS_NOT_SUPPORTED.
    for (auto &fn : m_driverObject.MajorFunction)
        fn = DefaultDispatchFn;

    m_wdfDriverGlobals = {};
    m_wdfDriverGlobals.Driver = &m_driverObject;
    m_wdfDriverGlobals.DriverTag = kWdfDriverTag;
    CopyDriverNameToWdfGlobals(m_driverName, m_wdfDriverGlobals.DriverName);
    {
        std::lock_guard<std::mutex> lock(s_driverObjectMapMutex);
        s_driverObjectMap[&m_driverObject] = this;
    }

    // ---- Initialize registry path UNICODE_STRING ------------------------
    if (registry_path.has_value())
    {
        m_registryPathBuf = *registry_path;
    }
    else
    {
        m_registryPathBuf = BuildDefaultRegistryPath();
    }
    m_registryPathStr.Buffer = const_cast<WCHAR *>(m_registryPathBuf.c_str());
    m_registryPathStr.Length = static_cast<USHORT>(m_registryPathBuf.size() * sizeof(WCHAR));
    m_registryPathStr.MaximumLength = m_registryPathStr.Length;

    // ---- Call DriverEntry ----------------------------------------------
    // Build the entry-point address.  On ARM32 (Thumb-2) the PE entry-point
    // RVA addresses the actual code but does NOT include the Thumb
    // interworking bit (bit 0).  We must set it so that an indirect branch
    // (BLX Rx) will switch the CPU to Thumb mode before executing the code.
    using DriverEntryFn = NTSTATUS(NTAPI *)(PDRIVER_OBJECT, PUNICODE_STRING);
    auto entry_addr = reinterpret_cast<ULONG_PTR>(
        static_cast<char *>(m_base) + nth->OptionalHeader.AddressOfEntryPoint);
#if defined(_M_ARM) || defined(__arm__)
    entry_addr |= 1U; // set Thumb interworking bit
#endif
    auto *entry = reinterpret_cast<DriverEntryFn>(entry_addr);
    DL_LOG_INFO("CallDriverEntry -> {:p}", reinterpret_cast<void *>(entry));
    gActiveEntryLoader = this;
    void *veh = AddVectoredExceptionHandler(1, &EntryExceptionDiagnostics);
    NTSTATUS status = entry(&m_driverObject, &m_registryPathStr);
    if (veh)
        RemoveVectoredExceptionHandler(veh);
    gActiveEntryLoader = nullptr;
    DL_LOG_INFO("CallDriverEntry <- 0x{:08X}", static_cast<unsigned long>(status));
    return status;
}

// ---------------------------------------------------------------------------
// GetExport  (by name)
// ---------------------------------------------------------------------------

void *DriverLoader::GetExport(const std::string &name) const
{
    if (!m_base)
        return nullptr;

    const IMAGE_DATA_DIRECTORY *export_dir = GetDataDir(m_base, IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (!export_dir)
        return nullptr;

    const auto *ied =
        static_cast<const IMAGE_EXPORT_DIRECTORY *>(RvaToPtr(m_base, export_dir->VirtualAddress));

    const DWORD *name_ptrs = static_cast<const DWORD *>(RvaToPtr(m_base, ied->AddressOfNames));
    const WORD *ordinals = static_cast<const WORD *>(RvaToPtr(m_base, ied->AddressOfNameOrdinals));
    const DWORD *funcs = static_cast<const DWORD *>(RvaToPtr(m_base, ied->AddressOfFunctions));

    for (DWORD i = 0; i < ied->NumberOfNames; ++i)
    {
        const char *export_name = static_cast<const char *>(RvaToPtr(m_base, name_ptrs[i]));
        if (name == export_name)
        {
            const DWORD rva = funcs[ordinals[i]];
            // Check for forwarded export (RVA inside the export directory).
            if (rva >= export_dir->VirtualAddress &&
                rva < export_dir->VirtualAddress + export_dir->Size)
                return nullptr; // Forwarded exports not resolved here.
            return RvaToPtr(m_base, rva);
        }
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// GetExport  (by ordinal)
// ---------------------------------------------------------------------------

void *DriverLoader::GetExport(std::uint16_t ordinal) const
{
    if (!m_base)
        return nullptr;

    const IMAGE_DATA_DIRECTORY *export_dir = GetDataDir(m_base, IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (!export_dir)
        return nullptr;

    const auto *ied =
        static_cast<const IMAGE_EXPORT_DIRECTORY *>(RvaToPtr(m_base, export_dir->VirtualAddress));

    if (ordinal < ied->Base || static_cast<DWORD>(ordinal - ied->Base) >= ied->NumberOfFunctions)
        return nullptr;

    const DWORD *funcs = static_cast<const DWORD *>(RvaToPtr(m_base, ied->AddressOfFunctions));

    const DWORD rva = funcs[ordinal - ied->Base];
    if (rva == 0)
        return nullptr;
    // Check for forwarded export (RVA falls inside the export directory).
    if (rva >= export_dir->VirtualAddress && rva < export_dir->VirtualAddress + export_dir->Size)
        return nullptr; // Forwarded exports not resolved here.
    return RvaToPtr(m_base, rva);
}

void *DriverLoader::GetDebugSymbol(const std::string &name) const
{
    if (!m_dbghelpAttached || m_dbghelpModuleBase == 0 || name.empty())
    {
        return nullptr;
    }

    SYMBOL_INFO_PACKAGE sip = {};
    sip.si.SizeOfStruct = sizeof(SYMBOL_INFO);
    sip.si.MaxNameLen = MAX_SYM_NAME;
    if (!SymFromName(GetCurrentProcess(), name.c_str(), &sip.si))
    {
        return nullptr;
    }
    return reinterpret_cast<void *>(sip.si.Address);
}

bool DriverLoader::GetDebugSymbolRange(
    const std::string &name, std::uintptr_t &start, std::uintptr_t &endExclusive) const
{
    start = 0;
    endExclusive = 0;
    if (!m_dbghelpAttached || m_dbghelpModuleBase == 0 || name.empty())
    {
        return false;
    }

    const HANDLE process = GetCurrentProcess();
    SYMBOL_INFO_PACKAGE sip = {};
    sip.si.SizeOfStruct = sizeof(SYMBOL_INFO);
    sip.si.MaxNameLen = MAX_SYM_NAME;
    if (!SymFromName(process, name.c_str(), &sip.si))
    {
        return false;
    }

    const DWORD64 symbol_start = sip.si.Address;
    DWORD64 symbol_end_exclusive = 0;
    if (sip.si.Size > 0)
    {
        symbol_end_exclusive = symbol_start + sip.si.Size;
    }
    else
    {
        NextSymbolSearch search{};
        search.start = symbol_start;
        search.next = 0;
        const DWORD64 module_base = SymGetModuleBase64(process, symbol_start);
        if (module_base != 0 &&
            SymEnumSymbols(process, module_base, nullptr, &FindNextSymbolCb, &search) &&
            search.next > symbol_start)
        {
            symbol_end_exclusive = search.next;
        }
    }

    if (symbol_end_exclusive <= symbol_start)
    {
        return false;
    }
    start = static_cast<std::uintptr_t>(symbol_start);
    endExclusive = static_cast<std::uintptr_t>(symbol_end_exclusive);
    return true;
}

std::optional<std::pair<std::uintptr_t, std::uintptr_t>>
DriverLoader::TryGetDebugSymbolRange(const std::string &name) const
{
    std::uintptr_t start = 0;
    std::uintptr_t endExclusive = 0;
    if (!GetDebugSymbolRange(name, start, endExclusive))
    {
        return std::nullopt;
    }
    return std::make_pair(start, endExclusive);
}

std::wstring DriverLoader::BuildDefaultRegistryPath() const
{
    std::wstring path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
    path += m_driverName;
    return path;
}

std::wstring DriverLoader::DeriveDriverNameFromPath(std::string_view path)
{
    const std::size_t slash = path.find_last_of("/\\");
    const std::string_view file = (slash == std::string_view::npos) ? path : path.substr(slash + 1);
    const std::size_t dot = file.find_last_of('.');
    const std::string_view stem = (dot == std::string_view::npos) ? file : file.substr(0, dot);

    if (stem.empty())
    {
        return {};
    }

    int required = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, stem.data(), static_cast<int>(stem.size()), nullptr, 0);
    if (required <= 0)
    {
        required =
            MultiByteToWideChar(CP_ACP, 0, stem.data(), static_cast<int>(stem.size()), nullptr, 0);
        if (required <= 0)
        {
            return {};
        }
        std::wstring out(static_cast<std::size_t>(required), L'\0');
        (void)MultiByteToWideChar(
            CP_ACP, 0, stem.data(), static_cast<int>(stem.size()), out.data(), required);
        return out;
    }

    std::wstring out(static_cast<std::size_t>(required), L'\0');
    (void)MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        stem.data(),
        static_cast<int>(stem.size()),
        out.data(),
        required);
    return out;
}

void DriverLoader::SetDriverName(std::wstring name)
{
    if (name.empty())
    {
        throw std::runtime_error("Driver name must not be empty");
    }
    m_driverName = std::move(name);
}

DriverLoader *DriverLoader::FromDriverObject(const DRIVER_OBJECT *driver_object) noexcept
{
    if (!driver_object)
        return nullptr;
    std::lock_guard<std::mutex> lock(s_driverObjectMapMutex);
    const auto it = s_driverObjectMap.find(driver_object);
    if (it == s_driverObjectMap.end())
        return nullptr;
    return it->second;
}
