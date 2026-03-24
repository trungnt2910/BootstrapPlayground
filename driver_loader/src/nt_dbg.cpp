// ---- Debug output ----------------------------------------------------------

#include <cstdio>

#include <windows.h>

#include "logger.hpp"
#include "nt_stubs_internal.hpp"

static
VOID
vprint_nt(std::string_view fmt, va_list args)
{
    size_t pos = 0;

    while (pos < fmt.size())
    {
        size_t nextPercent = fmt.find('%', pos);

        // Print literal text before the next '%'
        if (nextPercent > pos)
        {
            std::print(stderr, "{}", fmt.substr(pos, nextPercent - pos));
        }

        if (nextPercent == std::string_view::npos)
            break;

        pos = nextPercent + 1;
        if (pos >= fmt.size())
            break;

        // Handle specific format specifiers
        switch (fmt[pos])
        {
        case 'w': // Possible %wZ or %ws
            if (pos + 1 < fmt.size())
            {
                if (fmt[pos + 1] == 'Z')
                { // %wZ
                    if (auto pus = va_arg(args, PUNICODE_STRING); pus && pus->Buffer)
                    {
                        std::wstring_view wsv(pus->Buffer, pus->Length / sizeof(wchar_t));
                        for (auto c : wsv)
                            std::print(stderr, "{}", (char)c);
                    }
                    else
                    {
                        std::print(stderr, "(null)");
                    }
                    pos += 2;
                    continue;
                }
                else if (fmt[pos + 1] == 's')
                { // %ws
                    if (auto ws = va_arg(args, wchar_t *); ws)
                    {
                        while (*ws)
                            std::print(stderr, "{}", (char)*ws++);
                    }
                    else
                    {
                        std::print(stderr, "(null)");
                    }
                    pos += 2;
                    continue;
                }
            }
            break;

        case 'h': // Possible %hs
            if (pos + 1 < fmt.size() && fmt[pos + 1] == 's')
            {
                if (auto s = va_arg(args, const char *); s)
                {
                    std::print(stderr, "{}", s);
                }
                else
                {
                    std::print(stderr, "(null)");
                }
                pos += 2;
                continue;
            }
            break;

        case 'Z': // %Z (ANSI_STRING)
            if (auto pas = va_arg(args, PSTRING); pas && pas->Buffer)
            {
                std::print(stderr, "{}", std::string_view(pas->Buffer, pas->Length));
            }
            else
            {
                std::print(stderr, "(null)");
            }
            pos += 1;
            continue;

        case 'd':
        case 'i':
            std::print(stderr, "{}", va_arg(args, int));
            pos += 1;
            continue;

        case 'u':
            std::print(stderr, "{}", va_arg(args, unsigned int));
            pos += 1;
            continue;

        case 'x':
            std::print(stderr, "{:x}", va_arg(args, unsigned int));
            pos += 1;
            continue;

        case 'X': // Fix: use explicit compile-time strings
            std::print(stderr, "{:X}", va_arg(args, unsigned int));
            pos += 1;
            continue;

        case 'p':
            std::print(stderr, "{:p}", va_arg(args, void *));
            pos += 1;
            continue;

        case 'l': // Handle %llu / %llx (64-bit)
            if (pos + 1 < fmt.size() && fmt[pos + 1] == 'l')
            {
                pos += 2;
                if (pos < fmt.size())
                {
                    auto ull = va_arg(args, unsigned long long);
                    if (fmt[pos] == 'x')
                        std::print(stderr, "{:x}", ull);
                    else
                        std::print(stderr, "{}", ull);
                    pos += 1;
                    continue;
                }
            }
            break;

        case '%':
            std::print(stderr, "%");
            pos += 1;
            continue;
        }

        // Default fallback: If we don't recognize the sequence, just print the % and move on
        std::print(stderr, "%");
        DL_LOG_WARNING("Unimplemented printf specifier: {}", fmt[pos]);
    }
}

static ULONG impl_DbgPrint(const char *fmt, ...)
{
    NT_STUB_REPORT();
    va_list args;
    va_start(args, fmt);
    vprint_nt(fmt, args);
    va_end(args);
    return 0;
}

static ULONG impl_DbgPrintEx(ULONG /*componentId*/, ULONG /*level*/, const char *fmt, ...)
{
    NT_STUB_REPORT();
    va_list args;
    va_start(args, fmt);
    vprint_nt(fmt, args);
    va_end(args);
    return 0;
}
