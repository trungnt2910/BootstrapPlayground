"""
Wrap POSIX type #define macros in config.h with glibc guard macros.

When cross-compiling bash for a MinGW target from a Linux host, bash's
configure script writes #define macros into config.h for POSIX types that it
cannot find on the target (e.g. "#define uid_t int").  However, config.h is
also included by HOST-compiled build utilities (mksignames, mksyntax, etc.).
When those utilities then include glibc headers, glibc tries to typedef the
same type (e.g. "typedef __uid_t uid_t;"), but the preprocessor first expands
the uid_t macro, turning the typedef into "typedef unsigned int int;" which
triggers a "two or more data types in declaration specifiers" error.

Fix: wrap each such #define with the glibc guard macro that glibc sets after
it performs the typedef.  On the host, glibc has already set the guard by the
time config.h is processed, so the #define is skipped.  On the Windows target
the guard is never set, so the #define applies normally.
"""
import re
import sys

# Map each POSIX type to the glibc guard macro set when glibc typedefs it.
GUARDS = {
    "uid_t":   "__uid_t_defined",
    "gid_t":   "__gid_t_defined",
    "clock_t": "__clock_t_defined",
    "pid_t":   "__pid_t_defined",
    "mode_t":  "__mode_t_defined",
    "dev_t":   "__dev_t_defined",
    "ino_t":   "__ino_t_defined",
    "nlink_t": "__nlink_t_defined",
    "off_t":   "__off_t_defined",
    "time_t":  "__time_t_defined",
}

path = sys.argv[1] if len(sys.argv) > 1 else "config.h"

with open(path) as f:
    text = f.read()

for typename, guard in GUARDS.items():
    text = re.sub(
        rf"^(#define {re.escape(typename)} .+)$",
        rf"#ifndef {guard}\n\1\n#define {guard}\n#endif",
        text,
        flags=re.MULTILINE,
    )

with open(path, "w") as f:
    f.write(text)

print(f"Patched {path}")
