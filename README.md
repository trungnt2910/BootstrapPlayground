# BootstrapPlayground

[![Build](https://github.com/trungnt2910/BootstrapPlayground/actions/workflows/build.yml/badge.svg)](https://github.com/trungnt2910/BootstrapPlayground/actions/workflows/build.yml)
[![Discord Invite](https://img.shields.io/discord/1185622479436251227?logo=discord&logoColor=white&label=Discord&labelColor=%235865F2)][1]

A playground for cross-compiling Windows binaries with [llvm-mingw](https://github.com/mstorsjo/llvm-mingw) and validating them under [WINE](https://www.winehq.org/) running inside a QEMU-emulated Debian environment — for all four major Windows architectures.

## What it does

1. **Cross-compiles** a simple "Hello World!" C++ program for Windows (x86, x64, ARM, ARM64) using the latest stable llvm-mingw toolchain.
2. **Runs** each binary under WINE inside an architecture-matched Debian chroot, using QEMU user-mode emulation — even when the host architecture matches the target.
3. **Releases** all four binaries as a versioned ZIP (`YYYYMMDD.XX`) on every successful `master` push.

## CI/CD overview

| Step | Tool |
|------|------|
| Cross-compilation | [llvm-mingw](https://github.com/mstorsjo/llvm-mingw) (UCRT, Ubuntu toolchain) |
| Target environment | Debian bookworm chroot via `qemu-debootstrap` |
| Architecture emulation | `qemu-user-static` (explicit invocation, all arches) |
| Windows emulation | WINE (from Debian bookworm repositories) |
| Release versioning | `YYYYMMDD.XX` determined via GitHub API |

## Architectures

| Matrix name | MinGW target | Debian arch | QEMU arch |
|-------------|--------------|-------------|-----------|
| `x86`       | `i686-w64-mingw32`    | `i386`  | `i386`    |
| `x64`       | `x86_64-w64-mingw32`  | `amd64` | `x86_64`  |
| `ARM`       | `armv7-w64-mingw32`   | `armhf` | `arm`     |
| `ARM64`     | `aarch64-w64-mingw32` | `arm64` | `aarch64` |

## Community

This repo is a part of [Project Reality][1].

Need help using this project? Join me on [Discord][1], and let's find a solution together.

[1]: https://reality.trungnt2910.com/discord
