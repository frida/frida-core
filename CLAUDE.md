# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code)
when working with code in this repository.

## What This Is

frida-core is the core library of the Frida dynamic
instrumentation toolkit. It packages GumJS into a shared
library, injects JavaScript instrumentation into target
processes, provides bidirectional RPC communication with
injected scripts, and enumerates apps/processes/devices.
Written primarily in Vala with OS-specific glue in
C/Objective-C/asm.

## Build Commands

```bash
# First-time setup (fetches git submodules, configures build):
./configure \
    --enable-compiler-backend \
    --with-devkits=core \
    --enable-tests

# Build:
make

# Run tests:
make test

# Rebuild after code changes
make
```

The `configure` script and `Makefile` are thin wrappers
around `releng/meson_configure.py` and
`releng/meson_make.py`. The actual build system is Meson
(>=1.1.0).

Build artifacts go into `build/`. The triplet is
platform-dependent (e.g. `linux-x86_64`).

## Build Requirements

- **Vala compiler**: Must be the Frida-optimized fork from
  https://github.com/frida/vala (checks for `-frida` suffix
  in version)
- **C/C++ standards**: gnu99/c99 for C, c++17 for C++
- **Go >= 1.24**: Required for compiler backend
- **Python 3**: Build scripts

## Architecture

### Backend System

The core abstraction is a pluggable backend system. Each
backend implements `HostSessionBackend` and provides a
`HostSessionProvider` to create sessions with target
processes:

- **local** — Injects into processes on the local system
  (Linux, macOS, Windows, FreeBSD, QNX)
- **fruity** — iOS/tvOS/xrOS devices via USB/network
  (QUIC, lockdown protocols)
- **droidy** — Android devices via ADB/JDWP
- **socket** — Remote devices via TCP (connects to
  frida-server, frida-gadget, frida-portal)
- **barebone** — Minimal backend using QuickJS
- **simmy** — macOS Simulator
- **compiler** — TypeScript/ESBuild compilation backend
  (Go + TypeScript in `src/compiler/`)

Backends are selected at build time via meson options
(e.g. `-Dlocal_backend=enabled`).

### Key Source Layout

- **`src/frida.vala`** — Public API: `DeviceManager`,
  `Device`, `Session`, `Script`
- **`src/host-session-service.vala`** — Backend
  orchestration, provider registration
- **`src/control-service.vala`** — the guts of frida-server
- **`src/portal-service.vala`** — the guts of frida-portal,
  which looks like a frida-server that surfaces any joined
  processes (think aggregator/reverse proxy)
- **`lib/base/`** — Core primitives: Session, RPC, streams,
  sockets, P2P, buffers
- **`lib/agent/`** — In-process JavaScript agent runtime
- **`lib/payload/`** — Payload compilation and embedding
- **`lib/gadget/`** — Gadget (preloaded library)
  implementation
- **`src/<platform>/`** — Platform-specific injectors and
  helpers (`linux/`, `darwin/`, `windows/`, `freebsd/`,
  `qnx/`)
- **`src/fruity/`** — iOS device protocol stack (USB, QUIC,
  plist, XPC, LLDB)
- **`src/droidy/`** — Android device protocol stack
- **`src/compiler/`** — Go/TypeScript compiler backend

### Injection Flow

Each platform has its own injector (e.g. `Linjector` on
Linux, `Fruitjector` on Darwin, `Winjector` on Windows). A
helper process (`frida-helper`) performs privileged injection
operations out-of-process. Helpers and agents can be embedded
into the library or installed as separate files (controlled
by the `assets` meson option).

### Deliverables

- **frida-server** (`server/`) — Standalone daemon exposing
  the full API over the network
- **frida-portal** (`portal/`) — Cluster node for
  distributed instrumentation
- **frida-inject** (`inject/`) — CLI tool for one-shot
  script injection
- **frida-gadget** (`lib/gadget/`) — Shared library for
  preload-based instrumentation

### Resource Embedding

Build artifacts (frida-helper, frida-agent) are compiled
into resource blobs via `tools/resource-compiler.vala` and
embedding scripts (`src/embed-helper.py`,
`src/embed-agent.py`). On non-MSVC toolchains these become
`.S` assembly files; on MSVC they become `.obj` files.

## Tests

Tests are in `tests/` as Vala files using a custom async
test harness (`tests/async-harness.vala`). Test binary is
`tests/frida-tests`. Platform-specific runner scripts exist
(e.g. `tests/run-linux-x86_64.sh`).

Test modules: `test-system`, `test-injector`, `test-agent`,
`test-host-session`, `test-gadget`, `test-compiler`. Test
helper programs ("labrats") are in `tests/labrats/`.

## Commit Style

- Subject line: max 50 characters
- Body lines: wrap at 72 characters (use the full width, or
  slightly less if it avoids making the next line awkward)
