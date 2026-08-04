# Linux kernel module

The same agent that the Barebone backend injects into XNU from the outside, but
loaded from the inside as an ordinary kernel module.

## How it differs from the XNU flavour

|                   | XNU                                              | Linux                                     |
|-------------------|--------------------------------------------------|-------------------------------------------|
| Delivery          | remote stub injects a freestanding ELF           | `insmod frida-agent.ko`                   |
| Kernel primitives | addresses patched into `.kernel_addrs` by the host | direct calls into `frida-kmod.c`        |
| Bootstrap config  | GVariant blob written into guest memory          | module parameters                         |
| Transport         | virtio hostlink or vsock                         | `/dev/frida` character device             |
| Page permissions  | host rewrites descriptors over the hostlink      | `set_memory_*()`                          |
| Writable alias    | shadow copy, committed via physical-memory bridge | `vmap()` of the same pages               |
| Symbols           | table supplied by the host                       | kallsyms                                  |

Because the Linux agent performs its own memory work, it never issues the
`RemapWritablePages`, `MemoryProtect` or `PatchCode` host RPCs. The wire protocol
is otherwise identical, so the host side sees the same `(yqv)` frames.

## Building

    export GUMJS_DEVKIT_DIR=/path/to/frida-gum/build/bindings/gumjs/devkit
    make -C linux KDIR=/path/to/kernel/build

`make` builds the Rust staticlib itself, then prelinks it and hands the result to
kbuild. `KDIR` must be the configured build tree of the kernel the module is for:
same source commit, same config. Under `CONFIG_MODVERSIONS` anything else is rejected
at load time, and the `module_layout` CRC covers `struct module` itself, so even
config options that merely add fields to it — `CONFIG_DEBUG_INFO_BTF_MODULES`, for
one — have to match.

The prelink half runs anywhere; the kbuild half needs a Linux host. Cross-building
from macOS means running that step in a container holding the kernel tree.

### Getting a KDIR for an Android device

Nothing here needs the device's own kernel to be built, but the config alone is not
enough either. `uname -r` ends in the GKI commit and the build number — for
`6.1.145-android14-11-gc1de4747ac59-ab14219743` that is commit `c1de4747ac59` and
build `14219743` — and three pieces keyed to them are published:

- `modules_prepare_outdir.tar.gz` and `kernel_aarch64_Module.symvers` from
  `ci.android.com`, under that build's `kernel_aarch64` target. The first is the
  configured build tree with `scripts/` already compiled for a Linux x86-64 host; the
  second carries the CRCs `CONFIG_MODVERSIONS` checks.
- `kernel/common` at that commit, which a shallow single-commit fetch gets in a few
  hundred megabytes. Only its makefiles are wanted: the top-level `Makefile` in the
  prepared tree is a stub that includes the source's, so point it at wherever the
  fetch landed and build with `make -C <source> O=<outdir> M=<here>`.

A different GKI build of the same branch does not substitute for these: vermagic is
compared verbatim, and it names the exact build.

## Loading

    insmod frida-agent.ko

The module's init path returns as soon as the worker thread is running — watch
`dmesg` for `frida: listening on /dev/frida`. `rmmod frida-agent` unwinds in the
reverse order and does not return until the worker is off the module's text.

## Talking to it

The agent exposes `/dev/frida` and waits: one client at a time, `read`/`write` of the
same length-prefixed frames the other transports carry, with `poll` for readiness.
It never dials out, so there is no network namespace to get right and no ordering
requirement between loading the module and attaching a client.

On Android the node is created by devtmpfs without a policy-specific label, so an
SELinux-enforcing system needs the client's domain granted access to it before it can
open the device. A socket-based transport was the other option considered and is a
worse fit: `AF_VSOCK` only reaches a peer when a hypervisor is on the other side, and
having the kernel connect out to loopback needs something already listening before
the module loads.

### Reaching it from a host

Serve the Barebone device from a frida-server running on the target, so the `open()`
happens next to the device node and the host talks to an ordinary frida-server:

    FRIDA_BAREBONE_CONFIG=/data/local/tmp/linux-kmod.json \
        frida-server --device barebone -l 127.0.0.1:27042

`etc/linux-kmod.json` is that config. From the host, with `adb forward tcp:27042
tcp:27042` in place:

    frida -H 127.0.0.1:27042 -p 0

## What the target kernel has to provide

- **arm64.** The register-level pieces (`tcr_el1` for the page size, cache
  maintenance) are aarch64-only, matching the XNU flavour.
- **`CONFIG_KPROBES` and `CONFIG_KALLSYMS_ALL`.** A good deal of what the shim
  needs is compiled in but not exported — `kallsyms_lookup_name`,
  `kallsyms_on_each_symbol` and `set_memory_*` all are, and GKI trims its export
  table to the KMI symbol list on top of that. The shim resolves them by name
  through a kprobe, which is the standard way back in. Without kallsyms the module
  still loads but cannot look up symbols or change page permissions.
- **`CONFIG_VSOCKETS`**, plus a vsock transport for the guest.
- **Unsigned modules.** `CONFIG_MODULE_SIG_FORCE` must be off. Android's
  `CONFIG_MODULE_SIG_PROTECT` is fine: it only demands signatures for modules on
  the GKI list.

## Kernel ABI constraints

A hardened arm64 kernel imposes an ABI on anything linked into it, and both of the
constraints below are why this flavour is built against a soft-float SDK
(`none-arm64-softfloat`) rather than the prebuilt `none-arm64` one.

- **FP/SIMD.** JavaScript numbers are doubles, so a hardfloat build would use FP
  for as long as the runtime lives. Kernels from 6.9 preserve kernel-mode FP/SIMD
  across sleeping, but before 6.9 there is no correct way to hold it:
  `kernel_neon_begin()` runs with preemption disabled so we cannot sleep under it,
  and the scheduler does not save a kernel thread's FP registers — live values are
  lost on preemption and the FP state of whichever user task was interrupted is
  corrupted. Building everything `-mabi=aapcs-soft -mgeneral-regs-only` removes the
  question rather than answering it.
- **Shadow call stack.** With `CONFIG_SHADOW_CALL_STACK` the kernel reserves x18, so
  the SDK and Gum are built `-ffixed-x18` and the Rust half with `-Zfixed-x18`.
  Anything linked in that uses x18 as a scratch register overwrites the kernel's SCS
  pointer, and the thread then returns through whatever that address happens to hold.

  The Rust flag only reaches crates Cargo compiles, so `core`, `alloc` and
  `compiler_builtins` — which the toolchain ships prebuilt, and which between them
  account for every x18 write that used to reach the module — are rebuilt from source
  via `-Z build-std`. That needs `rustup component add rust-src`.

## The soft-float libc

The libc is picolibc and the compiler runtime is compiler-rt, both from the
`none-arm64-softfloat` SDK that `FRIDA_SDK` points at. `Makefile` trims a copy of its
`libc.a` before the prelink: the agent implements `malloc`, the C library's locks and
its process stubs over the kernel's own facilities, so picolibc's are duplicate
definitions rather than fallbacks. The set is derived from what the agent defines
rather than listed, since picolibc moves things between releases.

Those compiler-rt builtins are load-bearing in a way that is easy to miss. Rust's
toolchain carries its own `compiler_builtins`, compiled for the ordinary AAPCS where a
double travels in `d0`, and the prelink whole-archives the Rust staticlib — so without
the filtering step in `Makefile` those definitions answer the C library's calls to
`__muldf3` and friends, which pass the same double in `x0`. Nothing crashes. The
arithmetic simply returns garbage, and the first thing to notice is GLib deciding a
hash table need not grow.

## What a script may look like

The runtime compiles scripts on a kernel thread's stack, and QuickJS parses
expressions by recursion, so the ceiling is nesting rather than length: roughly
fourteen levels of parentheses or fifteen of object literals on arm64 Linux, where
that stack is 16 KiB. A script that exceeds it fails to compile rather than taking
anything down, though the message is not always `stack overflow` — an over-deep
`if`/`else` chain reports `expecting ';'`. Long scripts are fine; deep ones are not.
