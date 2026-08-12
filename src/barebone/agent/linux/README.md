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

Four inputs: this repository, a GumJS devkit built for `none-arm64-softfloat`, the
soft-float SDK it was built against, and the kernel the module is for. The example
below targets a Pixel; adapt the kernel step to whatever the system is.

### Toolchain

    rustup target add aarch64-unknown-none
    rustup component add rust-src
    sudo apt-get install build-essential clang binutils-aarch64-linux-gnu

clang must be 19 or newer, since that is where `-mabi=aapcs-soft` landed; GCC does
not implement it at any version. The binutils are for the prelink, which reads the
archive map that only GNU `nm` prints — the LLVM one does not. The host compiler is
for Cargo's own build scripts, which run on the machine doing the building.

The commands below are run from the top of this repository, with `releng` checked
out — `git submodule update --init releng` if the clone did not recurse.

### The devkit and the SDK

    version=17.17.0
    base=https://github.com/frida/frida/releases/download/$version
    curl -LO $base/frida-gumjs-devkit-$version-none-arm64-softfloat.tar.xz
    mkdir -p ~/gumjs-devkit
    tar -C ~/gumjs-devkit -xf frida-gumjs-devkit-$version-none-arm64-softfloat.tar.xz

    releng/deps.py sync sdk none-arm64-softfloat ~/sdk-none-arm64-softfloat

The SDK carries picolibc and the compiler-rt builtins the devkit expects to be linked
against, and `releng/deps.toml` pins which one. Mixing a devkit with an SDK built for
a different libc leaves undefined symbols at prelink time.

### The kernel

Nothing here needs the device's own kernel to be built, but the config alone is not
enough either. `uname -r` ends in the GKI commit and the build number:

    adb shell uname -r
    6.1.145-android14-11-gc1de4747ac59-ab14219743

which is commit `c1de4747ac59` and build `14219743`. Three pieces are keyed to them:

    commit=c1de4747ac59
    build=14219743
    ci=https://ci.android.com/builds/submitted/$build/kernel_aarch64/latest/raw

    mkdir -p ~/kernel-prepared ~/kernel-source
    curl -sSL $ci/modules_prepare_outdir.tar.gz | tar -xz -C ~/kernel-prepared
    curl -sSL $ci/kernel_aarch64_Module.symvers -o ~/kernel-prepared/Module.symvers
    curl -sSL https://android.googlesource.com/kernel/common/+archive/$commit.tar.gz \
        | tar -xz -C ~/kernel-source

`modules_prepare_outdir.tar.gz` is the configured build tree with `scripts/` already
compiled as x86-64 binaries, so the kbuild half has to run on an x86-64 Linux host —
an arm64 one gets as far as `CC [M]` and then fails to run `fixdep`. `Module.symvers`
carries the CRCs `CONFIG_MODVERSIONS` checks. The top-level `Makefile` in that prepared tree is a stub
that includes the source's, hence both `KDIR` and `KOUT` below.

A different GKI build of the same branch does not substitute for these: vermagic is
compared verbatim, and it names the exact build.

### Build

    make -C src/barebone/agent/linux \
        FRIDA_SDK=$HOME/sdk-none-arm64-softfloat \
        GUMJS_DEVKIT_DIR=$HOME/gumjs-devkit \
        AGENT_LD=aarch64-linux-gnu-ld \
        AGENT_AR=aarch64-linux-gnu-ar \
        AGENT_NM=aarch64-linux-gnu-nm \
        AGENT_OBJCOPY=aarch64-linux-gnu-objcopy \
        KDIR=$HOME/kernel-source \
        KOUT=$HOME/kernel-prepared \
        LLVM=1

`make` builds the Rust staticlib itself, prelinks it against the devkit and the SDK,
then hands the result to kbuild. The `AGENT_*` overrides are only needed because the
defaults name the `aarch64-none-elf-` toolchain the XNU flavour uses; drop them if
that is what is installed.

The prelink half runs anywhere; the kbuild half needs the x86-64 Linux host above.
Cross-building from macOS means running that step in a container holding the kernel
tree.

    adb push src/barebone/agent/linux/frida-agent.ko /data/local/tmp/

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

## Injecting into userspace

Loaded on a live system the module doubles as a ptrace-free injector for ordinary
processes — how the Linux local backend reaches its targets when the module is
present, falling back to `ptrace` when it is not. There is no second device node;
the channel is `prctl()` with a magic option and a token in the fifth argument,

    prctl(0x46524944, op, arg1, arg2, 0x1d5f9e6b2c7a4038)

and any call whose option or token does not match falls through to the real
prctl, so probing for the module looks like a stock kernel. `op` 32 pings and
returns the magic.

Allocate, free, read, write and spawn — the primitives the injector drives
against a target pid — require `CAP_SYS_ADMIN`. A spawned thread is a real
`CLONE_THREAD` sibling that adopts the target's mm, files, credentials,
namespaces, fs and SysV semaphore undo list, so it is a native member of the
group rather than a kernel thread wearing its address space.

Cloaking is Gum's own registry mirrored into the kernel so it holds against
`/proc` too: the module intercepts the `maps`, `smaps`, task and status readers
and drops cloaked threads, ranges and fds while keeping the counts consistent. A
process cloaks its own resources with the token alone — no capability — so an
injected agent self-cloaks by forwarding Gum's updates over the same channel,
and the loader adds the footprint the agent itself never sees. A cloaked thread
still sees through the cloak when it reads `/proc`, so the agent is not blind to
its own process.

## What the target kernel has to provide

- **arm64.** The register-level pieces (`tcr_el1` for the page size, cache
  maintenance) are aarch64-only, matching the XNU flavour.
- **`CONFIG_KPROBES` and `CONFIG_KALLSYMS_ALL`.** A good deal of what the shim
  needs is compiled in but not exported — `kallsyms_lookup_name`,
  `kallsyms_on_each_symbol` and `set_memory_*` all are, and GKI trims its export
  table to the KMI symbol list on top of that. The shim resolves them by name
  through a kprobe, which is the standard way back in. Without kallsyms the module
  still loads but cannot look up symbols or change page permissions.
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
