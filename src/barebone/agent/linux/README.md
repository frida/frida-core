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

How those bytes reach the host is deliberately left to whoever opens the device — on
a phone that means a small relay plus `adb forward`, in a VM whatever the guest
already has. On Android the node is created by devtmpfs without a policy-specific
label, so an SELinux-enforcing system needs the client's domain granted access to it
before it can open the device. A socket-based transport was the other option considered and is a worse
fit: `AF_VSOCK` only reaches a peer when a hypervisor is on the other side, and
having the kernel connect out to loopback needs something already listening before
the module loads.

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
- **Shadow call stack.** With `CONFIG_SHADOW_CALL_STACK` the kernel reserves x18,
  so the SDK and Gum are built `-ffixed-x18` and the Rust half with
  `+reserve-x18`. Anything linked in that uses x18 as a scratch register clobbers
  the kernel's SCS pointer and faults the next instrumented function it calls.

## The soft-float libc

The sysroot's `libc.a` is picolibc plus the compiler-rt builtins, with two families
of members removed — see `make-softfloat-libc.sh`, which is what assembles it:

- **The allocator.** The agent implements `malloc` and friends over the kernel's
  own allocator, so picolibc's would be a duplicate definition sitting on a fixed
  sbrk heap.
- **`memcpy-stub.c.o` and `memmove-stub.c.o`.** Both never return for the sizes the
  JavaScript engine actually uses, so the agent defines its own. `memcpy` hangs on
  a copy of sixteen bytes or more whose source is misaligned, which QuickJS first
  does while interning a predefined atom longer than fifteen characters — the agent
  then never finishes starting. `memmove` hangs while the compiler compacts
  bytecode, so a script parses and then wedges between being read and being run.
  Either way a CPU spins until the host's watchdog fires.

Re-run `make-softfloat-libc.sh` after rebuilding the SDK: a fresh picolibc puts all
of these back, and the agent hangs again.

## What a script may look like

The runtime compiles scripts on a kernel thread's stack, and QuickJS parses
expressions by recursion, so the ceiling is nesting rather than length: roughly
fourteen levels of parentheses or fifteen of object literals on arm64 Linux, where
that stack is 16 KiB. A script that exceeds it fails to compile rather than taking
anything down, though the message is not always `stack overflow` — an over-deep
`if`/`else` chain reports `expecting ';'`. Long scripts are fine; deep ones are not.
