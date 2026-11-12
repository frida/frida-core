# Linux kernel module

The agent the Barebone backend injects into a Linux guest from the outside,
loaded from the inside instead. The module is a loader and nothing more: it
carries the same `linux-injected` image a hypervisor would write into guest
memory, maps and relocates it, and starts it. Everything past that point is the
one implementation, whichever way the agent got in: the GumJS runtime, process
and module enumeration, cloaking, the userspace injector.

## What the loader does

|                    | From the outside                              | From the inside (`frida-agent.ko`)               |
|--------------------|-----------------------------------------------|--------------------------------------------------|
| Delivery           | host writes the image into guest memory       | `insmod`; the image is embedded in the module    |
| Relocation         | host applies `.rela.dyn`                      | loader applies `.rela.dyn` (`.rel.dyn` on x86)   |
| `.kernel_addrs`    | host fills the slots from its symbol source   | loader fills them from kallsyms                  |
| Struct layouts     | BTF                                           | `offsetof()` table from the module's headers, BTF behind it |
| Symbol table       | supplied by the host                          | built by the loader from kallsyms                |
| Transport          | virtio hostlink or vsock                      | `/dev/frida` character device                    |
| Writable alias     | host rewrites page tables                     | `vmap()` of the same pages                       |
| Lifetime           | ends when the host detaches                   | resident until `rmmod`                           |

The configuration the agent starts from is the same GVariant either way; the
loader writes one naming the character device as its transport. A slot the
loader fills that the host never does — the link functions, the layout table,
the writable alias — is what tells the agent it was loaded from the inside.

## Building

Three inputs besides this repository: a GumJS devkit for
`none-<arch>-softfloat_pic`, the SDK it was built against, and the kernel the
module is for. Building the image needs no kernel and runs anywhere; only the
kbuild step needs the kernel's build tree.

### Toolchain

    rustup toolchain install nightly
    rustup component add rust-src --toolchain nightly

The image links with `rust-lld`; nothing GNU is involved. clang has to be 19 or
newer, which is where `-mabi=aapcs-soft` landed. The kbuild step wants whatever
compiler the kernel was built with.

### The devkit and the SDK

    version=17.26.2
    arch=arm64          # or x86_64
    base=https://github.com/frida/frida/releases/download/$version
    curl -LO $base/frida-gumjs-devkit-$version-none-$arch-softfloat_pic.tar.xz
    mkdir -p ~/gumjs-devkit
    tar -C ~/gumjs-devkit -xf frida-gumjs-devkit-$version-none-$arch-softfloat_pic.tar.xz

    releng/deps.py sync sdk none-$arch-softfloat_pic ~/sdk-none-$arch-softfloat_pic

`releng/deps.toml` pins which SDK a devkit was built against, and mixing the two
leaves symbols undefined at link time.

### For the running kernel

    make -C src/barebone/agent/linux \
        FRIDA_SDK=$HOME/sdk-none-$arch-softfloat_pic \
        GUMJS_DEVKIT_DIR=$HOME/gumjs-devkit

`KDIR`, the Rust target and the kernel's name for the architecture all follow
from the running kernel. `make frida-agent.elf` stops after the image, which is
also what the Barebone backend injects from the outside.

### For an Android device

The image is built the same way; it is the kernel tree that takes assembling.
`uname -r` ends in the GKI commit and the build number:

    adb shell uname -r
    6.6.102-android15-8-g6eb5b2a8c46b-ab14739656-4k

which is commit `6eb5b2a8c46b` and build `14739656`. The source comes from the
commit, the CRCs `CONFIG_MODVERSIONS` checks from what CI published for the
build, and the config from the device itself:

    commit=6eb5b2a8c46b
    build=14739656
    ci=https://ci.android.com/builds/submitted/$build/kernel_aarch64/latest/raw

    mkdir -p ~/kernel
    curl -sSL https://android.googlesource.com/kernel/common/+archive/$commit.tar.gz \
        | tar -xz -C ~/kernel
    curl -sSL $ci/kernel_aarch64_Module.symvers -o ~/kernel/Module.symvers
    adb shell "su -c 'cat /proc/config.gz'" | gunzip > ~/kernel/.config
    make -C ~/kernel ARCH=arm64 LLVM=1 olddefconfig modules_prepare

That wants a Linux host, of either architecture, with clang and lld. With
`CONFIG_MODVERSIONS` the kernel matches a module by its CRCs rather than by the
release vermagic names, so the release this tree reports does not have to be
the device's; the vendor's own modules do not carry it either.

    make -C src/barebone/agent/linux \
        ARCH=arm64 BITS=64 \
        FRIDA_SDK=$HOME/sdk-none-arm64-softfloat_pic \
        GUMJS_DEVKIT_DIR=$HOME/gumjs-devkit \
        KDIR=$HOME/kernel \
        LLVM=1

    adb push src/barebone/agent/linux/frida-agent.ko /data/local/tmp/

## Loading

    insmod frida-agent.ko

Init returns once the agent's worker is running and `/dev/frida` is there.
`rmmod frida-agent` stops the agent, waits for its worker to leave the image,
and only then frees it.

## Talking to it

The agent waits on `/dev/frida`: one client at a time, `read`/`write` of the
same length-prefixed frames the other transports carry, with `poll` for
readiness. It never dials out, so there is no network namespace to get right
and no ordering between loading the module and attaching a client.

On Android devtmpfs creates the node without a policy-specific label, so an
SELinux-enforcing system needs the client's domain granted access to it.

Serve the Barebone device from a frida-server running on the target, so the
`open()` happens next to the device node:

    FRIDA_BAREBONE_CONFIG=/data/local/tmp/linux-kmod.json \
        frida-server --device barebone -l 127.0.0.1:27042

`etc/linux-kmod.json` is that config. Its `"type": "resident"` is what keeps a
client leaving from stopping the agent. From the host, with
`adb forward tcp:27042 tcp:27042` in place:

    frida -H 127.0.0.1:27042 -p 0

## Injecting into userspace

On x86_64 and arm64 a resident agent doubles as a ptrace-free injector for
ordinary processes — how the Linux local backend reaches its targets when the
agent is there, falling back to `ptrace` when it is not. The channel is
`prctl()` with a magic option and a token in the fifth argument,

    prctl(0x46524944, op, arg1, arg2, 0x1d5f9e6b2c7a4038)

and any call whose option or token does not match falls through to the real
prctl, so probing for the agent looks like a stock kernel. `op` 32 pings and
returns the magic.

Allocate, free, read, write and spawn — what the injector drives against a
target pid — require `CAP_SYS_ADMIN`. A spawned thread is a real member of the
target's thread group that adopts its mm, files, credentials, namespaces, fs
and SysV semaphore undo list, rather than a kernel thread wearing its address
space.

Cloaking is Gum's own registry mirrored into the kernel, so it holds against
`/proc` too: the agent intercepts the `maps`, `smaps`, task and status readers
and drops cloaked threads, ranges and fds while keeping the counts consistent. A
process cloaks its own resources with the token alone, so an injected agent
self-cloaks by forwarding Gum's updates over the same channel. A cloaked thread
still sees through the cloak when it reads `/proc`.

## What the target kernel has to provide

- **x86_64 or arm64** for everything above; 32-bit x86 and ARM load the agent
  but have no injector.
- **`CONFIG_KPROBES` and `CONFIG_KALLSYMS_ALL`.** Most of what the agent calls
  is compiled in but not exported, and GKI trims its export table to the KMI
  symbol list on top of that. The loader finds `kallsyms_lookup_name` through a
  kprobe and resolves the rest by name.
- **Unsigned modules.** `CONFIG_MODULE_SIG_FORCE` must be off. Android's
  `CONFIG_MODULE_SIG_PROTECT` is fine: it only demands signatures for modules on
  the GKI list.
- **No BTI on arm64.** The image has no landing pads, so a CPU implementing BTI
  under a kernel built with `CONFIG_ARM64_BTI_KERNEL` faults the first indirect
  call into it.

## Kernel ABI constraints

A hardened kernel imposes an ABI on anything running inside it, which the image
honors whichever way it got in:

- **FP/SIMD.** JavaScript numbers are doubles, so a hardfloat build would use FP
  for as long as the runtime lives, and neither architecture lets a kernel
  thread hold it for free — x86 wants every stretch bracketed by
  `kernel_fpu_begin()`, and on arm64 kernels before 6.9 there is no correct way
  to hold it at all. Building everything soft-float removes the question: the
  SDK, the devkit and the Rust target all use the soft-float ABI.
- **Indirect branch tracking (x86_64).** With `CONFIG_X86_KERNEL_IBT` an
  indirect call landing on anything but an `endbr64` faults, so the image is
  built `-fcf-protection=branch` and `-Zcf-protection=branch`, with switches
  compiled as comparisons rather than `notrack` jump tables. The kernel seals
  the `endbr64` of every function it saw no indirect call to, so the loader
  restores it on any it hands the agent to call.
- **Shadow call stack (arm64).** With `CONFIG_SHADOW_CALL_STACK` the kernel
  reserves x18, so the SDK, the devkit and the Rust target all leave it alone.
  `core`, `alloc` and `compiler_builtins` are rebuilt from source with
  `-Z build-std` so that holds for them too.
- **Stack.** The runtime runs on a kernel thread's stack, and QuickJS parses
  expressions by recursion, so the ceiling is nesting rather than length: around
  fourteen levels of parentheses or fifteen of object literals on a 16 KiB
  kernel stack. A script that exceeds it fails to compile rather than taking
  anything down, though the message is not always `stack overflow`.
