# Ptrace-free injection fallback (Linux/Android)

## Problem

Our Linux injection relies on `ptrace` for the brief window where we
seize the target, allocate memory, write the bootstrapper, and remote-call
into it. Some applications and RASP solutions defend against this by
having a helper process `PTRACE_ATTACH` to the target purely to occupy the
tracer slot, so that Frida's `PTRACE_SEIZE`/`PTRACE_ATTACH` fails with
`EPERM`/`EBUSY`. We have no fallback today.

## Key insight

The "self-ptrace" defense consumes the *single tracer slot*, but it does
**not** block `/proc/$pid/mem`. Opening and writing `/proc/$pid/mem` is
gated by `ptrace_may_access(task, PTRACE_MODE_ATTACH_REALCREDS)` — a
credentials + Yama check — not by whether someone is already attached. The
kernel write path uses `FOLL_FORCE`, so we can write read-only and
executable file-backed pages, and `copy_to_user_page` flushes the I-cache
for us.

So as root (or same-uid with `yama.ptrace_scope <= 1`) we retain full R/W
on a target that has deliberately occupied its own ptrace slot. This is
exactly the scenario the fallback targets.

What we lose without ptrace: no thread-stop, no register access, no
remote-call primitive. Everything must be done by patching code/data and
letting the target's own threads execute it.

## What `/proc/$pid/mem` does and does not guarantee

`/proc/$pid/mem` offers **no atomicity contract**. The write path is
`mem_rw -> access_remote_vm -> copy_to_user_page`, an arch `memcpy` plus a
cache flush. `memcpy` makes no promise about store width or ordering.

What we lean on instead is one notch weaker than "atomic" but far stronger
than nothing: for a **naturally-aligned, word-sized** write, the kernel's
`memcpy` fast path emits a single store (`movq` on x86-64, `str`/`stp` on
arm64). This is an empirical property of every Linux kernel `memcpy` we'd
run against, not an ABI guarantee.

The real qualitative split is therefore **"does the write fit in one
aligned word":**

- A pointer-sized GOT slot is a single aligned word -> single-store fast
  path -> observed all-or-nothing in practice.
- An arm64 `B` is a single aligned 4-byte instruction -> same fast path.
  *And* arm64 architecturally guarantees that concurrent modification of
  `B`/`BL`/`NOP`/`BRK` to/from each other is well-defined for a fetching
  core, so we are on firm ground there, not just trusting the kernel.
- An x86 5-byte `jmp rel32` spans multiple words. It tears with certainty
  and x86 has no concurrent-modification guarantee for it. Disqualified.

The only *truly* atomic store into the target must be issued **from inside
the target** (a real aligned store or `lock`-prefixed RMW). There is no
cross-process atomic-store primitive on Linux short of a shared mapping,
which we cannot establish without already being inside.

## "Firing once is enough"

The hook exists only to get **one** thread into our stub **once**. As soon
as that happens we spawn a clean worker thread that does all the heavy
lifting, and the hook is never needed again. So we never need a second,
"fuller" patch, and there is no warm escalation step. The cold primitive is
always a single aligned-word write; we only choose *which* word per
arch/runtime.

## Cold primitive per target

| Target                         | Cold write (one aligned word)                              | Trigger                          | Coverage                  |
| ------------------------------ | ---------------------------------------------------------- | -------------------------------- | ------------------------- |
| arm64 (any)                    | `B` over the target fn's first instruction                 | next natural call                | full, guaranteed          |
| x86 app_process / ART          | `libart.so`'s `malloc` import GOT slot                     | `SIGUSR1` -> SignalCatcher       | enough (one hit)          |
| x86 native, triggerable GOT    | that GOT slot                                              | natural traffic                  | enough (one hit)          |
| x86 native, no GOT path        | 2-byte `EB rel8` over a single >=2-byte insn -> near cave  | natural traffic                  | best-effort, log residual |

Notes:

- On arm64 the cold `B` catches *all* callers and is architecturally safe,
  so no GOT and no escalation are needed.
- On x86 the cold primitive must be a data (GOT) write. We pick a slot that
  sits on a path we can *force* traffic down. For `app_process`, ART's
  internal allocations — including the `SignalCatcher` thread's work when we
  send `SIGUSR1` — call libc `malloc` through `libart.so`'s own import slot,
  so patching that slot guarantees a hit. `FOLL_FORCE` punches through full
  RELRO.
- The native-x86 "no GOT path" corner is the only place we write code cold.
  The 2-byte short-jmp over a *single whole instruction* (length >= 2,
  trivially common) avoids the instruction-boundary hazard and shrinks the
  racy write to 2 bytes; it lands on a nearby trampoline within +/-127 bytes
  that does the full `rel32` to the cave. This is strictly better than a
  5-byte smear but is not race-free (x86 has no concurrent-modification
  guarantee), so it is gated behind the best-effort policy and logged.

## Degradation policy

- If the chosen cold word-write can be placed: proceed.
- If only a partial-coverage option exists (e.g. native x86 with a GOT slot
  that may not be on the trigger path): **best-effort** — install it, `log()`
  what is not covered, and proceed. Some injection beats none.
- If even a single word-write cannot be placed: **fail loudly**. This path is
  itself a fallback for when ptrace is blocked; installing a racy hook on top
  is worse than a clear error.

## The in-target stub

We need **no** executable cave at all. The bootstrap stub is written **into
`malloc`'s own body**, and the loader lives in a region the stub `mmap`s.

### The in-`malloc` bootstrap

`malloc` is small but big enough (128 bytes on the bionic we target) to host
a ~90-110-byte bootstrap. We patch it in three steps so threads already inside
`malloc` are never stepped on. The control word at `malloc+0` is the
architecture's smallest self-branch, written atomically:

- arm64: a 4-byte `B .`; release flips the whole word to `B malloc+4`.
- x86/x86_64: the 2-byte `EB FE` (`jmp .`); release is a 1-byte flip of the
  rel8 to `00` (`jmp malloc+2`), so the opcode byte never changes under a
  fetching core.

```
1. malloc+0      := <jmp self>    ; new callers spin in place
   (wait a moment for any thread already past +0 to drain out of the body)
2. malloc+BOFF.. := bootstrap     ; safe now: body is quiescent (BOFF = 4 arm64, 2 x86)
3. malloc+0      := <jmp BOFF>    ; release the spinners into the bootstrap
```

The bootstrap (~90-110 bytes), reached at `malloc+BOFF` (shown for arm64;
x86/x86_64 are the same shape with `lock cmpxchg` for the election and the
platform's mmap calling convention):

```
bootstrap (x0 = malloc's size arg on entry):
    stp x0, lr, [sp,-16]!
    ldr x16, =scratch
    casal w0, w17(=1), [x16]          ; LSE compare-and-swap: elect one winner
    if lost: goto loser
    region = mmap(NULL, region_size, R|X, PRIVATE|ANON, -1, 0)   ; bl mmap
    ldr x16, =scratch                 ; mmap clobbers x16 (IP0) — reload it
    *mmap_result = region
    while (!go) ;                      ; host stages the region, then sets go
    br region + entry_offset           ; winner only, into the region trampoline
loser:
    ldp x0, lr, [sp], 16               ; restore the frame...
    b malloc                           ; ...and bounce back to malloc+0
```

Only the **winner** enters the region; the region trampoline (host-written,
R-X) is therefore just:

```
region entry:
    mprotect(context_page, page_size, R|W)  ; frida_load stores into the context
    frida_load(context)                ; spawns the worker thread
    ldp x0, lr, [sp], 16
    br malloc                          ; re-run the real malloc for this call
```

Host side, after observing `mmap_result`: immediately re-block `malloc+0` with
`B .`, stage the loader at `region+0` / the trampoline at `region+entry_offset`
/ the context, libc table and argument strings into the region's trailing data
page, then raise `go`. Then drain and restore the body and the prologue word.

The point of re-blocking `malloc+0` the instant the winner is locked in:
**losers, re-entrants (`frida_load`'s `pthread_create` calls `malloc`), and
fresh callers all spin on that one `B .` instruction at `malloc+0`** — the
cleanest possible park. Restoring the prologue word releases them straight
into the real `malloc`. There is no loser path through the region, no parking
flag, and the winner simply `br malloc`s once `frida_load` returns.

Hard-won invariants (each cost a crash on the synthetic single-`malloc`/sec
target before it was understood):

- **Wait for `go` *in the stub*, not in the region.** The region is freshly
  `mmap`d and zero-filled until the host stages code into it; a winner that
  branches in before `go` executes zeros and faults.
- **Reload the scratch base after the `mmap` call.** `mmap` clobbers the
  caller-saved register holding it (arm64 `x16`/IP, x86_64 `r11`, x86 `edx`),
  so reload before publishing the result.
- **Elect without the load/store-exclusive monitor.** On arm64, use the LSE
  `casal`, not `ldaxr`/`stlxr`: under the foreign tracer the local monitor is
  cleared out from under us, livelocking `stlxr` and corrupting the address
  register across retries. x86 has no such hazard — a single `lock cmpxchg`.
- **x86 (32-bit) only:** keep `esp` 16-byte aligned at every `call` (pad the
  cdecl pushes), or a callee's aligned SSE access faults; and since `malloc`'s
  size arg lives on the stack, losers just `jmp malloc` without touching it.

### Why `mmap` for the loader

`malloc`'s 128 bytes hold the bootstrap but not the ~1.4 KB loader. Rather
than hunt for a large executable cave (rare in branch range on locked-down
layouts), the elected thread `mmap`s `PROT_READ|PROT_EXEC` space and the host
writes the loader into it through `/proc/$pid/mem` — `FOLL_FORCE` punches
through the missing write bit and `copy_to_user_page` flushes the I-cache for
us, so the code never needs to be writable by the target itself.

The same region carries the working set the loader reads: the libc table and
the argument strings (read-only, so they ride in the R-X pages) plus the
loader context, which `frida_load` stores its worker handle into. The context
therefore sits on a page-aligned trailing page that the winner flips to RW
with a single `mprotect` before calling the loader — so W and X stay disjoint
without ever mapping the region RWX. All we then borrow from the main thread's
stack are the 24 rendezvous bytes (`cas`/`mmap_result`/`go`) that must exist
before the region does, parked at the bottom of the stack (the deepest it has
ever grown — unused yet CPU-writable).

## Reuse of the existing bootstrapper/loader

`bootstrapper.c` and `loader.c` are reused **unchanged**. They already:

- probe the runtime and resolve libc across glibc/musl/uclibc/Android
  (`frida_resolve_libc_apis`),
- create the worker via `pthread_create` (`frida_load`, loader.c:61),
- perform the dlopen + socket handshake (`frida_main`, loader.c:66).

The proc-mem path changes only **delivery**: instead of a ptrace remote-call
into `frida_load`, the in-`malloc` bootstrap `mmap`s an R-X region, the host
stages the loader into it via `/proc/$pid/mem`, and the elected thread `br`s
into `frida_load` at the region base. From `frida_load` onward the flow is
identical to the ptrace path.

## Handshake (no remote call required)

The loader gets its control socket one of two ways (loader.c:82-103):

1. a pre-injected `ctrlfds[1]` from a target-side socketpair, or
2. the fallback `frida_connect(ctx->fallback_address)` to an **abstract**
   Unix socket.

The proc-mem path uses the **fallback**: the helper listens on an abstract
Unix socket and embeds that address as `ctx->fallback_address`, with
`ctrlfds` set to -1. The worker dials *out* (no fd-passing primitive needed),
sends `HELLO` with its tid, and the agent code fd arrives over `SCM_RIGHTS`
(`frida_receive_fd`, loader.c:331). `READY`/`ACK`/`BYE` proceed exactly as in
the ptrace path. So the entire handshake reuses verbatim.

## Trigger and bounding the wait

`await_region` polls the mmap-result slot for up to `TRIGGER_TIMEOUT_SECONDS`.

- Managed runtime (`libart.so` or `libdvm.so` present in the maps): if no
  thread has triggered the stub within `NUDGE_AFTER_SECONDS`, send `SIGUSR1`.
  Both ART and Dalvik's `SignalCatcher` react by forcing a GC, whose libc
  allocations fire the patched `malloc`. This is a *fallback* — a busy app
  usually triggers from natural traffic first, so we avoid the GC's cost when we
  can. `SIGUSR1` is benign: it does not write an HPROF and the app keeps running
  (verified on Android 16). (`SIGQUIT`, which forces a thread dump, is a heavier
  alternative we don't need.)
- Pure-native: no nudge; rely on natural allocation traffic until the timeout.

## Cleanup

The revert step restores `malloc` to its original bytes, so no hook overhead
is left behind. Residue is the leaked `mmap` region (R-X loader/code pages plus
one RW context page) and the 24 scribbled-on rendezvous bytes at the bottom of
the stack. The agent runs normally after the worker is up.

## Integration

`ProcMemInjectSession` (`proc-mem-injector.vala`) is the fallback path,
selected from `InjectTask.run` in `frida-helper-backend.vala` when:

- the regular `InjectSession` (ptrace) attempt fails with
  `Error.PERMISSION_DENIED`, **and**
- `ProcMemInjectSession.is_available` confirms an `O_RDWR` open of
  `/proc/$pid/mem` succeeds.

Note the EPERM shaping: a foreign tracer makes `PTRACE_SEIZE` fail with
`EPERM`, but in `INTERRUPT` mode `SeizeSession.init_async` then tries
`get_regs`, which fails with `ESRCH` and would otherwise surface as
`PROCESS_NOT_FOUND`. We translate that into `PERMISSION_DENIED` so the
fallback is actually reached.

Host-side staging reuses existing facilities: read `/proc/$pid/maps`
(`ProcMapsSnapshot`), resolve libc bases and `mmap`/`malloc`
(`RemoteLibcApi`), build the bootstrap (`build_malloc_stub`) and the region
trampoline (`build_region_code`). After patching, the host polls the
`mmap_result` slot (`await_region`), re-blocks `malloc+0`, stages the loader,
trampoline and data page (`write_region`) after zeroing the rendezvous words
(`write_rendezvous`), raises `go`, drains, and restores `malloc`. From the
worker handshake onward the flow is identical to the ptrace path, reusing
`RemoteAgent` over an abstract Unix socket.

## Implementation status

- **x86, x86_64 and arm64 — implemented and verified.** `build_malloc_stub`
  and `build_region_code` cover all three (it throws `NOT_SUPPORTED` on other
  ISAs). Verified end-to-end against a synthetic single-`malloc`/sec native
  target on each, plus a real multi-threaded ART app on arm64, each with a
  child process occupying the tracer slot: the agent loads and the target
  keeps running. Triggered by natural `malloc` traffic.

## Open items / risks

- The body-overwrite drain (`DRAIN_MS`) is a fixed wait for threads to leave
  `malloc`'s body before we patch/restore it. A genuinely-blocked thread deep
  in the allocator's slow path could in principle outlast it; the synthetic
  target exercises the common case but not pathological ones.
- The stack-bottom rendezvous words assume the main thread never recurses
  megabytes deep into that page during the injection window.
- The `mmap` region and the rendezvous words are left resident (see *Cleanup*).
- x86 overwrites `malloc+0` with a 2-byte `EB FE`; x86 has no architectural
  concurrent-modification guarantee, so this leans on the empirical atomicity
  of an aligned 2-byte store (the release/re-block are 1-byte rel8 flips, which
  are safe). The block/drain window keeps the exposure tiny.
- x86 (32-bit) stack alignment assumes a modern (16-byte-aligned) caller at the
  `malloc` call site.
