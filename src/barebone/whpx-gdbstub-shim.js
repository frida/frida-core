// Injected into the Android emulator's QEMU by the barebone backend to make its
// WHPX-backed gdbstub usable. whpx_get_registers() syncs the vcpu faithfully but
// never recomputes env->hflags, which upstream ends it with, so QEMU keeps a view
// of the guest as a 32-bit CPU that is not in long mode. Two things follow: the
// stub serializes every register through its 32-bit path, truncating each one to
// its low half, and the page-table walk behind a memory read picks non-long-mode
// paging, so every address fails to translate and the stub answers E14.
//
// Recomputing the long-mode bits after each sync is the whole fix. The function is
// found by the __func__ string it carries rather than by a pinned offset, and the
// fields it writes give away where the register file is.

const MOD = findQemu();
const FUNC_NAME = 'whpx_get_registers';

const HF_PE = 1 << 7;
const HF_CS32 = 1 << 4;
const HF_SS32 = 1 << 5;
const HF_ADDSEG = 1 << 6;
const HF_LMA = 1 << 14;
const HF_CS64 = 1 << 15;
const HF_VALID = 0x07ffffff;

let layout = null;

try {
  layout = locate();
} catch (e) {
  send({ type: 'shim-error', message: e.message });
  throw e;
}

Interceptor.attach(layout.getRegisters, {
  onEnter(args) {
    this.cpuState = args[0];
  },
  onLeave() {
    try {
      repair(this.cpuState.add(layout.envOffset).readPointer());
    } catch (e) {
    }
  }
});

send({ type: 'armed' });

// The guest is only ever read while the backend has it parked in the kernel, and a
// linear address above the 32-bit range is something a CPU outside long mode cannot
// be running, so it is the one signal here that does not need a field this build
// never filled in.
function repair(env) {
  const rip = env.add(layout.eipOffset).readU64();
  if (rip.shr(32).compare(0) === 0)
    return;

  const hflags = env.add(layout.hflagsOffset).readU32();
  const repaired = (hflags | HF_PE | HF_CS32 | HF_SS32 | HF_LMA | HF_CS64) & ~HF_ADDSEG;
  if (repaired !== hflags)
    env.add(layout.hflagsOffset).writeU32(repaired);
}

function locate() {
  const name = scanString(FUNC_NAME);
  if (name === null)
    throw new Error('this QEMU carries no ' + FUNC_NAME + ' to anchor on');

  for (const candidate of scanPrologues()) {
    const found = describe(candidate, name);
    if (found !== null)
      return found;
  }

  throw new Error('unable to find ' + FUNC_NAME + ' in this QEMU');
}

// The register file is reached as [cpu_state + N] on the way in, and the general
// purpose registers are written to it one qword at a time; whatever it writes right
// after the sixteenth of them is eip, which the rest of the layout follows from.
function describe(start, nameAddress) {
  let cursor = start;
  let envOffset = -1;
  let names = false;
  let stores = 0;
  let eipOffset = -1;

  for (let i = 0; i !== 160 && eipOffset === -1; i++) {
    let insn;
    try {
      insn = Instruction.parse(cursor);
    } catch (e) {
      return null;
    }

    const text = insn.mnemonic + ' ' + insn.opStr;

    if (envOffset === -1) {
      const m = /^mov rbx, qword ptr \[rcx \+ (0x[0-9a-f]+|\d+)\]$/.exec(text);
      if (m !== null)
        envOffset = displacement(m[1]);
    }

    if (!names && insn.mnemonic === 'lea') {
      const m = /\[rip \+ (0x[0-9a-f]+|\d+)\]$/.exec(insn.opStr);
      if (m !== null && insn.next.add(displacement(m[1])).equals(nameAddress))
        names = true;
    }

    const store = /^mov qword ptr \[rbx \+ (0x[0-9a-f]+|\d+)\], rax$/.exec(text);
    const first = /^mov qword ptr \[rbx\], rax$/.test(text);
    if (first) {
      stores = 1;
    } else if (store !== null) {
      stores++;
      if (stores === 17)
        eipOffset = displacement(store[1]);
    }

    cursor = insn.next;
  }

  if (!names || envOffset === -1 || eipOffset === -1)
    return null;

  // eip is followed by eflags and the lazy-flags block, and hflags sits after them.
  const hflagsOffset = eipOffset + 0x30;

  return { getRegisters: start, envOffset, eipOffset, hflagsOffset };
}

// Capstone spells a displacement below ten without its prefix.
function displacement(text) {
  return (text.indexOf('0x') === 0) ? parseInt(text.substring(2), 16) : parseInt(text, 10);
}

function scanPrologues() {
  // push r15/r14/r12/rsi/rdi/rbx, sub rsp, imm32, mov rdi, rcx
  return scan('x', '41 57 41 56 41 54 56 57 53 48 81 ec ?? ?? ?? ?? 48 89 cf');
}

function scanString(text) {
  const pattern = Array.from(text, c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ') + ' 00';
  const matches = scan('r', pattern);
  return (matches.length === 0) ? null : matches[0];
}

function scan(kind, pattern) {
  const found = [];
  const limit = MOD.base.add(MOD.size);
  for (const range of Process.enumerateRanges(kind)) {
    if (range.base.compare(MOD.base) < 0 || range.base.compare(limit) >= 0)
      continue;
    for (const m of Memory.scanSync(range.base, range.size, pattern))
      found.push(m.address);
  }
  return found;
}

function findQemu() {
  for (const m of Process.enumerateModules()) {
    if (m.name.toLowerCase().indexOf('qemu-system') === 0)
      return m;
  }
  return Process.enumerateModules()[0];
}
