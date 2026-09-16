const MOD = Process.mainModule;
const FUNC_NAME = 'whpx_get_registers';

const HF_PE = 1 << 7;
const HF_CS32 = 1 << 4;
const HF_SS32 = 1 << 5;
const HF_ADDSEG = 1 << 6;
const HF_LMA = 1 << 14;
const HF_CS64 = 1 << 15;

const layout = locate();

Interceptor.attach(layout.getRegisters, {
  onEnter(args) {
    this.cpuState = args[0];
  },
  onLeave() {
    repair(this.cpuState.add(layout.envOffset).readPointer());
  }
});

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

function repair(env) {
  const rip = env.add(layout.eipOffset).readU64();
  if (rip.shr(32).compare(0) === 0)
    return;

  const hflags = env.add(layout.hflagsOffset).readU32();
  const repaired = (hflags | HF_PE | HF_CS32 | HF_SS32 | HF_LMA | HF_CS64) & ~HF_ADDSEG;
  if (repaired !== hflags)
    env.add(layout.hflagsOffset).writeU32(repaired);
}

function scanString(text) {
  const pattern = Array.from(text, c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ') + ' 00';
  const matches = scan('r', pattern);
  return (matches.length === 0) ? null : matches[0];
}

function scanPrologues() {
  return scan('x', '41 57 41 56 41 54 56 57 53 48 81 ec ?? ?? ?? ?? 48 89 cf');
}

function scan(kind, pattern) {
  const found = [];
  for (const range of MOD.enumerateRanges(kind)) {
    for (const m of Memory.scanSync(range.base, range.size, pattern))
      found.push(m.address);
  }
  return found;
}

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

  const hflagsOffset = eipOffset + 0x30;

  return { getRegisters: start, envOffset, eipOffset, hflagsOffset };
}

function displacement(text) {
  return (text.indexOf('0x') === 0) ? parseInt(text.substring(2), 16) : parseInt(text, 10);
}
