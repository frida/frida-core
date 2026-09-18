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

const WHP = Module.load('WinHvPlatform.dll');

const PROP_EXTENDED_VM_EXITS = 1;
const PROP_EXCEPTION_EXIT_BITMAP = 2;
const EXTENDED_EXCEPTION_EXIT = 1 << 2;
const DEBUG_VECTOR = 1;
const EXIT_REASON_EXCEPTION = 0x1002;
const EXIT_REASON_CANCELED = 0x2001;
const VP_CONTEXT_RIP = 32;
const REGISTER_RSP = 0x04;
const REGISTER_DR0 = 0x21;
const REGISTER_DR6 = 0x25;
const REGISTER_DR7 = 0x26;
const DR7_ALWAYS_SET = 0x400;
const MAX_BREAKPOINTS = 4;
const REPORT_INTERVAL_MS = 50;
const ARM_INTERVAL_MS = 100;

const setPartitionProperty = new NativeFunction(WHP.getExportByName('WHvSetPartitionProperty'),
    'uint32', ['pointer', 'uint32', 'pointer', 'uint32']);
const getPartitionProperty = new NativeFunction(WHP.getExportByName('WHvGetPartitionProperty'),
    'uint32', ['pointer', 'uint32', 'pointer', 'uint32', 'pointer']);
const setRegisters = new NativeFunction(WHP.getExportByName('WHvSetVirtualProcessorRegisters'),
    'uint32', ['pointer', 'uint32', 'pointer', 'uint32', 'pointer']);
const cancelRun = new NativeFunction(WHP.getExportByName('WHvCancelRunVirtualProcessor'),
    'uint32', ['pointer', 'uint32', 'uint32']);
const getRegisters = new NativeFunction(WHP.getExportByName('WHvGetVirtualProcessorRegisters'),
    'uint32', ['pointer', 'uint32', 'pointer', 'uint32', 'pointer']);

const programmed = new Map();
const reported = new Map();
const seen = new Set();

let partition = null;
let armed = false;
let planted = [];
let generation = 0;

recv('breakpoints', onBreakpointsChanged);

Interceptor.attach(WHP.getExportByName('WHvGetVirtualProcessorRegisters'), {
  onEnter(args) {
    partition = args[0];
  }
});

Interceptor.attach(WHP.getExportByName('WHvRunVirtualProcessor'), {
  onEnter(args) {
    this.partition = args[0];
    this.vpIndex = args[1].toUInt32();
    this.exitContext = args[2];

    partition = args[0];

    seen.add(this.vpIndex);

    if (programmed.get(this.vpIndex) !== generation) {
      programmed.set(this.vpIndex, generation);
      programDebugRegisters(this.partition, this.vpIndex);
    }
  },
  onLeave() {
    if (this.exitContext.readU32() !== EXIT_REASON_EXCEPTION)
      return;

    const rip = this.exitContext.add(VP_CONTEXT_RIP).readU64();
    const which = readRegister(this.partition, this.vpIndex, REGISTER_DR6).and(0xf);
    writeRegister(this.partition, this.vpIndex, REGISTER_DR6, uint64(0));
    this.exitContext.writeU32(EXIT_REASON_CANCELED);

    if (which.compare(0) === 0)
      return;

    const episode = this.vpIndex + ':' + rip.toString(16);
    const now = Date.now();
    if (now - (reported.get(episode) || 0) < REPORT_INTERVAL_MS)
      return;
    reported.set(episode, now);

    send({
      type: 'breakpoint',
      address: '0x' + rip.toString(16),
      rsp: '0x' + readRegister(this.partition, this.vpIndex, REGISTER_RSP).toString(16),
      vp: this.vpIndex
    });
  }
});

setInterval(() => {
  if (!armed && partition !== null)
    armed = arm();
}, ARM_INTERVAL_MS);

function onBreakpointsChanged(message) {
  planted = message.addresses.slice(0, MAX_BREAKPOINTS);
  generation++;
  programmed.clear();
  reported.clear();

  if (partition !== null) {
    for (const vpIndex of seen)
      cancelRun(partition, vpIndex, 0);
  }

  recv('breakpoints', onBreakpointsChanged);
}

function arm() {
  const scratch = Memory.alloc(16);
  const written = Memory.alloc(4);

  getPartitionProperty(partition, PROP_EXTENDED_VM_EXITS, scratch, 8, written);
  scratch.writeU64(scratch.readU64().or(EXTENDED_EXCEPTION_EXIT));
  const extended = setPartitionProperty(partition, PROP_EXTENDED_VM_EXITS, scratch, 8);

  scratch.writeU64(1 << DEBUG_VECTOR);
  const bitmap = setPartitionProperty(partition, PROP_EXCEPTION_EXIT_BITMAP, scratch, 8);

  return extended === 0 && bitmap === 0;
}

function programDebugRegisters(partition, vpIndex) {
  let control = DR7_ALWAYS_SET;

  for (let slot = 0; slot !== MAX_BREAKPOINTS; slot++) {
    const address = (slot < planted.length) ? ptr(planted[slot]) : NULL;
    writeRegister(partition, vpIndex, REGISTER_DR0 + slot, uint64(address.toString()));
    if (slot < planted.length)
      control |= 1 << (slot * 2);
  }

  writeRegister(partition, vpIndex, REGISTER_DR7, uint64(control));
}

function readRegister(partition, vpIndex, name) {
  const names = Memory.alloc(4);
  names.writeU32(name);

  const values = Memory.alloc(16);
  getRegisters(partition, vpIndex, names, 1, values);

  return values.readU64();
}

function writeRegister(partition, vpIndex, name, value) {
  const names = Memory.alloc(4);
  names.writeU32(name);

  const values = Memory.alloc(16);
  values.writeU64(value);
  values.add(8).writeU64(0);

  return setRegisters(partition, vpIndex, names, 1, values);
}
