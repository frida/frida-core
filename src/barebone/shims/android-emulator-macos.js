const CPU_STATE_DIRTY = 0x82b3;
const CPU_STATE_FD = 0x82b4;

const cpuGdbWriteRegister = Module.getGlobalExportByName('aarch64_cpu_gdb_write_register');
const hvfPutRegisters = Module.getGlobalExportByName('hvf_put_registers');
const hvfGetRegisters = Module.getGlobalExportByName('hvf_get_registers');
const cpuBreakpointInsert = Module.getGlobalExportByName('cpu_breakpoint_insert');
const cpuBreakpointRemoveAll = Module.getGlobalExportByName('cpu_breakpoint_remove_all');
const hvfVcpuExec = Module.getGlobalExportByName('hvf_vcpu_exec');
const hvfHandleException = Module.getGlobalExportByName('hvf_handle_exception');

const hvSetReg = new NativeFunction(Module.getGlobalExportByName('hv_vcpu_set_reg'), 'int', ['uint64', 'uint32', 'uint64']);
const HV_REG_PC = 31;
const HV_REG_CPSR = 34;

const slide = cpuBreakpointInsert.sub(0x100024a6c);
const reasonCompare = slide.add(0x10012bfe8);
const breakpointInvalidate = slide.add(0x100024b2c);

const STATE_VCPU_FD = 0;
const STATE_BREAKPOINT_ARMED = 4;
const STATE_BREAKPOINT_ADDRESS = 8;
const state = Memory.alloc(16);
state.add(STATE_VCPU_FD).writeS32(-1);

let pendingRegisterCommit = null;

verifyBuild();
const cm = buildCModule();
captureVcpuFd();
commitGdbRegisterWrites();
emulateHardwareBreakpoints();
rewriteUnknownVcpuExits();
handleDebugExceptions();
rpc.exports.allowPipePath = allowPipePath;

function verifyBuild() {
  const sites = [
    [cpuBreakpointInsert, 0xa9bc5ff8, 'cpu_breakpoint_insert'],
    [reasonCompare, 0x7100051f, 'reason-compare'],
    [breakpointInvalidate, 0xd10103ff, 'breakpoint_invalidate'],
  ];
  for (const [address, expected, name] of sites) {
    const found = address.readU32();
    if (found !== expected) {
      throw new Error(`unexpected instruction at ${name}: got 0x${found.toString(16)}, want 0x${expected.toString(16)}`);
    }
  }
}

function buildCModule() {
  return new CModule(cModuleSource(), {
    frida_state: state,
    hv_set_sys_reg: Module.getGlobalExportByName('hv_vcpu_set_sys_reg'),
    hv_get_sys_reg: Module.getGlobalExportByName('hv_vcpu_get_sys_reg'),
    hv_set_reg: Module.getGlobalExportByName('hv_vcpu_set_reg'),
    hv_get_reg: Module.getGlobalExportByName('hv_vcpu_get_reg'),
    hv_set_trap_debug_exceptions: Module.getGlobalExportByName('hv_vcpu_set_trap_debug_exceptions'),
    gdb_set_stop_cpu: Module.getGlobalExportByName('gdb_set_stop_cpu'),
    qemu_system_debug_request: Module.getGlobalExportByName('qemu_system_debug_request'),
  });
}

function captureVcpuFd() {
  Interceptor.attach(hvfGetRegisters, {
    onEnter(args) {
      if (state.add(STATE_VCPU_FD).readS32() < 0)
        state.add(STATE_VCPU_FD).writeS32(args[0].add(CPU_STATE_FD).readU32());
    }
  });
}

function commitGdbRegisterWrites() {
  Interceptor.attach(cpuGdbWriteRegister, {
    onEnter(args) {
      this.cpuState = args[0];
      this.memBuf = args[1];
      this.register = args[2].toInt32();
    },
    onLeave() {
      const reg = this.register;
      const fd = this.cpuState.add(CPU_STATE_FD).readS32();
      let hvreg = -1;
      if (reg >= 0 && reg <= 30)
        hvreg = reg;
      else if (reg === 32)
        hvreg = HV_REG_PC;
      else if (reg === 33)
        hvreg = HV_REG_CPSR;
      if (hvreg >= 0 && fd >= 0)
        hvSetReg(uint64(fd), hvreg, this.memBuf.readU64());

      if (reg >= 31) {
        this.cpuState.add(CPU_STATE_DIRTY).writeU8(1);
        pendingRegisterCommit = this.cpuState;
      }
    }
  });

  Interceptor.attach(hvfPutRegisters, {
    onLeave() {
      if (pendingRegisterCommit !== null) {
        pendingRegisterCommit.add(CPU_STATE_DIRTY).writeU8(0);
        pendingRegisterCommit = null;
      }
    }
  });
}

function emulateHardwareBreakpoints() {
  Interceptor.replace(breakpointInvalidate, new NativeCallback(() => {}, 'void', ['pointer', 'uint64']));

  Interceptor.attach(cpuBreakpointInsert, {
    onEnter(args) {
      state.add(STATE_BREAKPOINT_ADDRESS).writeU64(uint64(args[1].toString()));
      state.add(STATE_BREAKPOINT_ARMED).writeU32(1);
    }
  });

  Interceptor.attach(cpuBreakpointRemoveAll, {
    onEnter() {
      state.add(STATE_BREAKPOINT_ARMED).writeU32(0);
    }
  });

  Interceptor.attach(hvfVcpuExec, { onEnter: cm.on_vcpu_exec });
}

function rewriteUnknownVcpuExits() {
  Interceptor.attach(reasonCompare, {
    onEnter() {
      if (this.context.x8.toUInt32() === 3)
        this.context.x8 = ptr(0);
    }
  });
}

function handleDebugExceptions() {
  Interceptor.attach(hvfHandleException, { onEnter: cm.on_handle_exception });
}

function allowPipePath(path) {
  const addAllowedPath = new NativeFunction(Module.getGlobalExportByName('android_unix_pipes_add_allowed_path'), 'void', ['pointer']);
  addAllowedPath(Memory.allocUtf8String(path));
}

function cModuleSource() {
  return `
#include <gum/guminterceptor.h>
#include <stdint.h>

#define CPU_STATE_EXIT 0x82c8
#define CPU_STATE_EXIT_REQUEST 0x82a4

#define STATE_VCPU_FD 0
#define STATE_BREAKPOINT_ARMED 4
#define STATE_BREAKPOINT_ADDRESS 8

#define ELR_EL1 0xc201
#define SPSR_EL1 0xc200
#define ESR_EL1 0xc290
#define VBAR_EL1 0xc600
#define MDSCR_EL1 0x8012
#define DBGBVR0_EL1 0x8004
#define DBGBCR0_EL1 0x8005
#define DBGBCR_ENABLE_EL0_EL1 0x1e7ULL
#define MDSCR_MDE 0xa000ULL
#define PSTATE_EL1H_MASKED 0x3c5ULL

#define HV_REG_PC 31
#define HV_REG_CPSR 34

extern uint8_t frida_state[];

extern int hv_set_sys_reg (uint64_t vcpu, uint32_t reg, uint64_t value);
extern int hv_get_sys_reg (uint64_t vcpu, uint32_t reg, uint64_t * value);
extern int hv_set_reg (uint64_t vcpu, uint32_t reg, uint64_t value);
extern int hv_get_reg (uint64_t vcpu, uint32_t reg, uint64_t * value);
extern int hv_set_trap_debug_exceptions (uint64_t vcpu, uint32_t enable);
extern void gdb_set_stop_cpu (void * cpu);
extern void qemu_system_debug_request (void);

#define VCPU_FD (*(volatile int32_t *) (frida_state + STATE_VCPU_FD))
#define BREAKPOINT_ARMED (*(volatile uint32_t *) (frida_state + STATE_BREAKPOINT_ARMED))
#define BREAKPOINT_ADDRESS (*(volatile uint64_t *) (frida_state + STATE_BREAKPOINT_ADDRESS))

static void
program_hardware_breakpoint (int32_t fd, int enable)
{
  if (enable)
  {
    hv_set_sys_reg (fd, DBGBVR0_EL1, BREAKPOINT_ADDRESS);
    hv_set_sys_reg (fd, DBGBCR0_EL1, DBGBCR_ENABLE_EL0_EL1);
    hv_set_sys_reg (fd, MDSCR_EL1, MDSCR_MDE);
    hv_set_trap_debug_exceptions (fd, 1);
  }
  else
  {
    hv_set_sys_reg (fd, DBGBCR0_EL1, 0);
    hv_set_sys_reg (fd, MDSCR_EL1, 0);
    hv_set_trap_debug_exceptions (fd, 0);
  }
}

static void
reinject_to_guest (int32_t fd, uint64_t syndrome)
{
  uint64_t pc = 0, cpsr = 0, vbar = 0;

  hv_get_reg (fd, HV_REG_PC, &pc);
  hv_get_reg (fd, HV_REG_CPSR, &cpsr);
  hv_get_sys_reg (fd, VBAR_EL1, &vbar);

  hv_set_sys_reg (fd, ELR_EL1, pc);
  hv_set_sys_reg (fd, SPSR_EL1, cpsr);
  hv_set_sys_reg (fd, ESR_EL1, syndrome & 0xffffffff);

  hv_set_reg (fd, HV_REG_PC, vbar + (((cpsr & 0xf) == 0) ? 0x400 : 0x200));
  hv_set_reg (fd, HV_REG_CPSR, PSTATE_EL1H_MASKED);
}

void
on_vcpu_exec (GumInvocationContext * ic)
{
  int32_t fd = VCPU_FD;
  if (fd < 0)
    return;
  program_hardware_breakpoint (fd, BREAKPOINT_ARMED != 0);
}

void
on_handle_exception (GumInvocationContext * ic)
{
  uint8_t * cpu = gum_invocation_context_get_nth_argument (ic, 0);
  uint64_t * syndrome = (uint64_t *) (*((uint8_t **) (cpu + CPU_STATE_EXIT)) + 8);
  uint64_t esr = *syndrome;
  uint32_t exception_class = (esr >> 26) & 0x3f;

  int is_breakpoint = (exception_class == 0x30 || exception_class == 0x31);
  int is_guest_debug = (exception_class == 0x3c || exception_class == 0x32 ||
      exception_class == 0x33 || exception_class == 0x34 || exception_class == 0x35);
  if (!is_breakpoint && !is_guest_debug)
    return;

  int32_t fd = VCPU_FD;

  if (is_breakpoint)
  {
    if (fd >= 0)
      program_hardware_breakpoint (fd, 0);
    gdb_set_stop_cpu (cpu);
    qemu_system_debug_request ();
  }
  else if (fd >= 0)
  {
    reinject_to_guest (fd, esr);
  }

  *((uint32_t *) (cpu + CPU_STATE_EXIT_REQUEST)) = 1;
  *syndrome = (esr & 0x03ffffff) | 0x04000000;
}
`;
}
