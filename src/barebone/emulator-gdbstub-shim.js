// Instrumentation for the Android emulator's qemu-system-aarch64-headless,
// making its HVF-backed gdbstub usable for Frida's barebone backend. The backend
// loads this into the emulator process itself (BareboneConnectionConfig.pid)
// before talking to the stub; it is not meant to be run by hand.
//
// Three gdbstub defects are fixed:
//
// 1. gdb register writes never reach the vcpu. A write updates QEMU's cached
//    CPUState (env), but a get on the resume path re-reads the hardware vcpu and
//    clobbers it before the put. Fix: on a gdb write of pc/sp/cpsr (reg >= 31),
//    set CPUState.vcpu_dirty so the clobbering get is skipped and the committing
//    put pushes our registers; clear it after that put so normal sync resumes.
//
// 2. gdb breakpoints crash the process and never fire. Insertion runs the TCG
//    breakpoint_invalidate (uninitialised mutex under HVF), and HVF guest-debug
//    is unimplemented. Fix: no-op breakpoint_invalidate; program the vcpu's
//    hardware breakpoint registers from the breakpoint list and enable the debug
//    trap on each resume; on a breakpoint exception (EC 0x30/0x31) disarm, report
//    the stop to gdb (gdb_set_stop_cpu + qemu_system_debug_request + exit_request)
//    and neutralise the syndrome so the original handler returns cleanly.
//
// 3. hv_vcpu_run occasionally returns HV_EXIT_REASON_UNKNOWN (3) while the debug
//    trap is armed; QEMU's exit switch handles only CANCELED/EXCEPTION/VTIMER and
//    aborts on anything else, killing the process. Fix: rewrite UNKNOWN to
//    CANCELED (0) so the CPU loop just re-runs the vcpu. Matters most when
//    injecting into an idle guest, whose WFI-heavy execution provokes it.
//
// A guest-originated synchronous exception (a kernel BUG()/WARN() BRK, or an
// unhandled class trapped here because debug exceptions are routed to the host)
// is delivered to the guest's own EL1 vector rather than aborting QEMU.
//
// Offsets/encodings are for one emulator build (qemu 2.12 fork, Runtime 13.3);
// the expected instruction at each patch site is verified before patching, and a
// mismatch is reported to the backend instead of corrupting a different build.
const M = n => Module.getGlobalExportByName(n);
const gwr=M('aarch64_cpu_gdb_write_register'), put=M('hvf_put_registers'), gget=M('hvf_get_registers');
const bpi=M('cpu_breakpoint_insert'), bprm=M('cpu_breakpoint_remove_all');
const vexec=M('hvf_vcpu_exec'), hexc=M('hvf_handle_exception');

const SLIDE=bpi.sub(0x100024a6c);
const REASON_CMP=SLIDE.add(0x10012bfe8), BREAKPOINT_INVALIDATE=SLIDE.add(0x100024b2c);
const EXPECTED=[[bpi,0xa9bc5ff8,'cpu_breakpoint_insert'],[REASON_CMP,0x7100051f,'reason-compare'],
  [BREAKPOINT_INVALIDATE,0xd10103ff,'breakpoint_invalidate']];
for(const [addr,want,name] of EXPECTED){ const got=addr.readU32();
  if(got!==want){ send({type:'shim-error',message:'unexpected instruction at '+name+': got 0x'+got.toString(16)+', want 0x'+want.toString(16)}); throw new Error('offset mismatch, refusing to patch'); } }

const set_sys=new NativeFunction(M('hv_vcpu_set_sys_reg'),'int',['uint64','uint32','uint64']);
const set_trap=new NativeFunction(M('hv_vcpu_set_trap_debug_exceptions'),'int',['uint64','uint32']);
const gdb_stop=new NativeFunction(M('gdb_set_stop_cpu'),'void',['pointer']);
const get_reg=new NativeFunction(M('hv_vcpu_get_reg'),'int',['uint64','uint32','pointer']);
const get_sys=new NativeFunction(M('hv_vcpu_get_sys_reg'),'int',['uint64','uint32','pointer']);
const set_reg=new NativeFunction(M('hv_vcpu_set_reg'),'int',['uint64','uint32','uint64']);
const dbgreq=new NativeFunction(M('qemu_system_debug_request'),'void',[]);
const HV_REG_PC=31, HV_REG_CPSR=34, ELR_EL1=0xC201, SPSR_EL1=0xC200, ESR_EL1=0xC290, VBAR_EL1=0xC600;
const DIRTY=0x82b3, FD=0x82b4, EXITREQ=0x82a4, EXITP=0x82c8;
const MDSCR=0x8012, DBGBVR0=0x8004, DBGBCR0=0x8005, DBGBCR_EL0_EL1=uint64('0x1e7');
const _tmp=Memory.alloc(8);
function rd_reg(i){ if(get_reg(fd,i,_tmp)===0) return _tmp.readU64(); return uint64(0); }
function rd_sys(e){ if(get_sys(fd,e,_tmp)===0) return _tmp.readU64(); return uint64(0); }
function reinject_to_guest(esr){ if(fd<0) return;
  const pc=rd_reg(HV_REG_PC), cpsr=rd_reg(HV_REG_CPSR), vbar=rd_sys(VBAR_EL1);
  set_sys(fd,ELR_EL1,pc); set_sys(fd,SPSR_EL1,cpsr); set_sys(fd,ESR_EL1,esr.and(uint64('0xffffffff')));
  const m=cpsr.and(uint64('0xf')).toNumber();
  set_reg(fd,HV_REG_PC, vbar.add((m===0)?0x400:0x200));
  set_reg(fd,HV_REG_CPSR, uint64('0x3c5')); }

Interceptor.replace(BREAKPOINT_INVALIDATE, new NativeCallback(function(){}, 'void', ['pointer','uint64']));
let fd=-1, bp=null, pendingCommit=null;
Interceptor.attach(gwr, { onEnter(a){ this.cs=a[0]; this.n=a[2].toInt32(); },
  onLeave(){ if(this.n>=31){ this.cs.add(DIRTY).writeU8(1); pendingCommit=this.cs; } } });
Interceptor.attach(put, { onLeave(){ if(pendingCommit){ pendingCommit.add(DIRTY).writeU8(0); pendingCommit=null; } } });
Interceptor.attach(gget, { onEnter(a){ if(fd<0) fd=a[0].add(FD).readU32(); } });
Interceptor.attach(bpi, { onEnter(a){ bp=uint64(a[1].toString()); } });
Interceptor.attach(bprm, { onEnter(){ bp=null; } });
function program(on){ if(fd<0) return;
  if(on && bp){ set_sys(fd,DBGBVR0,bp); set_sys(fd,DBGBCR0,DBGBCR_EL0_EL1); set_sys(fd,MDSCR,uint64('0xa000')); set_trap(fd,1); }
  else { set_sys(fd,DBGBCR0,uint64('0')); set_sys(fd,MDSCR,uint64('0')); set_trap(fd,0); } }
Interceptor.attach(vexec, { onEnter(){ program(bp!=null); } });

// Rewrite HV_EXIT_REASON_UNKNOWN (3) to CANCELED (0) at the exit-reason compare
// (ldr w8,[exit->reason]; cmp w8,#1) so the CPU loop re-runs the vcpu instead of
// aborting. Context regs are NativePointer, so use toUInt32(), not toNumber().
Interceptor.attach(REASON_CMP, { onEnter(){
  if(this.context.x8.toUInt32()===3) this.context.x8=ptr(0); } });
Interceptor.attach(hexc, { onEnter(a){ try{
  const synp=a[0].add(EXITP).readPointer().add(8);
  const ec=synp.readU64().shr(26).and(0x3f).toNumber();
  if(ec===0x30 || ec===0x31){ program(false); gdb_stop(a[0]); dbgreq(); a[0].add(EXITREQ).writeU32(1);
    synp.writeU64(synp.readU64().and(uint64('0x03ffffff')).or(uint64('0x04000000'))); }
  else if(ec===0x3c || ec===0x32 || ec===0x33 || ec===0x34 || ec===0x35){
    reinject_to_guest(synp.readU64()); a[0].add(EXITREQ).writeU32(1);
    synp.writeU64(synp.readU64().and(uint64('0x03ffffff')).or(uint64('0x04000000'))); }
}catch(e){} } });

// The pipe-over-vsock hostlink needs its unix socket path whitelisted in the
// emulator; the backend sends it once, if that transport is in use.
function allowPipePath(path){
  new NativeFunction(M('android_unix_pipes_add_allowed_path'), 'void', ['pointer'])(Memory.allocUtf8String(path));
}
recv('allow-pipe-path', m => { allowPipePath(m.path); });

send({type:'armed'});
