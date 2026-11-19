use core::ffi::{c_int, c_void};
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use core::ffi::c_ulong;
use core::ptr;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use core::sync::atomic::AtomicBool;
#[cfg(target_arch = "aarch64")]
use core::sync::atomic::AtomicPtr;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use core::sync::atomic::Ordering;

use crate::bindings::{
    gum_barebone_handle_exception, GumCpuContext,
    _GumExceptionType_GUM_EXCEPTION_ACCESS_VIOLATION as ACCESS_VIOLATION,
};
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use crate::bindings::{
    gpointer, gum_interceptor_replace_fast, gum_interceptor_revert,
    GumReplaceReturn_GUM_REPLACE_OK as GUM_REPLACE_OK,
};
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use crate::instrumentation::Instrumentation;

#[cfg(target_arch = "x86")]
pub fn install() {
    unsafe {
        build_resume_stub();
        take_over_fixups(frida_kcb_fixup_exception as *mut c_void);
    }
}

#[cfg(target_arch = "x86")]
pub fn uninstall() {
    give_back_fixups();
}

#[cfg(target_arch = "x86_64")]
pub fn install() {
    unsafe {
        take_over_fixups(frida_x86_64_fixup as *mut c_void);
        take_over_oopses();
    }
}

#[cfg(target_arch = "x86_64")]
pub fn uninstall() {
    give_back_fixups();
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn take_over_fixups(replacement: *mut c_void) {
    let mut original: gpointer = ptr::null_mut();
    let result = FIXUPS.apply(|interceptor| unsafe {
        gum_interceptor_replace_fast(
            interceptor,
            _fixup_exception as *mut c_void,
            replacement,
            &mut original,
            ptr::null(),
        )
    });
    assert_eq!(result, GUM_REPLACE_OK);
    unsafe { ORIGINAL_FIXUP = original as usize };
}

#[cfg(target_arch = "x86_64")]
unsafe fn take_over_oopses() {
    if unsafe { _page_fault_oops } == 0 {
        return;
    }
    let mut original: gpointer = ptr::null_mut();
    let result = FIXUPS.apply(|interceptor| unsafe {
        gum_interceptor_replace_fast(
            interceptor,
            _page_fault_oops as *mut c_void,
            frida_x86_64_page_fault_oops as *mut c_void,
            &mut original,
            ptr::null(),
        )
    });
    assert_eq!(result, GUM_REPLACE_OK);
    unsafe { ORIGINAL_OOPS = original as usize };
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn give_back_fixups() {
    FIXUPS.revert(|interceptor| unsafe {
        gum_interceptor_revert(interceptor, _fixup_exception as *mut c_void);
        #[cfg(target_arch = "x86_64")]
        if ORIGINAL_OOPS != 0 {
            gum_interceptor_revert(interceptor, _page_fault_oops as *mut c_void);
        }
    });
}

#[cfg(target_arch = "x86")]
#[unsafe(no_mangle)]
unsafe extern "C" fn frida_cb_fixup_exception(
    regs: *mut c_void,
    trapnr: c_int,
    error_code: c_ulong,
    fault_address: c_ulong,
) -> c_int {
    let fixed =
        unsafe { frida_k_call_fixup_exception(ORIGINAL_FIXUP as *mut c_void, regs, trapnr, error_code, fault_address) };
    let faulted_at = unsafe { (regs as *const u32).add(12).read() as usize };
    if fixed != 0 || !is_ours(faulted_at) {
        return fixed;
    }

    let mut context = unsafe { context_of(regs) };
    if !handled(faulted_at, fault_address as usize, &mut context) {
        crate::note_unhandled_fault(trapnr as u64, faulted_at as u64, fault_address as u64);
        context.eip = frida_park as *const () as usize as u32;
    }
    unsafe {
        (&raw mut RESUME_CONTEXT).write(context);
        (regs as *mut u32).add(12).write(RESUME_STUB as u32);
    }
    1
}

#[cfg(target_arch = "x86")]
unsafe fn build_resume_stub() {
    let stub = crate::kernel::alloc_code(16);
    unsafe {
        stub.write(0xbf);
        (stub.add(1) as *mut u32).write((&raw mut RESUME_CONTEXT) as u32);
        stub.add(5).write(0xe9);
        let rel = (frida_i386_resume as *const () as usize).wrapping_sub(stub as usize + 10) as u32;
        (stub.add(6) as *mut u32).write(rel);
        RESUME_STUB = stub as usize;
    }
}

#[cfg(target_arch = "x86")]
unsafe fn context_of(regs: *mut c_void) -> GumCpuContext {
    let r = regs as *const u32;
    let mut c: GumCpuContext = unsafe { core::mem::zeroed() };
    unsafe {
        c.ebx = r.add(0).read();
        c.ecx = r.add(1).read();
        c.edx = r.add(2).read();
        c.esi = r.add(3).read();
        c.edi = r.add(4).read();
        c.ebp = r.add(5).read();
        c.eax = r.add(6).read();
        c.eip = r.add(12).read();
        c.esp = ((&raw mut RESUME_SCRATCH) as usize + RESUME_SCRATCH_SIZE - 16) as u32;
    }
    c
}

#[cfg(target_arch = "x86")]
#[unsafe(naked)]
unsafe extern "C" fn frida_i386_resume() {
    core::arch::naked_asm!(
        "mov esi, [edi + 8]",
        "mov ebp, [edi + 12]",
        "mov ebx, [edi + 20]",
        "mov edx, [edi + 24]",
        "mov ecx, [edi + 28]",
        "mov eax, [edi + 32]",
        "mov esp, [edi + 16]",
        "push dword ptr [edi]",
        "mov edi, [edi + 4]",
        "ret",
    );
}

#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn frida_x86_64_fixup(regs: *mut c_void, trapnr: c_int, error_code: c_ulong, fault_address: c_ulong) -> c_int {
    let original: unsafe extern "C" fn(*mut c_void, c_int, c_ulong, c_ulong) -> c_int =
        unsafe { core::mem::transmute(ORIGINAL_FIXUP) };
    let fixed = unsafe { original(regs, trapnr, error_code, fault_address) };
    if fixed != 0 || !is_ours(unsafe { program_counter(regs) }) {
        return fixed;
    }

    unsafe { recover(regs, trapnr, fault_address as usize) };
    1
}

#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn frida_x86_64_page_fault_oops(regs: *mut c_void, error_code: c_ulong, fault_address: c_ulong) {
    if !is_ours(unsafe { program_counter(regs) }) {
        let original: unsafe extern "C" fn(*mut c_void, c_ulong, c_ulong) = unsafe { core::mem::transmute(ORIGINAL_OOPS) };
        unsafe { original(regs, error_code, fault_address) };
        return;
    }

    unsafe { recover(regs, PAGE_FAULT_TRAP, fault_address as usize) };
}

#[cfg(target_arch = "x86_64")]
unsafe fn recover(regs: *mut c_void, trapnr: c_int, accessed: usize) {
    let mut context = unsafe { context_of(regs) };
    let faulted_at = context.rip as usize;
    if !handled(faulted_at, accessed, &mut context) {
        crate::note_unhandled_fault(trapnr as u64, faulted_at as u64, accessed as u64);
        context.rip = frida_park as *const () as usize as u64;
        context.rsp = (context.rsp & !15) - 8;
    }
    unsafe { restore_context(regs, &context) };
}

#[cfg(target_arch = "x86_64")]
unsafe fn program_counter(regs: *mut c_void) -> usize {
    unsafe { (regs as *const u64).add(16).read() as usize }
}

#[cfg(target_arch = "x86_64")]
unsafe fn context_of(regs: *mut c_void) -> GumCpuContext {
    let r = regs as *const u64;
    let mut c: GumCpuContext = unsafe { core::mem::zeroed() };
    unsafe {
        c.r15 = r.add(0).read();
        c.r14 = r.add(1).read();
        c.r13 = r.add(2).read();
        c.r12 = r.add(3).read();
        c.rbp = r.add(4).read();
        c.rbx = r.add(5).read();
        c.r11 = r.add(6).read();
        c.r10 = r.add(7).read();
        c.r9 = r.add(8).read();
        c.r8 = r.add(9).read();
        c.rax = r.add(10).read();
        c.rcx = r.add(11).read();
        c.rdx = r.add(12).read();
        c.rsi = r.add(13).read();
        c.rdi = r.add(14).read();
        c.rip = r.add(16).read();
        c.rsp = r.add(19).read();
    }
    c
}

#[cfg(target_arch = "x86_64")]
unsafe fn restore_context(regs: *mut c_void, c: &GumCpuContext) {
    let r = regs as *mut u64;
    unsafe {
        r.add(0).write(c.r15);
        r.add(1).write(c.r14);
        r.add(2).write(c.r13);
        r.add(3).write(c.r12);
        r.add(4).write(c.rbp);
        r.add(5).write(c.rbx);
        r.add(6).write(c.r11);
        r.add(7).write(c.r10);
        r.add(8).write(c.r9);
        r.add(9).write(c.r8);
        r.add(10).write(c.rax);
        r.add(11).write(c.rcx);
        r.add(12).write(c.rdx);
        r.add(13).write(c.rsi);
        r.add(14).write(c.rdi);
        r.add(16).write(c.rip);
        r.add(19).write(c.rsp);
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
static FIXUPS: Instrumentation = Instrumentation::new();

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
static mut ORIGINAL_FIXUP: usize = 0;

#[cfg(target_arch = "x86_64")]
static mut ORIGINAL_OOPS: usize = 0;

#[cfg(target_arch = "x86_64")]
const PAGE_FAULT_TRAP: c_int = 14;

#[cfg(target_arch = "x86")]
static mut RESUME_CONTEXT: GumCpuContext = unsafe { core::mem::zeroed() };

#[cfg(target_arch = "x86")]
static mut RESUME_STUB: usize = 0;

#[cfg(target_arch = "x86")]
const RESUME_SCRATCH_SIZE: usize = 512;

#[cfg(target_arch = "x86")]
static mut RESUME_SCRATCH: [u8; RESUME_SCRATCH_SIZE] = [0; RESUME_SCRATCH_SIZE];

#[cfg(target_arch = "x86")]
unsafe extern "C" {
    static _fixup_exception: unsafe extern "C" fn();
    fn frida_kcb_fixup_exception();
    fn frida_k_call_fixup_exception(
        original: *mut c_void,
        regs: *mut c_void,
        trapnr: c_int,
        error_code: c_ulong,
        fault_address: c_ulong,
    ) -> c_int;
}

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    static _fixup_exception: unsafe extern "C" fn();
    static _page_fault_oops: usize;
}

#[cfg(target_arch = "arm")]
const PROLOGUE: [u32; 2] = [0xe92d4010, 0xe52de004];

#[cfg(target_arch = "arm")]
static ACTIVATED: AtomicBool = AtomicBool::new(false);

#[cfg(target_arch = "arm")]
const THUMB_STATE: u32 = 1 << 5;

#[cfg(target_arch = "arm")]
static mut ORIGINAL_STUB: usize = 0;

#[cfg(target_arch = "arm")]
static mut RESUME_STUB: usize = 0;

#[cfg(target_arch = "arm")]
static mut RESUME_TARGET: u32 = 0;

#[cfg(target_arch = "arm")]
const LDR_IP_FROM_LITERAL: u32 = 0xe59fc004;

#[cfg(target_arch = "arm")]
const LDR_IP_FROM_IP: u32 = 0xe59cc000;

#[cfg(target_arch = "arm")]
const BX_IP: u32 = 0xe12fff1c;

#[cfg(target_arch = "arm")]
pub fn install() {
    let target = unsafe { _fixup_exception } as *const u32;
    for slot in 0..2 {
        if unsafe { target.add(slot).read_volatile() } != PROLOGUE[slot] {
            return;
        }
    }

    unsafe { build_original_stub(target) };
    if unsafe { ORIGINAL_STUB } == 0 {
        return;
    }
    unsafe { build_resume_stub() };

    unsafe {
        let addr = target as *mut u32;
        _patch_text(addr.add(1) as *mut c_void, frida_arm_fixup as *const () as usize as u32);
        _patch_text(addr as *mut c_void, 0xe51ff004);
    }
    ACTIVATED.store(true, Ordering::Release);
}

#[cfg(target_arch = "arm")]
pub fn uninstall() {
    if !ACTIVATED.swap(false, Ordering::AcqRel) {
        return;
    }

    let target = unsafe { _fixup_exception } as *mut u32;
    unsafe {
        _patch_text(target as *mut c_void, PROLOGUE[0]);
        _patch_text(target.add(1) as *mut c_void, PROLOGUE[1]);
    }
}

#[cfg(target_arch = "arm")]
unsafe fn build_original_stub(target: *const u32) {
    let stub = crate::kernel::alloc_code(16) as *mut u32;
    if stub.is_null() {
        return;
    }
    unsafe {
        stub.add(0).write(PROLOGUE[0]);
        stub.add(1).write(PROLOGUE[1]);
        stub.add(2).write(0xe51ff004);
        stub.add(3).write(target.add(2) as u32);
        ORIGINAL_STUB = stub as usize;
    }
}

#[cfg(target_arch = "arm")]
unsafe fn build_resume_stub() {
    let stub = crate::kernel::alloc_code(16) as *mut u32;
    unsafe {
        stub.add(0).write(LDR_IP_FROM_LITERAL);
        stub.add(1).write(LDR_IP_FROM_IP);
        stub.add(2).write(BX_IP);
        stub.add(3).write((&raw const RESUME_TARGET) as u32);
        RESUME_STUB = stub as usize;
    }
}

#[cfg(target_arch = "arm")]
unsafe extern "C" fn frida_arm_fixup(regs: *mut c_void) -> c_int {
    let original: unsafe extern "C" fn(*mut c_void) -> c_int =
        unsafe { core::mem::transmute(ORIGINAL_STUB) };
    let fixed = unsafe { original(regs) };
    let mut context = unsafe { context_of(regs) };
    let faulted_at = context.pc as usize;
    if fixed != 0 || !is_ours(faulted_at) {
        return fixed;
    }

    let accessed: usize;
    unsafe { core::arch::asm!("mrc p15, 0, {}, c6, c0, 0", out(reg) accessed, options(nomem, nostack)) };
    let state_at_fault = context.cpsr;
    if !handled(faulted_at, accessed, &mut context) {
        let status: u32;
        unsafe { core::arch::asm!("mrc p15, 0, {}, c5, c0, 0", out(reg) status, options(nomem, nostack)) };
        crate::note_unhandled_fault(status as u64, faulted_at as u64, accessed as u64);
        context.pc = frida_park as *const () as usize as u32;
    }
    let resumes_in_thumb = context.pc & 1 != 0 || context.cpsr & THUMB_STATE != 0;
    context.pc &= !1;
    context.cpsr = state_at_fault;
    if resumes_in_thumb && state_at_fault & THUMB_STATE == 0 {
        unsafe { RESUME_TARGET = context.pc | 1 };
        context.pc = unsafe { RESUME_STUB } as u32;
    }
    unsafe { restore_context(regs, &context) };
    1
}

#[cfg(target_arch = "arm")]
unsafe fn context_of(regs: *mut c_void) -> GumCpuContext {
    let g = regs as *const u32;
    let mut r = [0u32; 8];
    for slot in 0..8 {
        r[slot] = unsafe { g.add(slot).read() };
    }
    let mut c: GumCpuContext = unsafe { core::mem::zeroed() };
    c.r = r;
    unsafe {
        c.r8 = g.add(8).read();
        c.r9 = g.add(9).read();
        c.r10 = g.add(10).read();
        c.r11 = g.add(11).read();
        c.r12 = g.add(12).read();
        c.sp = g.add(13).read();
        c.lr = g.add(14).read();
        c.pc = g.add(15).read();
        c.cpsr = g.add(16).read();
    }
    c
}

#[cfg(target_arch = "arm")]
unsafe fn restore_context(regs: *mut c_void, c: &GumCpuContext) {
    let g = regs as *mut u32;
    unsafe {
        for slot in 0..8 {
            g.add(slot).write(c.r[slot]);
        }
        g.add(8).write(c.r8);
        g.add(9).write(c.r9);
        g.add(10).write(c.r10);
        g.add(11).write(c.r11);
        g.add(12).write(c.r12);
        g.add(13).write(c.sp);
        g.add(14).write(c.lr);
        g.add(15).write(c.pc);
        g.add(16).write(c.cpsr);
    }
}

#[cfg(target_arch = "arm")]
unsafe extern "C" {
    static _fixup_exception: unsafe extern "C" fn();
    static _patch_text: unsafe extern "C" fn(*mut c_void, u32);
}

#[cfg(target_arch = "aarch64")]
struct Prologue {
    words: [u32; 4],
    call_original: unsafe extern "C" fn(*mut c_void) -> c_int,
}

#[cfg(target_arch = "aarch64")]
static PROLOGUES: [Prologue; 2] = [
    Prologue {
        words: [PACIASP, STP_FRAME_RECORD, MOV_FRAME_POINTER, STP_X19_X20],
        call_original: frida_arm64_call_original,
    },
    Prologue {
        words: [MOV_X9_X30, NOP, PACIASP, STP_FRAME_RECORD],
        call_original: frida_arm64_call_original_traceable,
    },
];

#[cfg(target_arch = "aarch64")]
const MOV_X9_X30: u32 = 0xaa1e03e9;
#[cfg(target_arch = "aarch64")]
const NOP: u32 = 0xd503201f;
#[cfg(target_arch = "aarch64")]
const PACIASP: u32 = 0xd503233f;
#[cfg(target_arch = "aarch64")]
const STP_FRAME_RECORD: u32 = 0xa9be7bfd;
#[cfg(target_arch = "aarch64")]
const MOV_FRAME_POINTER: u32 = 0x910003fd;
#[cfg(target_arch = "aarch64")]
const STP_X19_X20: u32 = 0xa90153f3;

#[cfg(target_arch = "aarch64")]
static INSTALLED: AtomicPtr<Prologue> = AtomicPtr::new(ptr::null_mut());

#[cfg(target_arch = "aarch64")]
const KERNEL_FAULT_PROLOGUE: [u32; 4] = [PACIASP, STP_FRAME_RECORD_48, MOV_FRAME_POINTER, STP_X19_X20];

#[cfg(target_arch = "aarch64")]
const STP_FRAME_RECORD_48: u32 = 0xa9bd7bfd;

#[cfg(target_arch = "aarch64")]
const ESR_CLASS_SHIFT: u64 = 26;

#[cfg(target_arch = "aarch64")]
const INSTRUCTION_ABORT_HERE: u64 = 0x21;

#[cfg(target_arch = "aarch64")]
static KERNEL_FAULTS_TAKEN: AtomicBool = AtomicBool::new(false);

#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
static mut FRIDA_ARM64_KERNEL_FAULT_CONT: u64 = 0;

#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
static mut FRIDA_ARM64_ORIGINAL_CONT: u64 = 0;

#[cfg(target_arch = "aarch64")]
pub fn install() {
    let target = unsafe { _fixup_exception } as *const u32;
    let present = core::array::from_fn(|slot| unsafe { target.add(slot).read_volatile() });
    let Some(prologue) = PROLOGUES.iter().find(|prologue| prologue.words == present) else {
        return;
    };

    unsafe { FRIDA_ARM64_ORIGINAL_CONT = target.add(4) as u64 };

    let jump = redirect_to(frida_arm64_fixup as *const () as usize);
    unsafe {
        let addr = target as *mut u32;
        _aarch64_insn_patch_text_nosync(addr.add(2) as *mut c_void, jump[2]);
        _aarch64_insn_patch_text_nosync(addr.add(3) as *mut c_void, jump[3]);
        _aarch64_insn_patch_text_nosync(addr.add(1) as *mut c_void, jump[1]);
        _aarch64_insn_patch_text_nosync(addr as *mut c_void, jump[0]);
    }
    INSTALLED.store(prologue as *const Prologue as *mut Prologue, Ordering::Release);

    unsafe { take_over_kernel_faults() };
}

#[cfg(target_arch = "aarch64")]
unsafe fn take_over_kernel_faults() {
    let target = unsafe { ___do_kernel_fault } as *const u32;
    if target.is_null() {
        return;
    }
    let present: [u32; 4] = core::array::from_fn(|slot| unsafe { target.add(slot).read_volatile() });
    if present != KERNEL_FAULT_PROLOGUE {
        return;
    }

    unsafe { FRIDA_ARM64_KERNEL_FAULT_CONT = target.add(4) as u64 };

    let jump = redirect_to(frida_arm64_kernel_fault as *const () as usize);
    unsafe {
        let addr = target as *mut u32;
        _aarch64_insn_patch_text_nosync(addr.add(2) as *mut c_void, jump[2]);
        _aarch64_insn_patch_text_nosync(addr.add(3) as *mut c_void, jump[3]);
        _aarch64_insn_patch_text_nosync(addr.add(1) as *mut c_void, jump[1]);
        _aarch64_insn_patch_text_nosync(addr as *mut c_void, jump[0]);
    }
    KERNEL_FAULTS_TAKEN.store(true, Ordering::Release);
}

#[cfg(target_arch = "aarch64")]
pub fn uninstall() {
    let prologue = INSTALLED.swap(ptr::null_mut(), Ordering::AcqRel);
    if prologue.is_null() {
        return;
    }

    let target = unsafe { _fixup_exception } as *mut u32;
    let words = unsafe { (*prologue).words };
    unsafe {
        for slot in 0..4 {
            _aarch64_insn_patch_text_nosync(target.add(slot) as *mut c_void, words[slot]);
        }
    }

    if KERNEL_FAULTS_TAKEN.swap(false, Ordering::AcqRel) {
        let target = unsafe { ___do_kernel_fault } as *mut u32;
        unsafe {
            for slot in 0..4 {
                _aarch64_insn_patch_text_nosync(target.add(slot) as *mut c_void, KERNEL_FAULT_PROLOGUE[slot]);
            }
        }
    }
}

#[cfg(target_arch = "aarch64")]
fn redirect_to(destination: usize) -> [u32; 4] {
    [0x58000050, 0xd61f0200, destination as u32, (destination >> 32) as u32]
}

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".globl frida_arm64_call_original",
    "frida_arm64_call_original:",
    "paciasp",
    "stp x29, x30, [sp, #-32]!",
    "mov x29, sp",
    "stp x19, x20, [sp, #16]",
    "adrp x16, {cont}",
    "add x16, x16, :lo12:{cont}",
    "ldr x16, [x16]",
    "br x16",
    ".globl frida_arm64_call_original_traceable",
    "frida_arm64_call_original_traceable:",
    "paciasp",
    "stp x29, x30, [sp, #-32]!",
    "adrp x16, {cont}",
    "add x16, x16, :lo12:{cont}",
    "ldr x16, [x16]",
    "br x16",
    ".globl frida_arm64_call_original_kernel_fault",
    "frida_arm64_call_original_kernel_fault:",
    "paciasp",
    "stp x29, x30, [sp, #-48]!",
    "mov x29, sp",
    "stp x19, x20, [sp, #16]",
    "adrp x16, {kernel_fault_cont}",
    "add x16, x16, :lo12:{kernel_fault_cont}",
    "ldr x16, [x16]",
    "br x16",
    cont = sym FRIDA_ARM64_ORIGINAL_CONT,
    kernel_fault_cont = sym FRIDA_ARM64_KERNEL_FAULT_CONT,
);

#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn frida_arm64_call_original(regs: *mut c_void) -> c_int;
    fn frida_arm64_call_original_traceable(regs: *mut c_void) -> c_int;
    fn frida_arm64_call_original_kernel_fault(address: usize, esr: u64, regs: *mut c_void);
}

#[cfg(target_arch = "aarch64")]
unsafe extern "C" fn frida_arm64_fixup(regs: *mut c_void) -> c_int {
    let prologue = INSTALLED.load(Ordering::Acquire);
    let fixed = unsafe { ((*prologue).call_original)(regs) };
    let mut context = unsafe { context_of(regs) };
    if fixed != 0 || !is_ours(context.pc as usize) {
        return fixed;
    }

    unsafe { recover(regs, &mut context) };
    1
}

#[cfg(target_arch = "aarch64")]
unsafe extern "C" fn frida_arm64_kernel_fault(address: usize, esr: u64, regs: *mut c_void) {
    let mut context = unsafe { context_of(regs) };
    if esr >> ESR_CLASS_SHIFT != INSTRUCTION_ABORT_HERE || !is_ours(context.pc as usize) {
        unsafe { frida_arm64_call_original_kernel_fault(address, esr, regs) };
        return;
    }

    unsafe { recover(regs, &mut context) };
}

#[cfg(target_arch = "aarch64")]
unsafe fn recover(regs: *mut c_void, context: &mut GumCpuContext) {
    let faulted_at = context.pc as usize;
    let accessed: usize;
    unsafe { core::arch::asm!("mrs {}, far_el1", out(reg) accessed, options(nomem, nostack)) };
    if !handled(faulted_at, accessed, context) {
        let esr: u64;
        unsafe { core::arch::asm!("mrs {}, esr_el1", out(reg) esr, options(nomem, nostack)) };
        crate::note_unhandled_fault(esr, faulted_at as u64, accessed as u64);
        context.pc = frida_park as *const () as usize as u64;
    }
    unsafe { restore_context(regs, context) };
}

#[cfg(target_arch = "aarch64")]
unsafe fn context_of(regs: *mut c_void) -> GumCpuContext {
    let r = regs as *const u64;
    let mut x = [0u64; 29];
    for slot in 0..29 {
        x[slot] = unsafe { r.add(slot).read() };
    }
    GumCpuContext {
        pc: unsafe { r.add(32).read() },
        sp: unsafe { r.add(31).read() },
        nzcv: unsafe { r.add(33).read() },
        x,
        fp: unsafe { r.add(29).read() },
        lr: unsafe { r.add(30).read() },
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn restore_context(regs: *mut c_void, c: &GumCpuContext) {
    let r = regs as *mut u64;
    unsafe {
        for slot in 0..29 {
            r.add(slot).write(c.x[slot]);
        }
        r.add(29).write(c.fp);
        r.add(30).write(c.lr);
        r.add(31).write(c.sp);
        r.add(32).write(c.pc);
        r.add(33).write(c.nzcv);
    }
}

#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    static _fixup_exception: unsafe extern "C" fn();
    static ___do_kernel_fault: usize;
    static _aarch64_insn_patch_text_nosync: unsafe extern "C" fn(*mut c_void, u32) -> c_int;
}

fn is_ours(faulted_at: usize) -> bool {
    let (base, size) = crate::own_range();
    (faulted_at >= base && faulted_at - base < size) || crate::on_js_thread()
}

fn handled(faulted_at: usize, accessed: usize, context: &mut GumCpuContext) -> bool {
    unsafe { gum_barebone_handle_exception(ACCESS_VIOLATION, faulted_at as *mut c_void, accessed as *mut c_void, context) != 0 }
}

extern "C" fn frida_park() -> ! {
    static mut PARK_TOKEN: u8 = 0;
    crate::tell_the_host_we_faulted();
    loop {
        crate::kernel::wait(ptr::addr_of!(PARK_TOKEN), None, &mut || false);
    }
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm", target_arch = "aarch64")))]
pub fn install() {}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm", target_arch = "aarch64")))]
pub fn uninstall() {}
