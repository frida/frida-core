// The host writes an address into each slot before it calls _start. Thus these functions are
// not link-time imports. They use the usual Windows convention, not VMM's registers, thus
// the code calls the slots directly.

use alloc::boxed::Box;
use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::kernel::{CpuState, ThreadEntry, ThreadInfo};

pub const MODULE_DIRECTORY: &str = "/WINDOWS/system32/";

const DEBUG_CONSOLE_PORT: u16 = 0xe9;

pub fn log(msg: &str) {
    for byte in msg.bytes() {
        if byte == 0 {
            break;
        }
        write_debug_byte(byte);
    }
}

pub fn log_hex(value: usize) {
    let mut shift = usize::BITS;
    while shift != 0 {
        shift -= 4;
        let digit = ((value >> shift) & 0xf) as u8;
        write_debug_byte(if digit < 10 { b'0' + digit } else { b'a' + digit - 10 });
    }
    write_debug_byte(b'\n');
}

fn write_debug_byte(byte: u8) {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") DEBUG_CONSOLE_PORT, in("al") byte,
            options(nomem, nostack, preserves_flags));
    }
}

pub fn panic(msg: &str) -> ! {
    log(msg);
    unsafe {
        (_KeBugCheckEx)(MANUALLY_INITIATED_CRASH, msg.as_ptr() as usize, 0, 0, 0);
    }
    loop {}
}

const MANUALLY_INITIATED_CRASH: u32 = 0xe2;

pub fn alloc(size: usize) -> *mut u8 {
    unsafe { (_ExAllocatePoolWithTag)(NON_PAGED_POOL, size, POOL_TAG) }
}

pub fn free(ptr: *mut u8, _size: usize) {
    unsafe {
        (_ExFreePoolWithTag)(ptr, POOL_TAG);
    }
}

// The non-paged pool is executable, and you can use it at a high IRQL.
pub fn alloc_code(size: usize) -> *mut u8 {
    alloc(size)
}

pub fn free_code(ptr: *mut u8, size: usize) {
    free(ptr, size);
}

const NON_PAGED_POOL: u32 = 0;
const POOL_TAG: u32 = 0x6469_7246;

// The host enters on a thread that waits in a system service. The IRQL is PASSIVE_LEVEL and
// the kernel stack is complete.
pub fn run_when_ready(action: fn()) {
    action();
}

pub fn spawn_thread(entry: ThreadEntry, parameter: *mut c_void) -> isize {
    let start = Box::into_raw(Box::new(ThreadStart { entry, parameter }));

    let mut handle: *mut c_void = core::ptr::null_mut();
    let status = unsafe {
        (_PsCreateSystemThread)(
            &mut handle,
            THREAD_ALL_ACCESS,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            thread_start,
            start as *mut c_void,
        )
    };
    if status < 0 {
        drop(unsafe { Box::from_raw(start) });
        return -1;
    }

    unsafe {
        (_ZwClose)(handle);
    }

    0
}

// The kernel gives a system thread a stack of a few pages, and you cannot increase it. The
// script runtime needs more space, thus the body runs on a different stack.
#[cfg(target_arch = "x86")]
unsafe extern "stdcall" fn thread_start(context: *mut c_void) {
    unsafe { start_on_own_stack(context) }
}

#[cfg(target_arch = "x86_64")]
unsafe extern "win64" fn thread_start(context: *mut c_void) {
    unsafe { start_on_own_stack(context) }
}

unsafe fn start_on_own_stack(context: *mut c_void) {
    let stack = alloc(THREAD_STACK_SIZE);
    unsafe {
        frida_winnt_run_on_stack(stack.add(THREAD_STACK_SIZE), run_agent, context);
    }
}

unsafe extern "C" fn run_agent(context: *mut c_void) {
    let start = unsafe { Box::from_raw(context as *mut ThreadStart) };
    unsafe {
        (start.entry)(start.parameter, 0);
        (_PsTerminateSystemThread)(0);
    }
}

const THREAD_STACK_SIZE: usize = 64 * 1024;

struct ThreadStart {
    entry: ThreadEntry,
    parameter: *mut c_void,
}

const THREAD_ALL_ACCESS: u32 = 0x1f_03ff;

pub fn wait(token: *const u8, timeout_us: Option<u64>, check: &mut dyn FnMut() -> bool) {
    let event = event_for(token);
    if check() {
        return;
    }

    unsafe {
        match timeout_us {
            None => (_KeWaitForSingleObject)(event, EXECUTIVE, KERNEL_MODE, 0, core::ptr::null()),
            Some(us) => {
                let due_time = -((us as i64) * 10);
                (_KeWaitForSingleObject)(event, EXECUTIVE, KERNEL_MODE, 0, &due_time)
            }
        };
    }
}

pub fn wake(token: *const u8) {
    unsafe {
        (_KeSetEvent)(event_for(token), 0, 0);
    }
}

// The kernel has no futex. Thus each token uses an event, which the code makes on first use.
fn event_for(token: *const u8) -> *mut c_void {
    let slot = (token as usize / core::mem::align_of::<usize>()) % EVENTS.len();
    let existing = EVENTS[slot].load(Ordering::Acquire);
    if existing != 0 {
        return existing as *mut c_void;
    }

    let created = alloc(EVENT_SIZE) as *mut c_void;
    unsafe {
        (_KeInitializeEvent)(created, SYNCHRONIZATION_EVENT, 0);
    }
    match EVENTS[slot].compare_exchange(0, created as usize, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => created,
        Err(raced) => {
            free(created as *mut u8, EVENT_SIZE);
            raced as *mut c_void
        }
    }
}

const NUM_EVENTS: usize = 64;
static EVENTS: [AtomicUsize; NUM_EVENTS] = [const { AtomicUsize::new(0) }; NUM_EVENTS];

const EVENT_SIZE: usize = 0x10;
const SYNCHRONIZATION_EVENT: u32 = 1;
const EXECUTIVE: u32 = 0;
const KERNEL_MODE: u32 = 0;

pub fn yield_now() {
    unsafe {
        (_ZwYieldExecution)();
    }
}

pub fn monotonic_micros() -> i64 {
    read_system_time(INTERRUPT_TIME_OFFSET) / 10
}

pub fn wall_clock_micros() -> (u32, u32) {
    let micros = (read_system_time(SYSTEM_TIME_OFFSET) / 10) - UNIX_EPOCH_MICROS;
    ((micros / 1_000_000) as u32, (micros % 1_000_000) as u32)
}

// The kernel writes the two halves without a lock. Thus read them again until they agree.
fn read_system_time(offset: usize) -> i64 {
    let time = (SHARED_DATA + offset) as *const u32;
    loop {
        unsafe {
            let high = time.add(2).read_volatile();
            let low = time.read_volatile();
            if time.add(1).read_volatile() == high {
                return (((high as u64) << 32) | (low as u64)) as i64;
            }
        }
    }
}

#[cfg(target_arch = "x86")]
const SHARED_DATA: usize = 0xffdf_0000;
#[cfg(target_arch = "x86_64")]
const SHARED_DATA: usize = 0xffff_f780_0000_0000;
const INTERRUPT_TIME_OFFSET: usize = 0x08;
const SYSTEM_TIME_OFFSET: usize = 0x14;
const UNIX_EPOCH_MICROS: i64 = 11_644_473_600_000_000;

pub fn current_thread_id() -> u64 {
    unsafe { (_PsGetCurrentThreadId)() as u64 }
}

pub use crate::winnt_paging::{enumerate_ranges, protect, protection_at};

// A 32-bit kernel receives the physical address as two halves. A 64-bit kernel receives it
// as one value.
#[cfg(target_arch = "x86")]
pub fn map_io(phys_addr: u64, size: u64) -> *mut c_void {
    unsafe {
        (_MmMapIoSpace)(
            phys_addr as u32,
            (phys_addr >> 32) as u32,
            size as usize,
            MM_NON_CACHED,
        )
    }
}

#[cfg(target_arch = "x86_64")]
pub fn map_io(phys_addr: u64, size: u64) -> *mut c_void {
    unsafe { (_MmMapIoSpace)(phys_addr as i64, size as usize, MM_NON_CACHED) }
}

pub fn virt_to_phys(vaddr: u64) -> u64 {
    unsafe { (_MmGetPhysicalAddress)(vaddr as *const c_void) }
}

const MM_NON_CACHED: u32 = 0;

pub fn install_interrupt_handler(
    irq: u32,
    target: *mut c_void,
    handler: InterruptHandler,
    refcon: *mut c_void,
) -> i32 {
    unsafe {
        HW_INT_HANDLER = Some(handler);
        HW_INT_TARGET = target;
        HW_INT_REFCON = refcon;
    }

    let mut irql: u8 = 0;
    let mut affinity: usize = 0;
    let vector = unsafe {
        (_HalGetInterruptVector)(PCI_BUS, 0, irq, irq, &mut irql, &mut affinity)
    };

    let status = unsafe {
        (_IoConnectInterrupt)(
            core::ptr::addr_of_mut!(INTERRUPT_OBJECT),
            on_hw_int,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            vector,
            irql,
            irql,
            LEVEL_SENSITIVE,
            1,
            affinity,
            0,
        )
    };
    if status < 0 { -1 } else { 0 }
}

#[cfg(target_arch = "x86")]
unsafe extern "stdcall" fn on_hw_int(interrupt: *mut c_void, context: *mut c_void) -> u8 {
    unsafe { serve_hw_int(interrupt, context) }
}

#[cfg(target_arch = "x86_64")]
unsafe extern "win64" fn on_hw_int(interrupt: *mut c_void, context: *mut c_void) -> u8 {
    unsafe { serve_hw_int(interrupt, context) }
}

unsafe fn serve_hw_int(_interrupt: *mut c_void, _context: *mut c_void) -> u8 {
    unsafe {
        if let Some(handler) = HW_INT_HANDLER {
            handler(HW_INT_TARGET, HW_INT_REFCON, core::ptr::null_mut(), 0);
        }
    }
    1
}

static mut INTERRUPT_OBJECT: *mut c_void = core::ptr::null_mut();
static mut HW_INT_HANDLER: Option<InterruptHandler> = None;
static mut HW_INT_TARGET: *mut c_void = core::ptr::null_mut();
static mut HW_INT_REFCON: *mut c_void = core::ptr::null_mut();

const PCI_BUS: u32 = 5;
const LEVEL_SENSITIVE: u32 = 1;

pub type InterruptHandler =
    unsafe extern "C" fn(target: *mut c_void, refcon: *mut c_void, nub: *mut c_void, source: i32);

// The kernel has no interface to install a handler, thus the code replaces the gates. Each
// processor has its own table, and these guests have one processor.
pub fn install_fault_reporter() {
    unsafe {
        FAULT_CHAIN[INVALID_OPCODE as usize] = hook_gate(INVALID_OPCODE, frida_winnt_fault_thunk_ud);
        FAULT_CHAIN[GENERAL_PROTECTION as usize] =
            hook_gate(GENERAL_PROTECTION, frida_winnt_fault_thunk_gp);
        FAULT_CHAIN[PAGE_FAULT as usize] = hook_gate(PAGE_FAULT, frida_winnt_fault_thunk_pf);
    }
}

#[cfg(target_arch = "x86")]
unsafe fn hook_gate(vector: u32, thunk: unsafe extern "C" fn()) -> usize {
    let gate = (descriptor_table_base() + (vector as usize * GATE_SIZE)) as *mut u16;

    unsafe {
        let previous = ((gate.add(3).read() as usize) << 16) | (gate.read() as usize);

        let handler = thunk as usize;
        gate.write(handler as u16);
        gate.add(3).write((handler >> 16) as u16);

        previous
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn hook_gate(vector: u32, thunk: unsafe extern "C" fn()) -> usize {
    let gate = (descriptor_table_base() + (vector as usize * GATE_SIZE)) as *mut u16;

    unsafe {
        let high = gate.add(4) as *mut u32;
        let previous = ((high.read() as usize) << 32)
            | ((gate.add(3).read() as usize) << 16)
            | (gate.read() as usize);

        let handler = thunk as usize;
        gate.write(handler as u16);
        gate.add(3).write((handler >> 16) as u16);
        high.write((handler >> 32) as u32);

        previous
    }
}

fn descriptor_table_base() -> usize {
    let mut descriptor = [0u8; DESCRIPTOR_SIZE];
    unsafe {
        core::arch::asm!("sidt [{0}]", in(reg) descriptor.as_mut_ptr(),
            options(nostack, preserves_flags));
        descriptor.as_ptr().add(2).cast::<usize>().read_unaligned()
    }
}

#[cfg(target_arch = "x86")]
const GATE_SIZE: usize = 8;
#[cfg(target_arch = "x86_64")]
const GATE_SIZE: usize = 16;

const DESCRIPTOR_SIZE: usize = 2 + core::mem::size_of::<usize>();

// Report only the faults from our own code. Send the other faults, primarily the paging
// faults of the kernel, to the handler that was there before.
#[cfg(target_arch = "x86")]
#[unsafe(no_mangle)]
extern "C" fn frida_winnt_on_fault(fault: u32, frame: *mut u32) -> usize {
    let eip_slot = fault_frame_pc_slot(fault);
    let eip = unsafe { frame.add(eip_slot).read() };
    if !is_ours(eip as u64) {
        return unsafe { FAULT_CHAIN[fault as usize] };
    }

    let mut cpu_context = unsafe {
        crate::bindings::_GumIA32CpuContext {
            eip,
            edi: frame.read(),
            esi: frame.add(1).read(),
            ebp: frame.add(2).read(),
            esp: frame.add(3).read(),
            ebx: frame.add(4).read(),
            edx: frame.add(5).read(),
            ecx: frame.add(6).read(),
            eax: frame.add(7).read(),
            xmm: core::ptr::null_mut(),
        }
    };

    if !handle(fault, eip as u64, &mut cpu_context) {
        return unsafe { FAULT_CHAIN[fault as usize] };
    }

    // Gum returns a different stack pointer, but an iret in the same privilege level does not
    // load one. Thus the thunk puts the registers back from a record.
    unsafe {
        frida_winnt_resume = [
            cpu_context.eip,
            cpu_context.edi,
            cpu_context.esi,
            cpu_context.ebp,
            cpu_context.esp,
            cpu_context.ebx,
            cpu_context.edx,
            cpu_context.ecx,
            cpu_context.eax,
            frame.add(eip_slot + 2).read(),
        ];
    }

    0
}

#[cfg(target_arch = "x86")]
#[unsafe(no_mangle)]
static mut frida_winnt_resume: [u32; 10] = [0; 10];

// A long-mode frame always contains the stack pointer. Thus write the values from Gum into
// the frame.
#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
extern "C" fn frida_winnt_on_fault(fault: u32, frame: *mut u64) -> usize {
    let rip_slot = fault_frame_pc_slot(fault);
    let rip = unsafe { frame.add(rip_slot).read() };
    if !is_ours(rip) {
        return unsafe { FAULT_CHAIN[fault as usize] };
    }

    let mut cpu_context = unsafe {
        crate::bindings::_GumX64CpuContext {
            rip,
            r15: frame.read(),
            r14: frame.add(1).read(),
            r13: frame.add(2).read(),
            r12: frame.add(3).read(),
            r11: frame.add(4).read(),
            r10: frame.add(5).read(),
            r9: frame.add(6).read(),
            r8: frame.add(7).read(),
            rdi: frame.add(8).read(),
            rsi: frame.add(9).read(),
            rbp: frame.add(10).read(),
            rsp: frame.add(rip_slot + STACK_POINTER_IN_FRAME).read(),
            rbx: frame.add(12).read(),
            rdx: frame.add(13).read(),
            rcx: frame.add(14).read(),
            rax: frame.add(15).read(),
            xmm: core::ptr::null_mut(),
        }
    };

    if !handle(fault, rip, &mut cpu_context) {
        return unsafe { FAULT_CHAIN[fault as usize] };
    }

    unsafe {
        frame.add(rip_slot).write(cpu_context.rip);
        frame.add(rip_slot + STACK_POINTER_IN_FRAME).write(cpu_context.rsp);

        frame.write(cpu_context.r15);
        frame.add(1).write(cpu_context.r14);
        frame.add(2).write(cpu_context.r13);
        frame.add(3).write(cpu_context.r12);
        frame.add(4).write(cpu_context.r11);
        frame.add(5).write(cpu_context.r10);
        frame.add(6).write(cpu_context.r9);
        frame.add(7).write(cpu_context.r8);
        frame.add(8).write(cpu_context.rdi);
        frame.add(9).write(cpu_context.rsi);
        frame.add(10).write(cpu_context.rbp);
        frame.add(12).write(cpu_context.rbx);
        frame.add(13).write(cpu_context.rdx);
        frame.add(14).write(cpu_context.rcx);
        frame.add(15).write(cpu_context.rax);
    }

    0
}

#[cfg(target_arch = "x86_64")]
const STACK_POINTER_IN_FRAME: usize = 3;

fn handle(fault: u32, pc: u64, cpu_context: &mut crate::bindings::GumCpuContext) -> bool {
    let handled = unsafe {
        crate::bindings::gum_barebone_handle_exception(
            exception_type_for(fault),
            pc as *mut c_void,
            faulting_address() as *mut c_void,
            cpu_context,
        )
    };

    handled != 0
}

fn is_ours(address: u64) -> bool {
    let own = unsafe { &*core::ptr::addr_of!(crate::OWN_RANGE) };
    if address >= own.base_address && address < own.base_address + own.size as u64 {
        return true;
    }
    crate::gum::is_agent_slab_if_idle(address).unwrap_or(false)
}

fn fault_frame_pc_slot(fault: u32) -> usize {
    const VECTOR: usize = 1;

    let error_code = match fault {
        8 | 10 | 11 | 12 | 13 | 14 | 17 | 21 => 1,
        _ => 0,
    };

    PUSHED_REGISTERS + VECTOR + error_code
}

#[cfg(target_arch = "x86")]
const PUSHED_REGISTERS: usize = 8;
#[cfg(target_arch = "x86_64")]
const PUSHED_REGISTERS: usize = 16;

fn exception_type_for(fault: u32) -> crate::bindings::GumExceptionType {
    use crate::bindings::*;

    match fault {
        INVALID_OPCODE => _GumExceptionType_GUM_EXCEPTION_ILLEGAL_INSTRUCTION,
        _ => _GumExceptionType_GUM_EXCEPTION_ACCESS_VIOLATION,
    }
}

fn faulting_address() -> usize {
    let address: usize;
    unsafe {
        core::arch::asm!("mov {0}, cr2", out(reg) address,
            options(nomem, nostack, preserves_flags));
    }
    address
}

static mut FAULT_CHAIN: [usize; 32] = [0; 32];

#[unsafe(no_mangle)]
static mut frida_winnt_fault_chain: usize = 0;

const INVALID_OPCODE: u32 = 6;
const GENERAL_PROTECTION: u32 = 13;
const PAGE_FAULT: u32 = 14;

pub fn enumerate_threads(found: &mut dyn FnMut(ThreadInfo)) {
    let Some(layout) = thread_layout() else {
        found(ThreadInfo { id: current_thread_id() as u32, cpu_state: None });
        return;
    };

    enumerate_processes(&mut |process| unsafe {
        let head = process.handle as usize + layout.head;
        let mut entry = (head as *const usize).read_volatile();
        while entry != head && entry != 0 {
            let thread = (entry - layout.entry) as *mut c_void;
            found(ThreadInfo {
                id: (_PsGetThreadId)(thread),
                cpu_state: capture(thread),
            });
            entry = (entry as *const usize).read_volatile();
        }
    });
}

// The kernel gives the registers of a thread only if the thread has a user-mode part. If the
// thread runs only in the kernel, the kernel reads after the end of its stack and stops the
// machine. A thread also cannot ask about itself.
unsafe fn capture(thread: *mut c_void) -> Option<CpuState> {
    unsafe {
        if (_PsGetProcessPeb)((_PsGetThreadProcess)(thread)).is_null() {
            return None;
        }
        if thread == (_PsGetCurrentThread)() {
            return None;
        }

        let context = &mut *core::ptr::addr_of_mut!(CONTEXT);
        context.fill(0);
        let base = context.as_mut_ptr().add(context.as_ptr().align_offset(CONTEXT_ALIGNMENT));
        base.add(CONTEXT_FLAGS).cast::<u32>().write_unaligned(CONTEXT_FULL);

        if (_PsGetContextThread)(thread, base, KERNEL_MODE as u8) < 0 {
            return None;
        }

        Some(cpu_state_of(base))
    }
}

static mut CONTEXT: [u8; CONTEXT_SIZE + CONTEXT_ALIGNMENT] = [0; CONTEXT_SIZE + CONTEXT_ALIGNMENT];

// No export gives the position of the thread list in a process. Thus calculate both offsets:
// the caller is on the list, and its own links go back into its process.
fn thread_layout() -> Option<ThreadLayout> {
    unsafe {
        if let Some(known) = THREAD_LAYOUT {
            return Some(known);
        }

        let me = (_PsGetCurrentThread)() as usize;
        let process = (_PsGetThreadProcess)(me as *mut c_void) as usize;

        for entry in (MIN_THREAD_ENTRY_OFFSET..MAX_OBJECT_SIZE).step_by(POINTER_SIZE) {
            let mut node = try_read_pointer(me + entry)?;
            for _ in 0..MAX_THREADS_PER_PROCESS {
                if node >= process && node < process + MAX_OBJECT_SIZE {
                    let layout = ThreadLayout { head: node - process, entry };
                    THREAD_LAYOUT = Some(layout);
                    return Some(layout);
                }
                let Some(next) = try_read_pointer(node) else {
                    break;
                };
                node = next;
            }
        }

        None
    }
}

#[derive(Clone, Copy)]
struct ThreadLayout {
    head: usize,
    entry: usize,
}

static mut THREAD_LAYOUT: Option<ThreadLayout> = None;

// This walk uses calculated addresses, thus read through Gum, which recovers from a fault.
unsafe fn try_read_pointer(address: usize) -> Option<usize> {
    unsafe {
        let mut read: crate::bindings::gsize = 0;
        let data = crate::bindings::gum_memory_read(address as *const c_void, POINTER_SIZE as crate::bindings::gsize,
            &mut read);
        if data.is_null() {
            return None;
        }

        let value = (data as *const usize).read_unaligned();
        crate::bindings::g_free(data as *mut c_void);

        Some(value)
    }
}

const POINTER_SIZE: usize = core::mem::size_of::<usize>();

#[cfg(target_arch = "x86")]
const MIN_THREAD_ENTRY_OFFSET: usize = 0x100;
#[cfg(target_arch = "x86")]
const MAX_OBJECT_SIZE: usize = 0x300;

#[cfg(target_arch = "x86_64")]
const MIN_THREAD_ENTRY_OFFSET: usize = 0x200;
#[cfg(target_arch = "x86_64")]
const MAX_OBJECT_SIZE: usize = 0x700;

const MAX_THREADS_PER_PROCESS: usize = 1024;

// The layout of a CONTEXT is part of the architecture, thus these offsets are known.
#[cfg(target_arch = "x86")]
unsafe fn cpu_state_of(base: *const u8) -> CpuState {
    let field = |offset: usize| unsafe { base.add(offset).cast::<u32>().read_unaligned() };

    CpuState {
        eip: field(0xb8),
        edi: field(0x9c),
        esi: field(0xa0),
        ebp: field(0xb4),
        esp: field(0xc4),
        ebx: field(0xa4),
        edx: field(0xa8),
        ecx: field(0xac),
        eax: field(0xb0),
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn cpu_state_of(base: *const u8) -> CpuState {
    let field = |offset: usize| unsafe { base.add(offset).cast::<u64>().read_unaligned() };

    CpuState {
        rip: field(0xf8),
        r15: field(0xf0),
        r14: field(0xe8),
        r13: field(0xe0),
        r12: field(0xd8),
        r11: field(0xd0),
        r10: field(0xc8),
        r9: field(0xc0),
        r8: field(0xb8),
        rdi: field(0xb0),
        rsi: field(0xa8),
        rbp: field(0xa0),
        rsp: field(0x98),
        rbx: field(0x90),
        rdx: field(0x88),
        rcx: field(0x80),
        rax: field(0x78),
    }
}

#[cfg(target_arch = "x86")]
const CONTEXT_SIZE: usize = 716;
#[cfg(target_arch = "x86")]
const CONTEXT_ALIGNMENT: usize = 4;
#[cfg(target_arch = "x86")]
const CONTEXT_FLAGS: usize = 0x00;
#[cfg(target_arch = "x86")]
const CONTEXT_FULL: u32 = 0x0001_0007;

#[cfg(target_arch = "x86_64")]
const CONTEXT_SIZE: usize = 1232;
#[cfg(target_arch = "x86_64")]
const CONTEXT_ALIGNMENT: usize = 16;
#[cfg(target_arch = "x86_64")]
const CONTEXT_FLAGS: usize = 0x30;
#[cfg(target_arch = "x86_64")]
const CONTEXT_FULL: u32 = 0x0010_0003;

pub struct ProcessInfo {
    pub id: u32,
    pub path: *const u8,
    pub command_line: *const u8,
    pub handle: *mut c_void,
}

// Find only the head of the list. Read the other data with the accessors that the kernel
// exports, thus the code assumes no layout.
pub fn enumerate_processes(found: &mut dyn FnMut(ProcessInfo)) {
    let head = unsafe { _PsActiveProcessHead };
    let system = unsafe { (_PsInitialSystemProcess as *const usize).read_volatile() };
    if head == 0 || system == 0 {
        return;
    }

    let first = unsafe { (head as *const usize).read_volatile() };
    let links = first.wrapping_sub(system);

    let mut entry = first;
    while entry != head && entry != 0 {
        let process = entry.wrapping_sub(links) as *mut c_void;
        unsafe {
            let (path, command_line) = describe(process);
            found(ProcessInfo {
                id: (_PsGetProcessId)(process),
                path,
                command_line,
                handle: process,
            });
        }
        entry = unsafe { (entry as *const usize).read_volatile() };
    }
}

// A process keeps its path in its user-mode block. Thus attach to that address space to read
// it. The processes of the kernel have no such block and keep a short name.
unsafe fn describe(process: *mut c_void) -> (*const u8, *const u8) {
    unsafe {
        let path = &mut *core::ptr::addr_of_mut!(PATH);
        let command_line = &mut *core::ptr::addr_of_mut!(COMMAND_LINE);
        path[0] = 0;
        command_line[0] = 0;

        let mut apc_state = [0usize; APC_STATE_WORDS];
        (_KeStackAttachProcess)(process, apc_state.as_mut_ptr() as *mut u8);

        let peb = (_PsGetProcessPeb)(process) as usize;
        if peb != 0 {
            let parameters = ((peb + PEB_PARAMETERS_OFFSET) as *const usize).read_unaligned();
            read_user_string(parameters + PARAMETERS_IMAGE_PATH_OFFSET, path);
            read_user_string(parameters + PARAMETERS_COMMAND_LINE_OFFSET, command_line);
        }

        (_KeUnstackDetachProcess)(apc_state.as_mut_ptr() as *mut u8);

        let name = if path[0] != 0 { path.as_ptr() } else { image_name(process) };
        (name, command_line.as_ptr())
    }
}

// This read can cause a fault if the page is not in memory. At PASSIVE_LEVEL the pager gets
// the page again.
unsafe fn read_user_string(address: usize, out: &mut [u8]) {
    unsafe {
        let string = address as *const u8;
        let length = (string as *const u16).read_unaligned() as usize;
        let buffer = (string.add(UNICODE_STRING_BUFFER_OFFSET) as *const usize).read_unaligned();
        if buffer == 0 {
            return;
        }

        let limit = out.len() - 1;
        let mut written = 0;
        for i in 0..length.min(limit) / 2 {
            let c = ((buffer as *const u16).add(i)).read_unaligned();
            written += encode_utf8(c, &mut out[written..limit]);
        }
        out[written] = 0;
    }
}

fn encode_utf8(c: u16, out: &mut [u8]) -> usize {
    if c < 0x80 && !out.is_empty() {
        out[0] = c as u8;
        return 1;
    }
    if c < 0x800 && out.len() >= 2 {
        out[0] = 0xc0 | (c >> 6) as u8;
        out[1] = 0x80 | (c & 0x3f) as u8;
        return 2;
    }
    if out.len() >= 3 {
        out[0] = 0xe0 | (c >> 12) as u8;
        out[1] = 0x80 | ((c >> 6) & 0x3f) as u8;
        out[2] = 0x80 | (c & 0x3f) as u8;
        return 3;
    }
    0
}

static mut PATH: [u8; MAX_PATH_SIZE] = [0; MAX_PATH_SIZE];
static mut COMMAND_LINE: [u8; MAX_COMMAND_LINE_SIZE] = [0; MAX_COMMAND_LINE_SIZE];

const APC_STATE_WORDS: usize = 8;

#[cfg(target_arch = "x86")]
const PEB_PARAMETERS_OFFSET: usize = 0x10;
#[cfg(target_arch = "x86")]
const PARAMETERS_IMAGE_PATH_OFFSET: usize = 0x38;
#[cfg(target_arch = "x86")]
const PARAMETERS_COMMAND_LINE_OFFSET: usize = 0x40;

#[cfg(target_arch = "x86_64")]
const PEB_PARAMETERS_OFFSET: usize = 0x20;
#[cfg(target_arch = "x86_64")]
const PARAMETERS_IMAGE_PATH_OFFSET: usize = 0x60;
#[cfg(target_arch = "x86_64")]
const PARAMETERS_COMMAND_LINE_OFFSET: usize = 0x70;

const UNICODE_STRING_BUFFER_OFFSET: usize = POINTER_SIZE;
const MAX_PATH_SIZE: usize = 1024;
const MAX_COMMAND_LINE_SIZE: usize = 2048;

// This field has a fixed width. It ends with a NUL only if the name is sufficiently short.
unsafe fn image_name(process: *mut c_void) -> *const u8 {
    unsafe {
        let field = (_PsGetProcessImageFileName)(process);
        let name = &mut *core::ptr::addr_of_mut!(IMAGE_NAME);
        core::ptr::copy_nonoverlapping(field, name.as_mut_ptr(), IMAGE_NAME_SIZE);
        name[IMAGE_NAME_SIZE] = 0;
        name.as_ptr()
    }
}

static mut IMAGE_NAME: [u8; IMAGE_NAME_SIZE + 1] = [0; IMAGE_NAME_SIZE + 1];

const IMAGE_NAME_SIZE: usize = 16;

pub fn enumerate_icons(path: *const u8, found: &mut dyn FnMut(&[u8])) {
    let mut read = || {
        let Some(file) = File::open(path) else {
            return;
        };

        crate::icons::enumerate(&file, found);
    };

    on_kernel_stack(&mut read);
}

// The system-service dispatcher accepts only the stack that the kernel gave to the thread.
// The agent uses a larger stack for the script runtime. Thus a different thread, which keeps
// its kernel stack, makes these calls while the caller waits.
fn on_kernel_stack(work: &mut dyn FnMut()) {
    unsafe {
        if READER_RUNNING == 0 {
            READER_RUNNING = 1;
            spawn_reader();
        }

        WORK = Some(core::mem::transmute::<&mut dyn FnMut(), *mut (dyn FnMut() + 'static)>(work));
        wake(request_token());

        while core::ptr::addr_of!(WORK).read().is_some() {
            wait(done_token(), None, &mut || core::ptr::addr_of!(WORK).read().is_none());
        }
    }
}

fn spawn_reader() {
    let mut handle: *mut c_void = core::ptr::null_mut();
    unsafe {
        let status = (_PsCreateSystemThread)(
            &mut handle,
            THREAD_ALL_ACCESS,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            reader_start,
            core::ptr::null_mut(),
        );
        if status >= 0 {
            (_ZwClose)(handle);
        }
    }
}

#[cfg(target_arch = "x86")]
unsafe extern "stdcall" fn reader_start(context: *mut c_void) {
    unsafe { read_for_others(context) }
}

#[cfg(target_arch = "x86_64")]
unsafe extern "win64" fn reader_start(context: *mut c_void) {
    unsafe { read_for_others(context) }
}

unsafe fn read_for_others(_context: *mut c_void) {
    loop {
        wait(request_token(), None, &mut || unsafe {
            core::ptr::addr_of!(WORK).read().is_some()
        });

        let pending = unsafe { core::ptr::addr_of!(WORK).read() };
        let Some(work) = pending else {
            continue;
        };

        unsafe {
            (*work)();
            WORK = None;
        }
        wake(done_token());
    }
}

fn request_token() -> *const u8 {
    core::ptr::addr_of!(READER_RUNNING)
}

fn done_token() -> *const u8 {
    core::ptr::addr_of!(WORK) as *const u8
}

static mut READER_RUNNING: u8 = 0;
static mut WORK: Option<*mut dyn FnMut()> = None;

struct File {
    handle: *mut c_void,
}

impl File {
    // This form is not always a form that the object manager accepts.
    fn open(path: *const u8) -> Option<File> {
        let name = unsafe { &mut *core::ptr::addr_of_mut!(OBJECT_NAME) };
        let mut length = 0;
        for c in object_directory_of(path).iter().copied().chain(ascii_of(path)) {
            if length == name.len() {
                return None;
            }
            name[length] = c as u16;
            length += 1;
        }

        let name = UnicodeString {
            length: (length * 2) as u16,
            maximum_length: (length * 2) as u16,
            buffer: name.as_ptr(),
        };
        let attributes = ObjectAttributes {
            length: core::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: core::ptr::null_mut(),
            object_name: &name,
            attributes: OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            security_descriptor: core::ptr::null_mut(),
            security_quality_of_service: core::ptr::null_mut(),
        };

        let mut handle: *mut c_void = core::ptr::null_mut();
        let mut status_block = [0usize; 2];
        let status = unsafe {
            (_ZwCreateFile)(
                &mut handle,
                GENERIC_READ | SYNCHRONIZE,
                &attributes,
                status_block.as_mut_ptr(),
                core::ptr::null(),
                0,
                FILE_SHARE_READ,
                FILE_OPEN,
                FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                core::ptr::null(),
                0,
            )
        };
        if status < 0 {
            return None;
        }

        Some(File { handle })
    }
}

impl crate::icons::Image for File {
    fn read_at(&self, position: u32, buffer: &mut [u8]) -> u32 {
        let mut status_block = [0usize; 2];
        let offset = position as i64;
        let status = unsafe {
            (_ZwReadFile)(
                self.handle,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                status_block.as_mut_ptr(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                &offset,
                core::ptr::null(),
            )
        };
        if status < 0 {
            return 0;
        }

        status_block[1] as u32
    }
}

impl Drop for File {
    fn drop(&mut self) {
        unsafe {
            (_ZwClose)(self.handle);
        }
    }
}

// A path with a drive letter goes through the directory of symbolic links. A path that starts
// at the root of the object manager needs no change.
fn object_directory_of(path: *const u8) -> &'static [u8] {
    if unsafe { path.read() } == b'\\' {
        return &[];
    }

    &DEVICE_PREFIX
}

fn ascii_of(text: *const u8) -> impl Iterator<Item = u8> {
    (0..).map_while(move |i| match unsafe { text.add(i).read() } {
        0 => None,
        c => Some(c),
    })
}

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: *mut c_void,
    object_name: *const UnicodeString,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

static mut OBJECT_NAME: [u16; MAX_PATH_SIZE] = [0; MAX_PATH_SIZE];

const DEVICE_PREFIX: [u8; 4] = [b'\\', b'?', b'?', b'\\'];
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const OBJ_KERNEL_HANDLE: u32 = 0x200;
const GENERIC_READ: u32 = 0x8000_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const FILE_SHARE_READ: u32 = 0x1;
const FILE_OPEN: u32 = 0x1;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
const FILE_NON_DIRECTORY_FILE: u32 = 0x40;

pub fn get_kernel_base() -> u64 {
    KERNEL_BASE.load(Ordering::Relaxed) as u64
}

pub fn set_kernel_base(base: u64) {
    KERNEL_BASE.store(base as usize, Ordering::Relaxed);
}

static KERNEL_BASE: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" {
    fn frida_winnt_run_on_stack(stack_top: *mut u8, entry: unsafe extern "C" fn(*mut c_void),
        context: *mut c_void);
    fn frida_winnt_fault_thunk_ud();
    fn frida_winnt_fault_thunk_gp();
    fn frida_winnt_fault_thunk_pf();
}

// To give a fault back to the kernel, remove only the vector from the frame. Thus the error
// code stays where the previous handler reads it.
#[cfg(target_arch = "x86")]
core::arch::global_asm!(
    r#"
.intel_syntax noprefix

.global frida_winnt_run_on_stack
frida_winnt_run_on_stack:
    mov ecx, [esp + 4]
    mov edx, [esp + 8]
    mov eax, [esp + 12]
    and ecx, -16
    mov esp, ecx
    push eax
    call edx
1:
    jmp 1b

.macro FAULT_THUNK name, vector
.global \name
\name:
    push \vector
    pushad
    push esp
    push \vector
    call frida_winnt_on_fault
    add esp, 8
    test eax, eax
    jnz 1f
    mov esp, [frida_winnt_resume + 16]
    push dword ptr [frida_winnt_resume + 36]
    popfd
    mov edi, [frida_winnt_resume + 4]
    mov esi, [frida_winnt_resume + 8]
    mov ebp, [frida_winnt_resume + 12]
    mov ebx, [frida_winnt_resume + 20]
    mov edx, [frida_winnt_resume + 24]
    mov ecx, [frida_winnt_resume + 28]
    mov eax, [frida_winnt_resume + 32]
    jmp dword ptr [frida_winnt_resume]
1:
    mov [frida_winnt_fault_chain], eax
    popad
    add esp, 4
    jmp dword ptr [frida_winnt_fault_chain]
.endm

FAULT_THUNK frida_winnt_fault_thunk_ud, 6
FAULT_THUNK frida_winnt_fault_thunk_gp, 13
FAULT_THUNK frida_winnt_fault_thunk_pf, 14
"#
);

// The code pushes the registers in the order that Gum uses, thus the handler reads them where
// they are. A long-mode iret loads the stack pointer from the frame, thus the handler changes
// the frame.
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    r#"
.intel_syntax noprefix

.global frida_winnt_run_on_stack
frida_winnt_run_on_stack:
    and rdi, -16
    mov rsp, rdi
    mov rdi, rdx
    call rsi
1:
    jmp 1b

.macro PUSH_GPRS
    push rax
    push rcx
    push rdx
    push rbx
    push rsp
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
.endm

.macro POP_GPRS
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    add rsp, 8
    pop rbx
    pop rdx
    pop rcx
    pop rax
.endm

// To chain, remove only the vector, thus the error code stays where the previous handler
// reads it. The return must also step over that code, because iret reads the frame from the
// position that the processor used.
.macro FAULT_THUNK name, vector, error_code
.global \name
\name:
    push \vector
    PUSH_GPRS
    mov rdi, \vector
    mov rsi, rsp
    mov rbx, rsp
    and rsp, -16
    call frida_winnt_on_fault
    mov rsp, rbx
    test rax, rax
    jnz 1f
    POP_GPRS
    add rsp, 8 + \error_code
    iretq
1:
    mov qword ptr [rip + frida_winnt_fault_chain], rax
    POP_GPRS
    add rsp, 8
    jmp qword ptr [rip + frida_winnt_fault_chain]
.endm

FAULT_THUNK frida_winnt_fault_thunk_ud, 6, 0
FAULT_THUNK frida_winnt_fault_thunk_gp, 13, 8
FAULT_THUNK frida_winnt_fault_thunk_pf, 14, 8
"#
);

#[cfg(target_arch = "x86")]
macro_rules! kernel_abi {
    ($($declaration:tt)*) => {
        unsafe extern "C" {
            $($declaration)*
        }

        type ThreadStartRoutine = unsafe extern "stdcall" fn(*mut c_void);
        type ServiceRoutine = unsafe extern "stdcall" fn(*mut c_void, *mut c_void) -> u8;
    };
}

#[cfg(target_arch = "x86_64")]
macro_rules! kernel_abi {
    ($($declaration:tt)*) => {
        unsafe extern "C" {
            $($declaration)*
        }

        type ThreadStartRoutine = unsafe extern "win64" fn(*mut c_void);
        type ServiceRoutine = unsafe extern "win64" fn(*mut c_void, *mut c_void) -> u8;
    };
}

#[cfg(target_arch = "x86")]
macro_rules! kernel_fn {
    ($($argument:ty),* $(,)?) => { unsafe extern "stdcall" fn($($argument),*) };
    ($($argument:ty),* $(,)? => $result:ty) => {
        unsafe extern "stdcall" fn($($argument),*) -> $result
    };
}

#[cfg(target_arch = "x86_64")]
macro_rules! kernel_fn {
    ($($argument:ty),* $(,)?) => { unsafe extern "win64" fn($($argument),*) };
    ($($argument:ty),* $(,)? => $result:ty) => {
        unsafe extern "win64" fn($($argument),*) -> $result
    };
}

kernel_abi! {
    static _ExAllocatePoolWithTag: kernel_fn!(u32, usize, u32 => *mut u8);
    static _ExFreePoolWithTag: kernel_fn!(*mut u8, u32);
    static _PsCreateSystemThread: kernel_fn!(
        *mut *mut c_void,
        u32,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        ThreadStartRoutine,
        *mut c_void,
        => i32);
    static _PsTerminateSystemThread: kernel_fn!(i32 => i32);
    static _PsGetCurrentThreadId: kernel_fn!( => u32);
    static _KeInitializeEvent: kernel_fn!(*mut c_void, u32, u8);
    static _KeWaitForSingleObject: kernel_fn!(*mut c_void, u32, u32, u8, *const i64 => i32);
    static _KeSetEvent: kernel_fn!(*mut c_void, u32, u8 => i32);
    static _ZwYieldExecution: kernel_fn!( => i32);
    static _KeBugCheckEx: kernel_fn!(u32, usize, usize, usize, usize => !);
    static _MmGetPhysicalAddress: kernel_fn!(*const c_void => u64);
    static _HalGetInterruptVector: kernel_fn!(u32, u32, u32, u32, *mut u8, *mut usize => u32);
    static _PsActiveProcessHead: usize;
    static _PsInitialSystemProcess: usize;
    static _PsGetProcessId: kernel_fn!(*mut c_void => u32);
    static _PsGetProcessImageFileName: kernel_fn!(*mut c_void => *const u8);
    static _PsGetProcessPeb: kernel_fn!(*mut c_void => *mut c_void);
    static _PsGetCurrentThread: kernel_fn!( => *mut c_void);
    static _PsGetThreadProcess: kernel_fn!(*mut c_void => *mut c_void);
    static _PsGetThreadId: kernel_fn!(*mut c_void => u32);
    static _PsGetContextThread: kernel_fn!(*mut c_void, *mut u8, u8 => i32);
    static _KeStackAttachProcess: kernel_fn!(*mut c_void, *mut u8);
    static _KeUnstackDetachProcess: kernel_fn!(*mut u8);
    static _ZwCreateFile: kernel_fn!(
        *mut *mut c_void,
        u32,
        *const ObjectAttributes,
        *mut usize,
        *const i64,
        u32,
        u32,
        u32,
        u32,
        *const c_void,
        u32,
        => i32);
    static _ZwReadFile: kernel_fn!(
        *mut c_void,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        *mut usize,
        *mut u8,
        u32,
        *const i64,
        *const u32,
        => i32);
    static _ZwClose: kernel_fn!(*mut c_void => i32);
    static _IoConnectInterrupt: kernel_fn!(
        *mut *mut c_void,
        ServiceRoutine,
        *mut c_void,
        *mut c_void,
        u32,
        u8,
        u8,
        u32,
        u8,
        usize,
        u8,
        => i32);
}

#[cfg(target_arch = "x86")]
unsafe extern "C" {
    static _MmMapIoSpace: unsafe extern "stdcall" fn(u32, u32, usize, u32) -> *mut c_void;
}

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    static _MmMapIoSpace: unsafe extern "win64" fn(i64, usize, u32) -> *mut c_void;
}
