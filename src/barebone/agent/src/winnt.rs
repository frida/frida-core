// The host writes an address into each slot before it calls _start. Thus these functions are
// not link-time imports. They use the usual Windows convention, not VMM's registers, thus
// the code calls the slots directly.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::kernel::{CpuState, ThreadEntry, ThreadInfo};

// A process is made in ring 3, thus a copy of the agent does this work.
pub use crate::winnt_user::{
    LoadedModule, LoaderEntryPoints, describe_module, enumerate_modules, loader_entry_points,
    on_module_load, on_module_load_with_flags, on_module_unload, resume_process, spawn_process,
};
use crate::winnt_paging::{GUM_PAGE_EXECUTE, GUM_PAGE_READ};

#[cfg(target_arch = "x86")]
macro_rules! windows_fn {
    ($($argument:ty),* $(,)?) => { unsafe extern "stdcall" fn($($argument),*) };
    ($($argument:ty),* $(,)? => $result:ty) => {
        unsafe extern "stdcall" fn($($argument),*) -> $result
    };
}

#[cfg(target_arch = "x86_64")]
macro_rules! windows_fn {
    ($($argument:ty),* $(,)?) => { unsafe extern "win64" fn($($argument),*) };
    ($($argument:ty),* $(,)? => $result:ty) => {
        unsafe extern "win64" fn($($argument),*) -> $result
    };
}

pub(crate) use windows_fn;

pub const MODULE_DIRECTORY: &str = "/WINDOWS/system32/";

const DEBUG_CONSOLE_PORT: u16 = 0xe9;

pub fn log(msg: &str) {
    (primitives().log)(msg)
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
    (primitives().alloc)(size)
}

pub fn free(ptr: *mut u8, size: usize) {
    (primitives().free)(ptr, size)
}

// The non-paged pool is executable, and you can use it at a high IRQL.
pub fn alloc_code(size: usize) -> *mut u8 {
    (primitives().alloc_code)(size)
}

pub fn free_code(ptr: *mut u8, size: usize) {
    (primitives().free_code)(ptr, size)
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
        free(stack, THREAD_STACK_SIZE);
    }
}

unsafe extern "C" fn run_agent(context: *mut c_void) {
    let start = unsafe { Box::from_raw(context as *mut ThreadStart) };
    unsafe {
        (start.entry)(start.parameter, 0);
    }
}

const THREAD_STACK_SIZE: usize = 64 * 1024;

struct ThreadStart {
    entry: ThreadEntry,
    parameter: *mut c_void,
}

const THREAD_ALL_ACCESS: u32 = 0x1f_03ff;

pub fn wait(token: *const u8, timeout_us: Option<u64>, check: &mut dyn FnMut() -> bool) {
    (primitives().wait)(token, timeout_us, check)
}

pub fn wake(token: *const u8) {
    (primitives().wake)(token)
}

// A copy in a different process can use a handle, but it cannot use our memory. Thus the
// loop waits on an event of the object manager. Install the event before the loop waits the
// first time, because a token keeps the first event it receives.
pub fn install_shareable_wake_event(token: *const u8) {
    let mut created: *mut c_void = core::ptr::null_mut();

    let mut make = || created = create_event_object();
    on_kernel_stack(&mut make);

    unsafe {
        SHAREABLE_WAKE_EVENT = created;
        SHAREABLE_TOKEN = token;
    }

    EVENTS[slot_for_token(token)].store(created as usize, Ordering::Release);
}

fn create_event_object() -> *mut c_void {
    let mut handle: *mut c_void = core::ptr::null_mut();
    let mut object: *mut c_void = core::ptr::null_mut();

    unsafe {
        if (_ZwCreateEvent)(&mut handle, EVENT_ALL_ACCESS, core::ptr::null_mut(),
                SYNCHRONIZATION_EVENT, 0) < 0 {
            return core::ptr::null_mut();
        }

        (_ObReferenceObjectByHandle)(handle, EVENT_ALL_ACCESS, core::ptr::null_mut(),
            KERNEL_MODE as u8, &mut object, core::ptr::null_mut());
        (_ZwClose)(handle);
    }

    object
}

fn open_event_in_current_process(event: *mut c_void) -> *mut c_void {
    if event.is_null() {
        return core::ptr::null_mut();
    }

    let mut handle: *mut c_void = core::ptr::null_mut();

    unsafe {
        let object_type = (_ExEventObjectType as *const *mut c_void).read();
        (_ObOpenObjectByPointer)(event, 0, core::ptr::null_mut(), EVENT_ALL_ACCESS, object_type,
            USER_MODE as u32, &mut handle);
    }

    handle
}

static mut SHAREABLE_WAKE_EVENT: *mut c_void = core::ptr::null_mut();
static mut SHAREABLE_TOKEN: *const u8 = core::ptr::null();

// The kernel has no futex. Thus each token uses an event, which the code makes on first use.
fn event_for(token: *const u8) -> *mut c_void {
    event_in(slot_for_token(token))
}

fn event_in(slot: usize) -> *mut c_void {
    loop {
        let existing = EVENTS[slot].load(Ordering::Acquire);
        if existing != 0 {
            return existing as *mut c_void;
        }

        let created = alloc(EVENT_SIZE) as *mut c_void;
        unsafe { (_KeInitializeEvent)(created, SYNCHRONIZATION_EVENT, 0) };
        if EVENTS[slot].compare_exchange(0, created as usize, Ordering::AcqRel, Ordering::Acquire)
                .is_ok() {
            return created;
        }

        free(created as *mut u8, EVENT_SIZE);
    }
}

fn slot_for_token(token: *const u8) -> usize {
    let start = slot_for(token);
    for step in 0..NUM_EVENTS {
        let slot = (start + step) % NUM_EVENTS;

        let owner = OWNERS[slot].load(Ordering::Acquire);
        if owner == token as usize {
            return slot;
        }
        if owner == 0
                && OWNERS[slot].compare_exchange(0, token as usize, Ordering::AcqRel,
                    Ordering::Acquire).is_ok() {
            return slot;
        }
    }

    0
}

fn slot_for(token: *const u8) -> usize {
    (token as usize / core::mem::align_of::<usize>()) % EVENTS.len()
}

const NUM_EVENTS: usize = 64;
static EVENTS: [AtomicUsize; NUM_EVENTS] = [const { AtomicUsize::new(0) }; NUM_EVENTS];
static OWNERS: [AtomicUsize; NUM_EVENTS] = [const { AtomicUsize::new(0) }; NUM_EVENTS];
static SLEEPERS: [AtomicUsize; NUM_EVENTS] = [const { AtomicUsize::new(0) }; NUM_EVENTS];

const EVENT_SIZE: usize = 0x10;
const SYNCHRONIZATION_EVENT: u32 = 1;
const EVENT_ALL_ACCESS: u32 = 0x1f_0003;
const EXECUTIVE: u32 = 0;
const KERNEL_MODE: u32 = 0;

pub fn yield_now() {
    (primitives().yield_now)()
}

// The kernel and the applications read the same page at different addresses.
fn shared_data() -> usize {
    (primitives().shared_data)()
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
    let time = (shared_data() + offset) as *const u32;
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
pub(crate) const USER_SHARED_DATA: usize = 0x7ffe_0000;
const INTERRUPT_TIME_OFFSET: usize = 0x08;
const SYSTEM_TIME_OFFSET: usize = 0x14;
const UNIX_EPOCH_MICROS: i64 = 11_644_473_600_000_000;

// A kernel export is not available in ring 3. Thus the copy reads its own block.
pub fn current_process_id() -> u32 {
    (primitives().current_process_id)()
}

pub fn current_thread_id() -> u64 {
    (primitives().current_thread_id)()
}

// Only the kernel half can read the page tables. The copy asks the memory manager.
pub fn protection_at(address: usize) -> u32 {
    (primitives().protection_at)(address)
}

pub fn enumerate_ranges(found: &mut dyn FnMut(u64, u64, u32)) {
    (primitives().enumerate_ranges)(found)
}

// The copy must ask the memory manager to do this.
pub fn protect(address: u64, size: usize, gum_prot: u32) -> bool {
    (primitives().protect)(address, size, gum_prot)
}

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

        let dpc = alloc(DPC_SIZE) as *mut c_void;
        (_KeInitializeDpc)(dpc, deferred_wake, core::ptr::null_mut());
        WAKE_DPC = dpc;
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
        IN_INTERRUPT = true;
    }
    unsafe {
        if let Some(handler) = HW_INT_HANDLER {
            handler(HW_INT_TARGET, HW_INT_REFCON, core::ptr::null_mut(), 0);
        }
        IN_INTERRUPT = false;
    }
    1
}

#[cfg(target_arch = "x86")]
unsafe extern "stdcall" fn deferred_wake(_dpc: *mut c_void, _context: *mut c_void,
        _first: *mut c_void, _second: *mut c_void) {
    serve_deferred_wake()
}

#[cfg(target_arch = "x86_64")]
unsafe extern "win64" fn deferred_wake(_dpc: *mut c_void, _context: *mut c_void,
        _first: *mut c_void, _second: *mut c_void) {
    serve_deferred_wake()
}

fn serve_deferred_wake() {
    let token = WAKE_WANTED.swap(0, Ordering::AcqRel);
    if token != 0 {
        kernel::wake(token as *const u8);
    }
}

static WAKE_WANTED: AtomicUsize = AtomicUsize::new(0);
static mut WAKE_DPC: *mut c_void = core::ptr::null_mut();
const DPC_SIZE: usize = 0x40;

static mut IN_INTERRUPT: bool = false;
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

pub fn release_fault_reporter() {
    unsafe {
        for vector in [INVALID_OPCODE, GENERAL_PROTECTION, PAGE_FAULT] {
            let previous = FAULT_CHAIN[vector as usize];
            if previous != 0 {
                FAULT_CHAIN[vector as usize] = 0;
                restore_gate(vector, previous);
            }
        }
    }
}

#[cfg(target_arch = "x86")]
unsafe fn restore_gate(vector: u32, handler: usize) {
    let gate = (descriptor_table_base() + (vector as usize * GATE_SIZE)) as *mut u16;

    unsafe {
        gate.write(handler as u16);
        gate.add(3).write((handler >> 16) as u16);
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn restore_gate(vector: u32, handler: usize) {
    let gate = (descriptor_table_base() + (vector as usize * GATE_SIZE)) as *mut u16;

    unsafe {
        gate.write(handler as u16);
        gate.add(3).write((handler >> 16) as u16);
        (gate.add(4) as *mut u32).write((handler >> 32) as u32);
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
    let rip_slot = fault_frame_pc_slot(fault);
    // A fault from ring 3 is never ours, because all of our code runs in ring 0. Do not use our
    // own ranges to decide this, because that reads our data in an unknown context.
    if (unsafe { frame.add(rip_slot + 1).read() } & 3) != 0 {
        return unsafe { FAULT_CHAIN[fault as usize] };
    }

    let eip_slot = rip_slot;
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
        RESUME = [
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

// A thunk cannot name data, the image being position-independent. Thus it asks for the record.
#[cfg(target_arch = "x86")]
#[unsafe(no_mangle)]
extern "C" fn frida_winnt_resume_block() -> *mut u32 {
    &raw mut RESUME as *mut u32
}

#[cfg(target_arch = "x86")]
static mut RESUME: [u32; 10] = [0; 10];

// A long-mode frame always contains the stack pointer. Thus write the values from Gum into
// the frame.
#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
extern "C" fn frida_winnt_on_fault(fault: u32, frame: *mut u64) -> usize {
    let rip_slot = fault_frame_pc_slot(fault);
    // A fault from ring 3 is never ours, because all of our code runs in ring 0. Do not use our
    // own ranges to decide this, because that reads our data in an unknown context.
    if (unsafe { frame.add(rip_slot + 1).read() } & 3) != 0 {
        return unsafe { FAULT_CHAIN[fault as usize] };
    }

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

const INVALID_OPCODE: u32 = 6;
const GENERAL_PROTECTION: u32 = 13;
const PAGE_FAULT: u32 = 14;

pub fn enumerate_threads(found: &mut dyn FnMut(ThreadInfo)) {
    let Some(layout) = thread_layout() else {
        found(ThreadInfo { id: current_thread_id() as u32, cpu_state: None });
        return;
    };

    let _ = layout;
    enumerate_thread_objects(&mut |thread| unsafe {
        found(ThreadInfo {
            id: (_PsGetThreadId)(thread),
            cpu_state: capture(thread),
        });
    });
}

fn enumerate_thread_objects(found: &mut dyn FnMut(*mut c_void)) {
    let Some(layout) = thread_layout() else {
        return;
    };

    enumerate_processes(&mut |process| unsafe {
        let head = process.handle as usize + layout.head;
        let mut entry = (head as *const usize).read_volatile();
        while entry != head && entry != 0 {
            found((entry - layout.entry) as *mut c_void);
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

pub(crate) const POINTER_SIZE: usize = core::mem::size_of::<usize>();

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
pub(crate) const CONTEXT_SIZE: usize = 716;
#[cfg(target_arch = "x86")]
pub(crate) const CONTEXT_ALIGNMENT: usize = 4;
#[cfg(target_arch = "x86")]
pub(crate) const CONTEXT_FLAGS: usize = 0x00;
#[cfg(target_arch = "x86")]
const CONTEXT_FULL: u32 = 0x0001_0007;

#[cfg(target_arch = "x86_64")]
pub(crate) const CONTEXT_SIZE: usize = 1232;
#[cfg(target_arch = "x86_64")]
pub(crate) const CONTEXT_ALIGNMENT: usize = 16;
#[cfg(target_arch = "x86_64")]
pub(crate) const CONTEXT_FLAGS: usize = 0x30;
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

        // A process that has not run yet has pages that nothing has touched, thus read the way
        // that recovers from a fault.
        let peb = (_PsGetProcessPeb)(process) as usize;
        if let Some(parameters) = try_read_pointer(peb + PEB_PARAMETERS_OFFSET) {
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
        let Some(length) = try_read_pointer(address).map(|word| word as u16 as usize) else {
            return;
        };
        let Some(buffer) = try_read_pointer(address + UNICODE_STRING_BUFFER_OFFSET) else {
            return;
        };
        if buffer == 0 {
            return;
        }

        let limit = out.len() - 1;
        let mut written = 0;
        for i in 0..length.min(limit) / 2 {
            let Some(word) = try_read_pointer(buffer + i * 2) else {
                break;
            };
            written += encode_utf8(word as u16, &mut out[written..limit]);
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
pub(crate) const PEB_PARAMETERS_OFFSET: usize = 0x10;
#[cfg(target_arch = "x86")]
const PARAMETERS_IMAGE_PATH_OFFSET: usize = 0x38;
#[cfg(target_arch = "x86")]
const PARAMETERS_COMMAND_LINE_OFFSET: usize = 0x40;

#[cfg(target_arch = "x86_64")]
pub(crate) const PEB_PARAMETERS_OFFSET: usize = 0x20;
#[cfg(target_arch = "x86_64")]
const PARAMETERS_IMAGE_PATH_OFFSET: usize = 0x60;
#[cfg(target_arch = "x86_64")]
const PARAMETERS_COMMAND_LINE_OFFSET: usize = 0x70;

pub(crate) const UNICODE_STRING_BUFFER_OFFSET: usize = POINTER_SIZE;
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

// The process receives the same code pages as the kernel half, because code is read-only. It
// also receives its own writable half, thus the two copies do not share data.
pub fn place_agent_in_process(pid: u32) -> bool {
    if unsafe { targets() }.contains_key(&pid) {
        return true;
    }

    put_a_copy_in_the_session_server(pid);

    let library = loader_library();

    let mut placed = Placement::default();

    let mut process: *mut c_void = core::ptr::null_mut();
    enumerate_processes(&mut |p| {
        if p.id == pid {
            process = p.handle;
        }
    });
    if process.is_null() {
        return false;
    }

    let own = unsafe { &*core::ptr::addr_of!(crate::OWN_RANGE) };
    let private_offset = crate::writable_half_start() - own.base_address as usize;
    let shared_size = private_offset;
    let private_size = own.size as usize - private_offset;

    let mut wake: *mut c_void = core::ptr::null_mut();
    let mut work = || unsafe {
        let private = alloc(private_size);
        if private.is_null() {
            return;
        }
        core::ptr::write_bytes(private, 0, private_size);

        let shared_mdl = (_IoAllocateMdl)(own.base_address as *mut c_void, shared_size as u32, 0, 0,
            core::ptr::null_mut());
        let private_mdl = (_IoAllocateMdl)(private as *mut c_void, private_size as u32, 0, 0,
            core::ptr::null_mut());
        if shared_mdl.is_null() || private_mdl.is_null() {
            return;
        }
        (_MmBuildMdlForNonPagedPool)(shared_mdl);
        (_MmBuildMdlForNonPagedPool)(private_mdl);
        placed.shared_mdl = shared_mdl;
        placed.private_mdl = private_mdl;

        let mut apc_state = [0usize; APC_STATE_WORDS];
        (_KeStackAttachProcess)(process, apc_state.as_mut_ptr() as *mut u8);

        // The memory manager selects the address of the code. The distance to the writable half is a
        // property of the image, thus the code asks for that address.
        for _ in 0..MAX_PLACEMENT_TRIES {
            let text = (_MmMapLockedPagesSpecifyCache)(shared_mdl, USER_MODE, MM_CACHED,
                core::ptr::null_mut(), 0, NORMAL_PAGE_PRIORITY);
            if text.is_null() {
                break;
            }

            let wanted = (text as usize + private_offset) as *mut c_void;
            if (_MmMapLockedPagesSpecifyCache)(private_mdl, USER_MODE, MM_CACHED, wanted, 0,
                    NORMAL_PAGE_PRIORITY) == wanted {
                // The mapping gives no permission to execute.
                protect(text as u64, shared_size, GUM_PAGE_READ | GUM_PAGE_EXECUTE);
                crate::install_writable_half(text as usize, private as usize);
                placed.seen_by_process = text as u64;
                placed.writable_from_here = private as u64;
                break;
            }

            (_MmUnmapLockedPages)(text, shared_mdl);
        }

        if placed.seen_by_process != 0 {
            let arena = alloc(ARENA_SIZE);
            core::ptr::write_bytes(arena, 0, ARENA_SIZE);

            let arena_mdl = (_IoAllocateMdl)(arena as *mut c_void, ARENA_SIZE as u32, 0, 0,
                core::ptr::null_mut());
            if !arena_mdl.is_null() {
                placed.arena_mdl = arena_mdl;
                (_MmBuildMdlForNonPagedPool)(arena_mdl);
                let seen = (_MmMapLockedPagesSpecifyCache)(arena_mdl, USER_MODE, MM_CACHED,
                    core::ptr::null_mut(), 0, NORMAL_PAGE_PRIORITY);
                if !seen.is_null() {
                    placed.arena_seen_by_process = seen as u64;
                    placed.arena_here = arena as u64;

                    wake = create_event_object();
                    (arena.add(AGENT_WAKE_HANDLE as usize) as *mut u64)
                        .write(open_event_in_current_process(SHAREABLE_WAKE_EVENT) as u64);
                    (arena.add(TARGET_WAKE_HANDLE as usize) as *mut u64)
                        .write(open_event_in_current_process(wake) as u64);
                    (arena.add(LOADER_LIBRARY as usize) as *mut u64).write(library);
                }
            }
        }

        (_KeUnstackDetachProcess)(apc_state.as_mut_ptr() as *mut u8);
    };

    on_kernel_stack(&mut work);

    if placed.arena_here != 0 {
        unsafe {
            targets().insert(pid, Target {
                introduced: false,
                arena: placed.arena_here,
                seen: placed.arena_seen_by_process,
                wake,
                started: false,
                text: placed.seen_by_process,
                size: own.size as u64,
                private: placed.writable_from_here,
                private_size,
                stack: 0,
                shared_mdl: placed.shared_mdl,
                private_mdl: placed.private_mdl,
                arena_mdl: placed.arena_mdl,
            })
        };
    }

    placed.arena_here != 0
}

#[derive(Default)]
pub struct Placement {
    pub seen_by_process: u64,
    pub writable_from_here: u64,
    pub arena_seen_by_process: u64,
    pub arena_here: u64,
    pub shared_mdl: *mut c_void,
    pub private_mdl: *mut c_void,
    pub arena_mdl: *mut c_void,
}

const MAX_PLACEMENT_TRIES: usize = 8;
const USER_MODE: u8 = 1;
const MM_CACHED: u32 = 1;
const NORMAL_PAGE_PRIORITY: u32 = 16;

// Start the copy on a thread of the target. The system makes the thread, thus ntdll accepts
// calls from it. The copy cannot answer from that thread, thus this function returns the
// process id only after the copy writes it.
pub fn release_interrupt() {
    let interrupt = unsafe { INTERRUPT_OBJECT };
    if interrupt.is_null() {
        return;
    }

    unsafe {
        INTERRUPT_OBJECT = core::ptr::null_mut();
        (_IoDisconnectInterrupt)(interrupt);
    }
}

pub fn detach_from_process(pid: u32) -> bool {
    let Some(target) = (unsafe { targets().remove(&pid) }) else {
        return false;
    };

    ask_copy_to_leave(&target);
    if !copy_has_left(&target) {
        return false;
    }

    let mut process: *mut c_void = core::ptr::null_mut();
    enumerate_processes(&mut |p| {
        if p.id == pid {
            process = p.handle;
        }
    });

    let mut work = || unsafe {
        if !process.is_null() {
            let mut apc_state = [0usize; APC_STATE_WORDS];
            (_KeStackAttachProcess)(process, apc_state.as_mut_ptr() as *mut u8);

            (_MmUnmapLockedPages)(target.text as *mut c_void, target.shared_mdl);
            (_MmUnmapLockedPages)((target.text + target.private_offset()) as *mut c_void,
                target.private_mdl);
            (_MmUnmapLockedPages)(target.seen as *mut c_void, target.arena_mdl);

            (_KeUnstackDetachProcess)(apc_state.as_mut_ptr() as *mut u8);
        }

        (_IoFreeMdl)(target.shared_mdl);
        (_IoFreeMdl)(target.private_mdl);
        (_IoFreeMdl)(target.arena_mdl);

        free(target.private as *mut u8, target.private_size);
        free(target.arena as *mut u8, ARENA_SIZE);

        if !target.wake.is_null() {
            (_ZwClose)(target.wake);
        }
    };
    on_kernel_stack(&mut work);

    true
}

fn ask_copy_to_leave(target: &Target) {
    unsafe {
        ((target.arena + STOP_REQUEST) as *mut u32).write_volatile(1);
        if !target.wake.is_null() {
            (_KeSetEvent)(target.wake, 0, 0);
        }
    }
}

fn copy_has_left(target: &Target) -> bool {
    for _ in 0..LEAVE_ATTEMPTS {
        if unsafe { ((target.arena + COPY_LEFT) as *const u32).read_volatile() } != 0 {
            return true;
        }

        wait(core::ptr::addr_of!(TEARDOWN_TOKEN), Some(LEAVE_SLICE_US), &mut || false);
    }

    false
}

const LEAVE_ATTEMPTS: u32 = 40;
const LEAVE_SLICE_US: u64 = 50_000;

pub fn stop_copies() {
    let pids: alloc::vec::Vec<u32> = unsafe { targets() }.keys().copied().collect();
    for pid in pids {
        detach_from_process(pid);
    }
}

static mut TEARDOWN_TOKEN: u8 = 0;

const TEARDOWN_GRACE_US: u64 = 500_000;

pub fn start_agent_in_process(pid: u32) -> u32 {
    let Some(target) = (unsafe { targets().get(&pid) }) else {
        return 0;
    };
    let (arena, seen) = (target.arena, target.seen);
    let own = unsafe { core::ptr::addr_of!(crate::OWN_RANGE).read() }.base_address as usize;
    let bootstrap = target.text + (crate::winnt_user::frida_winnt_user_bootstrap as usize
        - own) as u64;
    let entry = target.text + (crate::winnt_user::frida_winnt_user_main as usize - own) as u64;

    if !target.started {
        let mut process: *mut c_void = core::ptr::null_mut();
        enumerate_processes(&mut |p| {
            if p.id == pid {
                process = p.handle;
            }
        });
        if process.is_null() {
            return 0;
        }

        let mut stack = 0u64;
        let mut work = || {
            create_user_thread(process, arena, seen, bootstrap, entry, &mut stack);
        };
        on_kernel_stack(&mut work);

        unsafe {
            let target = targets().get_mut(&pid).unwrap();
            target.started = true;
            target.stack = stack;
        };
    }

    let observed = unsafe { ((arena + OBSERVED_PID) as *const u32).read_volatile() };
    if observed != 0 {
        introduce_to_session_server(pid);
    }

    observed
}

fn put_a_copy_in_the_session_server(pid: u32) {
    let server = session_server_pid();
    if server == 0 || server == pid || arena_for_pid(server).is_some() {
        return;
    }

    place_agent_in_process(server);
    start_agent_in_process(server);
}

fn introduce_to_session_server(pid: u32) {
    if unsafe { targets().get(&pid).map(|t| t.introduced) } != Some(false) {
        return;
    }

    let server = session_server_pid();
    if server == 0 || server == pid {
        return;
    }

    let (Some(here), Some(there)) = (arena_for_pid(pid), arena_for_pid(server)) else {
        return;
    };
    let thread = unsafe { ((here + OBSERVED_THREAD) as *const u32).read_volatile() };
    if thread == 0 {
        return;
    }

    unsafe {
        ((there + REGISTER_PROCESS) as *mut u32).write_volatile(pid);
        ((there + REGISTER_THREAD) as *mut u32).write_volatile(thread);
        targets().get_mut(&pid).unwrap().introduced = true;

        if let Some(wake) = targets().get(&server).map(|t| t.wake) {
            (_KeSetEvent)(wake, 0, 0);
        }
    }
}

fn session_server_pid() -> u32 {
    let mut found = 0;
    enumerate_processes(&mut |p| {
        if found == 0 && path_ends_with(p.path, b"csrss.exe") {
            found = p.id;
        }
    });

    found
}

fn path_ends_with(path: *const u8, wanted: &[u8]) -> bool {
    let mut length = 0;
    while unsafe { path.add(length).read() } != 0 {
        length += 1;
    }
    if length < wanted.len() {
        return false;
    }

    wanted.iter().enumerate().all(|(index, expected)| {
        unsafe { path.add(length - wanted.len() + index).read() }.to_ascii_lowercase()
            == *expected
    })
}

// What each word size puts where: the frame a service is entered with, the block a thread starts
// with, and the shape of the stubs on both sides.
#[cfg(target_arch = "x86_64")]
pub(crate) const CONTEXT_PC: u64 = 0xf8;
#[cfg(target_arch = "x86_64")]
const CONTEXT_SP: u64 = 0x98;
#[cfg(target_arch = "x86_64")]
const CONTEXT_RDI: u64 = 0xb0;
#[cfg(target_arch = "x86_64")]
const CONTEXT_CS: u64 = 0x38;
#[cfg(target_arch = "x86_64")]
const CONTEXT_SS: u64 = 0x42;
#[cfg(target_arch = "x86_64")]
const CONTEXT_EFLAGS: u64 = 0x44;
#[cfg(target_arch = "x86_64")]
const INITIAL_TEB_SIZE: usize = 40;
#[cfg(target_arch = "x86_64")]
const INITIAL_TEB_STACK_BASE: u64 = 0x10;
#[cfg(target_arch = "x86_64")]
const INITIAL_TEB_STACK_LIMIT: u64 = 0x18;
#[cfg(target_arch = "x86_64")]
const INITIAL_TEB_ALLOCATION_BASE: u64 = 0x20;
#[cfg(target_arch = "x86_64")]
const SERVICE_INDEX_OPCODE: usize = 3;
#[cfg(target_arch = "x86_64")]
const USER_CS: u64 = 0x33;
#[cfg(target_arch = "x86_64")]
const USER_SS: u64 = 0x2b;
#[cfg(target_arch = "x86_64")]
const ZW_STUB_SIZE: usize = 48;
#[cfg(target_arch = "x86_64")]
const ZW_STUB_PROLOGUE: usize = 12;
#[cfg(target_arch = "x86_64")]
const ZW_STUB_LEA_REL: usize = 15;
#[cfg(target_arch = "x86_64")]
const ZW_STUB_LEA_NEXT: usize = 19;
#[cfg(target_arch = "x86_64")]
const ZW_STUB_JMP_REL: usize = 26;
#[cfg(target_arch = "x86_64")]
const ZW_STUB_JMP_NEXT: usize = 30;

#[cfg(target_arch = "x86")]
pub(crate) const CONTEXT_PC: u64 = 0xb8;
#[cfg(target_arch = "x86")]
const CONTEXT_SP: u64 = 0xc4;
#[cfg(target_arch = "x86")]
const CONTEXT_CS: u64 = 0xbc;
#[cfg(target_arch = "x86")]
const CONTEXT_SS: u64 = 0xc8;
#[cfg(target_arch = "x86")]
const CONTEXT_DS: u64 = 0x98;
#[cfg(target_arch = "x86")]
const CONTEXT_ES: u64 = 0x94;
#[cfg(target_arch = "x86")]
const CONTEXT_FS: u64 = 0x90;
#[cfg(target_arch = "x86")]
const CONTEXT_EFLAGS: u64 = 0xc0;
#[cfg(target_arch = "x86")]
const INITIAL_TEB_SIZE: usize = 20;
#[cfg(target_arch = "x86")]
const INITIAL_TEB_STACK_BASE: u64 = 0x08;
#[cfg(target_arch = "x86")]
const INITIAL_TEB_STACK_LIMIT: u64 = 0x0c;
#[cfg(target_arch = "x86")]
const INITIAL_TEB_ALLOCATION_BASE: u64 = 0x10;
#[cfg(target_arch = "x86")]
const SERVICE_INDEX_OPCODE: usize = 0;
#[cfg(target_arch = "x86")]
const USER_CS: u64 = 0x1b;
#[cfg(target_arch = "x86")]
const USER_SS: u64 = 0x23;
#[cfg(target_arch = "x86")]
const USER_DS: u64 = 0x23;
#[cfg(target_arch = "x86")]
const USER_FS: u64 = 0x3b;
#[cfg(target_arch = "x86")]
const THREAD_ARGUMENT_BYTES: usize = 32;
#[cfg(target_arch = "x86")]
const ZW_STUB_SIZE: usize = 24;
#[cfg(target_arch = "x86")]
const ZW_STUB_CALL_REL: usize = 13;
#[cfg(target_arch = "x86")]
const ZW_STUB_CALL_NEXT: usize = 17;

// This kernel exports no ZwCreateThread, but a Zw stub is only a service number: it builds the
// frame the dispatcher expects, loads an index and calls it. Thus read the dispatcher out of an
// exported stub, take the index from ntdll's own stub for the service, and write a stub of our
// own.
fn synthesize_zw_stub(index: u32) -> usize {
    let template = unsafe { _ZwCreateEvent as *const u8 };
    let stub = alloc_code(ZW_STUB_SIZE);
    if stub.is_null() {
        return 0;
    }

    unsafe {
        let mut at = 0;
        let mut put = |bytes: &[u8]| {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), stub.add(at), bytes.len());
            at += bytes.len();
        };
        emit_zw_stub(template, stub, index, &mut put);
    }

    stub as usize
}

// The image is further from pool memory than a relative jump can reach here, thus the jump to
// the dispatcher is an indirect one.
#[cfg(target_arch = "x86_64")]
unsafe fn emit_zw_stub(template: *const u8, stub: *mut u8, index: u32,
        put: &mut dyn FnMut(&[u8])) {
    unsafe {
        let linkage = template.add(ZW_STUB_LEA_NEXT) as u64
            + (template.add(ZW_STUB_LEA_REL) as *const i32).read() as u64;
        let dispatcher = template.add(ZW_STUB_JMP_NEXT) as u64
            + (template.add(ZW_STUB_JMP_REL) as *const i32).read() as u64;

        put(core::slice::from_raw_parts(template, ZW_STUB_PROLOGUE));
        put(&[0x48, 0xb8]);
        put(&linkage.to_le_bytes());
        put(&[0x50]);
        put(&[0xb8]);
        put(&index.to_le_bytes());
        put(&[0xff, 0x25, 0x00, 0x00, 0x00, 0x00]);
        put(&dispatcher.to_le_bytes());
    }
}

// A relative call reaches anywhere in this kernel's half of the address space, so only its
// displacement has to be worked out again. How much the service takes off the stack is part of
// the stub, and differs from the one it was read from.
#[cfg(target_arch = "x86")]
unsafe fn emit_zw_stub(template: *const u8, stub: *mut u8, index: u32,
        put: &mut dyn FnMut(&[u8])) {
    unsafe {
        let dispatcher = template.add(ZW_STUB_CALL_NEXT) as u32
            + (template.add(ZW_STUB_CALL_REL) as *const i32).read() as u32;

        put(&[0xb8]);
        put(&index.to_le_bytes());
        put(&[0x8d, 0x54, 0x24, 0x04]);
        put(&[0x9c]);
        put(&[0x6a, 0x08]);
        put(&[0xe8]);
        let next = stub as u32 + ZW_STUB_CALL_NEXT as u32;
        put(&(dispatcher.wrapping_sub(next) as i32).to_le_bytes());
        put(&[0xc2]);
        put(&(THREAD_ARGUMENT_BYTES as u16).to_le_bytes());
    }
}

// ntdll's stub for a service begins by loading the same index that the kernel uses.
fn service_index_of(ntdll: usize, name: &[u8]) -> u32 {
    let stub = export(ntdll, name);
    if stub == 0 {
        return 0;
    }

    unsafe {
        let bytes = stub as *const u8;
        if bytes.add(SERVICE_INDEX_OPCODE).read() != 0xb8 {
            return 0;
        }
        (bytes.add(SERVICE_INDEX_OPCODE + 1) as *const u32).read()
    }
}

fn create_user_thread(process: *mut c_void, arena_here: u64, arena_seen: u64, _bootstrap: u64,
        entry: u64, stack: &mut u64) -> bool {
    unsafe {
        let mut process_handle: *mut c_void = core::ptr::null_mut();
        let process_type = (_PsProcessType as *const *mut c_void).read();
        if (_ObOpenObjectByPointer)(process, 0, core::ptr::null_mut(), PROCESS_ALL_ACCESS,
                process_type, KERNEL_MODE as u32, &mut process_handle) < 0 {
            return false;
        }

        let created = start_thread_in_process(process, process_handle, arena_here, arena_seen,
            entry, stack);

        (_ZwClose)(process_handle);

        created
    }
}

// The thread is made the way the system makes them, thus it arrives with a block of its own and
// ntdll accepts calls from it.
fn start_thread_in_process(process: *mut c_void, process_handle: *mut c_void, arena_here: u64,
        arena_seen: u64, entry: u64, remembered: &mut u64) -> bool {
    let stack = allocate_in_process(process_handle, STACK_SIZE, PAGE_READWRITE);
    if stack == 0 {
        return false;
    }
    *remembered = stack;

    // A process that is still held has no list of its libraries, thus take the address of the
    // loader from a process that is running. The code is in the target's space, so read it there.
    let ntdll = loader_library() as usize;
    let index;
    unsafe {
        let mut apc_state = [0usize; APC_STATE_WORDS];
        (_KeStackAttachProcess)(process, apc_state.as_mut_ptr() as *mut u8);
        index = service_index_of(ntdll, b"NtCreateThread");
        (_KeUnstackDetachProcess)(apc_state.as_mut_ptr() as *mut u8);
    }
    if index == 0 {
        return false;
    }

    let create: windows_fn!(
        *mut *mut c_void, u32, *mut c_void, *mut c_void, *mut c_void, *mut u8, *mut c_void, u8,
        => i32) = unsafe { core::mem::transmute(synthesize_zw_stub(index)) };

    let top = stack + STACK_SIZE as u64;
    let sp = seed_stack(process, top, arena_seen);
    let context = arena_here + CONTEXT_AREA;
    let teb = arena_here + INITIAL_TEB_AREA;

    unsafe {
        core::ptr::write_bytes(context as *mut u8, 0, CONTEXT_SIZE);
        ((context + CONTEXT_FLAGS as u64) as *mut u32).write(CONTEXT_FULL);
        ((context + CONTEXT_PC) as *mut usize).write(entry as usize);
        ((context + CONTEXT_SP) as *mut usize).write(sp as usize);
        ((context + CONTEXT_CS) as *mut u16).write(USER_CS as u16);
        ((context + CONTEXT_SS) as *mut u16).write(USER_SS as u16);
        ((context + CONTEXT_EFLAGS) as *mut u32).write(INITIAL_EFLAGS as u32);
        #[cfg(target_arch = "x86_64")]
        ((context + CONTEXT_RDI) as *mut u64).write(arena_seen);
        seed_segments(context);

        core::ptr::write_bytes(teb as *mut u8, 0, INITIAL_TEB_SIZE);
        ((teb + INITIAL_TEB_STACK_BASE) as *mut usize).write(top as usize);
        ((teb + INITIAL_TEB_STACK_LIMIT) as *mut usize).write(stack as usize);
        ((teb + INITIAL_TEB_ALLOCATION_BASE) as *mut usize).write(stack as usize);

        let mut thread: *mut c_void = core::ptr::null_mut();
        let mut client_id = [0usize; 2];
        let status = create(&mut thread, THREAD_ALL_ACCESS, core::ptr::null_mut(), process_handle,
            client_id.as_mut_ptr() as *mut c_void, context as *mut u8, teb as *mut c_void, 0);
        if status >= 0 {
            (_ZwClose)(thread);
        }

        status >= 0
    }
}

// The kernel takes the data segments of a new thread from the context.
#[cfg(target_arch = "x86")]
fn seed_segments(context: u64) {
    unsafe {
        ((context + CONTEXT_DS) as *mut u16).write(USER_DS as u16);
        ((context + CONTEXT_ES) as *mut u16).write(USER_DS as u16);
        ((context + CONTEXT_FS) as *mut u16).write(USER_FS as u16);
    }
}

#[cfg(target_arch = "x86_64")]
fn seed_segments(_context: u64) {}

// The argument travels in a register here, and the stack only has to be aligned the way a call
// would have left it.
#[cfg(target_arch = "x86_64")]
fn seed_stack(_process: *mut c_void, top: u64, _argument: u64) -> u64 {
    (top - 64) & !15
}

// A cdecl entry looks for its argument above the return address, thus the stack is laid out
// before the thread runs, in the process that will read it.
#[cfg(target_arch = "x86")]
fn seed_stack(process: *mut c_void, top: u64, argument: u64) -> u64 {
    let sp = (top - 32) & !15;

    unsafe {
        let mut apc_state = [0usize; APC_STATE_WORDS];
        (_KeStackAttachProcess)(process, apc_state.as_mut_ptr() as *mut u8);
        (sp as *mut u32).write(0);
        ((sp + 4) as *mut u32).write(argument as u32);
        (_KeUnstackDetachProcess)(apc_state.as_mut_ptr() as *mut u8);
    }

    sp
}

fn allocate_in_process(process_handle: *mut c_void, size: usize, protection: u32) -> u64 {
    let mut address: *mut u8 = core::ptr::null_mut();
    let mut region = size;

    unsafe {
        if (_ZwAllocateVirtualMemory)(process_handle, &mut address, 0, &mut region,
                MEM_COMMIT | MEM_RESERVE, protection) < 0 {
            return 0;
        }
    }

    address as u64
}

// This is a system thread, but it uses the address space of the target. The code after the
// descent runs in ring 3.
const STACK_SIZE: usize = 256 * 1024;
const BLOCK_SIZE: usize = 4096;
const PROCESS_ALL_ACCESS: u32 = 0x1f_0fff;

const INITIAL_EFLAGS: u64 = 0x200;

// The primitives that differ between the two halves. The kernel half runs on KERNEL, and the
// copy in a process selects USER before it does anything else. The order here is the order of
// the functions below.
pub struct Primitives {
    pub log: fn(&str),
    pub alloc: fn(usize) -> *mut u8,
    pub free: fn(*mut u8, usize),
    pub alloc_code: fn(usize) -> *mut u8,
    pub free_code: fn(*mut u8, usize),
    pub protect: fn(u64, usize, u32) -> bool,
    pub protection_at: fn(usize) -> u32,
    pub enumerate_ranges: fn(&mut dyn FnMut(u64, u64, u32)),
    pub wait: fn(*const u8, Option<u64>, &mut dyn FnMut() -> bool),
    pub wake: fn(*const u8),
    pub yield_now: fn(),
    pub current_process_id: fn() -> u32,
    pub current_thread_id: fn() -> u64,
    pub shared_data: fn() -> usize,
}

pub fn select_user() {
    unsafe { ACTIVE = &crate::winnt_user::USER };
}

fn primitives() -> &'static Primitives {
    unsafe { ACTIVE }
}

static mut ACTIVE: &Primitives = &KERNEL;

static KERNEL: Primitives = Primitives {
    log: kernel::log,
    alloc: kernel::alloc,
    free: kernel::free,
    alloc_code: kernel::alloc_code,
    free_code: kernel::free_code,
    protect: kernel::protect,
    protection_at: kernel::protection_at,
    enumerate_ranges: kernel::enumerate_ranges,
    wait: kernel::wait,
    wake: kernel::wake,
    yield_now: kernel::yield_now,
    current_process_id: kernel::current_process_id,
    current_thread_id: kernel::current_thread_id,
    shared_data: kernel::shared_data,
};

mod kernel {
    use super::*;

    pub fn log(msg: &str) {
        for byte in msg.bytes() {
            if byte == 0 {
                break;
            }
            write_debug_byte(byte);
        }
    }

    pub fn alloc(size: usize) -> *mut u8 {
        unsafe { (_ExAllocatePoolWithTag)(NON_PAGED_POOL, size, POOL_TAG) }
    }

    pub fn free(ptr: *mut u8, _size: usize) {
        unsafe {
            (_ExFreePoolWithTag)(ptr, POOL_TAG);
        }
    }

    pub fn alloc_code(size: usize) -> *mut u8 {
        alloc(size)
    }

    pub fn free_code(ptr: *mut u8, size: usize) {
        free(ptr, size);
    }

    pub fn protect(address: u64, size: usize, gum_prot: u32) -> bool {
        crate::winnt_paging::protect(address, size, gum_prot)
    }

    pub fn protection_at(address: usize) -> u32 {
        crate::winnt_paging::protection_at(address)
    }

    pub fn enumerate_ranges(found: &mut dyn FnMut(u64, u64, u32)) {
        crate::winnt_paging::enumerate_ranges(found)
    }

    pub fn wait(token: *const u8, timeout_us: Option<u64>, check: &mut dyn FnMut() -> bool) {
        let slot = slot_for_token(token);
        let event = event_in(slot);
        if check() {
            return;
        }

        SLEEPERS[slot].fetch_add(1, Ordering::AcqRel);

        unsafe {
            match timeout_us {
                None => (_KeWaitForSingleObject)(event, EXECUTIVE, KERNEL_MODE, 0, core::ptr::null()),
                Some(us) => {
                    let due_time = -((us as i64) * 10);
                    (_KeWaitForSingleObject)(event, EXECUTIVE, KERNEL_MODE, 0, &due_time)
                }
            };
        }
        SLEEPERS[slot].fetch_sub(1, Ordering::AcqRel);
    }

    pub fn wake(token: *const u8) {
        if unsafe { super::IN_INTERRUPT } {
            super::WAKE_WANTED.store(token as usize, Ordering::Release);
            let dpc = unsafe { super::WAKE_DPC };
            if !dpc.is_null() {
                unsafe { (_KeInsertQueueDpc)(dpc, core::ptr::null_mut(), core::ptr::null_mut()) };
            }

            return;
        }

        let slot = slot_for_token(token);
        let event = event_in(slot);

        let mut left = SLEEPERS[slot].load(Ordering::Acquire).max(1);
        while left != 0 {
            unsafe { (_KeSetEvent)(event, 0, 0) };
            left -= 1;
        }
    }

    pub fn yield_now() {
        unsafe {
            (_ZwYieldExecution)();
        }
    }

    pub fn current_process_id() -> u32 {
        unsafe { (_PsGetProcessId)((_PsGetThreadProcess)((_PsGetCurrentThread)())) }
    }

    pub fn current_thread_id() -> u64 {
        unsafe { (_PsGetCurrentThreadId)() as u64 }
    }

    pub fn shared_data() -> usize {
        SHARED_DATA
    }
}

#[cfg(target_arch = "x86")]
pub(crate) const BLOCK_PROCESS_ID: u32 = 0x20;
#[cfg(target_arch = "x86")]
pub(crate) const BLOCK_THREAD_ID: u32 = 0x24;
#[cfg(target_arch = "x86_64")]
pub(crate) const BLOCK_PROCESS_ID: u32 = 0x40;
#[cfg(target_arch = "x86_64")]
pub(crate) const BLOCK_THREAD_ID: u32 = 0x48;
pub(crate) const CURRENT_PROCESS: *mut c_void = -1isize as *mut c_void;
pub(crate) const MEM_COMMIT: u32 = 0x1000;
pub(crate) const MEM_RESERVE: u32 = 0x2000;
pub(crate) const MEM_RELEASE: u32 = 0x8000;
pub(crate) const PAGE_READWRITE: u32 = 0x04;
pub(crate) const PAGE_EXECUTE_READWRITE: u32 = 0x40;

// The loader's own list, walked in whichever address space is current: the copy walks its
// own, and the kernel half walks a target's while it is attached to it.
// A process that is still held has no list of its own yet, and this system puts the library at
// the same address in every process, thus take it from one that is running.
fn loader_library() -> u64 {
    let known = unsafe { LOADER_LIBRARY_SEEN };
    if known != 0 {
        return known;
    }

    let mut found = 0;
    enumerate_processes(&mut |process| {
        if found == 0 {
            found = loader_library_in(process.handle);
        }
    });
    unsafe { LOADER_LIBRARY_SEEN = found };

    found
}

fn loader_library_in(process: *mut c_void) -> u64 {
    let mut found = 0;

    let mut look = || unsafe {
        let mut apc_state = [0usize; APC_STATE_WORDS];
        (_KeStackAttachProcess)(process, apc_state.as_mut_ptr() as *mut u8);

        let peb = (_PsGetProcessPeb)(process) as usize;
        if peb != 0 && try_read_pointer(peb + PEB_LDR_OFFSET).unwrap_or(0) != 0 {
            found = module_base(peb, b"ntdll.dll") as u64;
        }

        (_KeUnstackDetachProcess)(apc_state.as_mut_ptr() as *mut u8);
    };
    on_kernel_stack(&mut look);

    found
}

static mut LOADER_LIBRARY_SEEN: u64 = 0;

pub(crate) fn module_base(peb: usize, wanted: &[u8]) -> usize {
    unsafe {
        let head = read_pointer(peb + PEB_LDR_OFFSET) + LDR_IN_LOAD_ORDER_OFFSET;

        let mut entry = read_pointer(head);
        while entry != head {
            let name = read_pointer(entry + ENTRY_BASE_NAME_OFFSET + UNICODE_STRING_BUFFER_OFFSET);
            if name_matches(name, wanted) {
                return read_pointer(entry + ENTRY_DLL_BASE_OFFSET);
            }
            entry = read_pointer(entry);
        }
    }

    0
}
// The loader writes the names as wide characters, and the letter case can be different.
fn name_matches(name: usize, wanted: &[u8]) -> bool {
    for (index, expected) in wanted.iter().enumerate() {
        let actual = unsafe { ((name + index * 2) as *const u16).read() };
        if actual == 0 || (actual as u8).to_ascii_lowercase() != expected.to_ascii_lowercase() {
            return false;
        }
    }

    unsafe { ((name + wanted.len() * 2) as *const u16).read() == 0 }
}
// A module says what it exports in its own headers, thus a copy can read them for the modules
// of the process it runs in.
pub(crate) fn enumerate_exports(base: usize, found: &mut dyn FnMut(*const u8, u64) -> bool) {
    unsafe {
        let exports = export_directory(base);
        if exports == base {
            return;
        }

        let count = read_u32(exports + EXPORT_NAME_COUNT_OFFSET) as usize;
        let functions = base + read_u32(exports + EXPORT_FUNCTIONS_OFFSET) as usize;
        let names = base + read_u32(exports + EXPORT_NAMES_OFFSET) as usize;
        let ordinals = base + read_u32(exports + EXPORT_ORDINALS_OFFSET) as usize;

        for index in 0..count {
            let name = base + read_u32(names + index * 4) as usize;
            let ordinal = ((ordinals + index * 2) as *const u16).read() as usize;
            let address = base + read_u32(functions + ordinal * 4) as usize;
            if !found(name as *const u8, address as u64) {
                break;
            }
        }
    }
}

unsafe fn export_directory(base: usize) -> usize {
    unsafe {
        let headers = base + read_u32(base + PE_HEADERS_OFFSET) as usize;
        let magic = (headers + OPTIONAL_HEADER_OFFSET) as *const u16;
        let directories = headers
            + OPTIONAL_HEADER_OFFSET
            + if magic.read() == PE32_PLUS_MAGIC {
                DATA_DIRECTORIES_OFFSET_64
            } else {
                DATA_DIRECTORIES_OFFSET_32
            };

        base + read_u32(directories) as usize
    }
}

pub(crate) fn export(base: usize, wanted: &[u8]) -> usize {
    unsafe {
        let headers = base + read_u32(base + PE_HEADERS_OFFSET) as usize;
        let magic = (headers + OPTIONAL_HEADER_OFFSET) as *const u16;
        let directories = headers
            + OPTIONAL_HEADER_OFFSET
            + if magic.read() == PE32_PLUS_MAGIC {
                DATA_DIRECTORIES_OFFSET_64
            } else {
                DATA_DIRECTORIES_OFFSET_32
            };

        let exports = base + read_u32(directories) as usize;
        let count = read_u32(exports + EXPORT_NAME_COUNT_OFFSET) as usize;
        let functions = base + read_u32(exports + EXPORT_FUNCTIONS_OFFSET) as usize;
        let names = base + read_u32(exports + EXPORT_NAMES_OFFSET) as usize;
        let ordinals = base + read_u32(exports + EXPORT_ORDINALS_OFFSET) as usize;

        for index in 0..count {
            let name = base + read_u32(names + index * 4) as usize;
            if name_is(name, wanted) {
                let ordinal = ((ordinals + index * 2) as *const u16).read() as usize;
                return base + read_u32(functions + ordinal * 4) as usize;
            }
        }
    }

    0
}
fn name_is(name: usize, wanted: &[u8]) -> bool {
    for (index, expected) in wanted.iter().enumerate() {
        if unsafe { ((name + index) as *const u8).read() } != *expected {
            return false;
        }
    }

    unsafe { ((name + wanted.len()) as *const u8).read() == 0 }
}
pub(crate) unsafe fn read_pointer(address: usize) -> usize {
    unsafe { (address as *const usize).read() }
}
pub(crate) unsafe fn read_u32(address: usize) -> u32 {
    unsafe { (address as *const u32).read() }
}

#[cfg(target_arch = "x86")]
pub(crate) const PEB_LDR_OFFSET: usize = 0x0c;
#[cfg(target_arch = "x86_64")]
pub(crate) const PEB_LDR_OFFSET: usize = 0x18;
#[cfg(target_arch = "x86")]
pub(crate) const LDR_IN_LOAD_ORDER_OFFSET: usize = 0x0c;
#[cfg(target_arch = "x86_64")]
pub(crate) const LDR_IN_LOAD_ORDER_OFFSET: usize = 0x10;
#[cfg(target_arch = "x86")]
pub(crate) const ENTRY_DLL_BASE_OFFSET: usize = 0x18;
#[cfg(target_arch = "x86_64")]
pub(crate) const ENTRY_DLL_BASE_OFFSET: usize = 0x30;
#[cfg(target_arch = "x86")]
pub(crate) const ENTRY_BASE_NAME_OFFSET: usize = 0x2c;
#[cfg(target_arch = "x86")]
pub(crate) const ENTRY_SIZE_OF_IMAGE_OFFSET: usize = 0x20;
#[cfg(target_arch = "x86")]
pub(crate) const ENTRY_FULL_NAME_OFFSET: usize = 0x24;
#[cfg(target_arch = "x86_64")]
pub(crate) const ENTRY_SIZE_OF_IMAGE_OFFSET: usize = 0x40;
#[cfg(target_arch = "x86_64")]
pub(crate) const ENTRY_FULL_NAME_OFFSET: usize = 0x48;
#[cfg(target_arch = "x86_64")]
pub(crate) const ENTRY_BASE_NAME_OFFSET: usize = 0x58;
const PE_HEADERS_OFFSET: usize = 0x3c;
const OPTIONAL_HEADER_OFFSET: usize = 0x18;
const PE32_PLUS_MAGIC: u16 = 0x20b;
const DATA_DIRECTORIES_OFFSET_32: usize = 0x60;
const DATA_DIRECTORIES_OFFSET_64: usize = 0x70;
const EXPORT_NAME_COUNT_OFFSET: usize = 0x18;
const EXPORT_FUNCTIONS_OFFSET: usize = 0x1c;
const EXPORT_NAMES_OFFSET: usize = 0x20;
const EXPORT_ORDINALS_OFFSET: usize = 0x24;
// Each copy reads this region at a different address. Thus all values in it are offsets from
// the start of the region.
struct Channel {
    length: u64,
    sequence: u64,
    ack: u64,
    buffer: u64,
}

impl Channel {
    fn publish(&self, arena: u64, frame: &[u8]) -> bool {
        if frame.len() > FRAME_BUFFER_SIZE {
            return false;
        }

        unsafe {
            let sequence = ((arena + self.sequence) as *const u32).read_volatile();
            while ((arena + self.ack) as *const u32).read_volatile() != sequence {
                yield_now();
            }

            core::ptr::copy_nonoverlapping(frame.as_ptr(), (arena + self.buffer) as *mut u8,
                frame.len());
            ((arena + self.length) as *mut u32).write_volatile(frame.len() as u32);
            ((arena + self.sequence) as *mut u32).write_volatile(sequence + 1);
        }

        true
    }

    fn take(&self, arena: u64) -> Option<&'static [u8]> {
        unsafe {
            let sequence = ((arena + self.sequence) as *const u32).read_volatile();
            if sequence == ((arena + self.ack) as *const u32).read_volatile() {
                return None;
            }

            let length = ((arena + self.length) as *const u32).read_volatile() as usize;

            Some(core::slice::from_raw_parts((arena + self.buffer) as *const u8, length))
        }
    }

    fn acknowledge(&self, arena: u64) {
        unsafe {
            let sequence = ((arena + self.sequence) as *const u32).read_volatile();
            ((arena + self.ack) as *mut u32).write_volatile(sequence);
        }
    }
}

pub(crate) const STOP_REQUEST: u64 = 0x00;
pub(crate) const OBSERVED_PID: u64 = 0x04;
pub(crate) const AGENT_WAKE_HANDLE: u64 = 0x08;
pub(crate) const TARGET_WAKE_HANDLE: u64 = 0x10;

pub(crate) const COPY_LEFT: u64 = 0x48;
pub(crate) const OBSERVED_THREAD: u64 = 0x40;
pub(crate) const LOADER_LIBRARY: u64 = 0x44;

pub(crate) const REGISTER_PROCESS: u64 = 0x18;
pub(crate) const REGISTER_THREAD: u64 = 0x1c;

// Where the kernel half leaves what the bootstrap needs. NtCreateThread reads the context and
// the stack description from the process itself, thus both live here.
pub(crate) const BOOTSTRAP_CREATE_THREAD: u64 = 0x100;
pub(crate) const BOOTSTRAP_TERMINATE_THREAD: u64 = 0x108;
pub(crate) const BOOTSTRAP_CONTEXT: u64 = 0x110;
pub(crate) const BOOTSTRAP_INITIAL_TEB: u64 = 0x118;
pub(crate) const BOOTSTRAP_HANDLE: u64 = 0x120;
pub(crate) const BOOTSTRAP_CLIENT_ID: u64 = 0x128;
const CONTEXT_AREA: u64 = 0x200;
const INITIAL_TEB_AREA: u64 = 0x700;

const TO_TARGET: Channel = Channel {
    length: 0x20,
    sequence: 0x24,
    ack: 0x28,
    buffer: 0x1000,
};

const FROM_TARGET: Channel = Channel {
    length: 0x30,
    sequence: 0x34,
    ack: 0x38,
    buffer: 0x1000 + FRAME_BUFFER_SIZE as u64,
};

pub fn arena_for_pid(pid: u32) -> Option<u64> {
    unsafe { targets().get(&pid).map(|t| t.arena) }
}

pub fn injected_arenas() -> alloc::vec::Vec<u64> {
    unsafe { targets().values().map(|t| t.arena).collect() }
}

// The copy waits for an event, thus set the event after you write the frame.
pub fn forward_frame(arena: u64, frame: &[u8]) -> bool {
    if !TO_TARGET.publish(arena, frame) {
        return false;
    }

    let wake = unsafe { targets().values().find(|t| t.arena == arena).map(|t| t.wake) };
    if let Some(wake) = wake {
        unsafe { (_KeSetEvent)(wake, 0, 0) };
    }

    true
}

pub fn take_frame_from_target(arena: u64) -> Option<&'static [u8]> {
    FROM_TARGET.take(arena)
}

pub fn acknowledge_frame_from_target(arena: u64) {
    FROM_TARGET.acknowledge(arena)
}

pub fn take_frame_from_host(arena: u64) -> Option<&'static [u8]> {
    TO_TARGET.take(arena)
}

pub fn acknowledge_frame_from_host(arena: u64) {
    TO_TARGET.acknowledge(arena)
}

// The kernel half waits for an event, thus set the event after you write the frame.
pub fn publish_frame_to_host(arena: u64, frame: &[u8]) -> bool {
    if !FROM_TARGET.publish(arena, frame) {
        return false;
    }

    crate::winnt_user::signal_kernel_half();

    true
}

unsafe fn targets() -> &'static mut BTreeMap<u32, Target> {
    unsafe { core::ptr::addr_of_mut!(TARGETS).as_mut().unwrap() }
}

static mut TARGETS: BTreeMap<u32, Target> = BTreeMap::new();

struct Target {
    arena: u64,
    seen: u64,
    wake: *mut c_void,
    started: bool,
    introduced: bool,
    text: u64,
    size: u64,
    private: u64,
    private_size: usize,
    stack: u64,
    shared_mdl: *mut c_void,
    private_mdl: *mut c_void,
    arena_mdl: *mut c_void,
}

impl Target {
    fn private_offset(&self) -> u64 {
        crate::writable_half_start() as u64
            - unsafe { core::ptr::addr_of!(crate::OWN_RANGE).read() }.base_address
    }
}

pub const ARENA_SIZE: usize = 0x1000 + 2 * FRAME_BUFFER_SIZE;
const FRAME_BUFFER_SIZE: usize = 0x4000;

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
    push ebp
    mov ebp, esp
    mov ecx, [ebp + 8]
    mov edx, [ebp + 12]
    mov eax, [ebp + 16]
    and ecx, -16
    mov esp, ecx
    push eax
    call edx
    mov esp, ebp
    pop ebp
    ret

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
    call frida_winnt_resume_block
    mov ebx, eax
    mov esp, [ebx + 16]
    push dword ptr [ebx + 36]
    popfd
    push dword ptr [ebx]
    push dword ptr [ebx + 32]
    push dword ptr [ebx + 20]
    mov edi, [ebx + 4]
    mov esi, [ebx + 8]
    mov ebp, [ebx + 12]
    mov edx, [ebx + 24]
    mov ecx, [ebx + 28]
    pop ebx
    pop eax
    ret
1:
    mov [esp + 32], eax
    popad
    ret
.endm

FAULT_THUNK frida_winnt_fault_thunk_ud, 6
FAULT_THUNK frida_winnt_fault_thunk_gp, 13
FAULT_THUNK frida_winnt_fault_thunk_pf, 14
"#
);

// To go to ring 3, make the frame that an interrupt makes, then do an iret. Set the block
// The code pushes the registers in the order that Gum uses, thus the handler reads them where
// they are. A long-mode iret loads the stack pointer from the frame, thus the handler changes
// the frame.
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    r#"
.intel_syntax noprefix

.global frida_winnt_run_on_stack
frida_winnt_run_on_stack:
    push rbp
    mov rbp, rsp
    and rdi, -16
    mov rsp, rdi
    mov rdi, rdx
    call rsi
    mov rsp, rbp
    pop rbp
    ret

.set GPR_BYTES, 128

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
    mov [rsp + GPR_BYTES], rax
    POP_GPRS
    ret
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
        type DeferredRoutine =
            unsafe extern "stdcall" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void);
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
        type DeferredRoutine =
            unsafe extern "win64" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void);
    };
}

kernel_abi! {
    static _ExAllocatePoolWithTag: windows_fn!(u32, usize, u32 => *mut u8);
    static _ExFreePoolWithTag: windows_fn!(*mut u8, u32);
    static _PsCreateSystemThread: windows_fn!(
        *mut *mut c_void,
        u32,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        ThreadStartRoutine,
        *mut c_void,
        => i32);
    static _PsGetCurrentThreadId: windows_fn!( => u32);
    static _KeInitializeEvent: windows_fn!(*mut c_void, u32, u8);
    static _KeWaitForSingleObject: windows_fn!(*mut c_void, u32, u32, u8, *const i64 => i32);
    static _KeSetEvent: windows_fn!(*mut c_void, u32, u8 => i32);
    static _KeInitializeDpc: windows_fn!(*mut c_void, DeferredRoutine, *mut c_void);
    static _KeInsertQueueDpc: windows_fn!(*mut c_void, *mut c_void, *mut c_void => u8);
    static _ZwYieldExecution: windows_fn!( => i32);
    static _KeBugCheckEx: windows_fn!(u32, usize, usize, usize, usize => !);
    static _MmGetPhysicalAddress: windows_fn!(*const c_void => u64);
    static _HalGetInterruptVector: windows_fn!(u32, u32, u32, u32, *mut u8, *mut usize => u32);
    static _PsActiveProcessHead: usize;
    static _PsInitialSystemProcess: usize;
    static _PsGetProcessId: windows_fn!(*mut c_void => u32);
    static _PsGetProcessImageFileName: windows_fn!(*mut c_void => *const u8);
    static _PsGetProcessPeb: windows_fn!(*mut c_void => *mut c_void);
    static _PsGetCurrentThread: windows_fn!( => *mut c_void);
    static _PsGetThreadProcess: windows_fn!(*mut c_void => *mut c_void);
    static _PsGetThreadId: windows_fn!(*mut c_void => u32);
    static _PsGetContextThread: windows_fn!(*mut c_void, *mut u8, u8 => i32);
    static _KeStackAttachProcess: windows_fn!(*mut c_void, *mut u8);
    static _KeUnstackDetachProcess: windows_fn!(*mut u8);
    static _ZwCreateFile: windows_fn!(
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
    static _ZwReadFile: windows_fn!(
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
    static _ZwClose: windows_fn!(*mut c_void => i32);
    static _ZwCreateEvent: windows_fn!(*mut *mut c_void, u32, *mut c_void, u32, u8 => i32);
    static _ZwAllocateVirtualMemory: windows_fn!(
        *mut c_void, *mut *mut u8, usize, *mut usize, u32, u32 => i32);
    static _PsProcessType: usize;
    static _ObReferenceObjectByHandle: windows_fn!(
        *mut c_void, u32, *mut c_void, u8, *mut *mut c_void, *mut c_void => i32);
    static _ObOpenObjectByPointer: windows_fn!(
        *mut c_void, u32, *mut c_void, u32, *mut c_void, u32, *mut *mut c_void => i32);
    static _ExEventObjectType: usize;
    static _IoFreeMdl: windows_fn!(*mut c_void => ());
    static _ZwFreeVirtualMemory: windows_fn!(*mut c_void, *mut *mut u8, *mut usize, u32 => i32);
    static _IoAllocateMdl: windows_fn!(*mut c_void, u32, u8, u8, *mut c_void => *mut c_void);
    static _MmBuildMdlForNonPagedPool: windows_fn!(*mut c_void);
    static _MmMapLockedPagesSpecifyCache: windows_fn!(
        *mut c_void, u8, u32, *mut c_void, u32, u32, => *mut c_void);
    static _MmUnmapLockedPages: windows_fn!(*mut c_void, *mut c_void);
    static _IoDisconnectInterrupt: windows_fn!(*mut c_void => ());
    static _IoConnectInterrupt: windows_fn!(
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
