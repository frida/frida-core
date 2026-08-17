// The VMM side of the blob flavor. Reached the way XNU is: the host fills in a
// slot per service before calling _start, so nothing here is a link-time import.
//
// The signatures follow the VxD service documentation; none of them has been
// exercised against a running kernel yet.

extern crate alloc;

use alloc::collections::BTreeMap;
use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::kernel::{CpuState, ThreadEntry, ThreadInfo};

// A process is made in ring 3, thus a copy of the agent does this work.
pub use crate::win9x_user::{resume_process, spawn_process};

pub const MODULE_DIRECTORY: &str = "/WINDOWS/SYSTEM/VMM32/";

const PAGE_SIZE: u32 = 4096;

const PG_SYS: u32 = 1;
const PAGE_FLAGS_CODE: u32 = PAGE_FIXED | PAGE_LOCKED | PAGE_ZERO_INIT;
const PAGE_FIXED: u32 = 0x8;
const PAGE_LOCKED: u32 = 0x80;
const PAGE_ZERO_INIT: u32 = 0x1;

const PAGE_PRESENT: u32 = 0x1;
const PAGE_WRITEABLE: u32 = 0x2;
pub(crate) const GUM_PAGE_WRITE: u32 = 0x2;

const BLOCK_SVC_INTS: u32 = 1 << 0;

const DEBUG_CONSOLE_PORT: u16 = 0xe9;

pub fn log(msg: &str) {
    for byte in msg.bytes() {
        if byte == 0 {
            break;
        }
        write_debug_byte(byte);
    }
}

pub fn log_hex(value: u32) {
    let mut shift = 32;
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

pub fn panic(msg: &str) {
    log(msg);
    unsafe {
        fatal_error_handler(msg.as_ptr(), 0);
    }
}

pub fn alloc(size: usize) -> *mut u8 {
    (primitives().alloc)(size)
}

pub fn free(ptr: *mut u8, size: usize) {
    (primitives().free)(ptr, size)
}

pub fn alloc_code(size: usize) -> *mut u8 {
    (primitives().alloc_code)(size)
}

pub fn free_code(ptr: *mut u8, size: usize) {
    (primitives().free_code)(ptr, size)
}

pub fn spawn_thread(entry: ThreadEntry, parameter: *mut c_void) -> isize {
    (primitives().spawn_thread)(entry, parameter)
}



// VMM refuses to build a thread from the borrowed context the host enters us on, and only
// says so by never returning, so hand the work to a point where VMM is between jobs.
pub fn run_when_ready(action: fn()) {
    unsafe {
        READY_ACTION = Some(action);
        schedule_global_event(frida_win9x_event_thunk);
    }
}

#[unsafe(no_mangle)]
extern "C" fn frida_win9x_on_event() {
    if let Some(action) = unsafe { READY_ACTION } {
        action();
    }
}

static mut READY_ACTION: Option<fn()> = None;

#[unsafe(no_mangle)]
extern "C" fn frida_win9x_thread_start() {
    unsafe {
        if let Some(entry) = THREAD_ENTRY {
            entry(THREAD_PARAMETER, 0);
        }
    }
}

static mut THREAD_ENTRY: Option<ThreadEntry> = None;
static mut THREAD_PARAMETER: *mut c_void = core::ptr::null_mut();

const THREAD_STACK_SIZE: usize = 64 * 1024;



pub fn wait(token: *const u8, timeout_us: Option<u64>, check: &mut dyn FnMut() -> bool) {
    (primitives().wait)(token, timeout_us, check)
}

fn block_until_signalled_or_timed_out(semaphore: u32, timeout_us: u64) {
    let timeout_ms = (timeout_us / 1000).max(1) as u32;
    let timeout = unsafe { set_global_time_out(timeout_ms, semaphore) };
    unsafe {
        wait_semaphore(semaphore, BLOCK_SVC_INTS);
    }
    if timeout != 0 {
        unsafe {
            cancel_time_out(timeout);
        }
    }
}

pub fn wake(token: *const u8) {
    (primitives().wake)(token)
}


pub fn yield_now() {
    (primitives().yield_now)()
}

pub fn allocate_shared(size: usize) -> u32 {
    alloc_shared(size) as u32
}

// The payload is a call into this image, not a copy of it. The pages of the agent are
// available in ring 3, thus the new thread runs the same code as the kernel half.
pub fn inject_agent(pid: u32) -> u32 {
    let process = process_for_pid(pid);
    if process == 0 {
        return 0;
    }

    let (image_base, entry) = place_shared_agent();

    let mut payload = [
        0xff, 0x74, 0x24, 0x04,
        0xba, 0, 0, 0, 0,
        0xff, 0xd2,
        0xeb, 0xfe,
    ];
    payload[5..9].copy_from_slice(&entry.to_le_bytes());

    let injection = inject(process, &payload);
    if injection.thread == 0 {
        return 0;
    }
    if !await_flag(injection.arena + OBSERVED_PID) {
        return 0;
    }

    let observed = unsafe { ((injection.arena + OBSERVED_PID) as *const u32).read_volatile() };
    unsafe {
        targets().insert(observed, Target {
            arena: injection.arena,
            stack: injection.stack,
            image_base,
        })
    };

    observed
}

// Only the copy knows when it is safe to stop. It runs on the stack and in the image that
// this function releases, thus the copy reports when it leaves both.
pub fn detach_from_process(pid: u32) -> bool {
    let Some(target) = (unsafe { targets().remove(&pid) }) else {
        return false;
    };
    let arena = target.arena;

    unsafe { ((arena + STOP_REQUEST) as *mut u32).write_volatile(1) };
    if !await_flag(arena + WORKER_STOPPED) || !await_flag(arena + MAIN_STOPPED) {
        return false;
    }

    // A thread sets the flag before it leaves. Thus wait for the time it needs to run its last
    // instructions and return into KERNEL32.
    wait(core::ptr::addr_of!(TEARDOWN_TOKEN), Some(TEARDOWN_GRACE_US), &mut || false);

    unsafe {
        free_shared(((arena + TO_TARGET.buffer) as *const u32).read_volatile());
        free_shared(((arena + FROM_TARGET.buffer) as *const u32).read_volatile());
    }
    free_shared(target.stack);
    free_shared(target.image_base);
    free_shared(arena);

    true
}

struct Target {
    arena: u32,
    stack: u32,
    image_base: u32,
}

static mut TEARDOWN_TOKEN: u8 = 0;

pub fn arena_for_pid(pid: u32) -> Option<u64> {
    unsafe { targets().get(&pid).map(|t| t.arena as u64) }
}

pub fn injected_arenas() -> alloc::vec::Vec<u64> {
    unsafe { targets().values().map(|t| t.arena as u64).collect() }
}

unsafe fn targets() -> &'static mut BTreeMap<u32, Target> {
    unsafe { core::ptr::addr_of_mut!(TARGETS).as_mut().unwrap() }
}

static mut TARGETS: BTreeMap<u32, Target> = BTreeMap::new();


fn process_for_pid(pid: u32) -> u32 {
    let slot = unsafe { (THREAD_BLOCK_SLOT as *const u32).read() };
    let vm = unsafe { get_sys_vm_handle() };
    let first = unsafe { get_initial_thread_handle(vm) };

    let mut thread = first;
    while thread != 0 {
        if unsafe { (thread as *const u32).add(0x2c / 4).read() } == WIN32_THREAD {
            let block = unsafe { (thread as *const u32).byte_add(slot as usize).read() };
            let pdb = unsafe { (block as *const u32).add(1).read() };
            if process_id(pdb) == pid {
                return pdb;
            }
        }

        let next = unsafe { get_next_thread_handle(thread) };
        thread = if next == first { 0 } else { next };
    }

    0
}

// The kernel half is already holding the code, and a page can be shown at a second address.
// Thus a process gets the same code pages, and only the half that gets written to is new memory.
fn place_shared_agent() -> (u32, u32) {
    let own = unsafe { &*core::ptr::addr_of!(crate::OWN_RANGE) };
    let private_offset = crate::writable_half_start() - own.base_address as usize;
    let pages = (own.size as usize).div_ceil(PAGE_SIZE as usize) as u32;
    let base = unsafe { __PageReserve(PR_SHARED, pages, 0) };
    let first = base / PAGE_SIZE;

    let shared_pages = (private_offset / PAGE_SIZE as usize) as u32;
    let own_first = own.base_address as u32 / PAGE_SIZE;
    for page in 0..shared_pages {
        let mut entry = 0;
        unsafe {
            __CopyPageTable(own_first + page, 1, &mut entry, 0);
            // A second address for a page that the memory manager does not own takes the user
            // bit only. The service refuses the flags that new pages take.
            __PageCommitPhys(first + page, 1, entry / PAGE_SIZE, PC_USER);
        }
    }

    unsafe {
        __PageCommit(first + shared_pages, pages - shared_pages, PD_FIXEDZERO, 0,
            PC_FIXED | PC_PRESENT | PC_USER | PC_WRITEABLE);
        crate::install_writable_half(base as usize, (base + private_offset as u32) as usize);
    }

    let entry = base + (crate::win9x_user::frida_win9x_user_main as usize
        - own.base_address as usize) as u32;

    (base, entry)
}

// Ring 3 cannot write to a different process. Thus KERNEL32 makes the thread in the target,
// with the stack and the payload in the shared arena, which all processes can read.
pub fn inject(process: u32, payload: &[u8]) -> Injection {
    let arena = alloc_shared(INJECTION_ARENA_SIZE) as u32;
    let entry = arena + PAYLOAD_OFFSET;
    unsafe {
        core::ptr::write_bytes(arena as *mut u8, 0, HANDSHAKE_SIZE);
        core::ptr::copy_nonoverlapping(payload.as_ptr(), entry as *mut u8, payload.len());
    }

    unsafe {
        ((arena + TO_TARGET.buffer) as *mut u32)
            .write_volatile(alloc_shared(FRAME_BUFFER_SIZE) as u32);
        ((arena + FROM_TARGET.buffer) as *mut u32)
            .write_volatile(alloc_shared(FRAME_BUFFER_SIZE) as u32);
    };

    let stack = alloc_shared(INJECTION_STACK_SIZE) as u32;
    write_trampoline(arena + TRAMPOLINE_OFFSET, entry, stack + INJECTION_STACK_SIZE as u32 - 0x40);

    create_suspended_thread(arena + STUB_OFFSET, arena + TRAMPOLINE_OFFSET, arena, process);
    if !await_flag(arena + THREAD_DATABASE) {
        return Injection { arena, thread: 0, stack };
    }

    // KERNEL32 writes the first frame on a stack in the process that calls it. Thus the target
    // needs these bytes at the same address before the thread runs.
    let database = unsafe { ((arena + THREAD_DATABASE) as *const u32).read_volatile() };
    let thread = unsafe { (database as *const u32).byte_add(TDB_CONTROL_BLOCK).read() };
    // TCB+0x1c gets its value only after the thread runs. Thus ask VWIN32 for the frame.
    let mut state = [0u8; CONTEXT_SIZE];
    state[..4].copy_from_slice(&CONTEXT_FULL.to_le_bytes());
    unsafe { __VWIN32_Get_Thread_Context(thread, state.as_mut_ptr()) };
    let esp = u32::from_le_bytes([
        state[CONTEXT_ESP],
        state[CONTEXT_ESP + 1],
        state[CONTEXT_ESP + 2],
        state[CONTEXT_ESP + 3],
    ]);
    mirror_startup_stack(process, esp);

    resume_thread(arena + RESUME_STUB_OFFSET, arena);
    if !await_flag(arena + RUNNING_FLAG) {
        return Injection { arena, thread: 0, stack };
    }
    unsafe { ((arena + GO_FLAG) as *mut u32).write_volatile(1) };

    Injection { arena, thread, stack }
}

// The two halves use the same protocol, thus the arena holds complete frames. The copy
// answers as it answers the host, and the kernel half sends these bytes without a change.
pub fn forward_frame(arena: u64, frame: &[u8]) -> bool {
    TO_TARGET.publish(arena as u32, frame)
}

pub fn take_frame_from_target(arena: u64) -> Option<&'static [u8]> {
    FROM_TARGET.take(arena as u32)
}

pub fn acknowledge_frame_from_target(arena: u64) {
    FROM_TARGET.acknowledge(arena as u32)
}

pub fn take_frame_from_host(arena: u64) -> Option<&'static [u8]> {
    TO_TARGET.take(arena as u32)
}

pub fn acknowledge_frame_from_host(arena: u64) {
    TO_TARGET.acknowledge(arena as u32)
}

pub fn publish_frame_to_host(arena: u64, frame: &[u8]) -> bool {
    FROM_TARGET.publish(arena as u32, frame)
}

// Each direction holds one frame. The reader acknowledges the frame before the writer uses
// the buffer again, thus a slow reader waits and loses no frames.
struct Channel {
    buffer: u32,
    length: u32,
    sequence: u32,
    ack: u32,
}

impl Channel {
    fn publish(&self, arena: u32, frame: &[u8]) -> bool {
        if frame.len() > FRAME_BUFFER_SIZE {
            return false;
        }

        let sequence = unsafe { ((arena + self.sequence) as *const u32).read_volatile() };
        while unsafe { ((arena + self.ack) as *const u32).read_volatile() } != sequence {
            yield_now();
        }

        let buffer = unsafe { ((arena + self.buffer) as *const u32).read_volatile() } as *mut u8;
        unsafe {
            core::ptr::copy_nonoverlapping(frame.as_ptr(), buffer, frame.len());
            ((arena + self.length) as *mut u32).write_volatile(frame.len() as u32);
            ((arena + self.sequence) as *mut u32).write_volatile(sequence + 1);
        }

        true
    }

    fn take(&self, arena: u32) -> Option<&'static [u8]> {
        let sequence = unsafe { ((arena + self.sequence) as *const u32).read_volatile() };
        if sequence == unsafe { ((arena + self.ack) as *const u32).read_volatile() } {
            return None;
        }

        let buffer = unsafe { ((arena + self.buffer) as *const u32).read_volatile() } as *const u8;
        let length = unsafe { ((arena + self.length) as *const u32).read_volatile() } as usize;

        Some(unsafe { core::slice::from_raw_parts(buffer, length) })
    }

    fn acknowledge(&self, arena: u32) {
        let sequence = unsafe { ((arena + self.sequence) as *const u32).read_volatile() };
        unsafe { ((arena + self.ack) as *mut u32).write_volatile(sequence) };
    }
}

const TO_TARGET: Channel = Channel {
    buffer: 0x1c,
    length: 0x20,
    sequence: 0x24,
    ack: 0x28,
};

const FROM_TARGET: Channel = Channel {
    buffer: 0x2c,
    length: 0x30,
    sequence: 0x34,
    ack: 0x38,
};

pub struct Injection {
    pub arena: u32,
    pub thread: u32,
    pub stack: u32,
}

// KERNEL32 makes threads from its own worker in ring 3. Thus an APC to thread -1 runs our
// code, and the target does nothing. CreateThread would use the process of that worker, not
// the target, thus the code calls the internal function, which receives the process. The
// thread starts suspended, which gives time to make the stack available.
fn create_suspended_thread(stub: u32, entry: u32, parameter: u32, process: u32) {
    let mut code = [
        0x6a, 0x68,
        0x68, 0, 0, 0, 0,
        0x68, 0, 0, 0, 0,
        0x68, 0x00, 0x00, 0x01, 0x00,
        0x68, 0, 0, 0, 0,
        0xe8, 0, 0, 0, 0,
        0xa3, 0, 0, 0, 0,
        0xc2, 0x04, 0x00,
    ];
    code[3..7].copy_from_slice(&parameter.to_le_bytes());
    code[8..12].copy_from_slice(&entry.to_le_bytes());
    code[18..22].copy_from_slice(&process.to_le_bytes());
    code[23..27].copy_from_slice(&(thread_creator() - (stub + 27)).to_le_bytes());
    code[28..32].copy_from_slice(&(parameter + THREAD_DATABASE).to_le_bytes());

    unsafe {
        core::ptr::copy_nonoverlapping(code.as_ptr(), stub as *mut u8, code.len());
        __VWIN32_QueueUserApc(stub, 0, ANY_THREAD);
    }
}

fn resume_thread(stub: u32, arena: u32) {
    let mut code = [
        0xff, 0x35, 0, 0, 0, 0,
        0xe8, 0, 0, 0, 0,
        0xc7, 0x05, 0, 0, 0, 0, 0x01, 0x00, 0x00, 0x00,
        0xc2, 0x04, 0x00,
    ];
    code[2..6].copy_from_slice(&(arena + THREAD_DATABASE).to_le_bytes());
    code[7..11].copy_from_slice(&(thread_resumer() - (stub + 11)).to_le_bytes());
    code[13..17].copy_from_slice(&(arena + RESUMED_FLAG).to_le_bytes());

    unsafe {
        core::ptr::copy_nonoverlapping(code.as_ptr(), stub as *mut u8, code.len());
        __VWIN32_QueueUserApc(stub, 0, ANY_THREAD);
    }
}

fn write_trampoline(trampoline: u32, entry: u32, stack_top: u32) {
    let mut code = [
        0x8b, 0x44, 0x24, 0x04,
        0xbc, 0, 0, 0, 0,
        0x50,
        0xba, 0, 0, 0, 0,
        0xff, 0xd2,
        0x6a, 0x00,
        0xba, 0, 0, 0, 0,
        0xff, 0xd2,
    ];
    code[5..9].copy_from_slice(&stack_top.to_le_bytes());
    code[11..15].copy_from_slice(&entry.to_le_bytes());
    code[20..24].copy_from_slice(&kernel32_export(b"ExitThread").to_le_bytes());

    unsafe { core::ptr::copy_nonoverlapping(code.as_ptr(), trampoline as *mut u8, code.len()) };
}


fn mirror_startup_stack(process: u32, esp: u32) {
    let base = esp & !0xffff;
    let first = base / PAGE_SIZE;
    let pages = 0x10000 / PAGE_SIZE;

    let carrier = alloc_code(0x10000);
    let mut present = [false; 0x10];
    for page in 0..pages {
        let address = base + page * PAGE_SIZE;
        present[page as usize] = page_entry(address) & PAGE_PRESENT != 0;
        if present[page as usize] {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    address as *const u8,
                    carrier.byte_add((page * PAGE_SIZE) as usize),
                    PAGE_SIZE as usize,
                )
            };
        }
    }

    let context = unsafe { (process as *const u32).byte_add(PDB_MEMORY_CONTEXT).read() };
    let saved = unsafe { __GetCurrentContext() };
    unsafe {
        __ContextSwitch(context);
        __PageReserve(first, pages, 0);
        __PageCommit(first, pages, PD_FIXEDZERO, 0,
            PC_FIXED | PC_PRESENT | PC_USER | PC_WRITEABLE);
        for page in 0..pages {
            if present[page as usize] {
                core::ptr::copy_nonoverlapping(
                    carrier.byte_add((page * PAGE_SIZE) as usize),
                    (base + page * PAGE_SIZE) as *mut u8,
                    PAGE_SIZE as usize,
                );
            }
        }
        __ContextSwitch(saved);
    }

    free_code(carrier, 0x10000);
}

fn page_entry(address: u32) -> u32 {
    let mut entry = 0u32;
    unsafe { __CopyPageTable(address / PAGE_SIZE, 1, &mut entry, 0) };
    entry
}


fn await_flag(address: u32) -> bool {
    static mut TOKEN: u8 = 0;
    for _ in 0..INJECTION_ATTEMPTS {
        wait(core::ptr::addr_of!(TOKEN), Some(INJECTION_POLL_US), &mut || false);
        if unsafe { (address as *const u32).read_volatile() } != 0 {
            return true;
        }
    }

    false
}

fn free_shared(address: u32) {
    unsafe { __PageFree(address as *mut u8, 0) };
}

fn alloc_shared(size: usize) -> *mut u8 {
    let pages = size.div_ceil(PAGE_SIZE as usize) as u32;
    let address = unsafe { __PageReserve(PR_SHARED, pages, 0) };
    let committed = unsafe {
        __PageCommit(address / PAGE_SIZE, pages, PD_FIXEDZERO, 0,
            PC_FIXED | PC_PRESENT | PC_USER | PC_WRITEABLE)
    };
    let _ = committed;

    address as *mut u8
}










// KERNEL32 exports neither the creator that receives a process nor the code behind
// ResumeThread. Thus find them by the shape of the code that calls them. The ring 3 worker
// The primitives that differ between the two halves. The kernel half runs on KERNEL, and
// the copy in a process selects USER before it does anything else. The order here is the
// order of the functions in each group.
pub struct Primitives {
    pub alloc: fn(usize) -> *mut u8,
    pub free: fn(*mut u8, usize),
    pub alloc_code: fn(usize) -> *mut u8,
    pub free_code: fn(*mut u8, usize),
    pub spawn_thread: fn(ThreadEntry, *mut c_void) -> isize,
    pub wait: fn(*const u8, Option<u64>, &mut dyn FnMut() -> bool),
    pub wake: fn(*const u8),
    pub yield_now: fn(),
    pub monotonic_micros: fn() -> i64,
    pub current_process_id: fn() -> u32,
    pub current_thread_id: fn() -> u64,
    pub protect: fn(u64, usize, u32) -> bool,
}

pub fn select_user() {
    unsafe { ACTIVE = &crate::win9x_user::USER };
}

fn primitives() -> &'static Primitives {
    unsafe { ACTIVE }
}

static mut ACTIVE: &Primitives = &KERNEL;

static KERNEL: Primitives = Primitives {
    alloc: kernel::alloc,
    free: kernel::free,
    alloc_code: kernel::alloc_code,
    free_code: kernel::free_code,
    spawn_thread: kernel::spawn_thread,
    wait: kernel::wait,
    wake: kernel::wake,
    yield_now: kernel::yield_now,
    monotonic_micros: kernel::monotonic_micros,
    current_process_id: kernel::current_process_id,
    current_thread_id: kernel::current_thread_id,
    protect: kernel::protect,
};

mod kernel {
    use super::*;

    pub fn alloc(size: usize) -> *mut u8 {
        unsafe { __HeapAllocate(size as u32, 0) }
    }

    pub fn free(ptr: *mut u8, _size: usize) {
        unsafe {
            __HeapFree(ptr, 0);
        }
    }

    pub fn alloc_code(size: usize) -> *mut u8 {
        let pages = size.div_ceil(PAGE_SIZE as usize) as u32;
        unsafe { __PageAllocate(pages, PG_SYS, 0, 0, 0, 0, core::ptr::null_mut(), PAGE_FLAGS_CODE) }
    }

    pub fn free_code(ptr: *mut u8, _size: usize) {
        unsafe {
            __PageFree(ptr, 0);
        }
    }

    pub fn spawn_thread(entry: ThreadEntry, parameter: *mut c_void) -> isize {
        unsafe {
            THREAD_ENTRY = Some(entry);
            THREAD_PARAMETER = parameter;

            vwin32_create_ring0_thread(
                THREAD_STACK_SIZE as u32,
                0,
                frida_win9x_thread_thunk as u32,
                0,
            ) as isize
        }
    }

    pub fn wait(token: *const u8, timeout_us: Option<u64>, check: &mut dyn FnMut() -> bool) {
        let semaphore = semaphore_for(token);
        if check() {
            return;
        }

        match timeout_us {
            None => unsafe { wait_semaphore(semaphore, BLOCK_SVC_INTS) },
            Some(us) => block_until_signalled_or_timed_out(semaphore, us),
        }
    }

    pub fn wake(token: *const u8) {
        unsafe {
            signal_semaphore(semaphore_for(token));
        }
    }

    pub fn yield_now() {
        unsafe {
            _Release_Time_Slice();
        }
    }

    pub fn monotonic_micros() -> i64 {
        unsafe { _Get_System_Time() as i64 * 1000 }
    }

    pub fn current_process_id() -> u32 {
        0
    }

    pub fn current_thread_id() -> u64 {
        unsafe { get_cur_thread_handle() as u64 }
    }

    pub fn protect(address: u64, size: usize, gum_prot: u32) -> bool {
        let first_page = address / PAGE_SIZE as u64;
        let pages = size.div_ceil(PAGE_SIZE as usize) as u32;

        let mut set = PAGE_PRESENT;
        if (gum_prot & GUM_PAGE_WRITE) != 0 {
            set |= PAGE_WRITEABLE;
        }
        let clear = PAGE_WRITEABLE & !set;

        unsafe { __PageModifyPermissions(first_page as u32, pages, !clear, set) != 0xffff_ffff }
    }
}


// for _VWIN32_CreateRing0Thread calls the creator with the same five arguments.
fn thread_creator() -> u32 {
    let cached = unsafe { core::ptr::addr_of!(THREAD_CREATOR).read() };
    if cached != 0 {
        return cached;
    }

    let base = unsafe { core::ptr::addr_of!(_KERNEL32_Base).read() };
    let last = base + image_size(base) - CREATE_CALL_SITE.len() as u32;
    let mut address = base;
    while address != last {
        if read_u8(address) == 0x6a && read_u8(address + 1) == 0x28 && matches_call_site(address) {
            let found = (address + CREATE_CALL_SITE.len() as u32)
                .wrapping_add(read_u32(address + 21));
            unsafe { THREAD_CREATOR = found };
            return found;
        }
        address += 1;
    }

    0
}

fn matches_call_site(address: u32) -> bool {
    for (offset, expected) in CREATE_CALL_SITE.iter().enumerate() {
        if *expected != 0 && read_u8(address + offset as u32) != *expected {
            return false;
        }
    }

    true
}

// ResumeThread gives the thread database to it and examines the result for -1.
fn thread_resumer() -> u32 {
    let cached = unsafe { core::ptr::addr_of!(THREAD_RESUMER).read() };
    if cached != 0 {
        return cached;
    }

    let entry = kernel32_export(b"ResumeThread");
    let mut address = entry;
    while address != entry + RESUME_SEARCH_RANGE {
        if read_u8(address) == 0x57
            && read_u8(address + 1) == 0xe8
            && read_u8(address + 6) == 0x83
            && read_u8(address + 7) == 0xf8
            && read_u8(address + 8) == 0xff
        {
            let found = (address + 6).wrapping_add(read_u32(address + 2));
            unsafe { THREAD_RESUMER = found };
            return found;
        }
        address += 1;
    }

    0
}

fn image_size(base: u32) -> u32 {
    read_u32(base + read_u32(base + DOS_HEADERS_OFFSET) + IMAGE_SIZE_OFFSET)
}

static mut THREAD_CREATOR: u32 = 0;
static mut THREAD_RESUMER: u32 = 0;

// push 0x28; push esi; push imm32; push [esi+8]; push [imm32]; mov edi,[esi+0x10]; call rel32
const CREATE_CALL_SITE: [u8; 25] = [
    0x6a, 0x28, 0x56, 0x68, 0, 0, 0, 0, 0xff, 0x76, 0x08, 0xff, 0x35, 0, 0, 0, 0, 0x8b, 0x7e,
    0x10, 0xe8, 0, 0, 0, 0,
];
const RESUME_SEARCH_RANGE: u32 = 0x60;
const DOS_HEADERS_OFFSET: u32 = 0x3c;
const IMAGE_SIZE_OFFSET: u32 = 0x50;

// The host cannot resolve these, because parts of the export names of KERNEL32 are out of
// memory. Only the guest can get these pages again.
pub fn kernel32_export(wanted: &[u8]) -> u32 {
    let base = unsafe { core::ptr::addr_of!(_KERNEL32_Base).read() };
    let headers = base + read_u32(base + DOS_HEADERS_OFFSET);
    let directory = base + read_u32(headers + EXPORT_DIRECTORY_OFFSET);
    let count = read_u32(directory + 0x18);
    let functions = base + read_u32(directory + 0x1c);
    let names = base + read_u32(directory + 0x20);
    let ordinals = base + read_u32(directory + 0x24);

    let mut lowest = 0;
    let mut highest = count;
    while lowest < highest {
        let middle = (lowest + highest) / 2;
        match compare_export(base + read_u32(names + middle * 4), wanted) {
            core::cmp::Ordering::Equal => {
                let ordinal = read_u16(ordinals + middle * 2) as u32;
                return base + read_u32(functions + ordinal * 4);
            }
            core::cmp::Ordering::Less => lowest = middle + 1,
            core::cmp::Ordering::Greater => highest = middle,
        }
    }

    0
}

fn compare_export(name: u32, wanted: &[u8]) -> core::cmp::Ordering {
    for (index, expected) in wanted.iter().enumerate() {
        let actual = read_u8(name + index as u32);
        if actual != *expected {
            return actual.cmp(expected);
        }
    }

    read_u8(name + wanted.len() as u32).cmp(&0)
}

fn read_u32(address: u32) -> u32 {
    unsafe { (address as *const u32).read_unaligned() }
}

fn read_u16(address: u32) -> u16 {
    unsafe { (address as *const u16).read_unaligned() }
}

fn read_u8(address: u32) -> u8 {
    unsafe { (address as *const u8).read() }
}

const EXPORT_DIRECTORY_OFFSET: u32 = 0x78;

pub(crate) const MEM_COMMIT: u32 = 0x0000_1000;
pub(crate) const MEM_RESERVE: u32 = 0x0000_2000;
pub(crate) const MEM_RELEASE: u32 = 0x0000_8000;
pub(crate) const PAGE_EXECUTE_READ: u32 = 0x20;
pub(crate) const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub(crate) const INFINITE: u32 = 0xffff_ffff;
pub(crate) const USER_THREAD_STACK_SIZE: u32 = 0x10000;

const INJECTION_ARENA_SIZE: usize = 0x1000;
const HANDSHAKE_SIZE: usize = 0x40;
pub(crate) const RUNNING_FLAG: u32 = 0x00;
pub(crate) const GO_FLAG: u32 = 0x04;
pub(crate) const OBSERVED_PID: u32 = 0x08;
const THREAD_DATABASE: u32 = 0x14;
const RESUMED_FLAG: u32 = 0x18;
pub(crate) const STOP_REQUEST: u32 = 0x0c;
pub(crate) const MAIN_STOPPED: u32 = 0x10;
pub(crate) const WORKER_STOPPED: u32 = 0x3c;
const FRAME_BUFFER_SIZE: usize = 0x4000;
const TEARDOWN_GRACE_US: u64 = 500_000;
const TDB_CONTROL_BLOCK: usize = 0x5c;
const IDLE_SLEEP_MS: u32 = 1000;
pub(crate) const PARKED_SLEEP_MS: u32 = 200;
const STUB_OFFSET: u32 = 0x100;
const PAYLOAD_OFFSET: u32 = 0x200;
const INJECTION_ATTEMPTS: u32 = 100;
const INJECTION_POLL_US: u64 = 100_000;
const ANY_THREAD: u32 = 0xffff_ffff;
const RESUME_STUB_OFFSET: u32 = 0x140;
const TRAMPOLINE_OFFSET: u32 = 0x180;

const INJECTION_STACK_SIZE: usize = 0x4000;
const THREAD_BLOCK_SLOT: u32 = 0xc002_11cc;
const PDB_MEMORY_CONTEXT: usize = 0x1c;
const PR_SHARED: u32 = 0x8006_0000;
const PD_FIXEDZERO: u32 = 0x3;
const PC_FIXED: u32 = 0x0000_0008;
const PC_WRITEABLE: u32 = 0x0002_0000;
const PC_USER: u32 = 0x0004_0000;
const PC_PRESENT: u32 = 0x8000_0000;

pub fn monotonic_micros() -> i64 {
    (primitives().monotonic_micros)()
}

pub fn wall_clock_micros() -> (u32, u32) {
    let micros = monotonic_micros() as u64;
    ((micros / 1_000_000) as u32, (micros % 1_000_000) as u32)
}

// Ring 0 is in no process, thus only the injected copy has an answer.
pub fn current_process_id() -> u32 {
    (primitives().current_process_id)()
}

pub fn current_thread_id() -> u64 {
    (primitives().current_thread_id)()
}

pub fn protect(address: u64, size: usize, gum_prot: u32) -> bool {
    (primitives().protect)(address, size, gum_prot)
}

// This kernel has no self-map, but VMM copies a run of page table entries into a buffer,
// which gives the same data. Report only the arena, because the memory below it belongs to
// the VM that is current.
pub fn enumerate_ranges(found: &mut dyn FnMut(u64, u64, u32)) {
    let mut base = 0usize;
    let mut size = 0usize;
    let mut protection = 0u32;

    let mut address = ARENA_START;
    while address != ARENA_END {
        let here = protection_at(address);

        if here != protection || base + size != address {
            if protection != 0 {
                found(base as u64, size as u64, protection);
            }
            base = address;
            size = 0;
            protection = here;
        }
        size += PAGE_SIZE as usize;

        address += PAGE_SIZE as usize;
    }

    if protection != 0 {
        found(base as u64, size as u64, protection);
    }
}

pub fn protection_at(address: usize) -> u32 {
    let mut entry: u32 = 0;
    let copied = unsafe { __CopyPageTable((address / PAGE_SIZE as usize) as u32, 1, &mut entry, 0) };
    if copied == 0 {
        return 0;
    }
    protection_of(entry)
}

// These processors have no execute permission, thus all present pages are executable.
fn protection_of(entry: u32) -> u32 {
    if (entry & PAGE_PRESENT) == 0 {
        return 0;
    }

    let mut prot = GUM_PAGE_READ | GUM_PAGE_EXECUTE;
    if (entry & PAGE_WRITEABLE) != 0 {
        prot |= GUM_PAGE_WRITE;
    }
    prot
}

const ARENA_START: usize = 0xc000_0000;
const ARENA_END: usize = 0xc400_0000;
const GUM_PAGE_READ: u32 = 0x1;
const GUM_PAGE_EXECUTE: u32 = 0x4;

pub fn map_io(phys_addr: u64, size: u64) -> *mut c_void {
    let pages = (size as usize).div_ceil(PAGE_SIZE as usize) as u32;
    unsafe { __MapPhysToLinear(phys_addr as u32, pages * PAGE_SIZE, 0) as *mut c_void }
}

pub fn virt_to_phys(vaddr: u64) -> u64 {
    let mut entry: u32 = 0;
    let page = (vaddr / PAGE_SIZE as u64) as u32;
    unsafe {
        __CopyPageTable(page, 1, &mut entry, 0);
    }
    ((entry & !(PAGE_SIZE - 1)) as u64) | (vaddr & (PAGE_SIZE - 1) as u64)
}

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

    unsafe {
        IRQ_DESCRIPTOR = VpicdIrqDescriptor {
            irq_number: irq as u16,
            options: VPICD_OPT_REF_DATA | VPICD_OPT_CAN_SHARE,
            hw_int_proc: frida_win9x_hw_int_thunk,
            virt_int_proc: 0,
            eoi_proc: 0,
            mask_change_proc: 0,
            iret_proc: 0,
            iret_time_out: VPICD_DEFAULT_IRET_TIME_OUT,
            hw_int_ref: 0,
        };
    }

    let handle = unsafe { vpicd_virtualize_irq(core::ptr::addr_of_mut!(IRQ_DESCRIPTOR)) };
    if handle != 0 {
        unsafe {
            IRQ_HANDLE = handle;
            vpicd_physically_unmask(handle);
        }
    }
    if handle == 0 { -1 } else { 0 }
}

// VMM schedules only ring 0 threads. The ring 3 part of a Win32 thread is not ours to report.
pub fn enumerate_threads(found: &mut dyn FnMut(ThreadInfo)) {
    let vm = unsafe { get_sys_vm_handle() };
    let first = unsafe { get_initial_thread_handle(vm) };

    let mut thread = first;
    while thread != 0 {
        found(ThreadInfo { id: thread, cpu_state: thread_cpu_state(thread) });

        let next = unsafe { get_next_thread_handle(thread) };
        thread = if next == first { 0 } else { next };
    }
}

// VWIN32 gives the registers of Win32 threads only, and it fails for the others.
fn thread_cpu_state(thread: u32) -> Option<CpuState> {
    let mut context = [0u8; CONTEXT_SIZE];
    let base = context.as_mut_ptr();

    unsafe {
        base.add(CONTEXT_FLAGS).cast::<u32>().write_unaligned(CONTEXT_FULL);

        if __VWIN32_Get_Thread_Context(thread, base) == 0 {
            return None;
        }

        let field = |offset: usize| base.add(offset).cast::<u32>().read_unaligned();

        Some(CpuState {
            eip: field(CONTEXT_EIP),
            edi: field(CONTEXT_EDI),
            esi: field(CONTEXT_ESI),
            ebp: field(CONTEXT_EBP),
            esp: field(CONTEXT_ESP),
            ebx: field(CONTEXT_EBX),
            edx: field(CONTEXT_EDX),
            ecx: field(CONTEXT_ECX),
            eax: field(CONTEXT_EAX),
        })
    }
}

const CONTEXT_SIZE: usize = 0xcc;
const CONTEXT_FULL: u32 = 0x0001_0007;
const CONTEXT_FLAGS: usize = 0x00;
const CONTEXT_EDI: usize = 0x9c;
const CONTEXT_ESI: usize = 0xa0;
const CONTEXT_EBX: usize = 0xa4;
const CONTEXT_EDX: usize = 0xa8;
const CONTEXT_ECX: usize = 0xac;
const CONTEXT_EAX: usize = 0xb0;
const CONTEXT_EBP: usize = 0xb4;
const CONTEXT_EIP: usize = 0xb8;
const CONTEXT_ESP: usize = 0xc4;

pub struct ProcessInfo {
    pub id: u32,
    pub path: *const u8,
    pub command_line: *const u8,
}

// Win32 threads carry the process they belong to in VWIN32's per-thread block, so the
// process list is the deduplicated set of those, and the image path is where the command
// line starts.
pub fn enumerate_processes(found: &mut dyn FnMut(ProcessInfo)) {
    let slot = unsafe { (0xc00211ccu32 as *const u32).read() };
    let vm = unsafe { get_sys_vm_handle() };
    let first = unsafe { get_initial_thread_handle(vm) };

    let mut seen: [u32; 64] = [0; 64];
    let mut count = 0usize;
    let mut thread = first;
    while thread != 0 && count < seen.len() {
        if unsafe { (thread as *const u32).add(0x2c / 4).read() } == WIN32_THREAD {
            let block = unsafe { (thread as *const u32).byte_add(slot as usize).read() };
            let pdb = unsafe { (block as *const u32).add(1).read() };
            if !seen[..count].contains(&pdb) {
                seen[count] = pdb;
                count += 1;
                found(ProcessInfo {
                    id: process_id(pdb),
                    path: image_path(pdb),
                    command_line: command_line(pdb),
                });
            }
        }

        let next = unsafe { get_next_thread_handle(thread) };
        thread = if next == first { 0 } else { next };
    }
}

// KERNEL32 hands out its process database pointer XOR a per-boot value, and so must we.
fn process_id(pdb: u32) -> u32 {
    let slot = unsafe { core::ptr::addr_of!(_KERNEL32_ProcessIdObfuscator).read() };
    if slot == 0 {
        return pdb;
    }

    pdb ^ unsafe { (slot as *const u32).read() }
}

fn command_line(pdb: u32) -> *const u8 {
    let env_db = unsafe { (pdb as *const u32).byte_add(PDB_ENVIRONMENT_OFFSET).read() };
    if env_db < ARENA_FLOOR {
        return core::ptr::null();
    }

    let text = unsafe { (env_db as *const u32).byte_add(ENVIRONMENT_COMMAND_LINE_OFFSET).read() };
    if text < ARENA_FLOOR {
        return core::ptr::null();
    }

    text as *const u8
}

// The command line would do for most processes, but it is empty for the ones Windows starts
// itself and can carry arguments besides. KERNEL32 names a module the way GetModuleFileName
// does: the process's own MODREF, indexed into the module table.
fn image_path(pdb: u32) -> *const u8 {
    let slot = unsafe { core::ptr::addr_of!(_KERNEL32_ModuleTable).read() };
    if slot == 0 {
        return core::ptr::null();
    }

    let table = unsafe { (slot as *const u32).read() };
    let modref = unsafe { (pdb as *const u32).byte_add(PDB_MODREF_OFFSET).read() };
    if table < ARENA_FLOOR || modref < ARENA_FLOOR {
        return core::ptr::null();
    }

    let index = unsafe { (modref as *const u16).byte_add(MODREF_MTE_INDEX_OFFSET).read() };
    let entry = unsafe { (table as *const u32).add(index as usize).read() };
    if entry < ARENA_FLOOR {
        return core::ptr::null();
    }

    let path = unsafe { (entry as *const u32).byte_add(IMTE_FILE_NAME_OFFSET).read() };
    if path < ARENA_FLOOR {
        return core::ptr::null();
    }

    path as *const u8
}

const WIN32_THREAD: u32 = 0x2a;
const ARENA_FLOOR: u32 = 0x10000;
const PDB_MODREF_OFFSET: usize = 0x94;
const PDB_ENVIRONMENT_OFFSET: usize = 0x40;
const ENVIRONMENT_COMMAND_LINE_OFFSET: usize = 0x08;
const MODREF_MTE_INDEX_OFFSET: usize = 0x10;
const IMTE_FILE_NAME_OFFSET: usize = 0x0c;

pub fn enumerate_icons(path: *const u8, found: &mut dyn FnMut(&[u8])) {
    let Some(file) = File::open(path) else {
        return;
    };

    crate::icons::enumerate(&file, found);
}

struct File {
    handle: u32,
}

impl File {
    fn open(path: *const u8) -> Option<File> {
        let handle = unsafe {
            ifsmgr_ring0_file_io(
                R0_OPENCREATFILE,
                0,
                0,
                ACTION_OPENEXISTING,
                path as u32,
                ACCESS_READONLY | SHARE_DENYNONE,
            )
        };
        if handle == 0 {
            return None;
        }

        Some(File { handle })
    }
}

impl crate::icons::Image for File {
    fn read_at(&self, position: u32, buffer: &mut [u8]) -> u32 {
        unsafe {
            ifsmgr_ring0_file_io(
                R0_READFILE,
                self.handle,
                buffer.len() as u32,
                position,
                buffer.as_mut_ptr() as u32,
                0,
            )
        }
    }
}

impl Drop for File {
    fn drop(&mut self) {
        unsafe { ifsmgr_ring0_file_io(R0_CLOSEFILE, self.handle, 0, 0, 0, 0) };
    }
}

const R0_OPENCREATFILE: u32 = 0xd500;
const R0_READFILE: u32 = 0xd600;
const R0_CLOSEFILE: u32 = 0xd700;
const ACCESS_READONLY: u32 = 0x0000;
const SHARE_DENYNONE: u32 = 0x0040;
const ACTION_OPENEXISTING: u32 = 0x01;



pub fn install_fault_reporter() {
    unsafe {
        FAULT_CHAIN[INVALID_OPCODE as usize] = hook_vmm_fault(INVALID_OPCODE, frida_win9x_fault_thunk_ud);
        FAULT_CHAIN[GENERAL_PROTECTION as usize] =
            hook_vmm_fault(GENERAL_PROTECTION, frida_win9x_fault_thunk_gp);
        FAULT_CHAIN[PAGE_FAULT as usize] = hook_vmm_fault(PAGE_FAULT, frida_win9x_fault_thunk_pf);
    }
}

#[unsafe(no_mangle)]
extern "C" fn frida_win9x_on_fault(fault: u32, frame: *mut u32) -> u32 {
    let mut cpu_context = unsafe {
        crate::bindings::_GumIA32CpuContext {
            eip: frame.add(fault_frame_eip_slot(fault)).read(),
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

    let handled = unsafe {
        crate::bindings::gum_barebone_handle_exception(
            exception_type_for(fault),
            cpu_context.eip as *mut c_void,
            faulting_address() as *mut c_void,
            &mut cpu_context,
        )
    };
    if handled == 0 {
        // Windows corrects most faults, and a page fault on an absent page is normal. Thus send those
        // to Windows. An invalid opcode is different: Windows runs the instruction again and the
        // machine stops. Thus stop the thread here, which keeps the guest available.
        let Some(faulted_at) = our_faulting_eip(frame) else {
            return unsafe { FAULT_CHAIN[fault as usize] };
        };
        if fault != INVALID_OPCODE {
            return unsafe { FAULT_CHAIN[fault as usize] };
        }

        report_unhandled_fault(fault, faulted_at);
        cpu_context.eip = frida_win9x_park as u32;
    }

    unsafe {
        frida_win9x_resume = [
            cpu_context.eip,
            cpu_context.edi,
            cpu_context.esi,
            cpu_context.ebp,
            cpu_context.esp,
            cpu_context.ebx,
            cpu_context.edx,
            cpu_context.ecx,
            cpu_context.eax,
        ];
    }

    0
}

// VMM enters a fault hook with EBP at the frame that the processor and its dispatcher made:
// the registers from pushad, then the error code, EIP, CS and the flags. Use that EIP. The
// frame of the thunk holds the address that VMM returns to.
fn our_faulting_eip(frame: *mut u32) -> Option<u32> {
    let registers = unsafe { frame.add(THUNK_FRAME_EBP).read() } as *const u32;
    let eip = unsafe { registers.byte_add(FAULT_FRAME_EIP).read() };
    let cs = unsafe { registers.byte_add(FAULT_FRAME_CS).read() };

    (cs & 3 == 0 && crate::own_range_contains(eip)).then_some(eip)
}

fn report_unhandled_fault(fault: u32, eip: u32) {
    log("frida: unhandled fault in the agent\n");
    log("frida:   vector ");
    log_hex(fault);
    log("frida:   eip ");
    log_hex(eip);
    log("frida:   address ");
    log_hex(faulting_address());
}

// Nothing can recover from this, thus the thread stops here.
extern "C" fn frida_win9x_park() -> ! {
    loop {
        wait(core::ptr::addr_of!(PARK_TOKEN), Some(PARK_SLICE_US), &mut || false);
    }
}

static mut PARK_TOKEN: u8 = 0;

#[unsafe(no_mangle)]
static mut frida_win9x_resume: [u32; 9] = [0; 9];

fn exception_type_for(fault: u32) -> crate::bindings::GumExceptionType {
    use crate::bindings::*;

    match fault {
        DIVIDE_ERROR | OVERFLOW | BOUND_RANGE_EXCEEDED | X87_FLOATING_POINT
        | SIMD_FLOATING_POINT => _GumExceptionType_GUM_EXCEPTION_ARITHMETIC,
        DEBUG => _GumExceptionType_GUM_EXCEPTION_SINGLE_STEP,
        BREAKPOINT => _GumExceptionType_GUM_EXCEPTION_BREAKPOINT,
        INVALID_OPCODE => _GumExceptionType_GUM_EXCEPTION_ILLEGAL_INSTRUCTION,
        STACK_SEGMENT_FAULT => _GumExceptionType_GUM_EXCEPTION_STACK_OVERFLOW,
        GENERAL_PROTECTION | PAGE_FAULT => _GumExceptionType_GUM_EXCEPTION_ACCESS_VIOLATION,
        _ => _GumExceptionType_GUM_EXCEPTION_SYSTEM,
    }
}

const DIVIDE_ERROR: u32 = 0;
const DEBUG: u32 = 1;
const BREAKPOINT: u32 = 3;
const OVERFLOW: u32 = 4;
const BOUND_RANGE_EXCEEDED: u32 = 5;
const STACK_SEGMENT_FAULT: u32 = 12;
const X87_FLOATING_POINT: u32 = 16;
const SIMD_FLOATING_POINT: u32 = 19;

fn fault_frame_eip_slot(fault: u32) -> usize {
    const PUSHED_REGISTERS: usize = 8;
    const VECTOR: usize = 1;

    let error_code = match fault {
        8 | 10 | 11 | 12 | 13 | 14 | 17 | 21 => 1,
        _ => 0,
    };

    PUSHED_REGISTERS + VECTOR + error_code
}

const THUNK_FRAME_EBP: usize = 2;
const FAULT_FRAME_EIP: usize = 0x24;
const FAULT_FRAME_CS: usize = 0x28;
const PARK_SLICE_US: u64 = 1_000_000;

fn faulting_address() -> u32 {
    let address: u32;
    unsafe { core::arch::asm!("mov {0:e}, cr2", out(reg) address, options(nomem, nostack, preserves_flags)) };
    address
}

static mut FAULT_CHAIN: [u32; 32] = [0; 32];


const INVALID_OPCODE: u32 = 6;
const GENERAL_PROTECTION: u32 = 13;
const PAGE_FAULT: u32 = 14;

#[unsafe(no_mangle)]
extern "C" fn frida_win9x_on_hw_int(_ref_data: *mut c_void) {
    unsafe {
        if let Some(handler) = HW_INT_HANDLER {
            handler(HW_INT_TARGET, HW_INT_REFCON, core::ptr::null_mut(), 0);
        }
        vpicd_phys_eoi(IRQ_HANDLE);
    }
}

static mut IRQ_HANDLE: u32 = 0;

static mut IRQ_DESCRIPTOR: VpicdIrqDescriptor = VpicdIrqDescriptor {
    irq_number: 0,
    options: 0,
    hw_int_proc: frida_win9x_hw_int_thunk,
    virt_int_proc: 0,
    eoi_proc: 0,
    mask_change_proc: 0,
    iret_proc: 0,
    iret_time_out: 0,
    hw_int_ref: 0,
};

static mut HW_INT_HANDLER: Option<InterruptHandler> = None;
static mut HW_INT_TARGET: *mut c_void = core::ptr::null_mut();
static mut HW_INT_REFCON: *mut c_void = core::ptr::null_mut();

#[repr(C)]
struct VpicdIrqDescriptor {
    irq_number: u16,
    options: u16,
    hw_int_proc: unsafe extern "C" fn(),
    virt_int_proc: u32,
    eoi_proc: u32,
    mask_change_proc: u32,
    iret_proc: u32,
    iret_time_out: u32,
    hw_int_ref: u32,
}

const VPICD_OPT_CAN_SHARE: u16 = 0x02;
const VPICD_OPT_REF_DATA: u16 = 0x04;
const VPICD_DEFAULT_IRET_TIME_OUT: u32 = 500;

pub type InterruptHandler =
    unsafe extern "C" fn(target: *mut c_void, refcon: *mut c_void, nub: *mut c_void, source: i32);

pub fn get_kernel_base() -> u64 {
    KERNEL_BASE.load(Ordering::Relaxed) as u64
}

pub fn set_kernel_base(base: u64) {
    KERNEL_BASE.store(base as u32, Ordering::Relaxed);
}

static KERNEL_BASE: AtomicU32 = AtomicU32::new(0);

// One semaphore per waited-on address, created on first use. VMM has no
// futex-alike, so the token has to be mapped onto something it does have.
fn semaphore_for(token: *const u8) -> u32 {
    let slot = (token as usize / core::mem::align_of::<usize>()) % SEMAPHORES.len();
    let existing = SEMAPHORES[slot].load(Ordering::Acquire);
    if existing != 0 {
        return existing;
    }

    let created = unsafe { create_semaphore(0) };
    match SEMAPHORES[slot].compare_exchange(0, created, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => created,
        Err(raced) => raced,
    }
}

const NUM_SEMAPHORES: usize = 64;
static SEMAPHORES: [AtomicU32; NUM_SEMAPHORES] = [const { AtomicU32::new(0) }; NUM_SEMAPHORES];
pub(crate) static EVENTS: [AtomicU32; NUM_SEMAPHORES] = [const { AtomicU32::new(0) }; NUM_SEMAPHORES];

unsafe extern "C" {
    fn wait_semaphore(semaphore: u32, flags: u32);
    fn signal_semaphore(semaphore: u32);
    fn create_semaphore(token_count: u32) -> u32;
    fn get_cur_thread_handle() -> u32;
    fn fatal_error_handler(message: *const u8, flags: u32);
    fn vpicd_virtualize_irq(descriptor: *mut VpicdIrqDescriptor) -> u32;
    fn vpicd_physically_unmask(handle: u32);
    fn vpicd_phys_eoi(handle: u32);
    fn set_global_time_out(milliseconds: u32, semaphore: u32) -> u32;
    fn cancel_time_out(timeout: u32);
    fn hook_vmm_fault(fault: u32, handler: unsafe extern "C" fn()) -> u32;
    fn frida_win9x_fault_thunk_ud();
    fn frida_win9x_fault_thunk_gp();
    fn frida_win9x_fault_thunk_pf();
    fn frida_win9x_time_out_thunk();
    fn get_cur_vm_handle() -> u32;
    fn get_sys_vm_handle() -> u32;
    fn schedule_global_event(callback: unsafe extern "C" fn()) -> u32;
    fn frida_win9x_event_thunk();
    fn get_next_vm_handle(vm: u32) -> u32;
    fn get_initial_thread_handle(vm: u32) -> u32;
    fn get_next_thread_handle(thread: u32) -> u32;
    fn ifsmgr_ring0_file_io(function: u32, ebx: u32, ecx: u32, edx: u32, esi: u32, edi: u32) -> u32;
    fn vwin32_create_ring0_thread(stack_size: u32, parameter: u32, entry: u32, event: u32) -> u32;
    fn frida_win9x_hw_int_thunk();
    fn frida_win9x_thread_thunk();
}

core::arch::global_asm!(
    r#"
.intel_syntax noprefix

// A position-independent image cannot name its data in an instruction. Thus the code reads the
// program counter, from which the offset to the data is known, and adds the offset. The frame
// pointer holds the result, because no service reads that register.
frida_win9x_get_pc_ebp:
    mov ebp, [esp]
    ret

frida_win9x_get_pc_ebx:
    mov ebx, [esp]
    ret

.macro CALL_SERVICE slot
    call frida_win9x_get_pc_ebp
    add ebp, offset _GLOBAL_OFFSET_TABLE_
    call dword ptr [ebp + \slot@GOTOFF]
.endm

.global wait_semaphore
wait_semaphore:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    mov eax, [ebp + 8]
    mov ecx, [ebp + 12]
    CALL_SERVICE _Wait_Semaphore
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.global signal_semaphore
signal_semaphore:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    mov eax, [ebp + 8]
    CALL_SERVICE _Signal_Semaphore
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.global create_semaphore
create_semaphore:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    mov ecx, [ebp + 8]
    CALL_SERVICE _Create_Semaphore
    cmc
    sbb ecx, ecx
    and eax, ecx
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.global get_cur_thread_handle
get_cur_thread_handle:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    CALL_SERVICE _Get_Cur_Thread_Handle
    mov eax, edi
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.global fatal_error_handler
fatal_error_handler:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    mov esi, [ebp + 8]
    mov eax, [ebp + 12]
    CALL_SERVICE _Fatal_Error_Handler
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.global schedule_global_event
schedule_global_event:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    mov esi, [ebp + 8]
    CALL_SERVICE _Schedule_Global_Event
    mov eax, ebx
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.global frida_win9x_event_thunk
frida_win9x_event_thunk:
    pushad
    call frida_win9x_on_event
    popad
    ret

.global get_sys_vm_handle
get_sys_vm_handle:
    push ebx
    CALL_SERVICE _Get_Sys_VM_Handle
    mov eax, ebx
    pop ebx
    ret

.global get_next_vm_handle
get_next_vm_handle:
    push ebp
    mov ebp, esp
    push ebx
    mov ebx, [ebp + 8]
    CALL_SERVICE _Get_Next_VM_Handle
    mov eax, ebx
    pop ebx
    pop ebp
    ret

.global get_initial_thread_handle
get_initial_thread_handle:
    push ebp
    mov ebp, esp
    push ebx
    push edi
    mov ebx, [ebp + 8]
    CALL_SERVICE _Get_Initial_Thread_Handle
    mov eax, edi
    pop edi
    pop ebx
    pop ebp
    ret

.global get_next_thread_handle
get_next_thread_handle:
    push ebp
    mov ebp, esp
    push ebx
    push edi
    mov edi, [ebp + 8]
    CALL_SERVICE _Get_Next_Thread_Handle
    mov eax, edi
    pop edi
    pop ebx
    pop ebp
    ret

.global vwin32_create_ring0_thread
vwin32_create_ring0_thread:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    mov ecx, [ebp + 8]
    mov edx, [ebp + 12]
    mov ebx, [ebp + 16]
    mov esi, [ebp + 20]
    CALL_SERVICE __VWIN32_CreateRing0Thread
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.global ifsmgr_ring0_file_io
ifsmgr_ring0_file_io:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    mov eax, [ebp + 8]
    mov ebx, [ebp + 12]
    mov ecx, [ebp + 16]
    mov edx, [ebp + 20]
    mov esi, [ebp + 24]
    mov edi, [ebp + 28]
    CALL_SERVICE _IFSMgr_Ring0_FileIO
    jnc 1f
    xor eax, eax
1:
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.global get_cur_vm_handle
get_cur_vm_handle:
    push ebx
    CALL_SERVICE _Get_Cur_VM_Handle
    mov eax, ebx
    pop ebx
    ret

.global hook_vmm_fault
hook_vmm_fault:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    mov eax, [ebp + 8]
    mov esi, [ebp + 12]
    CALL_SERVICE _Hook_VMM_Fault
    mov eax, esi
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.global frida_win9x_fault_thunk_ud
frida_win9x_fault_thunk_ud:
    push 6
    jmp frida_win9x_fault_common

.global frida_win9x_fault_thunk_gp
frida_win9x_fault_thunk_gp:
    push 13
    jmp frida_win9x_fault_common

.global frida_win9x_fault_thunk_pf
frida_win9x_fault_thunk_pf:
    push 14
    jmp frida_win9x_fault_common

frida_win9x_fault_common:
    pushad
    mov eax, [esp + 32]
    push esp
    push eax
    call frida_win9x_on_fault
    add esp, 8
    test eax, eax
    jz frida_win9x_fault_resume
    mov [esp + 32], eax
    popad
    ret
frida_win9x_fault_resume:
    call frida_win9x_get_pc_ebx
    add ebx, offset _GLOBAL_OFFSET_TABLE_
    lea ebx, [ebx + frida_win9x_resume@GOTOFF]
    mov esp, [ebx + 16]
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

.global set_global_time_out
set_global_time_out:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    mov eax, [ebp + 8]
    mov edx, [ebp + 12]
    call frida_win9x_get_pc_ebp
    add ebp, offset _GLOBAL_OFFSET_TABLE_
    lea esi, [ebp + frida_win9x_time_out_thunk@GOTOFF]
    call dword ptr [ebp + _Set_Global_Time_Out@GOTOFF]
    mov eax, esi
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.global cancel_time_out
cancel_time_out:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    mov esi, [ebp + 8]
    CALL_SERVICE _Cancel_Time_Out
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.global frida_win9x_time_out_thunk
frida_win9x_time_out_thunk:
    pushad
    mov eax, edx
    CALL_SERVICE _Signal_Semaphore
    popad
    ret

.global vpicd_phys_eoi
vpicd_phys_eoi:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    mov eax, [ebp + 8]
    CALL_SERVICE _VPICD_Phys_EOI
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.global vpicd_physically_unmask
vpicd_physically_unmask:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    mov eax, [ebp + 8]
    CALL_SERVICE _VPICD_Physically_Unmask
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.global vpicd_virtualize_irq
vpicd_virtualize_irq:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    mov edi, [ebp + 8]
    CALL_SERVICE _Get_Cur_VM_Handle
    CALL_SERVICE _VPICD_Virtualize_IRQ
    cmc
    sbb ecx, ecx
    and eax, ecx
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.global frida_win9x_thread_thunk
frida_win9x_thread_thunk:
    call frida_win9x_thread_start
1:
    jmp 1b

.global frida_win9x_hw_int_thunk
frida_win9x_hw_int_thunk:
    pushad
    push edx
    call frida_win9x_on_hw_int
    add esp, 4
    popad
    clc
    ret
"#
);

unsafe extern "C" {
    static _Get_Cur_VM_Handle: unsafe extern "C" fn();
    static _Get_Sys_VM_Handle: unsafe extern "C" fn();
    static _Schedule_Global_Event: unsafe extern "C" fn();
    static _Create_Semaphore: unsafe extern "C" fn();
    static _Wait_Semaphore: unsafe extern "C" fn();
    static _Signal_Semaphore: unsafe extern "C" fn();
    static _Get_Next_VM_Handle: unsafe extern "C" fn();
    static _Release_Time_Slice: unsafe extern "C" fn();
    static _Set_Global_Time_Out: unsafe extern "C" fn();
    static _Cancel_Time_Out: unsafe extern "C" fn();
    static _Get_System_Time: unsafe extern "C" fn() -> u32;
    static __HeapAllocate: unsafe extern "C" fn(u32, u32) -> *mut u8;
    static __HeapFree: unsafe extern "C" fn(*mut u8, u32);
    static __PageAllocate:
        unsafe extern "C" fn(u32, u32, u32, u32, u32, u32, *mut c_void, u32) -> *mut u8;
    static __PageFree: unsafe extern "C" fn(*mut u8, u32);
    static __CopyPageTable: unsafe extern "C" fn(u32, u32, *mut u32, u32) -> u32;
    static __MapPhysToLinear: unsafe extern "C" fn(u32, u32, u32) -> u32;
    static __PageReserve: unsafe extern "C" fn(u32, u32, u32) -> u32;
    static __PageCommit: unsafe extern "C" fn(u32, u32, u32, u32, u32) -> u32;
    static __PageCommitPhys: unsafe extern "C" fn(u32, u32, u32, u32) -> u32;
    static __VWIN32_QueueUserApc: unsafe extern "C" fn(u32, u32, u32) -> u32;
    static _Hook_VMM_Fault: unsafe extern "C" fn();
    static _Fatal_Error_Handler: unsafe extern "C" fn();
    static _Get_Cur_Thread_Handle: unsafe extern "C" fn();
    static _Get_Initial_Thread_Handle: unsafe extern "C" fn();
    static _Get_Next_Thread_Handle: unsafe extern "C" fn();
    static __Debug_Printf_Service: unsafe extern "C" fn(*const u8, ...);
    static __ContextSwitch: unsafe extern "C" fn(u32);
    static __PageModifyPermissions: unsafe extern "C" fn(u32, u32, u32, u32) -> u32;
    static __GetCurrentContext: unsafe extern "C" fn() -> u32;
    static _VPICD_Virtualize_IRQ: unsafe extern "C" fn();
    static _VPICD_Phys_EOI: unsafe extern "C" fn();
    static _VPICD_Physically_Unmask: unsafe extern "C" fn();
    static __VWIN32_Get_Thread_Context: unsafe extern "C" fn(u32, *mut u8) -> u32;
    static __VWIN32_CreateRing0Thread: unsafe extern "C" fn();
    static _IFSMgr_Ring0_FileIO: unsafe extern "C" fn();
    static _KERNEL32_Base: u32;
    static _KERNEL32_ProcessIdObfuscator: u32;
    static _KERNEL32_ModuleTable: u32;
}
