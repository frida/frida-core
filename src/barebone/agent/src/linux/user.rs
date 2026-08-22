use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;

use crate::kernel::ThreadEntry;

use super::arena::{Arena, FAULT_ADDRESS, FAULT_KIND, FAULT_LR, FAULT_PC, WOKEN};
use super::facade::Primitives;

pub fn entry_offset() -> usize {
    (frida_linux_user_entry as usize) - crate::own_range().0
}

// The copy's first word in the address space it was placed in: it says it is up, and from then
// on it sleeps until the kernel half has something for it. Nothing here looks at a clock.
pub extern "C" fn frida_linux_user_entry(begins: usize) -> ! {
    let arena = Arena::at(begins);

    super::facade::select_user();
    unsafe { ARENA = begins };
    stand_on_a_thread_pointer();
    install_fault_reporter();

    unsafe { crate::init_gum_without_exceptor() };
    let context = unsafe { crate::adopt_js_context() };
    unsafe { crate::route_frames_through(begins as u64) };

    open_the_pipes(arena);
    hear_what_the_kernel_half_says();

    arena.report_home();
    arena.tell_the_kernel_half();

    unsafe { CONTEXT = context };
    crate::watch_for_work(context, a_frame_is_waiting, serve_the_copy);

    loop {
        unsafe { crate::dispatch_pending_work(context) };
    }
}

fn a_frame_is_waiting() -> bool {
    let arena = Arena::at(unsafe { ARENA });

    arena.was_told_to_go()
        || arena.holds_a_thread()
        || super::relay::holds_a_frame_from_host(unsafe { ARENA } as u64)
}

fn serve_the_copy() {
    let arena = Arena::at(unsafe { ARENA });

    while let Some((thread, is_gone)) = arena.take_a_thread() {
        if is_gone {
            crate::gum_injected::thread_vanished(thread);
        } else {
            crate::gum_injected::thread_appeared(thread);
        }
    }

    while let Some(frame) = super::relay::take_frame_from_host(unsafe { ARENA } as u64) {
        crate::on_frame_from_host(&frame);
    }

    if arena.was_told_to_go() {
        leave();
    }
}

fn leave() -> ! {
    unsafe { crate::destroy_all_scripts(CONTEXT) };

    for descriptor in unsafe { [SAYING, SAYS_THROUGH, HEARING, HEARD_FROM] } {
        syscall(CLOSE, descriptor as usize, 0, 0, 0, 0, 0);
    }

    Arena::at(unsafe { ARENA }).gone();
    syscall(EXIT_GROUP, 0, 0, 0, 0, 0, 0);

    loop {}
}

pub static USER: Primitives = Primitives {
    log,
    panic,
    alloc,
    free,
    alloc_heap,
    alloc_code,
    free_code,
    page_size,
    protect,
    spawn_thread,
    wait,
    wake,
    yield_now,
    monotonic_micros,
    wall_clock_micros,
    home_process_id,
    current_process_id,
    current_thread_id,
    install_fault_reporter,
};

// The copy has no file to write to -- what it was given came from a thread of the kernel -- so
// what it has to say goes where the kernel half can read it.
fn log(msg: &str) {
    let arena = Arena::at(unsafe { ARENA });
    arena.say(msg);
    arena.note(SPOKE);
    arena.tell_the_kernel_half();
}

fn panic(msg: &str) -> ! {
    let arena = Arena::at(unsafe { ARENA });
    arena.say(msg);
    arena.note(PANICKED);
    arena.tell_the_kernel_half();

    syscall(EXIT_GROUP, 1, 0, 0, 0, 0, 0);

    loop {}
}

fn alloc(size: usize) -> *mut u8 {
    super::heap::take(size)
}

fn free(ptr: *mut u8, _size: usize) {
    super::heap::give_back(ptr);
}

// What the C library hands out is served from this, so it cannot come from the C library.
fn alloc_heap(size: usize) -> *mut u8 {
    map_writable(size)
}

fn alloc_code(size: usize) -> *mut u8 {
    map(size, READABLE | WRITABLE | EXECUTABLE)
}

fn free_code(ptr: *mut u8, size: usize) {
    syscall(MUNMAP, ptr as usize, size, 0, 0, 0, 0);
}

fn protect(address: u64, size: usize, protection: u32) -> bool {
    let wanted = ((protection & GUM_PAGE_READ) != 0) as usize * READABLE
        | ((protection & GUM_PAGE_WRITE) != 0) as usize * WRITABLE
        | ((protection & GUM_PAGE_EXECUTE) != 0) as usize * EXECUTABLE;

    let page = page_size();
    let first = (address as usize) & !(page - 1);
    let span = ((address as usize) + size + page - 1 & !(page - 1)) - first;

    syscall(MPROTECT, first, span, wanted, 0, 0, 0) == 0
}

pub fn map_writable(size: usize) -> *mut u8 {
    map(size, READABLE | WRITABLE)
}

fn map(size: usize, protection: usize) -> *mut u8 {
    let mapped = syscall(
        MMAP,
        0,
        size,
        protection,
        PRIVATE | ANONYMOUS,
        NO_FILE,
        0,
    );
    if mapped < 0 {
        return core::ptr::null_mut();
    }

    mapped as *mut u8
}

fn spawn_thread(entry: ThreadEntry, parameter: *mut c_void) -> isize {
    let stack = map_writable(THREAD_STACK_SIZE);
    if stack.is_null() {
        return -1;
    }

    let carried = alloc(size_of::<Carried>()) as *mut Carried;
    unsafe { carried.write(Carried { entry, parameter }) };

    let top = unsafe { stack.add(THREAD_STACK_SIZE) } as usize;

    unsafe { start_thread(top, carried as usize) }
}

// A task the kernel half makes has no thread pointer, and code of the process reads what it
// keeps there: musl's errno lives below it, and reading that at zero is what kills the copy the
// moment it calls into the C library it was placed beside.
#[cfg(target_arch = "aarch64")]
fn stand_on_a_thread_pointer() {
    let block = map_writable(THREAD_POINTER_BLOCK);
    if block.is_null() {
        return;
    }

    let pointer = unsafe { block.add(THREAD_POINTER_BLOCK / 2) } as usize;
    unsafe { core::arch::asm!("msr tpidr_el0, {}", in(reg) pointer, options(nomem, nostack)) };
}

const THREAD_POINTER_BLOCK: usize = 8192;

struct Carried {
    entry: ThreadEntry,
    parameter: *mut c_void,
}

unsafe extern "C" fn enter_thread(carried: usize) -> ! {
    stand_on_a_thread_pointer();

    let carried = carried as *mut Carried;
    unsafe {
        let Carried { entry, parameter } = carried.read();
        free(carried as *mut u8, size_of::<Carried>());

        entry(parameter, 0);
    }

    syscall(EXIT, 0, 0, 0, 0, 0, 0);

    loop {}
}

// The thread the kernel makes here starts on a stack of its own with nothing on it, so where it
// goes and what it is given are put in the registers the child keeps across the call.
#[cfg(target_arch = "aarch64")]
unsafe fn start_thread(stack: usize, carried: usize) -> isize {
    let spawned: isize;

    unsafe {
        core::arch::asm!(
            "svc #0",
            "cbnz x0, 2f",
            "mov x0, x22",
            "blr x21",
            "2:",
            in("x8") CLONE,
            inlateout("x0") THREAD_FLAGS => spawned,
            in("x1") stack,
            in("x2") 0,
            in("x3") 0,
            in("x4") 0,
            in("x21") enter_thread,
            in("x22") carried,
            clobber_abi("C"),
        );
    }

    spawned
}

fn open_the_pipes(arena: Arena) {
    let mut says = [0u32; 2];
    let mut hears = [0u32; 2];
    syscall(PIPE, says.as_mut_ptr() as usize, 0, 0, 0, 0, 0);
    syscall(PIPE, hears.as_mut_ptr() as usize, 0, 0, 0, 0, 0);

    unsafe {
        SAYING = says[1];
        SAYS_THROUGH = says[0];
        HEARING = hears[0];
        HEARD_FROM = hears[1];
    }

    arena.reachable_at(says[0], hears[1]);
}

pub fn say_something() {
    let byte = 0u8;
    syscall(WRITE, unsafe { SAYING } as usize, &byte as *const u8 as usize, 1, 0, 0, 0);
}

fn hear_what_the_kernel_half_says() {
    spawn_thread(listen_to_the_kernel_half, core::ptr::null_mut());
}

unsafe extern "C" fn listen_to_the_kernel_half(_parameter: *mut c_void, _reason: i32) {
    let mut heard = [0u8; 64];
    loop {
        let read = syscall(READ, unsafe { HEARING } as usize, heard.as_mut_ptr() as usize,
            heard.len(), 0, 0, 0);
        if read <= 0 {
            return;
        }

        wake(crate::glib::wakeup_token());
    }
}

static mut SAYING: u32 = 0;
static mut SAYS_THROUGH: u32 = 0;
static mut HEARING: u32 = 0;
static mut HEARD_FROM: u32 = 0;

fn wait(_token: *const u8, timeout_us: Option<u64>, check: &mut dyn FnMut() -> bool) {
    let unchanged = unchanged();
    if check() {
        return;
    }

    match timeout_us {
        Some(us) => {
            let until = [(us / 1_000_000) as i64, ((us % 1_000_000) * 1000) as i64];
            syscall(NANOSLEEP, until.as_ptr() as usize, 0, 0, 0, 0, 0);
        }
        None => wait_on(waited_on(), unchanged, None),
    }
}

fn wake(_token: *const u8) {
    bump_what_is_waited_on();
    wake_up(waited_on());
}

fn yield_now() {
    syscall(SCHED_YIELD, 0, 0, 0, 0, 0, 0);
}

fn monotonic_micros() -> i64 {
    micros_of(MONOTONIC)
}

fn wall_clock_micros() -> (u32, u32) {
    let now = read_clock(REALTIME);

    (now[0] as u32, (now[1] / 1000) as u32)
}

fn micros_of(clock: usize) -> i64 {
    let now = read_clock(clock);

    (now[0] * 1_000_000) + (now[1] / 1000)
}

fn read_clock(clock: usize) -> [i64; 2] {
    let mut now = [0i64; 2];
    syscall(CLOCK_GETTIME, clock, now.as_mut_ptr() as usize, 0, 0, 0, 0);

    now
}

// The copy has a task of its own, so which process it belongs to is what it was told.
fn home_process_id() -> u32 {
    Arena::at(unsafe { ARENA }).home()
}

fn current_process_id() -> u32 {
    syscall(GETPID, 0, 0, 0, 0, 0, 0) as u32
}

fn current_thread_id() -> u64 {
    syscall(GETTID, 0, 0, 0, 0, 0, 0) as u64
}

// A fault in the copy is nobody else's to report: the kernel kills the task and says nothing,
// so what it was is written down where the kernel half can read it.
fn install_fault_reporter() {
    for signal in [ILLEGAL, ABORTED, BUS, SEGMENT, ARITHMETIC, TRAPPED, BAD_CALL] {
        let action = Action {
            handler: report_fault as usize,
            flags: SIGINFO,
            restorer: 0,
            blocked: 0,
        };

        syscall(
            RT_SIGACTION,
            signal,
            &action as *const Action as usize,
            0,
            size_of::<u64>(),
            0,
            0,
        );
    }
}

#[repr(C)]
struct Action {
    handler: usize,
    flags: usize,
    restorer: usize,
    blocked: u64,
}

unsafe extern "C" fn report_fault(signal: usize, about: usize, running: usize) {
    let arena = Arena::at(unsafe { ARENA });

    arena.note(FAULTED);
    unsafe {
        arena.leave(
            FAULT_KIND,
            (signal as u64) | ((((about + ABOUT_CODE) as *const u32).read() as u64) << 32),
        );
        arena.leave(FAULT_ADDRESS, ((about + ABOUT_ADDRESS) as *const usize).read() as u64);
        arena.leave(
            FAULT_PC,
            ((running + RUNNING_STATE + STATE_PC) as *const usize).read() as u64,
        );
        arena.leave(
            FAULT_LR,
            ((running + RUNNING_STATE + STATE_LR) as *const usize).read() as u64,
        );

    }
    arena.tell_the_kernel_half();

    syscall(EXIT_GROUP, 1, 0, 0, 0, 0, 0);
}

// What the kernel was set up with is left in the arena, since asking the register is the
// kernel's own business.
fn page_size() -> usize {
    Arena::at(unsafe { ARENA }).page_size() as usize
}

pub fn names_in(directory: &core::ffi::CStr) -> Vec<String> {
    let listed = syscall(OPENAT, WORKING_DIRECTORY, directory.as_ptr() as usize, READ_ONLY, 0, 0, 0);
    if listed < 0 {
        return Vec::new();
    }

    let mut names = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = syscall(GETDENTS, listed as usize, chunk.as_mut_ptr() as usize, chunk.len(),
            0, 0, 0);
        if read <= 0 {
            break;
        }

        let mut at = 0;
        while at < read as usize {
            let entry = unsafe { chunk.as_ptr().add(at) };
            let length = unsafe { entry.add(16).cast::<u16>().read_unaligned() } as usize;
            let name = unsafe { core::ffi::CStr::from_ptr(entry.add(19)) };
            names.push(String::from_utf8_lossy(name.to_bytes()).into_owned());
            at += length;
        }
    }
    syscall(CLOSE, listed as usize, 0, 0, 0, 0, 0);

    names
}

pub fn contents_of(path: &core::ffi::CStr) -> Vec<u8> {
    let file = syscall(OPENAT, WORKING_DIRECTORY, path.as_ptr() as usize, READ_ONLY, 0, 0, 0);
    if file < 0 {
        return Vec::new();
    }

    let mut said = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = syscall(READ, file as usize, chunk.as_mut_ptr() as usize, chunk.len(), 0, 0, 0);
        if read <= 0 {
            break;
        }
        said.extend_from_slice(&chunk[..read as usize]);
    }
    syscall(CLOSE, file as usize, 0, 0, 0, 0, 0);

    said
}

fn waited_on() -> usize {
    unsafe { ARENA + WOKEN }
}

fn unchanged() -> u32 {
    unsafe { ((ARENA + WOKEN) as *const u32).read_volatile() }
}

fn bump_what_is_waited_on() {
    unsafe {
        let word = (ARENA + WOKEN) as *mut u32;
        word.write_volatile(word.read_volatile().wrapping_add(1));
    }
}

fn wait_on(word: usize, until_it_changes: u32, micros: Option<u64>) {
    let until = micros.map(|us| [(us / 1_000_000) as i64, ((us % 1_000_000) * 1000) as i64]);
    let deadline = match &until {
        Some(when) => when.as_ptr() as usize,
        None => 0,
    };

    syscall(
        FUTEX,
        word,
        FUTEX_WAIT_PRIVATE,
        until_it_changes as usize,
        deadline,
        0,
        0,
    );
}

pub fn wake_up(word: usize) {
    syscall(FUTEX, word, FUTEX_WAKE_PRIVATE, WAKE_EVERY_WAITER, 0, 0, 0);
}

#[cfg(target_arch = "aarch64")]
fn syscall(number: usize, a: usize, b: usize, c: usize, d: usize, e: usize, f: usize) -> isize {
    let answer: isize;

    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") number,
            inlateout("x0") a => answer,
            in("x1") b,
            in("x2") c,
            in("x3") d,
            in("x4") e,
            in("x5") f,
            options(nostack)
        );
    }

    answer
}

static mut ARENA: usize = 0;
static mut CONTEXT: *mut crate::bindings::GMainContext = core::ptr::null_mut();

pub const PANICKED: u32 = 9;
pub const SPOKE: u32 = 10;
pub const FAULTED: u32 = 8;

#[cfg(target_arch = "aarch64")]
const RT_SIGACTION: usize = 134;
const ILLEGAL: usize = 4;
const TRAPPED: usize = 5;
const ABORTED: usize = 6;
const ARITHMETIC: usize = 8;
const BAD_CALL: usize = 31;
const BUS: usize = 7;
const SEGMENT: usize = 11;
const SIGINFO: usize = 4;
const ABOUT_CODE: usize = 8;
const ABOUT_ADDRESS: usize = 16;
const RUNNING_STATE: usize = 176;
const STATE_PC: usize = 264;
const STATE_LR: usize = 248;

#[cfg(target_arch = "aarch64")]
#[cfg(target_arch = "aarch64")]
const OPENAT: usize = 56;
#[cfg(target_arch = "aarch64")]
const CLOSE: usize = 57;
#[cfg(target_arch = "aarch64")]
const NANOSLEEP: usize = 101;
#[cfg(target_arch = "aarch64")]
const PIPE: usize = 59;
#[cfg(target_arch = "aarch64")]
const GETDENTS: usize = 61;
#[cfg(target_arch = "aarch64")]
const POLL: usize = 73;
#[cfg(target_arch = "aarch64")]
const READ: usize = 63;
#[cfg(target_arch = "aarch64")]
const WRITE: usize = 64;
#[cfg(target_arch = "aarch64")]
const EXIT: usize = 93;
#[cfg(target_arch = "aarch64")]
const EXIT_GROUP: usize = 94;
#[cfg(target_arch = "aarch64")]
const FUTEX: usize = 98;
#[cfg(target_arch = "aarch64")]
#[cfg(target_arch = "aarch64")]
const CLOCK_GETTIME: usize = 113;
#[cfg(target_arch = "aarch64")]
const SCHED_YIELD: usize = 124;
#[cfg(target_arch = "aarch64")]
const GETPID: usize = 172;
#[cfg(target_arch = "aarch64")]
const GETTID: usize = 178;
#[cfg(target_arch = "aarch64")]
const MUNMAP: usize = 215;
#[cfg(target_arch = "aarch64")]
const CLONE: usize = 220;
#[cfg(target_arch = "aarch64")]
const MMAP: usize = 222;
#[cfg(target_arch = "aarch64")]
const MPROTECT: usize = 226;

const STANDARD_ERROR: usize = 2;
const WORKING_DIRECTORY: usize = -100isize as usize;
const READ_ONLY: usize = 0;
const POLL_IN: i32 = 1;
pub const READABLE: usize = 1;
pub const WRITABLE: usize = 2;
pub const EXECUTABLE: usize = 4;
const PRIVATE: usize = 2;
const ANONYMOUS: usize = 0x20;
const NO_FILE: usize = usize::MAX;

const MONOTONIC: usize = 1;
const REALTIME: usize = 0;

const THREAD_STACK_SIZE: usize = 1024 * 1024;
const THREAD_FLAGS: usize = 0x0000_0100 | 0x0000_0200 | 0x0000_0400 | 0x0000_0800 | 0x0001_0000;

const FUTEX_WAIT_PRIVATE: usize = 128;
const FUTEX_WAKE_PRIVATE: usize = 129;
const WAKE_EVERY_WAITER: usize = i32::MAX as usize;

const GUM_PAGE_READ: u32 = 1;
const GUM_PAGE_WRITE: u32 = 2;
const GUM_PAGE_EXECUTE: u32 = 4;

