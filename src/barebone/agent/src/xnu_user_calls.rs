
use core::arch::asm;
use core::ffi::c_void;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::kernel::ThreadEntry;
use crate::xnu::Primitives;

pub static SLOTS: crate::gthread::ThreadSlots = crate::gthread::ThreadSlots {
    take: take_thread_slot,
    get: read_thread_slot,
    set: write_thread_slot,
};

fn take_thread_slot() -> u32 {
    unsafe { TAKEN += 1; TAKEN }
}

fn read_thread_slot(slot: u32) -> *mut c_void {
    if slot as usize >= SLOTS_PER_THREAD {
        return null_mut();
    }

    held(|| unsafe { row_for(thread_id()) }.map(|row| row[slot as usize]).unwrap_or(null_mut()))
}

fn write_thread_slot(slot: u32, value: *mut c_void) {
    if slot as usize >= SLOTS_PER_THREAD {
        return;
    }

    held(|| {
        let id = thread_id();
        let rows = unsafe { (&raw mut ROWS).as_mut().unwrap() };
        if unsafe { row_for(id) }.is_none() {
            let free = rows.iter().position(|row| row.0 == 0);
            match free {
                Some(at) => rows[at].0 = id,
                None => return,
            }
        }
        if let Some(row) = unsafe { row_for(id) } {
            row[slot as usize] = value;
        }
    });
}

unsafe fn row_for(id: u64) -> Option<&'static mut [*mut c_void; SLOTS_PER_THREAD]> {
    let rows = unsafe { (&raw mut ROWS).as_mut().unwrap() };

    rows.iter_mut().find(|row| row.0 == id).map(|row| &mut row.1)
}

fn held<T>(what: impl FnOnce() -> T) -> T {
    while LOCK.swap(true, Ordering::Acquire) {
        core::hint::spin_loop();
    }
    let answer = what();
    LOCK.store(false, Ordering::Release);

    answer
}

static LOCK: AtomicBool = AtomicBool::new(false);
static mut TAKEN: u32 = 0;
static mut ROWS: [(u64, [*mut c_void; SLOTS_PER_THREAD]); MOST_THREADS] =
    [(0, [null_mut(); SLOTS_PER_THREAD]); MOST_THREADS];

const SLOTS_PER_THREAD: usize = 256;
const MOST_THREADS: usize = 128;

pub static USER: Primitives = Primitives {
    alloc,
    free,
    alloc_code,
    free_code,
    spawn_thread,
    wait,
    wake,
    yield_now,
    monotonic_micros,
    wall_clock_micros,
    current_process_id,
    current_thread_id,
    protect,
    page_size,
    protection_at,
    enumerate_ranges,
};

fn alloc(size: usize) -> *mut u8 {
    crate::heap::take(size)
}

fn free(ptr: *mut u8, _size: usize) {
    crate::heap::give_back(ptr);
}

fn page_size() -> usize {
    unsafe { PAGE_SIZE }
}

pub fn told_the_page_size(size: usize) {
    unsafe { PAGE_SIZE = size };
}

static mut PAGE_SIZE: usize = 16384;

pub fn map_writable(size: usize) -> *mut u8 {
    take_memory(size).unwrap_or(0) as *mut u8
}

fn alloc_code(size: usize) -> *mut u8 {
    take_memory(size).unwrap_or(0) as *mut u8
}

fn free_code(ptr: *mut u8, size: usize) {
    give_memory_back(ptr as u64, size);
}

fn protect(address: u64, size: usize, may: u32) -> bool {
    set_protection(address, size, may as u64)
}

fn wait(token: *const u8, timeout_us: Option<u64>, check: &mut dyn FnMut() -> bool) {
    if check() {
        return;
    }

    let value = unsafe { (token as *const u32).read_volatile() };
    unsafe {
        ask(ULOCK_WAIT, [COMPARE_AND_WAIT, token as u64, value as u64,
            timeout_us.unwrap_or(A_NAP)])
    };
}

const A_NAP: u64 = 1000;

fn wake(token: *const u8) {
    unsafe { ask(ULOCK_WAKE, [COMPARE_AND_WAIT | WAKE_ALL, token as u64, 0, 0]) };
}

fn yield_now() {
    give_up_the_processor();
}

fn monotonic_micros() -> i64 {
    micros() as i64
}

fn wall_clock_micros() -> (u32, u32) {
    let mut when = WhatTimeItIs { seconds: 0, micros: 0 };
    unsafe { ask(GET_TIME_OF_DAY, [&mut when as *mut WhatTimeItIs as u64, 0, 0, 0]) };

    (when.seconds as u32, when.micros as u32)
}

#[repr(C)]
struct WhatTimeItIs {
    seconds: i64,
    micros: i64,
}

fn current_process_id() -> u32 {
    process_id()
}

fn current_thread_id() -> u64 {
    thread_id()
}

fn enumerate_ranges(found: &mut dyn FnMut(u64, usize, u32)) {
    let mut at = 0u64;
    while let Some(region) = region_from(at) {
        found(region.address, region.size as usize, region.protection);
        at = region.address + region.size;
    }
}

fn protection_at(address: u64) -> u32 {
    match region_from(address) {
        Some(region) if region.address <= address => region.protection,
        _ => 0,
    }
}

fn region_from(address: u64) -> Option<Region> {
    let mut region = Region::default();
    let told = unsafe {
        svc7(PROC_INFO, [ABOUT_A_PROCESS, process_id() as u64, ABOUT_A_REGION, address,
            &mut region as *mut Region as u64, core::mem::size_of::<Region>() as u64, 0])
    };

    (told == core::mem::size_of::<Region>() as i64).then_some(region)
}

#[repr(C)]
#[derive(Default)]
struct Region {
    protection: u32,
    most_it_may_be: u32,
    inheritance: u32,
    flags: u32,
    offset: u64,
    behavior: u32,
    wired: u32,
    tag: u32,
    resident: u32,
    now_private: u32,
    swapped_out: u32,
    dirtied: u32,
    references: u32,
    shadow_depth: u32,
    share_mode: u32,
    private_resident: u32,
    shared_resident: u32,
    object: u32,
    depth: u32,
    address: u64,
    size: u64,
}

fn spawn_thread(entry: ThreadEntry, parameter: *mut c_void) -> isize {
    let Some(stack) = take_memory(STACK) else {
        return 0;
    };

    match crate::xnu_user::ask_for_a_thread(entry as usize as u64,
        stack + STACK as u64 - STACK_HEADROOM, parameter as u64)
    {
        true => 1,
        false => {
            give_memory_back(stack, STACK);
            0
        }
    }
}

const STACK: usize = 1024 * 1024;
const STACK_HEADROOM: u64 = 0x100;
const PLAIN_ADDRESSES: u32 = 1;



pub fn process_id() -> u32 {
    unsafe { ask(GET_PID, [0; 4]) as u32 }
}

pub fn thread_id() -> u64 {
    unsafe { ask(THREAD_SELF_ID, [0; 4]) as u64 }
}

pub fn give_up_the_processor() {
    unsafe { ask(SCHED_YIELD, [0; 4]) };
}

pub fn micros() -> u64 {
    let ticks: u64;
    let rate: u64;
    unsafe {
        asm!("isb", "mrs {0}, cntvct_el0", "mrs {1}, cntfrq_el0", out(reg) ticks, out(reg) rate);
    }

    ticks / (rate / 1_000_000)
}

pub fn take_memory(size: usize) -> Option<u64> {
    let mut address: u64 = 0;
    let told = unsafe {
        trap(MACH_VM_ALLOCATE, [task(), &mut address as *mut u64 as u64, size as u64, ANYWHERE])
    };

    (told == KERN_SUCCESS).then_some(address)
}

pub fn give_memory_back(address: u64, size: usize) {
    unsafe { trap(MACH_VM_DEALLOCATE, [task(), address, size as u64, 0]) };
}

fn set_protection(address: u64, size: usize, may: u64) -> bool {
    unsafe { trap(MACH_VM_PROTECT, [task(), address, size as u64, may]) == KERN_SUCCESS }
}

unsafe fn task() -> u64 {
    unsafe { trap(TASK_SELF, [0; 4]) as u64 }
}

unsafe fn trap(number: i64, args: [u64; 4]) -> i64 {
    unsafe { svc(number, args).0 }
}

unsafe fn ask(number: i64, args: [u64; 4]) -> i64 {
    let (answer, went_wrong) = unsafe { svc(number, args) };
    if went_wrong {
        return -answer;
    }

    answer
}

pub(crate) unsafe fn svc7(number: i64, args: [u64; 7]) -> i64 {
    let answer: i64;
    unsafe {
        asm!(
            "svc #0x80",
            inlateout("x16") number => _,
            inlateout("x0") args[0] => answer,
            inlateout("x1") args[1] => _,
            inlateout("x2") args[2] => _,
            inlateout("x3") args[3] => _,
            inlateout("x4") args[4] => _,
            inlateout("x5") args[5] => _,
            inlateout("x6") args[6] => _,
            clobber_abi("C"),
        );
    }

    answer
}

pub(crate) fn own_task() -> u32 {
    unsafe { trap(TASK_SELF, [0; 4]) as u32 }
}

pub fn own_thread() -> u32 {
    unsafe { trap(THREAD_SELF, [0; 4]) as u32 }
}

pub(crate) fn a_port_to_answer_on() -> u32 {
    unsafe { trap(REPLY_PORT, [0; 4]) as u32 }
}

unsafe fn svc(number: i64, args: [u64; 4]) -> (i64, bool) {
    let answer: i64;
    let went_wrong: u64;
    unsafe {
        asm!(
            "svc #0x80",
            "cset x4, cs",
            inlateout("x16") number => _,
            inlateout("x0") args[0] => answer,
            inlateout("x1") args[1] => _,
            inlateout("x2") args[2] => _,
            inlateout("x3") args[3] => _,
            lateout("x4") went_wrong,
            clobber_abi("C"),
        );
    }

    (answer, went_wrong != 0)
}
const KERN_SUCCESS: i64 = 0;
const ANYWHERE: u64 = 1;

const MACH_VM_ALLOCATE: i64 = -10;
const MACH_VM_DEALLOCATE: i64 = -12;
const MACH_VM_PROTECT: i64 = -14;
const TASK_SELF: i64 = -28;
const REPLY_PORT: i64 = -26;
const THREAD_SELF: i64 = -27;
pub(crate) const MACH_MSG: i64 = -31;

const COMPARE_AND_WAIT: u64 = 1;
const WAKE_ALL: u64 = 0x100;

const GET_PID: i64 = 20;
const GET_TIME_OF_DAY: i64 = 116;
const PROC_INFO: i64 = 336;
const ABOUT_A_PROCESS: u64 = 2;
const ABOUT_A_REGION: u64 = 7;
const ULOCK_WAIT: i64 = 515;
const ULOCK_WAKE: i64 = 516;
const SCHED_YIELD: i64 = 331;
const THREAD_SELF_ID: i64 = 372;
