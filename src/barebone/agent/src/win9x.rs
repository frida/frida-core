// The VMM side of the blob flavor. Reached the way XNU is: the host fills in a
// slot per service before calling _start, so nothing here is a link-time import.
//
// The signatures follow the VxD service documentation; none of them has been
// exercised against a running kernel yet.

use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::kernel::ThreadEntry;

const PAGE_SIZE: u32 = 4096;

// Fixed and locked down, which is what code the agent writes has to be: the
// system arena is visible in every context, and nothing may page it out.
const PAGE_FLAGS_CODE: u32 = PAGE_FIXED | PAGE_LOCKED | PAGE_ZERO_INIT;
const PAGE_FIXED: u32 = 0x8;
const PAGE_LOCKED: u32 = 0x80;
const PAGE_ZERO_INIT: u32 = 0x1;

// The processors this runs on have no execute permission to grant, so only
// writability is ever in question.
const PAGE_PRESENT: u32 = 0x1;
const PAGE_WRITEABLE: u32 = 0x2;
const GUM_PAGE_WRITE: u32 = 0x2;

pub fn log(msg: &str) {
    unsafe {
        _Debug_Printf_Service(msg.as_ptr());
    }
}

pub fn panic(msg: &str) {
    unsafe {
        _Fatal_Error_Handler(msg.as_ptr(), 0);
    }
}

pub fn alloc(size: usize) -> *mut u8 {
    unsafe { _HeapAllocate(size as u32, 0) }
}

pub fn free(ptr: *mut u8, _size: usize) {
    unsafe {
        _HeapFree(ptr, 0);
    }
}

pub fn alloc_code(size: usize) -> *mut u8 {
    let pages = size.div_ceil(PAGE_SIZE as usize) as u32;
    unsafe { _PageAllocate(pages, PAGE_FLAGS_CODE, 0, 0, 0, 0, core::ptr::null_mut()) }
}

pub fn free_code(ptr: *mut u8, _size: usize) {
    unsafe {
        _PageFree(ptr, 0);
    }
}

pub fn spawn_thread(entry: ThreadEntry, parameter: *mut c_void) -> isize {
    unsafe { _Create_Thread(entry, parameter, 0) }
}

pub fn wait(token: *const u8, timeout_us: Option<u64>, check: &mut dyn FnMut() -> bool) {
    let semaphore = semaphore_for(token);
    if check() {
        return;
    }

    let timeout_ms = match timeout_us {
        None => 0,
        Some(us) => (us / 1000).max(1) as u32,
    };
    unsafe {
        _Wait_Semaphore(semaphore, timeout_ms);
    }
}

pub fn wake(token: *const u8) {
    unsafe {
        _Signal_Semaphore(semaphore_for(token));
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

pub fn wall_clock_micros() -> (u32, u32) {
    let micros = monotonic_micros() as u64;
    ((micros / 1_000_000) as u32, (micros % 1_000_000) as u32)
}

pub fn current_thread_id() -> u64 {
    unsafe { _Get_Cur_Thread_Handle() as u64 }
}

pub fn protect(address: u64, size: usize, gum_prot: u32) -> bool {
    let first_page = address / PAGE_SIZE as u64;
    let pages = size.div_ceil(PAGE_SIZE as usize) as u32;

    let mut set = PAGE_PRESENT;
    if (gum_prot & GUM_PAGE_WRITE) != 0 {
        set |= PAGE_WRITEABLE;
    }
    let clear = PAGE_WRITEABLE & !set;

    unsafe { _PageModifyPermissions(first_page as u32, pages, !clear, set) != 0xffff_ffff }
}

pub fn map_io(phys_addr: u64, size: u64) -> *mut c_void {
    let pages = (size as usize).div_ceil(PAGE_SIZE as usize) as u32;
    unsafe { _MapPhysToLinear(phys_addr as u32, pages * PAGE_SIZE, 0) as *mut c_void }
}

pub fn virt_to_phys(vaddr: u64) -> u64 {
    unsafe { _CopyPageTable(vaddr as u32 / PAGE_SIZE, 1) as u64 & !((PAGE_SIZE - 1) as u64) }
}

pub fn install_interrupt_handler(
    irq: u32,
    target: *mut c_void,
    handler: InterruptHandler,
    refcon: *mut c_void,
) -> i32 {
    unsafe {
        _VPICD_Virtualize_IRQ(irq, handler, target, refcon);
    }
    0
}

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

    let created = unsafe { _Create_Semaphore(0) };
    match SEMAPHORES[slot].compare_exchange(0, created, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => created,
        Err(raced) => raced,
    }
}

const NUM_SEMAPHORES: usize = 64;
static SEMAPHORES: [AtomicU32; NUM_SEMAPHORES] = [const { AtomicU32::new(0) }; NUM_SEMAPHORES];

unsafe extern "C" {
    static _Fatal_Error_Handler: unsafe extern "C" fn(*const u8, u32);
    static _Debug_Printf_Service: unsafe extern "C" fn(*const u8, ...);
    static _HeapAllocate: unsafe extern "C" fn(u32, u32) -> *mut u8;
    static _HeapFree: unsafe extern "C" fn(*mut u8, u32);
    static _PageAllocate:
        unsafe extern "C" fn(u32, u32, u32, u32, u32, u32, *mut c_void) -> *mut u8;
    static _PageFree: unsafe extern "C" fn(*mut u8, u32);
    static _Create_Thread: unsafe extern "C" fn(ThreadEntry, *mut c_void, u32) -> isize;
    static _Get_System_Time: unsafe extern "C" fn() -> u32;
    static _Get_Cur_Thread_Handle: unsafe extern "C" fn() -> u32;
    static _Create_Semaphore: unsafe extern "C" fn(u32) -> u32;
    static _Wait_Semaphore: unsafe extern "C" fn(u32, u32);
    static _Signal_Semaphore: unsafe extern "C" fn(u32);
    static _Release_Time_Slice: unsafe extern "C" fn();
    static _PageModifyPermissions: unsafe extern "C" fn(u32, u32, u32, u32) -> u32;
    static _MapPhysToLinear: unsafe extern "C" fn(u32, u32, u32) -> u32;
    static _CopyPageTable: unsafe extern "C" fn(u32, u32) -> u32;
    static _VPICD_Virtualize_IRQ:
        unsafe extern "C" fn(u32, InterruptHandler, *mut c_void, *mut c_void);
}
