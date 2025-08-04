use core::ffi::c_void;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::kprintln;

static KERNEL_BASE: AtomicU64 = AtomicU64::new(0);

pub fn get_kernel_base() -> u64 {
    KERNEL_BASE.load(Ordering::Relaxed)
}

pub fn set_kernel_base(base: u64) {
    KERNEL_BASE.store(base, Ordering::Relaxed);
}

type ContinuationFn = unsafe extern "C" fn(_parameter: *mut c_void, _wait_result: i32);

unsafe extern "C" {
    static _panic: unsafe extern "C" fn(*const u8);
    static _IOLog: unsafe extern "C" fn(*const u8, ...);
    static _kalloc: unsafe extern "C" fn(usize) -> *mut u8;
    static _kfree: unsafe extern "C" fn(*mut u8, usize) -> *mut u8;
    static _thread_start: unsafe extern "C" fn(*const (), *mut c_void, *mut *mut c_void) -> isize;
    static _assert_wait: unsafe extern "C" fn(*const u8, u32) -> i32;
    static _assert_wait_timeout: unsafe extern "C" fn(*const u8, u32, u32, u32) -> i32;
    static _thread_block: unsafe extern "C" fn(Option<ContinuationFn>) -> i32;
    static _thread_wakeup: unsafe extern "C" fn(*const u8) -> i32;
    static _mach_absolute_time: unsafe extern "C" fn() -> u64;
    static _absolutetime_to_nanoseconds: unsafe extern "C" fn(u64, *mut u64);
    static _clock_get_calendar_microtime: unsafe extern "C" fn(*mut u32, *mut u32);
    static _ml_io_map: unsafe extern "C" fn(u64, u64) -> *mut c_void;
    static _ml_vtophys: unsafe extern "C" fn(u64) -> u64;
    static __ZN9IOService11getPlatformEv: unsafe extern "C" fn() -> *mut c_void;
    static __ZN9IOServiceC2Ev: unsafe extern "C" fn(*mut core::ffi::c_void);
    static __ZN8OSSymbol17withCStringNoCopyEPKc: unsafe extern "C" fn(*const core::ffi::c_char) -> *const OSSymbol;
    static __ZN6OSData9withBytesEPKvj: unsafe extern "C" fn(*const core::ffi::c_void, u32) -> *mut OSData;
}

const IO_SERVICE_VTABLE_LENGTH: isize = 168;

const VT_LOOKUP_IC: isize = IO_SERVICE_VTABLE_LENGTH + 25; // IOPlatformExpert
const VT_REGISTER_INT: isize = IO_SERVICE_VTABLE_LENGTH + 0; // IOInterruptController
const VT_ENABLE_INT: isize = IO_SERVICE_VTABLE_LENGTH + 3; // IOInterruptController

pub fn panic(msg: &str) {
    unsafe {
        _panic(msg.as_ptr())
    };
}

pub fn io_log(msg: &str) {
    unsafe {
        _IOLog(msg.as_ptr());
    }
}

pub fn kalloc(size: usize) -> *mut u8 {
    unsafe {
        _kalloc(size)
    }
}

pub fn free(ptr: *mut u8, size: usize) {
    unsafe {
        _kfree(ptr, size);
    }
}

pub fn kernel_thread_start(continuation: ContinuationFn, thread_parameter: *mut c_void) -> isize {
    let mut new_thread: *mut c_void = core::ptr::null_mut();
    return unsafe {
        let ptr = crate::pac::ptrauth_sign(continuation as *const u8, 0xd507);
        _thread_start(
            core::mem::transmute(ptr),
            thread_parameter,
            &mut new_thread as *mut *mut c_void,
        )
        // TODO: Call thread_deallocate()
    };
}

pub const THREAD_INTERRUPTIBLE: u32 = 1;
pub const THREAD_WAITING: i32 = -1;

pub fn assert_wait(event: *const u8, interruptible: u32) -> i32 {
    unsafe {
        _assert_wait(event, interruptible)
    }
}

pub fn assert_wait_timeout(
    event: *const u8,
    interruptible: u32,
    interval: u32,
    scale_factor: u32,
) -> i32 {
    unsafe {
        _assert_wait_timeout(event, interruptible, interval, scale_factor)
    }
}

pub fn thread_block(continuation: Option<ContinuationFn>) -> i32 {
    unsafe {
        _thread_block(continuation)
    }
}

pub fn thread_wakeup(event: *const u8) -> i32 {
    unsafe {
        _thread_wakeup(event)
    }
}

pub fn mach_absolute_time() -> u64 {
    unsafe {
        _mach_absolute_time()
    }
}

pub fn absolutetime_to_nanoseconds(abstime: u64) -> u64 {
    let mut nanoseconds: u64 = 0;
    unsafe {
        _absolutetime_to_nanoseconds(abstime, &mut nanoseconds);
    }
    nanoseconds
}

pub fn clock_get_calendar_microtime() -> (u32, u32) {
    let mut secs: u32 = 0;
    let mut microsecs: u32 = 0;
    unsafe {
        _clock_get_calendar_microtime(&mut secs, &mut microsecs);
    }
    (secs, microsecs)
}

pub fn ml_io_map(phys_addr: u64, size: u64) -> *mut c_void {
    unsafe {
        kprintln!("ml_io_map(phys_addr={:x}, size={:x})", phys_addr, size);
        let vaddr = _ml_io_map(phys_addr, size);
        kprintln!("	=> vaddr={:x}", vaddr as u64);
        vaddr
    }
}

pub fn ml_vtophys(vaddr: u64) -> u64 {
    unsafe {
        _ml_vtophys(vaddr)
    }
}

pub type IOInterruptHandler =
    extern "C" fn(target: *mut c_void, refcon: *mut c_void, nub: *mut c_void, source: i32);

pub fn install_interrupt_handler(
    irq: u32,
    target: *mut c_void,
    handler: IOInterruptHandler,
    refcon: *mut c_void,
) -> i32 {
    let pe = unsafe {
        __ZN9IOService11getPlatformEv()
    };

    let name = unsafe {
        __ZN8OSSymbol17withCStringNoCopyEPKc(c"IOInterruptController0000001A".as_ptr())
    };

    let lookup: extern "C" fn(*mut IOPlatformExpert, *mut OSSymbol) -> *mut IOInterruptController =
        vf(pe as _, VT_LOOKUP_IC);
    let ic = lookup(pe as *mut IOPlatformExpert, name as *mut OSSymbol);
    if ic.is_null() {
        panic!("Failed to lookup IOInterruptController");
    }

    let nub = kalloc(0x88);
    unsafe {
        core::ptr::write_bytes(nub, 0, 0x88);
        __ZN9IOServiceC2Ev(nub as *mut core::ffi::c_void);
    }

    type IOServiceInitFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> bool;
    let init_fn: IOServiceInitFn = vf(nub as *mut c_void, 21);
    unsafe { init_fn(nub as *mut c_void, core::ptr::null_mut()) };

    let interrupt_sources = kalloc(core::mem::size_of::<IOInterruptSource>()) as *mut IOInterruptSource;

    let source_bytes = irq.to_ne_bytes();
    let vector_data = unsafe {
        __ZN6OSData9withBytesEPKvj(source_bytes.as_ptr() as *const core::ffi::c_void, 4)
    };

    unsafe {
        (*interrupt_sources).interrupt_controller = ic;
        (*interrupt_sources).vector_data = vector_data;
    }

    unsafe {
        let interrupt_sources_ptr = (nub as *mut u8).offset(0x80) as *mut *mut IOInterruptSource;
        *interrupt_sources_ptr = interrupt_sources;
    }

    let reg: extern "C" fn(
        *mut _,
        *mut c_void,
        i32,
        *mut c_void,
        IOInterruptHandler,
        *mut c_void,
    ) -> i32 = vf(ic as _, VT_REGISTER_INT);

    let signed_handler = unsafe {
        let handler_ptr = crate::pac::ptrauth_sign(handler as *const u8, 0xd36);
        core::mem::transmute::<*const u8, IOInterruptHandler>(handler_ptr)
    };

    let kr = reg(
        ic,
        nub as *mut c_void,
        0,
        target,
        signed_handler,
        refcon,
    );
    if kr != 0 {
        return kr;
    }

    let en: extern "C" fn(*mut _, *mut c_void, i32) -> i32 = vf(ic as _, VT_ENABLE_INT);
    en(ic, nub as *mut c_void, 0)
}

#[repr(C)]
struct IOPlatformExpert {
    _p: [u8; 0],
}

#[repr(C)]
struct IOInterruptController {
    _p: [u8; 0],
}

#[repr(C)]
struct OSSymbol {
    _p: [u8; 0],
}

#[repr(C)]
struct OSData {
    _p: [u8; 0],
}

#[repr(C)]
struct IOInterruptSource {
    interrupt_controller: *mut IOInterruptController,
    vector_data: *mut OSData,
}

#[inline(always)]
fn vf<T>(obj: *mut c_void, slot: isize) -> T
where
    T: Copy,
{
    let vtable_ptr = unsafe { *(obj as *const *const usize) };
    let vtable = unsafe { crate::pac::ptrauth_strip_data(vtable_ptr as *const u8) as *const usize };
    let entry = unsafe { *vtable.offset(slot) };
    let entry_ptr = unsafe { crate::pac::ptrauth_strip_data(entry as *const u8) };
    unsafe { core::mem::transmute_copy::<*const u8, T>(&entry_ptr) }
}
