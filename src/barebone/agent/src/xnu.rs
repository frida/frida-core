use core::ffi::c_void;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::kprintln;

static KERNEL_BASE: AtomicU64 = AtomicU64::new(0xfffffff007004000);

pub fn get_kernel_base() -> u64 {
    KERNEL_BASE.load(Ordering::Relaxed)
}

pub fn set_kernel_base(base: u64) {
    KERNEL_BASE.store(base, Ordering::Relaxed);
}

const PANIC_ADDR: usize = 0xfffffff0_097d_b944;
const IOLOG_ADDR: usize = 0xfffffff0_07ff_1b68;
const KALLOC_ADDR: usize = 0xfffffff0_07a3_c278;
const KFREE_ADDR: usize = 0xfffffff0_07a3_c338;
const KERNEL_THREAD_START_ADDR: usize = 0xfffffff0_07a7_4674;
const ASSERT_WAIT_ADDR: usize = 0xfffffff0_07a5_1294;
const ASSERT_WAIT_TIMEOUT_ADDR: usize = 0xfffffff0_07a5_1430;
const THREAD_BLOCK_ADDR: usize = 0xfffffff0_07a5_5728;
const THREAD_WAKEUP_ADDR: usize = 0xfffffff0_07a5_8ea0;
const MACH_ABSOLUTE_TIME_ADDR: usize = 0xfffffff0_07b6_0cc0;
const ABSOLUTETIME_TO_NANOSECONDS_ADDR: usize = 0xfffffff0_07b6_11e4;
const CLOCK_GET_CALENDAR_MICROTIME_ADDR: usize = 0xfffffff0_07a2_332c;
const ML_IO_MAP_ADDR: usize = 0xfffffff0_07b5_ba04;
const ML_VTOPHYS_ADDR: usize = 0xfffffff0_07b5_c4a0;
const IO_SERVICE_GET_PLATFORM_ADDR: usize = 0xfffffff0_0801_ed48;
const OS_SYMBOL_WITH_CSTRING_NO_COPY_ADDR: usize = 0xfffffff0_07fc_45dc;
const OSDATA_WITH_BYTES_ADDR: usize = 0xfffffff0_07f8_c588;

pub fn panic(msg: &str) {
    type PanicFn = unsafe extern "C" fn(msg: *const u8);
    unsafe {
        let func: PanicFn = core::mem::transmute(PANIC_ADDR);
        func(msg.as_ptr())
    };
}

pub fn io_log(msg: &str) {
    type LogFn = unsafe extern "C" fn(fmt: *const u8, ...);
    unsafe {
        let f: LogFn = core::mem::transmute(IOLOG_ADDR);
        f(msg.as_ptr());
    }
}

pub fn kalloc(size: usize) -> *mut u8 {
    type KallocFn = unsafe extern "C" fn(size: usize) -> *mut u8;
    return unsafe {
        let func: KallocFn = core::mem::transmute(KALLOC_ADDR);
        func(size)
    };
}

pub fn free(ptr: *mut u8, size: usize) {
    type KfreeFn = unsafe extern "C" fn(*mut u8, size: usize) -> *mut u8;
    return unsafe {
        let free: KfreeFn = core::mem::transmute(KFREE_ADDR);
        free(ptr, size);
    };
}

pub fn kernel_thread_start(continuation: ContinuationFn, thread_parameter: *mut c_void) -> isize {
    type KernelThreadStartFn = unsafe extern "C" fn(
        continuation: *const (),
        parameter: *mut c_void,
        new_thread: *mut *mut c_void,
    ) -> isize;

    let mut new_thread: *mut c_void = core::ptr::null_mut();
    return unsafe {
        let func: KernelThreadStartFn = core::mem::transmute(KERNEL_THREAD_START_ADDR as *const ());
        let ptr = crate::pac::ptrauth_sign(continuation as *const u8, 0xd507);
        func(
            core::mem::transmute(ptr),
            thread_parameter,
            &mut new_thread as *mut *mut c_void,
        )
        // TODO: Call thread_deallocate()
    };
}

type ContinuationFn = unsafe extern "C" fn(_parameter: *mut c_void, _wait_result: i32);

pub const THREAD_INTERRUPTIBLE: u32 = 1;
pub const THREAD_WAITING: i32 = -1;

pub fn assert_wait(event: *const u8, interruptible: u32) -> i32 {
    type AssertWaitFn = unsafe extern "C" fn(event: *const u8, interruptible: u32) -> i32;
    unsafe {
        let func: AssertWaitFn = core::mem::transmute(ASSERT_WAIT_ADDR);
        func(event, interruptible)
    }
}

pub fn assert_wait_timeout(
    event: *const u8,
    interruptible: u32,
    interval: u32,
    scale_factor: u32,
) -> i32 {
    type AssertWaitTimeoutFn = unsafe extern "C" fn(
        event: *const u8,
        interruptible: u32,
        interval: u32,
        scale_factor: u32,
    ) -> i32;
    unsafe {
        let func: AssertWaitTimeoutFn = core::mem::transmute(ASSERT_WAIT_TIMEOUT_ADDR);
        func(event, interruptible, interval, scale_factor)
    }
}

pub fn thread_block(continuation: Option<ContinuationFn>) -> i32 {
    type ThreadBlockFn = unsafe extern "C" fn(continuation: Option<ContinuationFn>) -> i32;
    unsafe {
        let func: ThreadBlockFn = core::mem::transmute(THREAD_BLOCK_ADDR);
        func(continuation)
    }
}

pub fn thread_wakeup(event: *const u8) -> i32 {
    type ThreadWakeupFn = unsafe extern "C" fn(event: *const u8) -> i32;
    unsafe {
        let func: ThreadWakeupFn = core::mem::transmute(THREAD_WAKEUP_ADDR);
        func(event)
    }
}

pub fn mach_absolute_time() -> u64 {
    type MachAbsoluteTimeFn = unsafe extern "C" fn() -> u64;
    unsafe {
        let func: MachAbsoluteTimeFn = core::mem::transmute(MACH_ABSOLUTE_TIME_ADDR);
        func()
    }
}

pub fn absolutetime_to_nanoseconds(abstime: u64) -> u64 {
    type AbsoluteTimeToNanoFn = unsafe extern "C" fn(abstime: u64, nanoseconds: *mut u64);
    let mut nanoseconds: u64 = 0;
    unsafe {
        let func: AbsoluteTimeToNanoFn = core::mem::transmute(ABSOLUTETIME_TO_NANOSECONDS_ADDR);
        func(abstime, &mut nanoseconds);
    }
    nanoseconds
}

pub fn clock_get_calendar_microtime() -> (u32, u32) {
    type ClockGetCalendarMicrotimeFn = unsafe extern "C" fn(secs: *mut u32, microsecs: *mut u32);
    let mut secs: u32 = 0;
    let mut microsecs: u32 = 0;
    unsafe {
        let func: ClockGetCalendarMicrotimeFn =
            core::mem::transmute(CLOCK_GET_CALENDAR_MICROTIME_ADDR);
        func(&mut secs, &mut microsecs);
    }
    (secs, microsecs)
}

pub fn ml_io_map(phys_addr: u64, size: u64) -> *mut c_void {
    type MlIoMapFn = unsafe extern "C" fn(phys_addr: u64, size: u64) -> *mut c_void;
    unsafe {
        let func: MlIoMapFn = core::mem::transmute(ML_IO_MAP_ADDR);
        func(phys_addr, size)
    }
}

pub fn ml_vtophys(vaddr: u64) -> u64 {
    type MlVtophysFn = unsafe extern "C" fn(vaddr: u64) -> u64;
    unsafe {
        let func: MlVtophysFn = core::mem::transmute(ML_VTOPHYS_ADDR);
        func(vaddr)
    }
}

pub type IOInterruptHandler =
    extern "C" fn(target: *mut c_void, refcon: *mut c_void, nub: *mut c_void, source: i32);

pub fn install_interrupt_handler(
    source: i32,
    target: *mut c_void,
    handler: IOInterruptHandler,
    refcon: *mut c_void,
) -> i32 {
    let get_platform: GetPlatformFn = unsafe { core::mem::transmute(IO_SERVICE_GET_PLATFORM_ADDR) };
    let ossym_cstr: OSSymWithCStrFn =
        unsafe { core::mem::transmute(OS_SYMBOL_WITH_CSTRING_NO_COPY_ADDR) };

    let nub = kalloc(0x88);
    unsafe {
        core::ptr::write_bytes(nub, 0, 0x88);
    }
    const IOSERVICE_CONSTRUCTOR_ADDR: usize = 0xfffffff00801c318;
    type IOServiceConstructorFn = unsafe extern "C" fn(*mut c_void);
    let ioservice_ctor: IOServiceConstructorFn =
        unsafe { core::mem::transmute(IOSERVICE_CONSTRUCTOR_ADDR) };
    unsafe { ioservice_ctor(nub as *mut c_void) };
    kprintln!("[FRIDA] Created IOService nub at {:#x}", nub as u64);

    let pe = get_platform();
    kprintln!("[FRIDA] IOPlatformExpert={:#x}", pe as u64);

    let name = ossym_cstr(c"IOInterruptController0000001A".as_ptr());
    kprintln!(
        "[FRIDA] Resolved IOInterruptController0000001A to {:?}",
        name
    );

    let lookup: extern "C" fn(*mut IOPlatformExpert, *mut OSSymbol) -> *mut IOInterruptController =
        vf(pe as _, VT_LOOKUP_IC);
    kprintln!("[FRIDA] Before lookup");
    let ic = lookup(pe, name);
    kprintln!("[FRIDA] After lookup");

    kprintln!("[FRIDA] IOInterruptController={:#x}", ic as u64);
    if ic.is_null() {
        panic!("Failed to lookup IOInterruptController");
    }

    let interrupt_sources = kalloc(core::mem::size_of::<IOInterruptSource>()) as *mut IOInterruptSource;

    let osdata_with_bytes: OSDataWithBytesFn = unsafe { core::mem::transmute(OSDATA_WITH_BYTES_ADDR) };
    let source_bytes = (source as u32).to_ne_bytes(); // Convert source to native-endian uint32
    let vector_data = osdata_with_bytes(source_bytes.as_ptr() as *const c_void, 4);

    unsafe {
        (*interrupt_sources).interrupt_controller = ic;
        (*interrupt_sources).vector_data = vector_data;
    }

    unsafe {
        let interrupt_sources_ptr = (nub as *mut u8).offset(0x80) as *mut *mut IOInterruptSource;
        *interrupt_sources_ptr = interrupt_sources;
    }

    kprintln!("[FRIDA] Allocated _interruptSources at {:#x}", interrupt_sources as u64);

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
    kprintln!(
        "[FRIDA] Registering interrupt handler for source {} returned {:#x}",
        source,
        kr
    );
    if kr != 0 {
        return kr;
    }

    let en: extern "C" fn(*mut _, *mut c_void, i32) -> i32 = vf(ic as _, VT_ENABLE_INT);
    let enable_result = en(ic, nub as *mut c_void, 0);
    kprintln!(
        "Enabling interrupt for source {} returned {}",
        source,
        enable_result
    );

    enable_result
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

type GetPlatformFn = extern "C" fn() -> *mut IOPlatformExpert;
type OSSymWithCStrFn = extern "C" fn(*const u8) -> *mut OSSymbol;
type OSDataWithBytesFn = extern "C" fn(*const c_void, u32) -> *mut OSData;

#[inline(always)]
fn vf<T>(obj: *mut c_void, slot: isize) -> T
where
    T: Copy,
{
    let vtable_ptr = unsafe { *(obj as *const *const usize) };
    kprintln!(
        "[FRIDA] VTable for object at {:#x} is at {:#x}",
        obj as u64,
        vtable_ptr as u64
    );
    let vtable = unsafe { crate::pac::ptrauth_strip_data(vtable_ptr as *const u8) as *const usize };
    kprintln!("[FRIDA] VTable stripped pointer is at {:#x}", vtable as u64);
    let entry = unsafe { *vtable.offset(slot) };
    kprintln!(
        "[FRIDA] VTable entry at offset {} is at {:#x}",
        slot,
        entry as u64
    );
    let entry_ptr = unsafe { crate::pac::ptrauth_strip_data(entry as *const u8) };
    kprintln!(
        "[FRIDA] VTable entry stripped pointer is at {:#x}",
        entry_ptr as u64
    );
    unsafe { core::mem::transmute_copy::<*const u8, T>(&entry_ptr) }
}

const IO_SERVICE_VTABLE_LENGTH: isize = 168;

const VT_LOOKUP_IC: isize = IO_SERVICE_VTABLE_LENGTH + 25; // IOPlatformExpert
const VT_REGISTER_INT: isize = IO_SERVICE_VTABLE_LENGTH + 0; // IOInterruptController
const VT_ENABLE_INT: isize = IO_SERVICE_VTABLE_LENGTH + 3; // IOInterruptController
