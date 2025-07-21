use core::sync::atomic::{AtomicU64, Ordering};

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

pub fn kernel_thread_start(
    continuation: ContinuationFn,
    thread_parameter: *mut core::ffi::c_void,
) -> isize {
    type KernelThreadStartFn = unsafe extern "C" fn(
        continuation: *const (),
        parameter: *mut core::ffi::c_void,
        new_thread: *mut *mut core::ffi::c_void,
    ) -> isize;

    let mut new_thread: *mut core::ffi::c_void = core::ptr::null_mut();
    return unsafe {
        let func: KernelThreadStartFn = core::mem::transmute(KERNEL_THREAD_START_ADDR as *const ());
        let ptr = crate::pac::ptrauth_sign(continuation as *const u8, 0xd507);
        func(
            core::mem::transmute(ptr),
            thread_parameter,
            &mut new_thread as *mut *mut core::ffi::c_void,
        )
        // TODO: Call thread_deallocate()
    };
}

type ContinuationFn = unsafe extern "C" fn(_parameter: *mut core::ffi::c_void, _wait_result: i32);

pub const THREAD_UNINT: u32 = 0;
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
