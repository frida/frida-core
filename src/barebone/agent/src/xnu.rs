const PANIC_ADDR: usize = 0xfffffff0_097d_b944;
const IOLOG_ADDR: usize = 0xfffffff0_07ff_1b68;
const KALLOC_ADDR: usize = 0xfffffff0_07a3_c278;
const KFREE_ADDR: usize = 0xfffffff0_07a3_c338;
const KERNEL_THREAD_START_ADDR: usize = 0xfffffff0_07a7_4674;
const ASSERT_WAIT_TIMEOUT_ADDR: usize = 0xfffffff0_07a8_def0; // TODO: Find actual address
const THREAD_BLOCK_ADDR: usize = 0xfffffff0_07a8_5678; // TODO: Find actual address  
const THREAD_WAKEUP_ADDR: usize = 0xfffffff0_07a8_9abc; // TODO: Find actual address

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
    };
}

/// XNU wait/wakeup constants
pub const THREAD_INTERRUPTIBLE: u32 = 1;
pub const THREAD_UNINT: u32 = 2;
pub const THREAD_ABORTSAFE: u32 = 4;

/// XNU timeout constants
pub const TIMEOUT_WAIT_FOREVER: u32 = 0xFFFFFFFF;

/// XNU wait result constants
pub const THREAD_AWAKENED: i32 = 0;
pub const THREAD_TIMED_OUT: i32 = 1;
pub const THREAD_INTERRUPTED: i32 = 2;
pub const THREAD_RESTART: i32 = 3;

/// Assert that the current thread should wait on the specified event with timeout
/// 
/// This is the unified waiting function that handles both finite and infinite timeouts.
/// For infinite timeouts, pass TIMEOUT_WAIT_FOREVER as the timeout value.
pub fn assert_wait_timeout(event: *const u8, interruptible: u32, timeout_ms: u32) -> i32 {
    type AssertWaitTimeoutFn = unsafe extern "C" fn(event: *const u8, interruptible: u32, timeout_ms: u32) -> i32;
    unsafe {
        let func: AssertWaitTimeoutFn = core::mem::transmute(ASSERT_WAIT_TIMEOUT_ADDR);
        func(event, interruptible, timeout_ms)
    }
}

/// Block the current thread until woken up or timeout
pub fn thread_block(reason: i32) -> i32 {
    type ThreadBlockFn = unsafe extern "C" fn(reason: i32) -> i32;
    unsafe {
        let func: ThreadBlockFn = core::mem::transmute(THREAD_BLOCK_ADDR);
        func(reason)
    }
}

/// Wake up all threads waiting on the specified event
pub fn thread_wakeup(event: *const u8) -> i32 {
    type ThreadWakeupFn = unsafe extern "C" fn(event: *const u8) -> i32;
    unsafe {
        let func: ThreadWakeupFn = core::mem::transmute(THREAD_WAKEUP_ADDR);
        func(event)
    }
}

type ContinuationFn = unsafe extern "C" fn(_parameter: *mut core::ffi::c_void, _wait_result: i32);
