const PANIC_ADDR: usize = 0xfffffff0_097d_b944;
const IOLOG_ADDR: usize = 0xfffffff0_07ff_1b68;
const KALLOC_ADDR: usize = 0xfffffff0_07a3_c278;
const KFREE_ADDR: usize = 0xfffffff0_07a3_c338;
const KERNEL_THREAD_START_ADDR: usize = 0xfffffff0_07a7_4674;

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

type ContinuationFn = unsafe extern "C" fn(_parameter: *mut core::ffi::c_void, _wait_result: i32);
