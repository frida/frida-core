mod pac {
    use core::arch::asm;
    pub unsafe fn ptrauth_sign(ptr: *const u8, discriminator: usize) -> *const u8 {
        let signed: usize;
        unsafe {
            asm!(
                ".inst 0xdac10020",       // pacia x0, x1
                in("x0") ptr as usize,
                in("x1") discriminator,
                lateout("x0") signed,
                options(nomem, nostack),
            );
        }
        signed as *const u8
    }
}

//panic
static PANIC_ADDR: usize = 0xfffffff0_097d_b944;
pub fn panic(msg: &str) {
    type PanicFn = unsafe extern "C" fn(msg: *const u8);
    unsafe {
        let func: PanicFn = core::mem::transmute(PANIC_ADDR);
        func(msg.as_ptr())
    };
}

//log
static LOG_ADDR: usize = 0xfffffff0_07a2_b31c;
pub fn log(message: &str) {
    type LogFn = unsafe extern "C" fn(a: *const u8, b: *const u8);
    unsafe {
        let log: LogFn = core::mem::transmute(LOG_ADDR);
        log(message.as_ptr(), message.as_ptr());
    }
}

//IOLog
static IOLOG_ADDR: usize = 0xfffffff0_07ff_1b68;
pub fn IOLog(msg: &str) {
    type LogFn = unsafe extern "C" fn(fmt: *const u8, ...);
    unsafe {
        let f: LogFn = core::mem::transmute(IOLOG_ADDR);
        f(msg.as_ptr());
    }
}

// alloc
static KALLOC_ADDR: usize = 0xfffffff0_07a3_c278;
pub fn kalloc(size: usize) -> *mut u8 {
    type KallocFn = unsafe extern "C" fn(size: usize) -> *mut u8;
    return unsafe {
        let func: KallocFn = core::mem::transmute(KALLOC_ADDR);
        func(size)
    };
}

static KFREE_ADDR: usize = 0xfffffff0_07a3_c338;
pub fn free(ptr: *mut u8, size: usize) {
    type KfreeFn = unsafe extern "C" fn(*mut u8, size: usize) -> *mut u8;
    return unsafe {
        let free: KfreeFn = core::mem::transmute(KFREE_ADDR);
        free(ptr, size);
    };
}

//kernel_thread_start
const KERNEL_THREAD_START_ADDR: usize = 0xfffffff0_07a7_4674;
type PenisFn = unsafe extern "C" fn(_parameter: *mut core::ffi::c_void, _wait_result: i32);
pub fn kernel_thread_start(continuation: PenisFn) -> isize {
    type KernelThreadStartFn = unsafe extern "C" fn(
        continuation: *const (),
        parameter: *mut core::ffi::c_void,
        new_thread: *mut *mut core::ffi::c_void,
    ) -> isize;

    let mut new_thread: *mut core::ffi::c_void = core::ptr::null_mut();
    let thread_parameter = 12345usize as *mut core::ffi::c_void;
    return unsafe {
        let func: KernelThreadStartFn = core::mem::transmute(KERNEL_THREAD_START_ADDR as *const ());
        let ptr = pac::ptrauth_sign(continuation as *const u8, 0xd507);
        func(
            core::mem::transmute(ptr),
            thread_parameter,
            &mut new_thread as *mut *mut core::ffi::c_void,
        )
    };
}
