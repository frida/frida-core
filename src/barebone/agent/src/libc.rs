use core::ptr;
use crate::bindings::GMutex;
use crate::gthread;

#[unsafe(no_mangle)]
pub extern "C" fn _fini() {
}

#[unsafe(no_mangle)]
pub extern "C" fn _exit(_status: i32) -> ! {
    loop {}
}

#[unsafe(no_mangle)]
pub extern "C" fn _kill(_pid: i32, _sig: i32) -> i32 {
    -1
}

#[unsafe(no_mangle)]
pub extern "C" fn _sbrk(incr: isize) -> *mut u8 {
    const HEAP_SIZE: usize = 32 * 1024 * 1024; // 32 MB

    static mut HEAP_START: *mut u8 = ptr::null_mut();
    static mut HEAP_CURRENT: *mut u8 = ptr::null_mut();
    static mut HEAP_MUTEX: GMutex = unsafe { core::mem::zeroed() };

    unsafe {
        gthread::g_mutex_lock(ptr::addr_of_mut!(HEAP_MUTEX));

        if HEAP_START.is_null() {
            HEAP_START = crate::xnu::kalloc(HEAP_SIZE);
            if HEAP_START.is_null() {
                gthread::g_mutex_unlock(ptr::addr_of_mut!(HEAP_MUTEX));
                panic!("Failed to allocate 32 MB heap");
            }
            HEAP_CURRENT = HEAP_START;
        }

        let prev_heap_current = HEAP_CURRENT;
        let new_heap_current = HEAP_CURRENT.add(incr as usize);

        if new_heap_current > HEAP_START.add(HEAP_SIZE) {
            gthread::g_mutex_unlock(ptr::addr_of_mut!(HEAP_MUTEX));
            panic!("Heap exhausted: requested {} bytes, {} bytes remaining",
                   incr,
                   HEAP_START.add(HEAP_SIZE).offset_from(HEAP_CURRENT));
        }

        HEAP_CURRENT = new_heap_current;

        gthread::g_mutex_unlock(ptr::addr_of_mut!(HEAP_MUTEX));
        prev_heap_current
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _getpid() -> i32 {
    0
}

#[repr(C)]
struct Timeval {
    tv_sec: i64,
    tv_usec: i64,
}

#[unsafe(no_mangle)]
pub extern "C" fn _gettimeofday(tp: *mut core::ffi::c_void, _tzp: *mut core::ffi::c_void) -> i32 {
    let (secs, microsecs) = crate::xnu::clock_get_calendar_microtime();
    let timeval = Timeval {
        tv_sec: secs as i64,
        tv_usec: microsecs as i64,
    };
    unsafe {
        ptr::copy_nonoverlapping(
            &timeval as *const Timeval as *const u8,
            tp as *mut u8,
            core::mem::size_of::<Timeval>(),
        );
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn _isatty(_fd: i32) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn _open(_path: *const u8, _flags: i32, _mode: i32) -> i32 {
    -1
}

#[unsafe(no_mangle)]
pub extern "C" fn _close(_fd: i32) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn _read(_fd: i32, _buf: *mut u8, _count: usize) -> isize {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn _write(_fd: i32, _buf: *const u8, count: usize) -> isize {
    count as isize
}

#[unsafe(no_mangle)]
pub extern "C" fn _lseek(_fd: i32, _offset: isize, _whence: i32) -> isize {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn _fstat(_fd: i32, _st: *mut core::ffi::c_void) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn _link(_old: *const u8, _new: *const u8) -> i32 {
    -1
}

#[unsafe(no_mangle)]
pub extern "C" fn _unlink(_path: *const u8) -> i32 {
    -1
}

#[unsafe(no_mangle)]
pub extern "C" fn __clear_cache(_start: *const u8, _end: *const u8) {
    // On AArch64, we need to flush the instruction cache
    // This is a simplified implementation for the kernel environment
    unsafe {
        core::arch::asm!(
            "ic iallu",     // Invalidate all instruction caches
            "dsb sy",       // Data synchronization barrier
            "isb",          // Instruction synchronization barrier
            options(nomem, nostack),
        );
    }
}
