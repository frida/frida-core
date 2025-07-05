use core::ptr;
use core::ptr::addr_of_mut;

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
    unsafe extern "C" {
        static mut _heap_start: u8;
    }

    static mut HEAP_END: *mut u8 = ptr::null_mut();

    unsafe {
        if HEAP_END.is_null() {
            HEAP_END = addr_of_mut!(_heap_start);
        }

        let prev_heap_end = HEAP_END;
        HEAP_END = HEAP_END.add(incr as usize);
        prev_heap_end
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _getpid() -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn _gettimeofday(tp: *mut core::ffi::c_void, _tzp: *mut core::ffi::c_void) -> i32 {
    if !tp.is_null() {
        unsafe { ptr::write_bytes(tp, 0, core::mem::size_of::<core::ffi::c_void>()) };
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
