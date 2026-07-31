// The C library's lower edge. Nothing here does real work: the agent has no
// filesystem and never exits, so these exist to satisfy references and to give
// malloc some memory to hand out.
//
// The two flavours link against different C libraries, and they disagree on what
// this layer is called. newlib asks for the underscore-prefixed syscall names;
// picolibc, which the soft-float flavour needs because newlib has no soft-float
// build for arm64, calls them without the prefix. The bodies are shared and the
// exported names live in the two `exports` modules at the end.

use core::ptr;
use core::sync::atomic::Ordering;

use crate::bindings::{GMutex, GRecMutex};
use crate::gthread;

// Serialises the C library. Which hooks the library reaches for differs: newlib asks
// for __malloc_lock/__malloc_unlock, picolibc for the retargetable lock API below,
// whose default implementation is an empty function — so on picolibc malloc runs
// unlocked unless we supply these, and any second thread corrupts the heap.
static mut LIBC_LOCK: GRecMutex = unsafe { core::mem::zeroed() };

fn libc_lock() {
    gthread::g_rec_mutex_lock(ptr::addr_of_mut!(LIBC_LOCK));
}

fn libc_unlock() {
    gthread::g_rec_mutex_unlock(ptr::addr_of_mut!(LIBC_LOCK));
    offer_preemption_point();
}

fn offer_preemption_point() {
    let total = ALLOCATIONS_TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
    if total % ALLOCATIONS_PER_YIELD == 0 {
        crate::kernel::yield_now();
    }
}

static ALLOCATIONS_TOTAL: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
const ALLOCATIONS_PER_YIELD: u32 = 1024;

// GLib's g_get_num_processors() probes this; report a single CPU so the
// parallel scanners fall back to their inline path.
#[unsafe(no_mangle)]
pub extern "C" fn sysconf(_name: i32) -> isize {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn __clear_cache(_start: *const u8, _end: *const u8) {
    unsafe {
        core::arch::asm!(
            "ic iallu",     // Invalidate all instruction caches
            "dsb sy",       // Data synchronization barrier
            "isb",          // Instruction synchronization barrier
            options(nomem, nostack),
        );
    }
}

fn sbrk_impl(incr: isize) -> *mut u8 {
    const HEAP_SIZE: usize = 32 * 1024 * 1024; // 32 MB

    static mut HEAP_START: *mut u8 = ptr::null_mut();
    static mut HEAP_CURRENT: *mut u8 = ptr::null_mut();
    static mut HEAP_MUTEX: GMutex = unsafe { core::mem::zeroed() };

    unsafe {
        gthread::g_mutex_lock(ptr::addr_of_mut!(HEAP_MUTEX));

        if HEAP_START.is_null() {
            HEAP_START = crate::kernel::alloc(HEAP_SIZE);
            if HEAP_START.is_null() {
                gthread::g_mutex_unlock(ptr::addr_of_mut!(HEAP_MUTEX));
                panic!("Failed to allocate 32 MB heap");
            }
            HEAP_CURRENT = HEAP_START;
        }

        let prev_heap_current = HEAP_CURRENT;
        // Signed: the allocator hands memory back by asking for a negative increment.
        let new_heap_current = HEAP_CURRENT.offset(incr);

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

#[repr(C)]
struct Timeval {
    tv_sec: i64,
    tv_usec: i64,
}

fn gettimeofday_impl(tp: *mut core::ffi::c_void) -> i32 {
    let (secs, microsecs) = crate::kernel::wall_clock_micros();
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

fn write_impl(count: usize) -> isize {
    count as isize
}

#[cfg(feature = "xnu")]
mod exports {
    use super::*;

    #[unsafe(no_mangle)]
    pub extern "C" fn __malloc_lock(_reent: *mut core::ffi::c_void) {
        libc_lock();
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn __malloc_unlock(_reent: *mut core::ffi::c_void) {
        libc_unlock();
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn _fini() {}

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
        sbrk_impl(incr)
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn _getpid() -> i32 {
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn _gettimeofday(
        tp: *mut core::ffi::c_void,
        _tzp: *mut core::ffi::c_void,
    ) -> i32 {
        gettimeofday_impl(tp)
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
        write_impl(count)
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
    pub extern "C" fn _stat(_path: *const u8, _st: *mut core::ffi::c_void) -> i32 {
        -1
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
    pub extern "C" fn creat(_path: *const u8, _mode: i32) -> i32 {
        -1
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn access(_path: *const u8, _mode: i32) -> i32 {
        -1
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn chmod(_path: *const u8, _mode: i32) -> i32 {
        -1
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn chdir(_path: *const u8) -> i32 {
        -1
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn rmdir(_path: *const u8) -> i32 {
        -1
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn gethostname(_name: *mut u8, _len: usize) -> i32 {
        -1
    }

    // newlib wires these up for exit(), which we never reach: the agent runs until
    // the kernel goes down or the module is unloaded.
    #[unsafe(no_mangle)]
    pub static __libc_fini: Option<extern "C" fn()> = None;

    #[unsafe(no_mangle)]
    pub static __fini_array_start: [extern "C" fn(); 0] = [];

    #[unsafe(no_mangle)]
    pub static __fini_array_end: [extern "C" fn(); 0] = [];
}

#[cfg(feature = "linux")]
mod exports {
    use super::*;

    // The C library's own allocator sits on a fixed sbrk heap and carries its own
    // locking; inside a kernel module the kernel's allocator is already there, already
    // safe to share between threads, and not capped at a size we picked up front.
    // Every C allocation goes here instead.
    //
    // The sixteen bytes before the returned pointer hold the block the kernel gave us
    // and its total size, so a pointer that was moved forward to satisfy an alignment
    // request frees exactly like one that was not.
    use core::ffi::c_void;

    const HEAP_HEADER_SIZE: usize = 16;

    #[unsafe(no_mangle)]
    pub extern "C" fn malloc(size: usize) -> *mut c_void {
        let total = size + HEAP_HEADER_SIZE;
        let block = crate::kernel::alloc(total);
        if block.is_null() {
            return ptr::null_mut();
        }

        offer_preemption_point();

        unsafe { attach_header(block, total, block.add(HEAP_HEADER_SIZE)) }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn posix_memalign(
        result: *mut *mut c_void,
        alignment: usize,
        size: usize,
    ) -> i32 {
        let total = size + alignment + HEAP_HEADER_SIZE;
        let block = crate::kernel::alloc(total);
        if block.is_null() {
            return 12; // ENOMEM
        }

        unsafe {
            let lowest = block.add(HEAP_HEADER_SIZE) as usize;
            let aligned = (lowest + alignment - 1) & !(alignment - 1);
            *result = attach_header(block, total, aligned as *mut u8);
        }

        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn free(p: *mut c_void) {
        if p.is_null() {
            return;
        }

        unsafe {
            let (block, total) = header_of(p);
            crate::kernel::free(block, total);
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn malloc_usable_size(p: *mut c_void) -> usize {
        unsafe { usable_size(p) }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn calloc(count: usize, size: usize) -> *mut c_void {
        let total = count * size;
        let p = malloc(total);
        if !p.is_null() {
            unsafe { ptr::write_bytes(p as *mut u8, 0, total) };
        }
        p
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn realloc(p: *mut c_void, size: usize) -> *mut c_void {
        if p.is_null() {
            return malloc(size);
        }

        let previous_size = unsafe { usable_size(p) };
        let grown = malloc(size);
        if !grown.is_null() {
            unsafe {
                ptr::copy_nonoverlapping(p as *const u8, grown as *mut u8, previous_size.min(size))
            };
            free(p);
        }
        grown
    }

    unsafe fn attach_header(block: *mut u8, total: usize, p: *mut u8) -> *mut c_void {
        unsafe {
            let header = p.sub(HEAP_HEADER_SIZE) as *mut usize;
            *header = block as usize;
            *header.add(1) = total;
        }
        p as *mut c_void
    }

    unsafe fn header_of(p: *mut c_void) -> (*mut u8, usize) {
        unsafe {
            let header = (p as *mut u8).sub(HEAP_HEADER_SIZE) as *const usize;
            (*header as *mut u8, *header.add(1))
        }
    }

    unsafe fn usable_size(p: *mut c_void) -> usize {
        unsafe {
            let (block, total) = header_of(p);
            total - (p as usize - block as usize)
        }
    }

    // One recursive mutex covers every lock the C library asks for. They are coarse
    // and few, and over-serialising them is safe where getting it wrong is not.
    type Lock = *mut core::ffi::c_void;

    // The lock object itself, which we define so the C library's own no-op lock
    // implementation is never pulled out of its archive. Its contents are never
    // read: the address is just a token, and one mutex covers them all.
    #[allow(non_upper_case_globals)]
    #[unsafe(no_mangle)]
    pub static mut __lock___libc_recursive_mutex: u8 = 0;

    #[unsafe(no_mangle)]
    pub extern "C" fn __retarget_lock_init(_lock: *mut Lock) {}

    #[unsafe(no_mangle)]
    pub extern "C" fn __retarget_lock_init_recursive(_lock: *mut Lock) {}

    #[unsafe(no_mangle)]
    pub extern "C" fn __retarget_lock_close(_lock: Lock) {}

    #[unsafe(no_mangle)]
    pub extern "C" fn __retarget_lock_close_recursive(_lock: Lock) {}

    #[unsafe(no_mangle)]
    pub extern "C" fn __retarget_lock_acquire(_lock: Lock) {
        libc_lock();
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn __retarget_lock_acquire_recursive(_lock: Lock) {
        libc_lock();
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn __retarget_lock_release(_lock: Lock) {
        libc_unlock();
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn __retarget_lock_release_recursive(_lock: Lock) {
        libc_unlock();
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn exit(_status: i32) -> ! {
        loop {}
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn _exit(_status: i32) -> ! {
        loop {}
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn kill(_pid: i32, _sig: i32) -> i32 {
        -1
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn sbrk(incr: isize) -> *mut u8 {
        sbrk_impl(incr)
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn getpid() -> i32 {
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn gettimeofday(
        tp: *mut core::ffi::c_void,
        _tzp: *mut core::ffi::c_void,
    ) -> i32 {
        gettimeofday_impl(tp)
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn isatty(_fd: i32) -> i32 {
        1
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn open(_path: *const u8, _flags: i32, _mode: i32) -> i32 {
        -1
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn close(_fd: i32) -> i32 {
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn read(_fd: i32, _buf: *mut u8, _count: usize) -> isize {
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn write(_fd: i32, _buf: *const u8, count: usize) -> isize {
        write_impl(count)
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn lseek(_fd: i32, _offset: isize, _whence: i32) -> isize {
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn fstat(_fd: i32, _st: *mut core::ffi::c_void) -> i32 {
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn stat(_path: *const u8, _st: *mut core::ffi::c_void) -> i32 {
        -1
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn unlink(_path: *const u8) -> i32 {
        -1
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn rename(_old: *const u8, _new: *const u8) -> i32 {
        -1
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn access(_path: *const u8, _mode: i32) -> i32 {
        -1
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn chmod(_path: *const u8, _mode: i32) -> i32 {
        -1
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn chdir(_path: *const u8) -> i32 {
        -1
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn rmdir(_path: *const u8) -> i32 {
        -1
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn gethostname(_name: *mut u8, _len: usize) -> i32 {
        -1
    }

    #[repr(C)]
    pub struct Timespec {
        tv_sec: i64,
        tv_nsec: i64,
    }

    const CLOCK_MONOTONIC: i32 = 1;

    #[unsafe(no_mangle)]
    pub extern "C" fn clock_gettime(clock_id: i32, tp: *mut Timespec) -> i32 {
        let (secs, nsecs) = if clock_id == CLOCK_MONOTONIC {
            let micros = crate::kernel::monotonic_micros();
            (micros / 1_000_000, (micros % 1_000_000) * 1000)
        } else {
            let (secs, micros) = crate::kernel::wall_clock_micros();
            (secs as i64, (micros as i64) * 1000)
        };

        unsafe {
            (*tp).tv_sec = secs;
            (*tp).tv_nsec = nsecs;
        }

        0
    }

    // picolibc consults this for errno values it does not know itself.
    #[unsafe(no_mangle)]
    pub extern "C" fn _user_strerror(_errnum: i32) -> *const core::ffi::c_char {
        ptr::null()
    }

    // No dynamic loader here. Gum calls dladdr() to describe an address and already
    // falls back to printing it raw when the lookup fails.
    #[unsafe(no_mangle)]
    pub extern "C" fn dladdr(_address: *const core::ffi::c_void, _info: *mut core::ffi::c_void) -> i32 {
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn dlopen(_file: *const u8, _mode: i32) -> *mut core::ffi::c_void {
        ptr::null_mut()
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn dlsym(
        _handle: *mut core::ffi::c_void,
        _name: *const u8,
    ) -> *mut core::ffi::c_void {
        ptr::null_mut()
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn dlclose(_handle: *mut core::ffi::c_void) -> i32 {
        -1
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn dlerror() -> *mut core::ffi::c_char {
        ptr::null_mut()
    }

    // picolibc declares the standard streams and leaves defining them to the
    // application. The agent has no I/O — its logging goes to the kernel's own log —
    // so nothing should ever reach for one of these.
    #[repr(transparent)]
    pub struct Stream(*mut core::ffi::c_void);

    unsafe impl Sync for Stream {}

    #[unsafe(no_mangle)]
    pub static stdin: Stream = Stream(ptr::null_mut());

    #[unsafe(no_mangle)]
    pub static stdout: Stream = Stream(ptr::null_mut());

    #[unsafe(no_mangle)]
    pub static stderr: Stream = Stream(ptr::null_mut());
}
