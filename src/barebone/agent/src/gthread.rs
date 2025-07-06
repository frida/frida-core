use crate::bindings::GCond;
use crate::bindings::GMutex;
use crate::bindings::GPrivate;
use crate::bindings::GRWLock;
use crate::bindings::GRecMutex;
use crate::bindings::GSystemThread;
use crate::bindings::GThreadFunc;
use crate::bindings::{gpointer, gulong};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use core::arch::asm;
use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// Our implementation structures that overlay the opaque GLib structures

#[repr(C, align(8))]
struct MutexImpl {
    lock: AtomicU32,
    _padding: [u8; core::mem::size_of::<GMutex>() - core::mem::size_of::<AtomicU32>()],
}

#[repr(C, align(8))]
struct RecMutexImpl {
    owner: AtomicU64,     // Thread ID of the owner (uses the 'p' field)
    count: AtomicU32,     // Recursion count (uses i[0])
    _unused: u32,         // Unused (uses i[1])
}

#[repr(C, align(8))]
struct RWLockImpl {
    state: AtomicU32,     // Lock state (readers count + writer bit)
    _padding: [u8; core::mem::size_of::<GRWLock>() - core::mem::size_of::<AtomicU32>()],
}

#[repr(C, align(8))]
struct CondImpl {
    signal: AtomicU32,    // Signal state
    _padding: [u8; core::mem::size_of::<GCond>() - core::mem::size_of::<AtomicU32>()],
}

const _: () = assert!(core::mem::size_of::<MutexImpl>() == core::mem::size_of::<GMutex>());
const _: () = assert!(core::mem::align_of::<MutexImpl>() == core::mem::align_of::<GMutex>());
const _: () = assert!(core::mem::size_of::<RecMutexImpl>() == core::mem::size_of::<GRecMutex>());
const _: () = assert!(core::mem::align_of::<RecMutexImpl>() == core::mem::align_of::<GRecMutex>());
const _: () = assert!(core::mem::size_of::<RWLockImpl>() == core::mem::size_of::<GRWLock>());
const _: () = assert!(core::mem::align_of::<RWLockImpl>() == core::mem::align_of::<GRWLock>());
const _: () = assert!(core::mem::size_of::<CondImpl>() == core::mem::size_of::<GCond>());
const _: () = assert!(core::mem::align_of::<CondImpl>() == core::mem::align_of::<GCond>());

// System thread implementation
#[repr(C)]
struct SystemThreadImpl {
    mutex: GMutex,            // Protects the thread state
    cond: GCond,              // Signals thread completion
    thread_id: AtomicU64,     // XNU thread ID
    func: GThreadFunc,        // Thread function
    data: gpointer,           // User data
    finished: AtomicU32,      // Whether thread has finished (0 = running, 1 = finished)
    detached: AtomicU32,      // Whether thread is detached (1) or joinable (0)
}

// Thread wrapper data passed to XNU kernel thread
#[repr(C)]
struct ThreadWrapperData {
    func: GThreadFunc,
    data: gpointer,
    system_thread: *mut SystemThreadImpl,
}

unsafe fn mutex_impl<'a>(mutex: *mut GMutex) -> &'a mut MutexImpl {
    unsafe { &mut *(mutex as *mut MutexImpl) }
}

unsafe fn rec_mutex_impl<'a>(rec_mutex: *mut GRecMutex) -> &'a mut RecMutexImpl {
    unsafe { &mut *(rec_mutex as *mut RecMutexImpl) }
}

unsafe fn rw_lock_impl<'a>(rw_lock: *mut GRWLock) -> &'a mut RWLockImpl {
    unsafe { &mut *(rw_lock as *mut RWLockImpl) }
}

unsafe fn cond_impl<'a>(cond: *mut GCond) -> &'a mut CondImpl {
    unsafe { &mut *(cond as *mut CondImpl) }
}

// TODO: Clean up Thread-Local Storage (TLS) entries when threads exit
static mut TLS_STORAGE: Option<Box<BTreeMap<(u64, *mut GPrivate), *mut c_void>>> = None;
static TLS_LOCK: AtomicU32 = AtomicU32::new(0);

#[unsafe(no_mangle)]
pub extern "C" fn g_mutex_init(mutex: *mut GMutex) {
    unsafe {
        let impl_ = mutex_impl(mutex);
        impl_.lock.store(0, Ordering::Relaxed);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_mutex_clear(_mutex: *mut GMutex) {}

#[unsafe(no_mangle)]
pub extern "C" fn g_mutex_lock(mutex: *mut GMutex) {
    unsafe {
        let impl_ = mutex_impl(mutex);
        lock_acquire(&impl_.lock);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_mutex_unlock(mutex: *mut GMutex) {
    unsafe {
        let impl_ = mutex_impl(mutex);
        lock_release(&impl_.lock);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_mutex_trylock(mutex: *mut GMutex) -> u32 {
    unsafe {
        let impl_ = mutex_impl(mutex);
        if lock_try_acquire(&impl_.lock) {
            1
        } else {
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_rec_mutex_init(rec_mutex: *mut GRecMutex) {
    unsafe {
        let impl_ = rec_mutex_impl(rec_mutex);
        impl_.owner.store(0, Ordering::Relaxed);
        impl_.count.store(0, Ordering::Relaxed);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_rec_mutex_clear(_rec_mutex: *mut GRecMutex) {
}

#[unsafe(no_mangle)]
pub extern "C" fn g_rec_mutex_lock(rec_mutex: *mut GRecMutex) {
    unsafe {
        let impl_ = rec_mutex_impl(rec_mutex);
        let current_thread = get_current_thread_id();

        loop {
            if rec_mutex_try_acquire(impl_, current_thread) {
                break;
            }
            rec_mutex_wait(impl_);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_rec_mutex_trylock(rec_mutex: *mut GRecMutex) -> u32 {
    unsafe {
        let impl_ = rec_mutex_impl(rec_mutex);
        let current_thread = get_current_thread_id();

        if rec_mutex_try_acquire(impl_, current_thread) {
            1
        } else {
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_rec_mutex_unlock(rec_mutex: *mut GRecMutex) {
    unsafe {
        let impl_ = rec_mutex_impl(rec_mutex);

        loop {
            let current_count = impl_.count.load(Ordering::Relaxed);

            if current_count == 1 {
                if impl_.count
                    .compare_exchange_weak(1, 0, Ordering::Release, Ordering::Relaxed)
                    .is_ok()
                {
                    impl_.owner.store(0, Ordering::Relaxed);
                    lock_notify_all();
                    break;
                }
            } else {
                if impl_.count
                    .compare_exchange_weak(current_count, current_count - 1, Ordering::Release, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            }
        }
    }
}

unsafe fn rec_mutex_try_acquire(impl_: &mut RecMutexImpl, current_thread: u64) -> bool {
    let current_count = impl_.count.load(Ordering::Relaxed);

    if current_count == 0 {
        if impl_.count
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            impl_.owner.store(current_thread, Ordering::Relaxed);
            return true;
        }
    } else {
        let current_owner = impl_.owner.load(Ordering::Relaxed);
        if current_owner == current_thread {
            if impl_.count
                .compare_exchange_weak(
                    current_count,
                    current_count + 1,
                    Ordering::Acquire,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return true;
            }
        }
    }
    false
}

unsafe fn rec_mutex_wait(impl_: &mut RecMutexImpl) {
    while impl_.count.load(Ordering::Relaxed) != 0 {
        unsafe { lock_wait_primitive() };
    }
}

// Read-Write Lock implementation
// We use a simple scheme where the atomic value represents:
// - 0: unlocked
// - 1-0x7FFFFFFF: number of readers holding the lock
// - 0x80000000: writer lock held
const RW_WRITER_LOCK_BIT: u32 = 0x80000000;

#[unsafe(no_mangle)]
pub extern "C" fn g_rw_lock_init(rw_lock: *mut GRWLock) {
    unsafe {
        let impl_ = rw_lock_impl(rw_lock);
        impl_.state.store(0, Ordering::Relaxed);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_rw_lock_clear(_rw_lock: *mut GRWLock) {}

#[unsafe(no_mangle)]
pub extern "C" fn g_rw_lock_writer_lock(rw_lock: *mut GRWLock) {
    unsafe {
        let impl_ = rw_lock_impl(rw_lock);
        loop {
            if rw_lock_writer_try_acquire(impl_) {
                break;
            }
            rw_lock_wait_for_all(impl_);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_rw_lock_writer_trylock(rw_lock: *mut GRWLock) -> u32 {
    unsafe {
        let impl_ = rw_lock_impl(rw_lock);
        if rw_lock_writer_try_acquire(impl_) {
            1
        } else {
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_rw_lock_writer_unlock(rw_lock: *mut GRWLock) {
    unsafe {
        let impl_ = rw_lock_impl(rw_lock);
        impl_.state.store(0, Ordering::Release);
        lock_notify_all();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_rw_lock_reader_lock(rw_lock: *mut GRWLock) {
    unsafe {
        let impl_ = rw_lock_impl(rw_lock);
        loop {
            let current = impl_.state.load(Ordering::Relaxed);
            if current & RW_WRITER_LOCK_BIT != 0 {
                rw_lock_wait_for_writers(impl_);
                continue;
            }
            if impl_.state
                .compare_exchange_weak(current, current + 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_rw_lock_reader_trylock(rw_lock: *mut GRWLock) -> u32 {
    unsafe {
        let impl_ = rw_lock_impl(rw_lock);
        if rw_lock_reader_try_acquire(impl_) {
            1
        } else {
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_rw_lock_reader_unlock(rw_lock: *mut GRWLock) {
    unsafe {
        let impl_ = rw_lock_impl(rw_lock);
        loop {
            let current = impl_.state.load(Ordering::Relaxed);
            if impl_.state
                .compare_exchange_weak(current, current - 1, Ordering::Release, Ordering::Relaxed)
                .is_ok()
            {
                if current - 1 == 0 {
                    lock_notify_all();
                }
                break;
            }
        }
    }
}

unsafe fn rw_lock_writer_try_acquire(impl_: &mut RWLockImpl) -> bool {
    impl_.state
        .compare_exchange_weak(0, RW_WRITER_LOCK_BIT, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
}

unsafe fn rw_lock_reader_try_acquire(impl_: &mut RWLockImpl) -> bool {
    let current = impl_.state.load(Ordering::Relaxed);
    if current & RW_WRITER_LOCK_BIT != 0 {
        return false;
    }
    impl_.state
        .compare_exchange_weak(current, current + 1, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
}

unsafe fn rw_lock_wait_for_writers(impl_: &mut RWLockImpl) {
    while impl_.state.load(Ordering::Relaxed) & RW_WRITER_LOCK_BIT != 0 {
        unsafe { lock_wait_primitive() };
    }
}

unsafe fn rw_lock_wait_for_all(impl_: &mut RWLockImpl) {
    while impl_.state.load(Ordering::Relaxed) != 0 {
        unsafe { lock_wait_primitive() };
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_cond_init(cond: *mut GCond) {
    unsafe {
        let impl_ = cond_impl(cond);
        impl_.signal.store(0, Ordering::Relaxed);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_cond_clear(_cond: *mut GCond) {}

#[unsafe(no_mangle)]
pub extern "C" fn g_cond_wait(cond: *mut GCond, mutex: *mut GMutex) {
    unsafe {
        g_mutex_unlock(mutex);

        let impl_ = cond_impl(cond);
        while impl_.signal.load(Ordering::Acquire) == 0 {
            lock_wait_primitive();
        }

        g_mutex_lock(mutex);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_cond_signal(cond: *mut GCond) {
    unsafe {
        let impl_ = cond_impl(cond);
        impl_.signal.store(1, Ordering::Release);
        lock_notify_all();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_cond_broadcast(cond: *mut GCond) {
    unsafe {
        let impl_ = cond_impl(cond);
        impl_.signal.store(1, Ordering::Release);
        lock_notify_all();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_cond_wait_until(cond: *mut GCond, mutex: *mut GMutex, _end_time: i64) -> u32 {
    // TODO: Implement proper timeout handling
    g_cond_wait(cond, mutex);
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn g_private_get(key: *mut GPrivate) -> *mut c_void {
    unsafe {
        let thread_id = get_current_thread_id();
        lock_acquire(&TLS_LOCK);

        ensure_tls_storage();
        let storage_ptr = core::ptr::addr_of_mut!(TLS_STORAGE);
        let storage = (*storage_ptr).as_ref().unwrap();

        let value = storage
            .get(&(thread_id, key))
            .copied()
            .unwrap_or(core::ptr::null_mut());

        lock_release(&TLS_LOCK);
        value
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_private_set(key: *mut GPrivate, value: *mut c_void) {
    unsafe {
        let thread_id = get_current_thread_id();
        lock_acquire(&TLS_LOCK);

        ensure_tls_storage();
        let storage_ptr = core::ptr::addr_of_mut!(TLS_STORAGE);
        let storage = (*storage_ptr).as_mut().unwrap();

        storage.insert((thread_id, key), value);

        lock_release(&TLS_LOCK);
    }
}

unsafe fn ensure_tls_storage() {
    let storage_ptr = core::ptr::addr_of_mut!(TLS_STORAGE);
    unsafe {
        if (*storage_ptr).is_none() {
            *storage_ptr = Some(Box::new(BTreeMap::new()));
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _g_system_thread_create(
    _stack_size: gulong,
    _name: *const core::ffi::c_char,
    func: GThreadFunc,
    data: gpointer,
) -> *mut GSystemThread {
    unsafe {
        let system_thread = crate::xnu::kalloc(core::mem::size_of::<SystemThreadImpl>()) as *mut SystemThreadImpl;

        g_mutex_init(&mut (*system_thread).mutex);
        g_cond_init(&mut (*system_thread).cond);
        (*system_thread).thread_id.store(0, Ordering::Relaxed);
        (*system_thread).func = func;
        (*system_thread).data = data;
        (*system_thread).finished.store(0, Ordering::Relaxed);
        (*system_thread).detached.store(0, Ordering::Relaxed);

        let wrapper_data = crate::xnu::kalloc(core::mem::size_of::<ThreadWrapperData>()) as *mut ThreadWrapperData;
        (*wrapper_data).func = func;
        (*wrapper_data).data = data;
        (*wrapper_data).system_thread = system_thread;

        let _xnu_result = crate::xnu::kernel_thread_start(thread_wrapper, wrapper_data as *mut c_void);

        system_thread as *mut GSystemThread
    }
}

extern "C" fn thread_wrapper(parameter: *mut c_void, _wait_result: i32) {
    unsafe {
        let wrapper_data = parameter as *mut ThreadWrapperData;
        let func = (*wrapper_data).func;
        let data = (*wrapper_data).data;
        let system_thread = (*wrapper_data).system_thread;

        let current_thread_id = get_current_thread_id();
        (*system_thread).thread_id.store(current_thread_id, Ordering::Relaxed);

        func.unwrap()(data);

        g_mutex_lock(&mut (*system_thread).mutex);
        (*system_thread).finished.store(1, Ordering::Relaxed);
        g_cond_signal(&mut (*system_thread).cond);

        let detached = (*system_thread).detached.load(Ordering::Relaxed);
        g_mutex_unlock(&mut (*system_thread).mutex);

        if detached != 0 {
            cleanup_system_thread(system_thread);
        }

        cleanup_wrapper_data(wrapper_data);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _g_system_thread_detach(thread: *mut GSystemThread) {
    unsafe {
        let system_thread = thread as *mut SystemThreadImpl;

        g_mutex_lock(&mut (*system_thread).mutex);
        (*system_thread).detached.store(1, Ordering::Relaxed);

        let finished = (*system_thread).finished.load(Ordering::Relaxed);
        g_mutex_unlock(&mut (*system_thread).mutex);
        if finished != 0 {
            cleanup_system_thread(system_thread);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _g_system_thread_wait(thread: *mut GSystemThread) {
    unsafe {
        let system_thread = thread as *mut SystemThreadImpl;

        loop {
            let thread_id = (*system_thread).thread_id.load(Ordering::Acquire);
            if thread_id != 0 {
                break;
            }
            core::hint::spin_loop();
        }

        g_mutex_lock(&mut (*system_thread).mutex);
        while (*system_thread).finished.load(Ordering::Relaxed) == 0 {
            g_cond_wait(&mut (*system_thread).cond, &mut (*system_thread).mutex);
        }
        g_mutex_unlock(&mut (*system_thread).mutex);

        cleanup_system_thread(system_thread);
    }
}

unsafe fn cleanup_system_thread(system_thread: *mut SystemThreadImpl) {
    crate::xnu::free(system_thread as *mut u8, core::mem::size_of::<SystemThreadImpl>());
}

unsafe fn cleanup_wrapper_data(wrapper_data: *mut ThreadWrapperData) {
    crate::xnu::free(wrapper_data as *mut u8, core::mem::size_of::<ThreadWrapperData>());
}

unsafe fn lock_acquire(lock: &AtomicU32) {
    loop {
        if unsafe { lock_try_acquire(lock) } {
            break;
        }
        unsafe { lock_wait(lock) };
    }
}

unsafe fn lock_try_acquire(lock: &AtomicU32) -> bool {
    lock.compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
}

unsafe fn lock_release(lock: &AtomicU32) {
    lock.store(0, Ordering::Release);
    unsafe { lock_notify_all() };
}

unsafe fn lock_wait(lock: &AtomicU32) {
    while lock.load(Ordering::Relaxed) != 0 {
        unsafe { lock_wait_primitive() };
    }
}

unsafe fn lock_wait_primitive() {
    unsafe {
        asm!("wfe", options(nomem, nostack));
    }
}

unsafe fn lock_notify_all() {
    unsafe {
        asm!("sev", options(nomem, nostack));
    }
}

unsafe fn get_current_thread_id() -> u64 {
    let thread_ptr: u64;
    unsafe {
        asm!("mrs {}, tpidr_el1", out(reg) thread_ptr, options(nomem, nostack));
    }
    thread_ptr
}
