use crate::bindings::GCond;
use crate::bindings::GMutex;
use crate::bindings::GPrivate;
use crate::bindings::GRWLock;
use crate::bindings::GRecMutex;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use core::arch::asm;
use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// TODO: Clean up Thread-Local Storage (TLS) entries when threads exit
static mut TLS_STORAGE: Option<Box<BTreeMap<(u64, *mut GPrivate), *mut c_void>>> = None;
static TLS_LOCK: AtomicU32 = AtomicU32::new(0);

#[unsafe(no_mangle)]
pub extern "C" fn g_mutex_init(mutex: *mut GMutex) {
    unsafe {
        let lock = &mut *(mutex as *mut AtomicU32);
        lock.store(0, Ordering::Relaxed);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_mutex_clear(_mutex: *mut GMutex) {}

#[unsafe(no_mangle)]
pub extern "C" fn g_mutex_lock(_mutex: *mut GMutex) {
    unsafe {
        let lock = &*(_mutex as *const AtomicU32);
        lock_acquire(lock);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_mutex_unlock(_mutex: *mut GMutex) {
    unsafe {
        let lock = &*(_mutex as *const AtomicU32);
        lock_release(lock);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_mutex_trylock(mutex: *mut GMutex) -> u32 {
    unsafe {
        let lock = &*(mutex as *const AtomicU32);
        match lock.compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => 1,
            Err(_) => 0,
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_rec_mutex_init(rec_mutex: *mut GRecMutex) {
    unsafe {
        let rec_mutex_ref = &mut *rec_mutex;
        let owner = &mut *(rec_mutex_ref.p as *mut AtomicU64);
        let count = &mut *(rec_mutex_ref.i.as_mut_ptr() as *mut AtomicU32);
        owner.store(0, Ordering::Relaxed);
        count.store(0, Ordering::Relaxed);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_rec_mutex_clear(_rec_mutex: *mut GRecMutex) {
}

#[unsafe(no_mangle)]
pub extern "C" fn g_rec_mutex_lock(rec_mutex: *mut GRecMutex) {
    unsafe {
        let rec_mutex_ref = &*rec_mutex;
        let owner = &*(rec_mutex_ref.p as *const AtomicU64);
        let count = &*(rec_mutex_ref.i.as_ptr() as *const AtomicU32);
        let current_thread = get_current_thread_id();

        loop {
            let current_count = count.load(Ordering::Relaxed);

            if current_count == 0 {
                if count
                    .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    owner.store(current_thread, Ordering::Relaxed);
                    break;
                }
            } else {
                let current_owner = owner.load(Ordering::Relaxed);
                if current_owner == current_thread {
                    if count
                        .compare_exchange_weak(
                            current_count,
                            current_count + 1,
                            Ordering::Acquire,
                            Ordering::Relaxed,
                        )
                        .is_ok()
                    {
                        break;
                    }
                } else {
                    while count.load(Ordering::Relaxed) != 0 {
                        asm!("wfe", options(nomem, nostack));
                    }
                }
            }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_rec_mutex_trylock(rec_mutex: *mut GRecMutex) -> u32 {
    unsafe {
        let rec_mutex_ref = &*rec_mutex;
        let owner = &*(rec_mutex_ref.p as *const AtomicU64);
        let count = &*(rec_mutex_ref.i.as_ptr() as *const AtomicU32);
        let current_thread = get_current_thread_id();

        let current_count = count.load(Ordering::Relaxed);

        if current_count == 0 {
            if count
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                owner.store(current_thread, Ordering::Relaxed);
                return 1;
            }
        } else {
            let current_owner = owner.load(Ordering::Relaxed);
            if current_owner == current_thread {
                if count
                    .compare_exchange_weak(
                        current_count,
                        current_count + 1,
                        Ordering::Acquire,
                        Ordering::Relaxed,
                    )
                    .is_ok()
                {
                    return 1;
                }
            }
        }
        0
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_rec_mutex_unlock(rec_mutex: *mut GRecMutex) {
    unsafe {
        let rec_mutex_ref = &*rec_mutex;
        let owner = &*(rec_mutex_ref.p as *const AtomicU64);
        let count = &*(rec_mutex_ref.i.as_ptr() as *const AtomicU32);

        loop {
            let current_count = count.load(Ordering::Relaxed);

            if current_count == 0 {
                break;
            }

            if current_count == 1 {
                if count
                    .compare_exchange_weak(1, 0, Ordering::Release, Ordering::Relaxed)
                    .is_ok()
                {
                    owner.store(0, Ordering::Relaxed);
                    asm!("sev", options(nomem, nostack));
                    break;
                }
            } else {
                if count
                    .compare_exchange_weak(current_count, current_count - 1, Ordering::Release, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            }
        }
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
        let lock = &mut *(rw_lock as *mut AtomicU32);
        lock.store(0, Ordering::Relaxed);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_rw_lock_clear(_rw_lock: *mut GRWLock) {}

#[unsafe(no_mangle)]
pub extern "C" fn g_rw_lock_writer_lock(rw_lock: *mut GRWLock) {
    unsafe {
        let lock = &*(rw_lock as *const AtomicU32);
        loop {
            if lock
                .compare_exchange_weak(0, RW_WRITER_LOCK_BIT, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
            while lock.load(Ordering::Relaxed) != 0 {
                asm!("wfe", options(nomem, nostack));
            }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_rw_lock_writer_trylock(rw_lock: *mut GRWLock) -> u32 {
    unsafe {
        let lock = &*(rw_lock as *const AtomicU32);
        match lock.compare_exchange_weak(
            0,
            RW_WRITER_LOCK_BIT,
            Ordering::Acquire,
            Ordering::Relaxed,
        ) {
            Ok(_) => 1,
            Err(_) => 0,
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_rw_lock_writer_unlock(rw_lock: *mut GRWLock) {
    unsafe {
        let lock = &*(rw_lock as *const AtomicU32);
        lock.store(0, Ordering::Release);
        asm!("sev", options(nomem, nostack));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_rw_lock_reader_lock(rw_lock: *mut GRWLock) {
    unsafe {
        let lock = &*(rw_lock as *const AtomicU32);
        loop {
            let current = lock.load(Ordering::Relaxed);
            if current & RW_WRITER_LOCK_BIT != 0 {
                while lock.load(Ordering::Relaxed) & RW_WRITER_LOCK_BIT != 0 {
                    asm!("wfe", options(nomem, nostack));
                }
                continue;
            }
            if lock
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
        let lock = &*(rw_lock as *const AtomicU32);
        let current = lock.load(Ordering::Relaxed);
        if current & RW_WRITER_LOCK_BIT != 0 {
            return 0;
        }
        match lock.compare_exchange_weak(current, current + 1, Ordering::Acquire, Ordering::Relaxed)
        {
            Ok(_) => 1,
            Err(_) => 0,
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_rw_lock_reader_unlock(rw_lock: *mut GRWLock) {
    unsafe {
        let lock = &*(rw_lock as *const AtomicU32);
        loop {
            let current = lock.load(Ordering::Relaxed);
            if lock
                .compare_exchange_weak(current, current - 1, Ordering::Release, Ordering::Relaxed)
                .is_ok()
            {
                if current - 1 == 0 {
                    asm!("sev", options(nomem, nostack));
                }
                break;
            }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_cond_init(cond: *mut GCond) {
    unsafe {
        let lock = &mut *(cond as *mut AtomicU32);
        lock.store(0, Ordering::Relaxed);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_cond_clear(_cond: *mut GCond) {}

#[unsafe(no_mangle)]
pub extern "C" fn g_cond_wait(cond: *mut GCond, mutex: *mut GMutex) {
    unsafe {
        g_mutex_unlock(mutex);

        let cond_lock = &*(cond as *const AtomicU32);
        while cond_lock.load(Ordering::Acquire) == 0 {
            asm!("wfe", options(nomem, nostack));
        }

        g_mutex_lock(mutex);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_cond_signal(cond: *mut GCond) {
    unsafe {
        let cond_lock = &*(cond as *const AtomicU32);
        cond_lock.store(1, Ordering::Release);
        asm!("sev", options(nomem, nostack));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn g_cond_broadcast(cond: *mut GCond) {
    unsafe {
        let cond_lock = &*(cond as *const AtomicU32);
        cond_lock.store(1, Ordering::Release);
        asm!("sev", options(nomem, nostack));
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

unsafe fn lock_acquire(lock: &AtomicU32) {
    loop {
        if lock
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            break;
        }
        while lock.load(Ordering::Relaxed) != 0 {
            unsafe {
                asm!("wfe", options(nomem, nostack));
            }
        }
    }
}

unsafe fn lock_release(lock: &AtomicU32) {
    lock.store(0, Ordering::Release);
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
