use core::ffi::{c_int, c_void};
use core::mem::size_of;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use super::layout::field_offset;
use super::native::{self, hold, let_go, lock_spinlock, unlock_spinlock};
use super::processes::{
    HeldTask, append_for_readers, detach_pid, free_pids, unlink, unlink_for_readers,
    write_lock_tasklist, write_unlock_tasklist,
};

pub fn start_in_process(id: u32, entry: usize, stack: usize, argument: usize, tls: usize) -> c_int {
    let Some(layout) = describe_thread_group() else {
        return -ENOSYS;
    };
    let Some(task) = HeldTask::with_id(id) else {
        return -ESRCH;
    };
    let Some(leader) = task.leader() else {
        return -ESRCH;
    };
    let mm = unsafe { _get_task_mm(task.address() as *mut c_void) };
    if mm.is_null() {
        return -ESRCH;
    }

    let birth = native::alloc(size_of::<Birth>()) as *mut Birth;
    unsafe {
        birth.write(Birth { entry, stack, argument, tls, leader: leader.into_address(), layout });

        _kthread_use_mm(mm);
        let started = _user_mode_thread(thread_entry(), birth as *mut c_void, 0);
        _kthread_unuse_mm(mm);
        _mmput(mm);

        if started < 0 {
            drop(HeldTask::from_address((*birth).leader));
            native::free(birth as *mut u8, size_of::<Birth>());
        }

        started
    }
}

struct Birth {
    entry: usize,
    stack: usize,
    argument: usize,
    tls: usize,
    leader: usize,
    layout: ThreadGroupLayout,
}

fn thread_entry() -> native::KthreadFn {
    native::kernel_thread_function(&THREAD_ENTRY, frida_cb_user_thread)
}

static THREAD_ENTRY: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn frida_cb_user_thread(argument: *mut c_void) -> c_int {
    let birth = unsafe { (argument as *const Birth).read() };
    native::free(argument as *mut u8, size_of::<Birth>());

    let leader = unsafe { HeldTask::from_address(birth.leader) };
    let child = native::current_task() as usize;
    join_thread_group(child, leader.address(), &birth.layout);
    adopt_context_of(child, leader.address(), &birth.layout);
    drop(leader);

    super::injection::hand_userland_to(birth.entry, birth.stack, birth.argument);
    use_thread_pointer(child, birth.tls, &birth.layout);

    0
}

fn join_thread_group(child: usize, leader: usize, layout: &ThreadGroupLayout) {
    let task = &layout.task;
    let old_signal = read_word(child + task.signal);
    let old_sighand = read_word(child + task.sighand);
    let signal = read_word(leader + task.signal);
    let sighand = read_word(leader + task.sighand);
    let mut freed = [ptr::null_mut::<c_void>(); PIDTYPE_MAX];

    let flags = write_lock_tasklist();

    unsafe {
        detach_pid(freed.as_mut_ptr(), child as *mut c_void, PIDTYPE_SID);
        detach_pid(freed.as_mut_ptr(), child as *mut c_void, PIDTYPE_PGID);
        detach_pid(freed.as_mut_ptr(), child as *mut c_void, PIDTYPE_TGID);

        unlink_for_readers(child + task.tasks);
        unlink(child + task.sibling);
        unlink_for_readers(child + task.thread_node);
    }

    let parent = read_word(leader + task.real_parent);
    write_word(child + task.real_parent, parent);
    write_word(child + task.parent, parent);
    write_word(child + task.group_leader, leader);
    write_i32(child + task.tgid, read_i32(leader + task.tgid));
    write_i32(child + task.exit_signal, -1);
    write_word(child + task.signal, signal);
    write_word(child + task.sighand, sighand);

    hold(sighand + layout.sighand.count);

    lock_spinlock(sighand + layout.sighand.siglock);

    write_i32(signal + layout.signal.nr_threads, read_i32(signal + layout.signal.nr_threads) + 1);
    if let Some(quick_threads) = layout.signal.quick_threads {
        write_i32(signal + quick_threads, read_i32(signal + quick_threads) + 1);
    }
    hold(signal + layout.signal.live);
    hold(signal + layout.signal.sigcnt);

    unsafe {
        (layout.calls.task_join_group_stop)(child as *mut c_void);

        if let Some(thread_group) = task.thread_group {
            append_for_readers(child + thread_group, leader + thread_group);
        }
        append_for_readers(child + task.thread_node, signal + layout.signal.thread_head);
    }

    unlock_spinlock(sighand + layout.sighand.siglock);

    write_unlock_tasklist(flags);

    unsafe {
        free_pids(freed.as_mut_ptr());

        (layout.calls.cleanup_sighand)(old_sighand as *mut c_void);
        if let_go(old_signal + layout.signal.sigcnt) {
            _kmem_cache_free(*_signal_cachep, old_signal as *mut c_void);
        }
    }
}

fn adopt_context_of(child: usize, leader: usize, layout: &ThreadGroupLayout) {
    let task = &layout.task;

    let files = read_word(leader + task.files);
    let old_files = read_word(child + task.files);
    hold(files + layout.files_count);
    lock_spinlock(child + task.alloc_lock);
    write_word(child + task.files, files);
    unlock_spinlock(child + task.alloc_lock);
    unsafe { (layout.calls.put_files_struct)(old_files as *mut c_void) };

    let fs = read_word(leader + task.fs);
    let old_fs = read_word(child + task.fs);
    lock_spinlock(fs + layout.fs.lock);
    write_i32(fs + layout.fs.users, read_i32(fs + layout.fs.users) + 1);
    unlock_spinlock(fs + layout.fs.lock);
    lock_spinlock(child + task.alloc_lock);
    write_word(child + task.fs, fs);
    unlock_spinlock(child + task.alloc_lock);
    lock_spinlock(old_fs + layout.fs.lock);
    let users_left = read_i32(old_fs + layout.fs.users) - 1;
    write_i32(old_fs + layout.fs.users, users_left);
    unlock_spinlock(old_fs + layout.fs.lock);
    if users_left == 0 {
        unsafe { (layout.calls.free_fs_struct)(old_fs as *mut c_void) };
    }

    let real_cred = read_word(leader + task.real_cred);
    let cred = read_word(leader + task.cred);
    let old_real_cred = read_word(child + task.real_cred);
    let old_cred = read_word(child + task.cred);
    hold(real_cred + layout.cred_usage);
    write_word(child + task.real_cred, real_cred);
    hold(cred + layout.cred_usage);
    unsafe { AtomicUsize::from_ptr((child + task.cred) as *mut usize).store(cred, Ordering::Release) };
    release_cred(old_cred, layout);
    release_cred(old_real_cred, layout);

    let namespaces = read_word(leader + task.nsproxy);
    hold(namespaces + layout.nsproxy_count);
    unsafe { (layout.calls.switch_task_namespaces)(child as *mut c_void, namespaces as *mut c_void) };

    if let Some(undo) = &layout.semaphore_undo {
        let undo_list = read_word(leader + undo.list);
        if undo_list != 0 {
            hold(undo_list + undo.refcnt);
            write_word(child + undo.list, undo_list);
        }
    }

    #[cfg(target_arch = "aarch64")]
    if let Some(lengths) = &layout.vector_lengths {
        adopt_vector_lengths(child, leader, lengths);
    }
}

fn release_cred(cred: usize, layout: &ThreadGroupLayout) {
    if let_go(cred + layout.cred_usage) {
        unsafe { (layout.calls.put_cred)(cred as *mut c_void) };
    }
}

#[cfg(target_arch = "aarch64")]
fn adopt_vector_lengths(child: usize, leader: usize, lengths: &VectorLengthLayout) {
    for array in [lengths.current, lengths.on_exec] {
        for kind in 0..VECTOR_KINDS {
            let at = array + kind * size_of::<u32>();
            write_i32(child + at, read_i32(leader + at));
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn use_thread_pointer(child: usize, tls: usize, layout: &ThreadGroupLayout) {
    const MSR_FS_BASE: u32 = 0xc000_0100;

    write_word(child + layout.task.thread_pointer, tls);
    unsafe {
        core::arch::asm!("wrmsr", in("ecx") MSR_FS_BASE, in("eax") tls as u32,
            in("edx") (tls >> 32) as u32, options(nostack));
    }
}

#[cfg(target_arch = "aarch64")]
fn use_thread_pointer(child: usize, tls: usize, layout: &ThreadGroupLayout) {
    write_word(child + layout.task.thread_pointer, tls);
    unsafe { core::arch::asm!("msr tpidr_el0, {}", in(reg) tls, options(nostack)) };
}

struct ThreadGroupLayout {
    calls: ThreadGroupCalls,
    task: TaskLayout,
    signal: SignalLayout,
    sighand: SighandLayout,
    fs: FsLayout,
    files_count: usize,
    cred_usage: usize,
    nsproxy_count: usize,
    semaphore_undo: Option<SemaphoreUndoLayout>,
    #[cfg(target_arch = "aarch64")]
    vector_lengths: Option<VectorLengthLayout>,
}

struct ThreadGroupCalls {
    task_join_group_stop: unsafe extern "C" fn(*mut c_void),
    cleanup_sighand: unsafe extern "C" fn(*mut c_void),
    put_files_struct: unsafe extern "C" fn(*mut c_void),
    free_fs_struct: unsafe extern "C" fn(*mut c_void),
    put_cred: unsafe extern "C" fn(*mut c_void),
    switch_task_namespaces: unsafe extern "C" fn(*mut c_void, *mut c_void),
}

struct TaskLayout {
    tgid: usize,
    real_parent: usize,
    parent: usize,
    group_leader: usize,
    exit_signal: usize,
    signal: usize,
    sighand: usize,
    tasks: usize,
    sibling: usize,
    thread_node: usize,
    thread_group: Option<usize>,
    files: usize,
    fs: usize,
    cred: usize,
    real_cred: usize,
    nsproxy: usize,
    alloc_lock: usize,
    thread_pointer: usize,
}

struct SignalLayout {
    nr_threads: usize,
    quick_threads: Option<usize>,
    live: usize,
    sigcnt: usize,
    thread_head: usize,
}

struct SighandLayout {
    count: usize,
    siglock: usize,
}

struct FsLayout {
    users: usize,
    lock: usize,
}

struct SemaphoreUndoLayout {
    list: usize,
    refcnt: usize,
}

#[cfg(target_arch = "aarch64")]
struct VectorLengthLayout {
    current: usize,
    on_exec: usize,
}

fn describe_thread_group() -> Option<ThreadGroupLayout> {
    Some(ThreadGroupLayout {
        calls: unsafe {
            ThreadGroupCalls {
                task_join_group_stop: _task_join_group_stop?,
                cleanup_sighand: ___cleanup_sighand?,
                put_files_struct: _put_files_struct?,
                free_fs_struct: _free_fs_struct?,
                put_cred: ___put_cred?,
                switch_task_namespaces: _switch_task_namespaces?,
            }
        },
        task: TaskLayout {
            tgid: field_offset("task_struct", "tgid")?,
            real_parent: field_offset("task_struct", "real_parent")?,
            parent: field_offset("task_struct", "parent")?,
            group_leader: field_offset("task_struct", "group_leader")?,
            exit_signal: field_offset("task_struct", "exit_signal")?,
            signal: field_offset("task_struct", "signal")?,
            sighand: field_offset("task_struct", "sighand")?,
            tasks: field_offset("task_struct", "tasks")?,
            sibling: field_offset("task_struct", "sibling")?,
            thread_node: field_offset("task_struct", "thread_node")?,
            thread_group: field_offset("task_struct", "thread_group"),
            files: field_offset("task_struct", "files")?,
            fs: field_offset("task_struct", "fs")?,
            cred: field_offset("task_struct", "cred")?,
            real_cred: field_offset("task_struct", "real_cred")?,
            nsproxy: field_offset("task_struct", "nsproxy")?,
            alloc_lock: field_offset("task_struct", "alloc_lock")?,
            thread_pointer: field_offset("task_struct", THREAD_POINTER_FIELD)?,
        },
        signal: SignalLayout {
            nr_threads: field_offset("signal_struct", "nr_threads")?,
            quick_threads: field_offset("signal_struct", "quick_threads"),
            live: field_offset("signal_struct", "live")?,
            sigcnt: field_offset("signal_struct", "sigcnt")?,
            thread_head: field_offset("signal_struct", "thread_head")?,
        },
        sighand: SighandLayout {
            count: field_offset("sighand_struct", "count")?,
            siglock: field_offset("sighand_struct", "siglock")?,
        },
        fs: FsLayout {
            users: field_offset("fs_struct", "users")?,
            lock: field_offset("fs_struct", "lock").or_else(|| field_offset("fs_struct", "seq.lock"))?,
        },
        files_count: field_offset("files_struct", "count")?,
        cred_usage: field_offset("cred", "usage")?,
        nsproxy_count: field_offset("nsproxy", "count")?,
        semaphore_undo: describe_semaphore_undo(),
        #[cfg(target_arch = "aarch64")]
        vector_lengths: describe_vector_lengths(),
    })
}

fn describe_semaphore_undo() -> Option<SemaphoreUndoLayout> {
    Some(SemaphoreUndoLayout {
        list: field_offset("task_struct", "sysvsem.undo_list")?,
        refcnt: field_offset("sem_undo_list", "refcnt")?,
    })
}

#[cfg(target_arch = "aarch64")]
fn describe_vector_lengths() -> Option<VectorLengthLayout> {
    Some(VectorLengthLayout {
        current: field_offset("task_struct", "thread.vl")?,
        on_exec: field_offset("task_struct", "thread.vl_onexec")?,
    })
}

#[cfg(target_arch = "x86_64")]
const THREAD_POINTER_FIELD: &str = "thread.fsbase";
#[cfg(target_arch = "aarch64")]
const THREAD_POINTER_FIELD: &str = "thread.uw.tp_value";

#[cfg(target_arch = "aarch64")]
const VECTOR_KINDS: usize = 2;

fn read_word(address: usize) -> usize {
    unsafe { (address as *const usize).read() }
}

fn write_word(address: usize, value: usize) {
    unsafe { (address as *mut usize).write(value) };
}

fn read_i32(address: usize) -> i32 {
    unsafe { (address as *const i32).read() }
}

fn write_i32(address: usize, value: i32) {
    unsafe { (address as *mut i32).write(value) };
}

const PIDTYPE_TGID: c_int = 1;
const PIDTYPE_PGID: c_int = 2;
const PIDTYPE_SID: c_int = 3;
const PIDTYPE_MAX: usize = 4;

const ESRCH: c_int = 3;
const ENOSYS: c_int = 38;

unsafe extern "C" {
    static _get_task_mm: unsafe extern "C" fn(*mut c_void) -> *mut c_void;
    static _mmput: unsafe extern "C" fn(*mut c_void);
    static _kthread_use_mm: unsafe extern "C" fn(*mut c_void);
    static _kthread_unuse_mm: unsafe extern "C" fn(*mut c_void);
    static _user_mode_thread: unsafe extern "C" fn(native::KthreadFn, *mut c_void, usize) -> c_int;
    static _task_join_group_stop: Option<unsafe extern "C" fn(*mut c_void)>;
    static ___cleanup_sighand: Option<unsafe extern "C" fn(*mut c_void)>;
    static _kmem_cache_free: unsafe extern "C" fn(*mut c_void, *mut c_void);
    static _signal_cachep: *const *mut c_void;
    static _put_files_struct: Option<unsafe extern "C" fn(*mut c_void)>;
    static _free_fs_struct: Option<unsafe extern "C" fn(*mut c_void)>;
    static ___put_cred: Option<unsafe extern "C" fn(*mut c_void)>;
    static _switch_task_namespaces: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>;
}
