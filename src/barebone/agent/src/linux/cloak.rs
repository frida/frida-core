use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicBool, Ordering};

use super::layout::field_offset;
use super::native;

pub fn add_thread(tgid: i32, tid: i32) {
    let fresh = Cloak::of(tgid);
    registry().with(|cloaks| {
        let threads = &mut cloaks.entry(tgid).or_insert(fresh).threads;
        if !threads.contains(&tid) {
            threads.push(tid);
        }
    });
}

pub fn remove_thread(tgid: i32, tid: i32) {
    registry().with(|cloaks| {
        if let Some(cloak) = cloaks.get_mut(&tgid) {
            cloak.threads.retain(|t| *t != tid);
        }
    });
}

pub fn add_range(tgid: i32, base: usize, size: usize) {
    let fresh = Cloak::of(tgid);
    registry().with(|cloaks| {
        cloaks.entry(tgid).or_insert(fresh).ranges.push((base, base + size));
    });
}

pub fn remove_range(tgid: i32, base: usize, size: usize) {
    registry().with(|cloaks| {
        if let Some(cloak) = cloaks.get_mut(&tgid) {
            if let Some(index) = cloak.ranges.iter().position(|r| *r == (base, base + size)) {
                cloak.ranges.swap_remove(index);
            }
        }
    });
}

pub fn add_fd(tgid: i32, fd: i32) {
    let fresh = Cloak::of(tgid);
    registry().with(|cloaks| {
        let fds = &mut cloaks.entry(tgid).or_insert(fresh).fds;
        if !fds.contains(&fd) {
            fds.push(fd);
        }
    });
}

pub fn remove_fd(tgid: i32, fd: i32) {
    registry().with(|cloaks| {
        if let Some(cloak) = cloaks.get_mut(&tgid) {
            cloak.fds.retain(|f| *f != fd);
        }
    });
}

pub fn install_hooks() {
    let Some(layout) = describe_readers() else {
        return;
    };
    unsafe { LAYOUT = Some(layout) };

    let interceptor = unsafe { crate::bindings::gum_interceptor_obtain() };
    unsafe {
        crate::bindings::gum_interceptor_begin_transaction(interceptor);
        replace(interceptor, _show_map, frida_cb_show_map as *mut c_void, &raw mut SHOW_MAP);
        replace(interceptor, _show_smap, frida_cb_show_smap as *mut c_void, &raw mut SHOW_SMAP);
        replace(interceptor, _proc_fill_cache, frida_cb_proc_fill_cache as *mut c_void,
            &raw mut PROC_FILL_CACHE);
        replace(interceptor, _proc_pid_status, frida_cb_proc_pid_status as *mut c_void,
            &raw mut PROC_PID_STATUS);
        replace(interceptor, _do_task_stat, frida_cb_do_task_stat as *mut c_void, &raw mut DO_TASK_STAT);
        replace(interceptor, _release_task, frida_cb_release_task as *mut c_void, &raw mut RELEASE_TASK);
        crate::bindings::gum_interceptor_end_transaction(interceptor);
    }
}

pub fn remove_hooks() {
    if unsafe { (*(&raw const LAYOUT)).is_none() } {
        return;
    }

    let interceptor = unsafe { crate::bindings::gum_interceptor_obtain() };
    unsafe {
        crate::bindings::gum_interceptor_begin_transaction(interceptor);
        for target in [_show_map, _show_smap, _proc_fill_cache, _proc_pid_status, _do_task_stat, _release_task] {
            if target != 0 {
                crate::bindings::gum_interceptor_revert(interceptor, target as *mut c_void);
            }
        }
        crate::bindings::gum_interceptor_end_transaction(interceptor);
    }

    registry().with(|cloaks| cloaks.clear());
}

unsafe fn replace(interceptor: *mut crate::bindings::GumInterceptor, target: usize, replacement: *mut c_void,
        original: *mut usize) {
    if target == 0 {
        return;
    }

    unsafe {
        crate::bindings::gum_interceptor_replace(interceptor, target as *mut c_void, replacement,
            original as *mut *mut c_void, core::ptr::null_mut());
    }
}

unsafe extern "C" fn frida_cb_show_map(m: *mut c_void, vma: *mut c_void) -> c_int {
    if hides_the_area(vma) {
        return 0;
    }

    unsafe { call::<ShowFn>(SHOW_MAP)(m, vma) }
}

unsafe extern "C" fn frida_cb_show_smap(m: *mut c_void, vma: *mut c_void) -> c_int {
    if hides_the_area(vma) {
        return 0;
    }

    unsafe { call::<ShowFn>(SHOW_SMAP)(m, vma) }
}

unsafe extern "C" fn frida_cb_proc_fill_cache(file: *mut c_void, ctx: *mut c_void, name: *const u8, len: u32,
        instantiate: usize, task: *mut c_void, ptr: *const c_void) -> bool {
    if hides_the_entry(instantiate, task as usize, ptr as usize) {
        return true;
    }

    unsafe { call::<FillCacheFn>(PROC_FILL_CACHE)(file, ctx, name, len, instantiate, task, ptr) }
}

unsafe extern "C" fn frida_cb_proc_pid_status(m: *mut c_void, ns: *mut c_void, pid: *mut c_void,
        task: *mut c_void) -> c_int {
    let layout = layout();
    let start = read_word(m as usize + layout.seq_count);

    let result = unsafe { call::<StatusFn>(PROC_PID_STATUS)(m, ns, pid, task) };

    if let Some(hidden) = threads_hidden_from_the_reader(task as usize) {
        let said = said_since(m as usize, start);
        if let Some(at) = find(said, b"Threads:\t") {
            take_from_the_number_at(m as usize, start + at + b"Threads:\t".len(), hidden);
        }
    }

    result
}

unsafe extern "C" fn frida_cb_do_task_stat(m: *mut c_void, ns: *mut c_void, pid: *mut c_void,
        task: *mut c_void, whole: c_int) -> c_int {
    let layout = layout();
    let start = read_word(m as usize + layout.seq_count);

    let result = unsafe { call::<StatFn>(DO_TASK_STAT)(m, ns, pid, task, whole) };

    if let Some(hidden) = threads_hidden_from_the_reader(task as usize) {
        if let Some(at) = where_the_thread_count_is(said_since(m as usize, start)) {
            take_from_the_number_at(m as usize, start + at, hidden);
        }
    }

    result
}

unsafe extern "C" fn frida_cb_release_task(task: *mut c_void) {
    let layout = layout();
    let task = task as usize;
    let tgid = read_i32(task + layout.task_tgid);

    remove_thread(tgid, read_i32(task + layout.task_pid));
    if read_word(task + layout.task_group_leader) == task {
        registry().with(|cloaks| {
            cloaks.remove(&tgid);
        });
    }

    unsafe { call::<ReleaseFn>(RELEASE_TASK)(task as *mut c_void) };
}

fn hides_the_area(vma: *mut c_void) -> bool {
    let layout = layout();
    let vma = vma as usize;
    let mm = read_word(vma + layout.vma_mm);
    let start = read_word(vma + layout.vma_start);
    let end = read_word(vma + layout.vma_end);

    !the_reader_is_cloaked() && registry().with(|cloaks| {
        cloaks.values().any(|cloak| {
            cloak.mm == mm && cloak.ranges.iter().any(|(s, e)| start < *e && *s < end)
        })
    })
}

fn hides_the_entry(instantiate: usize, task: usize, ptr: usize) -> bool {
    if the_reader_is_cloaked() {
        return false;
    }

    let layout = layout();
    if instantiate == unsafe { _proc_task_instantiate } {
        let tid = read_i32(task + layout.task_pid);
        return registry().with(|cloaks| cloaks.values().any(|cloak| cloak.threads.contains(&tid)));
    }

    if instantiate == unsafe { _proc_fd_instantiate } || instantiate == unsafe { _proc_fdinfo_instantiate } {
        let tgid = read_i32(task + layout.task_tgid);
        let fd = read_i32(ptr + layout.fd_data_fd);
        return registry().with(|cloaks| cloaks.get(&tgid).is_some_and(|cloak| cloak.fds.contains(&fd)));
    }

    false
}

fn threads_hidden_from_the_reader(task: usize) -> Option<i32> {
    if the_reader_is_cloaked() {
        return None;
    }

    let tgid = read_i32(task + layout().task_tgid);
    let hidden = registry().with(|cloaks| cloaks.get(&tgid).map_or(0, |cloak| cloak.threads.len()));

    (hidden != 0).then_some(hidden as i32)
}

// A cloaked thread is one of ours, so let it see through the cloak; RASP threads in the same
// process are not cloaked and keep getting the censored view.
fn the_reader_is_cloaked() -> bool {
    let tid = read_i32(native::current_task() as usize + layout().task_pid);

    registry().with(|cloaks| cloaks.values().any(|cloak| cloak.threads.contains(&tid)))
}

fn said_since(m: usize, start: usize) -> &'static [u8] {
    let layout = layout();
    let count = read_word(m + layout.seq_count);
    if start >= count || count >= read_word(m + layout.seq_size) {
        return &[];
    }

    unsafe { core::slice::from_raw_parts((read_word(m + layout.seq_buf) + start) as *const u8, count - start) }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn where_the_thread_count_is(said: &[u8]) -> Option<usize> {
    let name_end = said.iter().rposition(|b| *b == b')')?;

    said[name_end..]
        .iter()
        .enumerate()
        .filter(|(_, b)| **b == b' ')
        .nth(17)
        .map(|(at, _)| name_end + at + 1)
}

fn take_from_the_number_at(m: usize, at: usize, hidden: i32) {
    let layout = layout();
    let buf = read_word(m + layout.seq_buf);
    let count = read_word(m + layout.seq_count);
    let said = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, count) };

    let digits = said[at..].iter().take_while(|b| b.is_ascii_digit()).count();
    let value = said[at..at + digits].iter().fold(0i32, |n, b| n * 10 + i32::from(b - b'0'));
    let shown = if value > hidden { value - hidden } else { 1 };
    let rendered = alloc::format!("{shown}");

    said.copy_within(at + digits..count, at + rendered.len());
    said[at..at + rendered.len()].copy_from_slice(rendered.as_bytes());
    write_word(m + layout.seq_count, count - digits + rendered.len());
}

struct Cloak {
    mm: usize,
    threads: Vec<i32>,
    ranges: Vec<(usize, usize)>,
    fds: Vec<i32>,
}

impl Cloak {
    fn of(tgid: i32) -> Self {
        let mm = super::processes::HeldTask::with_id(tgid as u32)
            .map_or(0, |task| read_word(task.address() + layout().task_mm));

        Self { mm, threads: Vec::new(), ranges: Vec::new(), fds: Vec::new() }
    }
}

struct Registry {
    busy: AtomicBool,
    cloaks: core::cell::UnsafeCell<BTreeMap<i32, Cloak>>,
}

unsafe impl Sync for Registry {}

impl Registry {
    fn with<R>(&self, action: impl FnOnce(&mut BTreeMap<i32, Cloak>) -> R) -> R {
        native::disable_preemption();
        while self.busy.swap(true, Ordering::Acquire) {
            core::hint::spin_loop();
        }
        let result = action(unsafe { &mut *self.cloaks.get() });
        self.busy.store(false, Ordering::Release);
        native::enable_preemption();
        result
    }
}

fn registry() -> &'static Registry {
    &REGISTRY
}

static REGISTRY: Registry = Registry {
    busy: AtomicBool::new(false),
    cloaks: core::cell::UnsafeCell::new(BTreeMap::new()),
};

struct ReaderLayout {
    task_pid: usize,
    task_tgid: usize,
    task_mm: usize,
    task_group_leader: usize,
    vma_mm: usize,
    vma_start: usize,
    vma_end: usize,
    seq_buf: usize,
    seq_size: usize,
    seq_count: usize,
    fd_data_fd: usize,
}

fn describe_readers() -> Option<ReaderLayout> {
    Some(ReaderLayout {
        task_pid: field_offset("task_struct", "pid")?,
        task_tgid: field_offset("task_struct", "tgid")?,
        task_mm: field_offset("task_struct", "mm")?,
        task_group_leader: field_offset("task_struct", "group_leader")?,
        vma_mm: field_offset("vm_area_struct", "vm_mm")?,
        vma_start: field_offset("vm_area_struct", "vm_start")?,
        vma_end: field_offset("vm_area_struct", "vm_end")?,
        seq_buf: field_offset("seq_file", "buf")?,
        seq_size: field_offset("seq_file", "size")?,
        seq_count: field_offset("seq_file", "count")?,
        fd_data_fd: field_offset("fd_data", "fd")?,
    })
}

fn layout() -> &'static ReaderLayout {
    unsafe { (*(&raw const LAYOUT)).as_ref().unwrap() }
}

static mut LAYOUT: Option<ReaderLayout> = None;

unsafe fn call<F: Copy>(original: usize) -> F {
    unsafe { core::mem::transmute_copy(&original) }
}

fn read_word(address: usize) -> usize {
    unsafe { (address as *const usize).read() }
}

fn write_word(address: usize, value: usize) {
    unsafe { (address as *mut usize).write(value) };
}

fn read_i32(address: usize) -> i32 {
    unsafe { (address as *const i32).read() }
}

type ShowFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;
type FillCacheFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *const u8, u32, usize, *mut c_void, *const c_void) -> bool;
type StatusFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> c_int;
type StatFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void, c_int) -> c_int;
type ReleaseFn = unsafe extern "C" fn(*mut c_void);

static mut SHOW_MAP: usize = 0;
static mut SHOW_SMAP: usize = 0;
static mut PROC_FILL_CACHE: usize = 0;
static mut PROC_PID_STATUS: usize = 0;
static mut DO_TASK_STAT: usize = 0;
static mut RELEASE_TASK: usize = 0;

unsafe extern "C" {
    static _show_map: usize;
    static _show_smap: usize;
    static _proc_fill_cache: usize;
    static _proc_pid_status: usize;
    static _do_task_stat: usize;
    static _release_task: usize;
    static _proc_task_instantiate: usize;
    static _proc_fd_instantiate: usize;
    static _proc_fdinfo_instantiate: usize;
}
