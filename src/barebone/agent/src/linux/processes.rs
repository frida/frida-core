use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

pub struct ProcessInfo {
    pub id: u32,
    pub name: *const u8,
    pub path: *const u8,
    pub command_line: *const u8,
    pub uid: u32,
    pub user: *const u8,
    pub ppid: u32,
    pub started: i64,
}

pub fn enumerate_processes(found: &mut dyn FnMut(ProcessInfo)) {
    let Some(layout) = task_layout() else {
        return;
    };

    let mut path = Vec::new();
    path.resize(PATH_MAX, 0u8);
    let mut cmdline = Vec::new();
    cmdline.resize(CMDLINE_MAX, 0u8);
    let mut label = Vec::new();
    label.resize(NAME_MAX, 0u8);
    let mut owner = Vec::new();
    owner.resize(NAME_MAX, 0u8);

    let (now_boottime, now_realtime) = current_time();

    for task in take_task_snapshot(layout) {
        if !task.memory.is_null() {
            let (name, command_line) = describe(task.memory, &mut cmdline, &mut label)
                .unwrap_or((task.name.as_ptr(), ptr::null()));
            found(ProcessInfo {
                id: task.id,
                name,
                path: path_of(task.executable, &mut path),
                command_line,
                uid: task.uid,
                user: format_user(task.uid, &mut owner),
                ppid: task.ppid,
                started: wall_time(task.started, now_boottime, now_realtime),
            });
            unsafe { _mmput(task.memory) };
        }

        if !task.executable.is_null() {
            unsafe { _fput(task.executable) };
        }
    }
}

pub fn running_task_ids() -> Vec<u32> {
    let Some(layout) = task_layout() else {
        return Vec::new();
    };

    let flags = lock_tasklist();
    let ids = tasks_of(layout.init, layout.list)
        .map(|task| read_id(task, layout))
        .collect();
    unlock_tasklist(flags);

    ids
}

pub unsafe fn let_go_of(file: *mut c_void) {
    unsafe { _fput(file) };
}

pub fn task_with_id(id: u32) -> Option<usize> {
    let layout = task_layout()?;

    let flags = lock_tasklist();
    let found = tasks_of(layout.init, layout.list).find(|task| read_id(*task, layout) == id);
    unlock_tasklist(flags);

    found
}

pub fn describe_process(process: &ProcessInfo) -> *const u8 {
    process.name
}

pub fn enumerate_icons(_path: *const u8, _found: &mut dyn FnMut(&[u8])) {}

struct Task {
    id: u32,
    name: [u8; NAME_SIZE + 1],
    executable: *mut c_void,
    memory: *mut c_void,
    uid: u32,
    ppid: u32,
    started: u64,
}

fn take_task_snapshot(layout: &Layout) -> Vec<Task> {
    let mut snapshot = Vec::with_capacity(tasks_of(layout.init, layout.list).count() + SNAPSHOT_HEADROOM);

    let flags = lock_tasklist();
    for task in tasks_of(layout.init, layout.list) {
        if snapshot.len() == snapshot.capacity() {
            break;
        }
        snapshot.push(read_task(task, layout));
    }
    unlock_tasklist(flags);

    snapshot
}

fn read_task(task: usize, layout: &Layout) -> Task {
    let mut name = [0u8; NAME_SIZE + 1];
    read_kernel(task + layout.name, &mut name[..NAME_SIZE]);

    Task {
        id: read_id(task, layout),
        name,
        executable: unsafe { _get_task_exe_file(task as *mut c_void) },
        memory: unsafe { _get_task_mm(task as *mut c_void) },
        uid: read_uid(task, layout),
        ppid: read_ppid(task, layout),
        started: layout.started.and_then(|at| read_kernel_word(task + at)).unwrap_or(0) as u64,
    }
}

fn read_uid(task: usize, layout: &Layout) -> u32 {
    let (Some(credentials), Some(uid)) = (layout.credentials, layout.uid) else {
        return 0;
    };
    let Some(cred) = read_kernel_word(task + credentials) else {
        return 0;
    };
    read_kernel_u32(cred + uid)
}

fn read_ppid(task: usize, layout: &Layout) -> u32 {
    let (Some(parent), Some(group)) = (layout.parent, layout.group) else {
        return 0;
    };
    let Some(task) = read_kernel_word(task + parent) else {
        return 0;
    };
    read_kernel_u32(task + group)
}

fn read_id(task: usize, layout: &Layout) -> u32 {
    read_kernel_u32(task + layout.id)
}

fn read_kernel_u32(address: usize) -> u32 {
    let mut bytes = [0u8; 4];
    if !read_kernel(address, &mut bytes) {
        return 0;
    }

    u32::from_ne_bytes(bytes)
}

#[cfg(target_arch = "aarch64")]
fn describe(memory: *mut c_void, cmdline: &mut [u8], label: &mut [u8]) -> Option<(*const u8, *const u8)> {
    let read = read_cmdline(memory, cmdline)?;
    let name = base_name(&cmdline[..read], label);
    let command_line = join_arguments(cmdline, read);
    Some((name, command_line))
}

#[cfg(not(target_arch = "aarch64"))]
fn describe(_memory: *mut c_void, _cmdline: &mut [u8], _label: &mut [u8]) -> Option<(*const u8, *const u8)> {
    None
}

#[cfg(target_arch = "aarch64")]
fn read_cmdline(memory: *mut c_void, buffer: &mut [u8]) -> Option<usize> {
    let start = read_kernel_word(memory as usize + super::layout::field_offset("mm_struct", "arg_start")?)?;
    if start == 0 {
        return None;
    }

    let room = buffer.len() - 1;
    unsafe { _kthread_use_mm(memory) };
    let missed = unsafe {
        ___arch_copy_from_user(buffer.as_mut_ptr() as *mut c_void, start as *const c_void, room)
    };
    unsafe { _kthread_unuse_mm(memory) };

    let read = room - missed;
    (read != 0).then_some(read)
}

#[cfg(target_arch = "aarch64")]
fn base_name(arguments: &[u8], label: &mut [u8]) -> *const u8 {
    let first = &arguments[..arguments.iter().position(|byte| *byte == 0).unwrap_or(arguments.len())];
    let start = first.iter().rposition(|byte| *byte == b'/').map_or(0, |slash| slash + 1);
    let name = &first[start..];

    let taken = name.len().min(label.len() - 1);
    label[..taken].copy_from_slice(&name[..taken]);
    label[taken] = 0;

    label.as_ptr()
}

#[cfg(target_arch = "aarch64")]
fn join_arguments(cmdline: &mut [u8], read: usize) -> *const u8 {
    for byte in &mut cmdline[..read] {
        if *byte == 0 {
            *byte = b' ';
        }
    }
    cmdline[read] = 0;

    cmdline.as_ptr()
}

fn format_user(uid: u32, buffer: &mut [u8]) -> *const u8 {
    let text = user_label(uid);
    let bytes = text.as_bytes();

    let taken = bytes.len().min(buffer.len() - 1);
    buffer[..taken].copy_from_slice(&bytes[..taken]);
    buffer[taken] = 0;

    buffer.as_ptr()
}

fn user_label(uid: u32) -> String {
    let user = uid / AID_USER_OFFSET;
    let app = uid % AID_USER_OFFSET;

    if (AID_APP_START..AID_APP_END).contains(&app) {
        return format!("u{}_a{}", user, app - AID_APP_START);
    }

    match app {
        0 => "root".into(),
        1000 => "system".into(),
        1001 => "radio".into(),
        2000 => "shell".into(),
        _ => format!("{}", uid),
    }
}

fn wall_time(started: u64, now_boottime: u64, now_realtime: u64) -> i64 {
    if started == 0 || started > now_boottime {
        return 0;
    }
    let age = now_boottime - started;
    if age > now_realtime {
        return 0;
    }

    ((now_realtime - age) / 1_000_000_000) as i64
}

#[cfg(not(target_arch = "x86"))]
fn current_time() -> (u64, u64) {
    let mut wall = Timespec { seconds: 0, nanoseconds: 0 };
    unsafe { _ktime_get_real_ts64(&mut wall) };
    let wallclock = (wall.seconds as u64) * 1_000_000_000 + (wall.nanoseconds as u64);
    let uptime = unsafe { _ktime_get_mono_fast_ns() };

    (uptime, wallclock)
}

#[cfg(target_arch = "x86")]
fn current_time() -> (u64, u64) {
    (0, 0)
}

#[repr(C)]
struct Timespec {
    seconds: i64,
    nanoseconds: i64,
}

fn path_of(executable: *mut c_void, buffer: &mut [u8]) -> *const u8 {
    if executable.is_null() {
        return ptr::null();
    }

    let path = unsafe {
        _file_path(
            executable,
            buffer.as_mut_ptr() as *mut c_char,
            buffer.len() as c_int,
        )
    };
    if (path as usize) >= ERROR_POINTER_START {
        return ptr::null();
    }

    path as *const u8
}

fn tasks_of(init: usize, list: usize) -> TaskList {
    TaskList {
        head: init + list,
        node: init + list,
        list,
        left: MAX_TASKS,
    }
}

struct TaskList {
    head: usize,
    node: usize,
    list: usize,
    left: usize,
}

impl Iterator for TaskList {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;

        let node = read_kernel_word(self.node)?;
        if node == self.head {
            return None;
        }
        self.node = node;

        Some(node - self.list)
    }
}

fn task_layout() -> Option<&'static Layout> {
    unsafe {
        let known = (&raw mut LAYOUT).as_mut().unwrap();
        if known.is_none() {
            *known = discover_layout();
        }
        known.as_ref()
    }
}

static mut LAYOUT: Option<Layout> = None;

struct Layout {
    init: usize,
    list: usize,
    name: usize,
    id: usize,
    credentials: Option<usize>,
    uid: Option<usize>,
    parent: Option<usize>,
    group: Option<usize>,
    started: Option<usize>,
}

fn discover_layout() -> Option<Layout> {
    let init = unsafe { _init_task } as usize;

    if let Some(layout) = described_layout(init) {
        return Some(layout);
    }

    let image = read_task_image(init);

    let name = find(&image, IDLE_TASK_NAME)?;
    let (list, id) = find_task_list(init, &image, name)?;

    Some(Layout {
        init,
        list,
        name,
        id,
        credentials: None,
        uid: None,
        parent: None,
        group: None,
        started: None,
    })
}

fn described_layout(init: usize) -> Option<Layout> {
    use super::layout::field_offset;

    Some(Layout {
        init,
        list: field_offset("task_struct", "tasks")?,
        name: field_offset("task_struct", "comm")?,
        id: field_offset("task_struct", "pid")?,
        credentials: field_offset("task_struct", "real_cred"),
        uid: field_offset("cred", "uid"),
        parent: field_offset("task_struct", "real_parent"),
        group: field_offset("task_struct", "tgid"),
        started: field_offset("task_struct", "start_time"),
    })
}

fn read_task_image(task: usize) -> Vec<u8> {
    let mut image = Vec::new();
    image.resize(MAX_TASK_SIZE, 0u8);

    let mut readable = 0;
    while readable != image.len() {
        if !read_kernel(task + readable, &mut image[readable..readable + READ_CHUNK]) {
            break;
        }
        readable += READ_CHUNK;
    }
    image.truncate(readable);

    image
}

fn find(image: &[u8], text: &[u8]) -> Option<usize> {
    image.windows(text.len()).position(|window| window == text)
}

fn find_task_list(init: usize, image: &[u8], name: usize) -> Option<(usize, usize)> {
    let mut longest: Option<(usize, usize, usize)> = None;

    for list in (0..image.len() - LIST_SIZE).step_by(WORD_SIZE) {
        if !heads_a_circular_list(init, image, list) {
            continue;
        }

        let Some(tasks) = sample_tasks(init, list, name) else {
            continue;
        };
        let Some(id) = find_identifier(&tasks) else {
            continue;
        };

        let longer = match longest {
            Some((sampled, _, _)) => tasks.len() > sampled,
            None => true,
        };
        if longer {
            longest = Some((tasks.len(), list, id));
        }
    }

    longest.map(|(_, list, id)| (list, id))
}

fn heads_a_circular_list(init: usize, image: &[u8], list: usize) -> bool {
    let head = init + list;
    let next = word_in(image, list);
    let previous = word_in(image, list + WORD_SIZE);

    let kernel_space = kernel_space_holding(init);
    if !is_kernel_address(next, kernel_space) || !is_kernel_address(previous, kernel_space) || next == head {
        return false;
    }

    read_kernel_word(next + WORD_SIZE) == Some(head) && read_kernel_word(previous) == Some(head)
}

fn sample_tasks(init: usize, list: usize, name: usize) -> Option<Vec<usize>> {
    let mut tasks = Vec::new();

    for task in tasks_of(init, list) {
        if !names_a_task(task + name) {
            return None;
        }

        tasks.push(task);
        if tasks.len() == MAX_SAMPLED_TASKS {
            break;
        }
    }

    if tasks.len() < MIN_SAMPLED_TASKS {
        return None;
    }

    Some(tasks)
}

fn names_a_task(name: usize) -> bool {
    let mut text = [0u8; NAME_SIZE];
    if !read_kernel(name, &mut text) {
        return false;
    }

    let Some(end) = text.iter().position(|letter| *letter == 0) else {
        return false;
    };

    end != 0 && text[..end].iter().all(|letter| *letter >= 0x20 && *letter < 0x7f)
}

fn find_identifier(tasks: &[usize]) -> Option<usize> {
    let mut identifiers = Vec::with_capacity(tasks.len());

    for id in (0..MAX_TASK_SIZE - 8).step_by(4) {
        identifiers.clear();

        let leads_every_task = tasks.iter().all(|task| {
            let Some((own, group)) = read_kernel_pair(*task + id) else {
                return false;
            };
            if own != group || own >= MAX_IDENTIFIER || identifiers.contains(&own) {
                return false;
            }
            identifiers.push(own);

            true
        });

        if leads_every_task {
            return Some(id);
        }
    }

    None
}

fn read_kernel_pair(address: usize) -> Option<(u32, u32)> {
    let mut bytes = [0u8; 8];
    if !read_kernel(address, &mut bytes) {
        return None;
    }

    Some((
        u32::from_ne_bytes(bytes[..4].try_into().unwrap()),
        u32::from_ne_bytes(bytes[4..].try_into().unwrap()),
    ))
}

fn read_kernel_word(address: usize) -> Option<usize> {
    let mut bytes = [0u8; WORD_SIZE];
    if !read_kernel(address, &mut bytes) {
        return None;
    }

    Some(usize::from_ne_bytes(bytes))
}

fn read_kernel(address: usize, destination: &mut [u8]) -> bool {
    let read = unsafe {
        _copy_from_kernel_nofault(
            destination.as_mut_ptr() as *mut c_void,
            address as *const c_void,
            destination.len(),
        )
    };

    read == 0
}

fn word_in(image: &[u8], offset: usize) -> usize {
    usize::from_ne_bytes(image[offset..offset + WORD_SIZE].try_into().unwrap())
}

fn is_kernel_address(address: usize, kernel_space: usize) -> bool {
    address >= kernel_space && address % WORD_SIZE == 0
}

fn kernel_space_holding(address: usize) -> usize {
    address & !(SPLIT_GRANULARITY - 1)
}

const SPLIT_GRANULARITY: usize = 1 << 30;

#[cfg(target_arch = "x86")]
fn lock_tasklist() -> usize {
    unsafe { frida_k_lock_tasklist() }
}

#[cfg(not(target_arch = "x86"))]
fn lock_tasklist() -> usize {
    unsafe {
        match (__raw_read_lock_irqsave, __raw_read_unlock_irqrestore) {
            (Some(lock), Some(_)) => lock(_tasklist_lock),
            _ => {
                __raw_read_lock.unwrap()(_tasklist_lock);
                0
            }
        }
    }
}

#[cfg(target_arch = "x86")]
fn unlock_tasklist(flags: usize) {
    unsafe { frida_k_unlock_tasklist(flags) };
}

#[cfg(not(target_arch = "x86"))]
fn unlock_tasklist(flags: usize) {
    unsafe {
        match (__raw_read_lock_irqsave, __raw_read_unlock_irqrestore) {
            (Some(_), Some(unlock)) => unlock(_tasklist_lock, flags),
            _ => __raw_read_unlock.unwrap()(_tasklist_lock),
        }
    }
}

const PIDTYPE_TGID: c_int = 1;
const PIDTYPE_MAX: usize = 4;

pub fn cloak_task(task: *mut c_void) {
    // detach_pid's arity differs across kernels (the classic detach_pid(task, type)
    // versus the batched detach_pid(pids, task, type) paired with free_pids); calling
    // the wrong one drives a UBSAN/CFI trap on hardened kernels. Leave the thread
    // visible rather than risk it.
    if true {
        let _ = task;
        return;
    }
    let (Some(tasks), Some(sibling), Some(thread_node)) = (
        super::layout::field_offset("task_struct", "tasks"),
        super::layout::field_offset("task_struct", "sibling"),
        super::layout::field_offset("task_struct", "thread_node"),
    ) else {
        return;
    };

    let mut freed: [*mut c_void; PIDTYPE_MAX] = [ptr::null_mut(); PIDTYPE_MAX];

    let flags = write_lock_tasklist();
    unsafe {
        detach_pid(freed.as_mut_ptr(), task, PIDTYPE_TGID);
        unlink(task as usize + tasks);
        unlink(task as usize + sibling);
        unlink(task as usize + thread_node);
    }
    write_unlock_tasklist(flags);

    unsafe { free_pids(freed.as_mut_ptr()) };
}

#[cfg(target_arch = "x86")]
unsafe fn detach_pid(pids: *mut *mut c_void, task: *mut c_void, kind: c_int) {
    unsafe { frida_k_detach_pid(pids, task, kind) };
}

#[cfg(not(target_arch = "x86"))]
unsafe fn detach_pid(pids: *mut *mut c_void, task: *mut c_void, kind: c_int) {
    unsafe { _detach_pid(pids, task, kind) };
}

#[cfg(target_arch = "x86")]
unsafe fn free_pids(pids: *mut *mut c_void) {
    unsafe { frida_k_free_pids(pids) };
}

#[cfg(not(target_arch = "x86"))]
unsafe fn free_pids(pids: *mut *mut c_void) {
    unsafe { _free_pids(pids) };
}

unsafe fn unlink(node: usize) {
    let next = unsafe { (node as *const usize).read() };
    let prev = unsafe { ((node + WORD_SIZE) as *const usize).read() };
    unsafe {
        (prev as *mut usize).write(next);
        ((next + WORD_SIZE) as *mut usize).write(prev);
        (node as *mut usize).write(node);
        ((node + WORD_SIZE) as *mut usize).write(node);
    }
}

#[cfg(target_arch = "x86")]
fn write_lock_tasklist() -> usize {
    unsafe { frida_k_write_lock_tasklist() }
}

#[cfg(not(target_arch = "x86"))]
fn write_lock_tasklist() -> usize {
    unsafe {
        match (__raw_write_lock_irqsave, __raw_write_unlock_irqrestore) {
            (Some(lock), Some(_)) => lock(_tasklist_lock),
            _ => {
                __raw_write_lock.unwrap()(_tasklist_lock);
                0
            }
        }
    }
}

#[cfg(target_arch = "x86")]
fn write_unlock_tasklist(flags: usize) {
    unsafe { frida_k_write_unlock_tasklist(flags) };
}

#[cfg(not(target_arch = "x86"))]
fn write_unlock_tasklist(flags: usize) {
    unsafe {
        match (__raw_write_lock_irqsave, __raw_write_unlock_irqrestore) {
            (Some(_), Some(unlock)) => unlock(_tasklist_lock, flags),
            _ => __raw_write_unlock.unwrap()(_tasklist_lock),
        }
    }
}

const IDLE_TASK_NAME: &[u8] = b"swapper";
const NAME_SIZE: usize = 16;
const PATH_MAX: usize = 4096;
const CMDLINE_MAX: usize = 512;
const NAME_MAX: usize = 256;
const AID_USER_OFFSET: u32 = 100000;
const AID_APP_START: u32 = 10000;
const AID_APP_END: u32 = 20000;

const MAX_TASK_SIZE: usize = 16 * 1024;
const READ_CHUNK: usize = 64;
const WORD_SIZE: usize = size_of::<usize>();
const LIST_SIZE: usize = 2 * WORD_SIZE;

const MAX_TASKS: usize = 8192;
const SNAPSHOT_HEADROOM: usize = 64;
const MIN_SAMPLED_TASKS: usize = 4;
const MAX_SAMPLED_TASKS: usize = 32;
const MAX_IDENTIFIER: u32 = 4 * 1024 * 1024;

const ERROR_POINTER_START: usize = usize::MAX - 4095;

unsafe extern "C" {
    static _init_task: *const c_void;
    static _tasklist_lock: *mut c_void;
    static __raw_read_lock: Option<unsafe extern "C" fn(*mut c_void)>;
    static __raw_read_unlock: Option<unsafe extern "C" fn(*mut c_void)>;
    static __raw_read_lock_irqsave: Option<unsafe extern "C" fn(*mut c_void) -> usize>;
    static __raw_read_unlock_irqrestore: Option<unsafe extern "C" fn(*mut c_void, usize)>;
    #[cfg(not(target_arch = "x86"))]
    static _detach_pid: unsafe extern "C" fn(*mut *mut c_void, *mut c_void, c_int);
    #[cfg(not(target_arch = "x86"))]
    static _free_pids: unsafe extern "C" fn(*mut *mut c_void);
    #[cfg(not(target_arch = "x86"))]
    static __raw_write_lock: Option<unsafe extern "C" fn(*mut c_void)>;
    #[cfg(not(target_arch = "x86"))]
    static __raw_write_unlock: Option<unsafe extern "C" fn(*mut c_void)>;
    #[cfg(not(target_arch = "x86"))]
    static __raw_write_lock_irqsave: Option<unsafe extern "C" fn(*mut c_void) -> usize>;
    #[cfg(not(target_arch = "x86"))]
    static __raw_write_unlock_irqrestore: Option<unsafe extern "C" fn(*mut c_void, usize)>;
    #[cfg(not(target_arch = "x86"))]
    static _get_task_exe_file: unsafe extern "C" fn(*mut c_void) -> *mut c_void;
    #[cfg(not(target_arch = "x86"))]
    static _file_path: unsafe extern "C" fn(*mut c_void, *mut c_char, c_int) -> *const c_char;
    #[cfg(not(target_arch = "x86"))]
    static _fput: unsafe extern "C" fn(*mut c_void);
    #[cfg(not(target_arch = "x86"))]
    static _copy_from_kernel_nofault:
        unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> c_long;
    #[cfg(not(target_arch = "x86"))]
    static _get_task_mm: unsafe extern "C" fn(*mut c_void) -> *mut c_void;
    #[cfg(not(target_arch = "x86"))]
    static _mmput: unsafe extern "C" fn(*mut c_void);
    #[cfg(target_arch = "aarch64")]
    static _kthread_use_mm: unsafe extern "C" fn(*mut c_void);
    #[cfg(target_arch = "aarch64")]
    static _kthread_unuse_mm: unsafe extern "C" fn(*mut c_void);
    #[cfg(target_arch = "aarch64")]
    static ___arch_copy_from_user:
        unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> usize;
    #[cfg(not(target_arch = "x86"))]
    static _ktime_get_real_ts64: unsafe extern "C" fn(*mut Timespec);
    #[cfg(not(target_arch = "x86"))]
    static _ktime_get_mono_fast_ns: unsafe extern "C" fn() -> u64;
}

#[cfg(target_arch = "x86")]
unsafe extern "C" {
    #[link_name = "frida_k_copy_from_kernel_nofault"]
    fn _copy_from_kernel_nofault(a0: *mut c_void, a1: *const c_void, a2: usize) -> c_long;
    fn frida_k_lock_tasklist() -> usize;
    fn frida_k_unlock_tasklist(flags: usize);
    fn frida_k_write_lock_tasklist() -> usize;
    fn frida_k_write_unlock_tasklist(flags: usize);
    fn frida_k_detach_pid(pids: *mut *mut c_void, task: *mut c_void, kind: c_int);
    fn frida_k_free_pids(pids: *mut *mut c_void);
}

#[cfg(target_arch = "x86")]
unsafe extern "C" {
    #[link_name = "frida_k_get_task_exe_file"]
    fn _get_task_exe_file(a0: *mut c_void) -> *mut c_void;
    #[link_name = "frida_k_file_path"]
    fn _file_path(a0: *mut c_void, a1: *mut c_char, a2: c_int) -> *const c_char;
    #[link_name = "frida_k_fput"]
    fn _fput(a0: *mut c_void);
    #[link_name = "frida_k_get_task_mm"]
    fn _get_task_mm(a0: *mut c_void) -> *mut c_void;
    #[link_name = "frida_k_mmput"]
    fn _mmput(a0: *mut c_void);
}
