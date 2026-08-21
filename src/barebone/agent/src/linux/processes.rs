use alloc::vec::Vec;
use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

pub struct ProcessInfo {
    pub id: u32,
    pub name: *const u8,
    pub path: *const u8,
    pub command_line: *const u8,
}

pub fn enumerate_processes(found: &mut dyn FnMut(ProcessInfo)) {
    let Some(layout) = task_layout() else {
        return;
    };

    let mut path = Vec::new();
    path.resize(PATH_MAX, 0u8);

    for task in take_task_snapshot(layout) {
        found(ProcessInfo {
            id: task.id,
            name: task.name.as_ptr(),
            path: path_of(task.executable, &mut path),
            command_line: ptr::null(),
        });

        if !task.executable.is_null() {
            unsafe { _fput(task.executable) };
        }
    }
}

pub fn describe_process(process: &ProcessInfo) -> *const u8 {
    process.name
}

pub fn enumerate_icons(_path: *const u8, _found: &mut dyn FnMut(&[u8])) {}

struct Task {
    id: u32,
    name: [u8; NAME_SIZE + 1],
    executable: *mut c_void,
}

fn take_task_snapshot(layout: &Layout) -> Vec<Task> {
    let mut snapshot = Vec::with_capacity(tasks_of(layout.init, layout.list).count() + SNAPSHOT_HEADROOM);

    unsafe { __raw_read_lock(_tasklist_lock) };
    for task in tasks_of(layout.init, layout.list) {
        if snapshot.len() == snapshot.capacity() {
            break;
        }
        snapshot.push(read_task(task, layout));
    }
    unsafe { __raw_read_unlock(_tasklist_lock) };

    snapshot
}

fn read_task(task: usize, layout: &Layout) -> Task {
    let mut name = [0u8; NAME_SIZE + 1];
    read_kernel(task + layout.name, &mut name[..NAME_SIZE]);

    Task {
        id: read_id(task, layout),
        name,
        executable: unsafe { _get_task_exe_file(task as *mut c_void) },
    }
}

fn read_id(task: usize, layout: &Layout) -> u32 {
    let mut id = [0u8; 4];
    read_kernel(task + layout.id, &mut id);

    u32::from_ne_bytes(id)
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
}

fn discover_layout() -> Option<Layout> {
    let init = unsafe { _init_task } as usize;

    if let Some(layout) = described_layout(init) {
        return Some(layout);
    }

    let image = read_task_image(init);

    let name = find(&image, IDLE_TASK_NAME)?;
    let (list, id) = find_task_list(init, &image, name)?;

    Some(Layout { init, list, name, id })
}

fn described_layout(init: usize) -> Option<Layout> {

    Some(Layout {
        init,
        list: super::layout::field_offset("task_struct", "tasks")?,
        name: super::layout::field_offset("task_struct", "comm")?,
        id: super::layout::field_offset("task_struct", "pid")?,
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

    if !is_kernel_address(next) || !is_kernel_address(previous) || next == head {
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

fn is_kernel_address(address: usize) -> bool {
    address >= KERNEL_SPACE_START && address % WORD_SIZE == 0
}

const IDLE_TASK_NAME: &[u8] = b"swapper";
const NAME_SIZE: usize = 16;
const PATH_MAX: usize = 4096;

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

#[cfg(target_pointer_width = "64")]
const KERNEL_SPACE_START: usize = 0xffff_0000_0000_0000;
#[cfg(target_pointer_width = "32")]
const KERNEL_SPACE_START: usize = 0xc000_0000;

unsafe extern "C" {
    static _init_task: *const c_void;
    static _tasklist_lock: *mut c_void;
    static __raw_read_lock: unsafe extern "C" fn(*mut c_void);
    static __raw_read_unlock: unsafe extern "C" fn(*mut c_void);
    static _get_task_exe_file: unsafe extern "C" fn(*mut c_void) -> *mut c_void;
    static _file_path: unsafe extern "C" fn(*mut c_void, *mut c_char, c_int) -> *const c_char;
    static _fput: unsafe extern "C" fn(*mut c_void);
    static _copy_from_kernel_nofault:
        unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> c_long;
}
