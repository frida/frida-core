use core::ffi::{c_int, c_void};
use core::ptr;

use alloc::collections::BTreeMap;

use super::layout::{field_offset, struct_size};
use super::native;
use super::processes::task_with_id;
use super::user::bootstrap_offset;

pub fn inject_into_process(id: u32) -> u32 {
    if let Some(placed) = unsafe { placements() }.get(&id) {
        return pid_reported_by(placed);
    }

    let Some(task) = task_with_id(id) else {
        return 0;
    };
    let Some(base) = give_the_copy_a_home(task, id) else {
        return 0;
    };

    unsafe { placements() }.insert(id, Placement { task, base });

    0
}

struct Placement {
    task: usize,
    base: usize,
}

impl Placement {
    fn arena(&self) -> usize {
        self.base + crate::own_range().1
    }
}

fn pid_reported_by(placed: &Placement) -> u32 {
    let mut reported = [0u8; 4];
    unsafe {
        _access_process_vm(
            placed.task as *mut c_void,
            placed.arena() + ARENA_REPORTED_PID,
            reported.as_mut_ptr() as *mut c_void,
            reported.len(),
            0,
        )
    };

    u32::from_ne_bytes(reported)
}

// The copy is given a task of its own that shares the address space it was mapped into, so
// nothing of the target is borrowed and a target that never runs is no obstacle.
fn give_the_copy_a_home(task: usize, id: u32) -> Option<usize> {
    let memory = unsafe { _get_task_mm(task as *mut c_void) };
    if memory.is_null() {
        return None;
    }

    unsafe { _kthread_use_mm(memory) };
    let placed = map_and_start(id);
    unsafe { _kthread_unuse_mm(memory) };

    unsafe { _mmput(memory) };

    placed
}

fn map_and_start(id: u32) -> Option<usize> {
    let base = map_a_copy()?;
    let stack = map_a_stack()?;

    let arena = base + crate::own_range().1;
    give(arena + ARENA_HOME, &id as *const u32 as usize, size_of::<u32>())?;

    start(base, arena, stack);

    Some(base)
}

fn map_a_stack() -> Option<usize> {
    let base = unsafe {
        _vm_mmap(
            ptr::null_mut(),
            0,
            STACK_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            0,
        )
    };
    if base >= FIRST_ERROR_ADDRESS {
        return None;
    }

    Some(base + STACK_SIZE - STACK_HEADROOM)
}

fn map_a_copy() -> Option<usize> {
    let (own, size) = crate::own_range();
    let shared = crate::writable_half_start() - own;
    let private = crate::writable_half_size();

    let base = unsafe {
        _vm_mmap(
            ptr::null_mut(),
            0,
            size + ARENA_SIZE,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANONYMOUS,
            0,
        )
    };
    if base >= FIRST_ERROR_ADDRESS {
        return None;
    }

    give(base, own, shared)?;

    let rebased = native::alloc(private);
    unsafe { crate::install_writable_half(base, rebased as usize) };
    let handed_over = give(base + shared, rebased as usize, private);
    native::free(rebased, private);
    handed_over?;

    Some(base)
}

fn give(destination: usize, source: usize, size: usize) -> Option<()> {
    let left =
        unsafe { ___arch_copy_to_user(destination as *mut c_void, source as *const c_void, size) };
    if left != 0 {
        return None;
    }

    Some(())
}

fn start(base: usize, arena: usize, stack: usize) {
    let entry = native::alloc(size_of::<Entry>()) as *mut Entry;
    unsafe {
        entry.write(Entry {
            arena,
            bootstrap: base + bootstrap_offset(),
            stack,
        });

        _user_mode_thread(enter_user, entry as *mut c_void, CLONE_VM | CLONE_FS | CLONE_FILES);
    }
}

#[repr(C)]
struct Entry {
    arena: usize,
    bootstrap: usize,
    stack: usize,
}

// Runs on the new task before the kernel lets it out, which is where what it starts with in
// userland is written down.
unsafe extern "C" fn enter_user(argument: *mut c_void) -> c_int {
    let entry = argument as *mut Entry;
    let (arena, bootstrap, stack) = unsafe { ((*entry).arena, (*entry).bootstrap, (*entry).stack) };
    native::free(entry as *mut u8, size_of::<Entry>());

    let Some(places) = describe_registers() else {
        return 0;
    };
    let registers = registers_of_this_task(&places);

    unsafe {
        ((registers + places.pc) as *mut usize).write(bootstrap);
        ((registers + places.stack) as *mut usize).write(stack);
        ((registers + places.flags) as *mut usize).write(USER_EXECUTION);
        ((registers + places.first) as *mut usize).write(arena);
    }

    0
}

// What a task starts with in userland is at the top of the kernel stack it was given.
fn registers_of_this_task(places: &Places) -> usize {
    let stack = unsafe {
        ((native::current_task() as usize + places.stack_of_task) as *const usize).read()
    };

    stack + STACK_SPAN - places.size
}

struct Places {
    size: usize,
    first: usize,
    stack: usize,
    pc: usize,
    flags: usize,
    stack_of_task: usize,
}

fn describe_registers() -> Option<Places> {
    Some(Places {
        size: struct_size("pt_regs")?,
        first: field_offset("user_pt_regs", "regs")?,
        stack: field_offset("user_pt_regs", "sp")?,
        pc: field_offset("user_pt_regs", "pc")?,
        flags: field_offset("user_pt_regs", "pstate")?,
        stack_of_task: field_offset("task_struct", "stack")?,
    })
}

unsafe fn placements() -> &'static mut BTreeMap<u32, Placement> {
    unsafe { (&raw mut PLACEMENTS).as_mut().unwrap() }
}

static mut PLACEMENTS: BTreeMap<u32, Placement> = BTreeMap::new();

const ARENA_SIZE: usize = 2 * 1024 * 1024;
const ARENA_REPORTED_PID: usize = 0;
const ARENA_HOME: usize = 4;
const STACK_SPAN: usize = 16 * 1024;
const USER_EXECUTION: usize = 0;

const PROT_READ: usize = 1;
const PROT_WRITE: usize = 2;
const PROT_EXEC: usize = 4;
const MAP_PRIVATE: usize = 2;
const MAP_ANONYMOUS: usize = 0x20;
const FIRST_ERROR_ADDRESS: usize = usize::MAX - 4095;
const CLONE_VM: usize = 0x100;
const CLONE_FS: usize = 0x200;
const CLONE_FILES: usize = 0x400;
const STACK_SIZE: usize = 1024 * 1024;
const STACK_HEADROOM: usize = 16;

unsafe extern "C" {
    static _get_task_mm: unsafe extern "C" fn(*mut c_void) -> *mut c_void;
    static _kthread_use_mm: unsafe extern "C" fn(*mut c_void);
    static _kthread_unuse_mm: unsafe extern "C" fn(*mut c_void);
    static _mmput: unsafe extern "C" fn(*mut c_void);
    static _vm_mmap: unsafe extern "C" fn(*mut c_void, usize, usize, usize, usize, usize) -> usize;
    static ___arch_copy_to_user: unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> usize;
    static _access_process_vm:
        unsafe extern "C" fn(*mut c_void, usize, *mut c_void, usize, c_int) -> c_int;
    static _user_mode_thread:
        unsafe extern "C" fn(unsafe extern "C" fn(*mut c_void) -> c_int, *mut c_void, usize) -> c_int;
}
