use core::ffi::{c_int, c_void};
use core::ptr;

use alloc::collections::BTreeMap;

use super::native;
use super::processes::task_with_id;

pub fn inject_into_process(id: u32) -> u32 {
    let Some(target) = (unsafe { placements() }).get(&id) else {
        let Some(task) = task_with_id(id) else {
            return 0;
        };
        let Some(placed) = place_in(task) else {
            return 0;
        };

        unsafe { placements() }.insert(id, Placement { task, base: placed });

        return 0;
    };

    let _ = target;

    0
}

pub struct Placement {
    pub task: usize,
    pub base: usize,
}

fn place_in(task: usize) -> Option<usize> {
    let memory = unsafe { _get_task_mm(task as *mut c_void) };
    if memory.is_null() {
        return None;
    }

    unsafe { _kthread_use_mm(memory) };
    let placed = map_a_copy();
    unsafe { _kthread_unuse_mm(memory) };

    unsafe { _mmput(memory) };

    placed
}

// The mapping takes the image as it stands, and then the half that gets written to as it was
// before this agent wrote to any of it, with every address in it moved to where the copy runs.
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
    let left = unsafe {
        ___arch_copy_to_user(destination as *mut c_void, source as *const c_void, size)
    };
    if left != 0 {
        return None;
    }

    Some(())
}

unsafe fn placements() -> &'static mut BTreeMap<u32, Placement> {
    unsafe { (&raw mut PLACEMENTS).as_mut().unwrap() }
}

static mut PLACEMENTS: BTreeMap<u32, Placement> = BTreeMap::new();

const ARENA_SIZE: usize = 2 * 1024 * 1024;
const PROT_READ: usize = 1;
const PROT_WRITE: usize = 2;
const PROT_EXEC: usize = 4;
const MAP_PRIVATE: usize = 2;
const MAP_ANONYMOUS: usize = 0x20;
const FIRST_ERROR_ADDRESS: usize = usize::MAX - 4095;

unsafe extern "C" {
    static _get_task_mm: unsafe extern "C" fn(*mut c_void) -> *mut c_void;
    static _kthread_use_mm: unsafe extern "C" fn(*mut c_void);
    static _kthread_unuse_mm: unsafe extern "C" fn(*mut c_void);
    static _mmput: unsafe extern "C" fn(*mut c_void);
    static _vm_mmap: unsafe extern "C" fn(*mut c_void, usize, usize, usize, usize, usize) -> usize;
    static ___arch_copy_to_user: unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> usize;
    static _access_process_vm:
        unsafe extern "C" fn(*mut c_void, usize, *mut c_void, usize, c_int) -> c_int;
}
