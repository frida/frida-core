use core::ffi::{c_int, c_void};
use core::ptr;

use alloc::collections::BTreeMap;

use super::layout::{field_offset, struct_size};
use super::native;
use super::processes::task_with_id;
use super::arena::{Arena, HOME, REPORTED, WOKEN};
use super::user::entry_offset;

pub fn inject_into_process(id: u32) -> u32 {
    if let Some(placed) = unsafe { placements() }.get_mut(&id) {
        let home = pid_reported_by(placed);
        if home != 0 && placed.says.is_null() {
            take_what_the_copy_opened(placed);
        }

        return home;
    }

    let Some(task) = task_with_id(id) else {
        return 0;
    };
    let Some(home) = give_the_copy_a_home(task, id) else {
        return 0;
    };

    let placed = Placement {
        task,
        base: home.base,
        arena: home.arena,
        seen_by_the_copy: home.seen_by_the_copy,
        stack: home.stack,
        says: ptr::null_mut(),
        hears: ptr::null_mut(),
    };
    unsafe { placements() }.insert(id, placed);
    watch_the_threads();

    0
}

fn take_what_the_copy_opened(placed: &mut Placement) {
    let arena = Arena::at(placed.arena);

    placed.says = native::take_the_file(arena.says_through());
    placed.hears = native::take_the_file(arena.hears_through());
    listen_to_the_copy(placed.says);
}

fn listen_to_the_copy(says: *mut c_void) {
    native::spawn_thread(carry_what_the_copy_says, says);
}

unsafe extern "C" fn carry_what_the_copy_says(argument: *mut c_void, _reason: i32) {
    while native::wait_for_a_word(argument) {
        native::wake(argument as *const u8);
    }
}

struct Placement {
    task: usize,
    base: usize,
    arena: usize,
    seen_by_the_copy: usize,
    stack: usize,
    says: *mut c_void,
    hears: *mut c_void,
}

fn pid_reported_by(placed: &Placement) -> u32 {
    unsafe { ((placed.arena + REPORTED) as *const u32).read_volatile() }
}

// The copy is given a task of its own that shares the address space it was mapped into, so
// nothing of the target is borrowed and a target that never runs is no obstacle.
struct Home {
    base: usize,
    arena: usize,
    seen_by_the_copy: usize,
    stack: usize,
}

fn give_the_copy_a_home(task: usize, id: u32) -> Option<Home> {
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

fn map_and_start(id: u32) -> Option<Home> {
    let base = map_a_copy()?;
    let stack = map_a_stack()?;

    let where_the_copy_sees_it = base + crate::own_range().1;
    give(
        where_the_copy_sees_it + HOME,
        &id as *const u32 as usize,
        size_of::<u32>(),
    )?;
    let page = native::page_size() as u32;
    give(
        where_the_copy_sees_it + super::arena::PAGE_SIZE,
        &page as *const u32 as usize,
        size_of::<u32>(),
    )?;

    let arena = view_of(where_the_copy_sees_it)?;

    start(base, where_the_copy_sees_it, stack);

    Some(Home {
        base,
        arena,
        seen_by_the_copy: where_the_copy_sees_it,
        stack,
    })
}

// The kernel half reaches the same pages by an address of its own, so what the two leave for
// each other needs neither the address space borrowed nor a copy made.
fn borrowed_memory() -> Option<usize> {
    let at = field_offset("task_struct", "mm")?;

    Some(unsafe { ((native::current_task() as usize + at) as *const usize).read() })
}

fn view_of(seen_by_the_copy: usize) -> Option<usize> {
    let memory = borrowed_memory()?;
    let count = ARENA_SIZE / PAGE_SIZE;
    let pages = native::alloc(count * size_of::<usize>()) as *mut c_void;

    let reading = memory + field_offset("mm_struct", "mmap_lock")?;
    let held = unsafe {
        _down_read(reading as *mut c_void);
        let held = _get_user_pages_remote(
            memory as *mut c_void,
            seen_by_the_copy,
            count,
            FOLL_WRITE,
            pages,
            ptr::null_mut(),
        );
        _up_read(reading as *mut c_void);

        held
    };
    if held != count as isize {
        native::free(pages as *mut u8, count * size_of::<usize>());
        return None;
    }

    let view = native::map_pages(pages, count);
    native::free(pages as *mut u8, count * size_of::<usize>());

    if view.is_null() {
        return None;
    }

    Some(view as usize)
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
            bootstrap: base + entry_offset(),
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

pub fn arena_for_pid(id: u32) -> Option<u64> {
    unsafe { placements() }.get(&id).map(|placed| placed.arena as u64)
}

pub fn arenas() -> alloc::vec::Vec<u64> {
    unsafe { placements() }
        .values()
        .map(|placed| placed.arena as u64)
        .collect()
}

pub fn tell_the_copy_at(arena: u64) {
    let Some(id) = (unsafe { placements() })
        .iter()
        .find(|(_, placed)| placed.arena as u64 == arena)
        .map(|(id, _)| *id)
    else {
        return;
    };

    tell_the_copy(id);
}

pub fn a_copy_has_something_to_say() -> bool {
    unsafe { placements() }.values().any(|placed| what_it_says(placed).is_some())
}

pub fn report_what_the_copies_hit() {
    for placed in unsafe { placements() }.values() {
        let Some(hit) = what_it_says(placed) else {
            continue;
        };
        bump_to(placed.arena + super::arena::PROGRESS, NOTHING_MORE);

        let arena = Arena::at(placed.arena);
        let said = arena.said();
        if hit == super::user::SPOKE {
            native::log(&alloc::format!("copy in {}: {}\n", pid_reported_by(placed), said));
        } else if hit == super::user::PANICKED {
            native::log(&alloc::format!("copy in {} gave up: {}\n", pid_reported_by(placed), said));
        } else {
            let kind = read_address(placed.arena + super::arena::FAULT_KIND);
            native::log(&alloc::format!(
                "copy in {} died on signal {} ({}) at {:#x}, pc {:#x}, lr {:#x}, image at {:#x}, {}\n",
                pid_reported_by(placed),
                kind as u32,
                (kind >> 32) as u32,
                read_address(placed.arena + super::arena::FAULT_ADDRESS),
                read_address(placed.arena + super::arena::FAULT_PC),
                read_address(placed.arena + super::arena::FAULT_LR),
                placed.base,
                said
            ));
        }
    }
}

// A copy notes where it is on its way up as well, and those steps are not for reporting.
fn what_it_says(placed: &Placement) -> Option<u32> {
    let said = read_word(placed.arena + super::arena::PROGRESS);
    if said != super::user::FAULTED && said != super::user::PANICKED && said != super::user::SPOKE {
        return None;
    }

    Some(said)
}

fn bump_to(address: usize, value: u32) {
    unsafe { (address as *mut u32).write_volatile(value) };
}

const NOTHING_MORE: u32 = 0;

fn watch_the_threads() {
    if WATCHING.swap(true, core::sync::atomic::Ordering::AcqRel) {
        return;
    }

    unsafe {
        _tracepoint_probe_register(___tracepoint_sched_process_fork,
            a_thread_appeared as *mut c_void, ptr::null_mut());
        _tracepoint_probe_register(___tracepoint_sched_process_exit,
            a_thread_left as *mut c_void, ptr::null_mut());
    }
}

unsafe extern "C" fn a_thread_appeared(_data: *mut c_void, _parent: *mut c_void,
        child: *mut c_void) {
    note_a_thread(child as usize, false);
}

unsafe extern "C" fn a_thread_left(_data: *mut c_void, task: *mut c_void, _group_dead: bool) {
    note_a_thread(task as usize, true);
}

fn note_a_thread(task: usize, is_gone: bool) {
    let Some(home) = group_of(task) else {
        return;
    };
    let Some(thread) = id_of(task) else {
        return;
    };

    let Some(placed) = (unsafe { placements() }).get(&home) else {
        return;
    };

    Arena::at(placed.arena).note_a_thread(thread, is_gone);
    if !placed.hears.is_null() {
        native::leave_a_word(placed.hears);
    }
}

fn group_of(task: usize) -> Option<u32> {
    let at = field_offset("task_struct", "tgid")?;

    Some(unsafe { ((task + at) as *const u32).read() })
}

fn id_of(task: usize) -> Option<u32> {
    let at = field_offset("task_struct", "pid")?;

    Some(unsafe { ((task + at) as *const u32).read() })
}

static WATCHING: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn detach_from_process(id: u32) -> bool {
    let Some(placed) = (unsafe { placements() }.remove(&id)) else {
        return false;
    };

    let memory = unsafe { _get_task_mm(placed.task as *mut c_void) };
    ask_it_to_leave(&placed);
    take_back_what_it_was_given(&placed, memory);

    super::relay::forget(placed.arena as u64);

    true
}

fn ask_it_to_leave(placed: &Placement) {
    let arena = Arena::at(placed.arena);
    arena.tell_it_to_go();
    if !placed.hears.is_null() {
        native::leave_a_word(placed.hears);
    }

    let waited_on = &placed.arena as *const usize as *const u8;
    while !arena.has_gone() {
        native::wait(waited_on, Some(LEAVING_GRACE_US), &mut || arena.has_gone());
    }
}

fn take_back_what_it_was_given(placed: &Placement, memory: *mut c_void) {
    if !placed.says.is_null() {
        native::let_the_file_go(placed.says);
        native::let_the_file_go(placed.hears);
    }

    unsafe { _vunmap(placed.arena as *mut c_void) };

    if memory.is_null() {
        return;
    }

    let (_, image) = crate::own_range();
    unsafe {
        _kthread_use_mm(memory);
        _vm_munmap(placed.base, image + ARENA_SIZE);
        _vm_munmap(placed.stack + STACK_HEADROOM - STACK_SIZE, STACK_SIZE);
        _kthread_unuse_mm(memory);

        _mmput(memory);
    }
}

const LEAVING_GRACE_US: u64 = 100_000;

pub fn tell_the_copy(id: u32) {
    let Some(placed) = (unsafe { placements() }).get_mut(&id) else {
        return;
    };

    bump(placed.arena + WOKEN);
    if placed.hears.is_null() {
        return;
    }

    native::leave_a_word(placed.hears);
}

fn read_address(address: usize) -> u64 {
    unsafe { (address as *const u64).read_volatile() }
}

fn read_word(address: usize) -> u32 {
    unsafe { (address as *const u32).read_volatile() }
}

fn bump(address: usize) {
    unsafe { (address as *mut u32).write_volatile(read_word(address).wrapping_add(1)) };
}

unsafe fn placements() -> &'static mut BTreeMap<u32, Placement> {
    unsafe { (&raw mut PLACEMENTS).as_mut().unwrap() }
}

static mut PLACEMENTS: BTreeMap<u32, Placement> = BTreeMap::new();

const ARENA_SIZE: usize = 2 * 1024 * 1024;

const STACK_SPAN: usize = 16 * 1024;
const USER_EXECUTION: usize = 0;

const PROT_READ: usize = 1;
const PROT_WRITE: usize = 2;
const PROT_EXEC: usize = 4;
const MAP_PRIVATE: usize = 2;
const MAP_ANONYMOUS: usize = 0x20;
const FIRST_ERROR_ADDRESS: usize = usize::MAX - 4095;
const PAGE_SIZE: usize = 4096;
const FOLL_WRITE: c_int = 1;
const FUTEX_WAIT: c_int = 128;
const FUTEX_WAKE: c_int = 129;
const WAKE_EVERY_WAITER: u32 = i32::MAX as u32;

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
    static _vm_munmap: unsafe extern "C" fn(usize, usize) -> c_int;
    static _tracepoint_probe_register:
        unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> c_int;
    static ___tracepoint_sched_process_fork: *mut c_void;
    static ___tracepoint_sched_process_exit: *mut c_void;
    static _vunmap: unsafe extern "C" fn(*mut c_void);
    static ___arch_copy_to_user: unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> usize;
    static _down_read: unsafe extern "C" fn(*mut c_void);
    static _up_read: unsafe extern "C" fn(*mut c_void);
    static _get_user_pages_remote: unsafe extern "C" fn(
        *mut c_void,
        usize,
        usize,
        c_int,
        *mut c_void,
        *mut c_void,
    ) -> isize;
    static ___arch_copy_from_user:
        unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> usize;
    static _do_futex: unsafe extern "C" fn(usize, c_int, u32, usize, usize, u32, u32) -> isize;
    static _user_mode_thread:
        unsafe extern "C" fn(unsafe extern "C" fn(*mut c_void) -> c_int, *mut c_void, usize) -> c_int;
}
