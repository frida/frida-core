
use core::ffi::{c_int, c_void};

pub fn inject_into_process(id: u32) -> u32 {
    let Some(process) = process_with_id(id) else {
        return 0;
    };

    let placed = give_the_copy_a_home(process.map);
    unsafe { release_process(process.handle) };

    let Some(home) = placed else {
        return 0;
    };

    let arena = home.arena_here;
    let arena_here = arena;
    if !start(process.task, home) {
        return 0;
    }

    if !woke_up(arena_here) {
        return 0;
    }

    unsafe { arenas() }.insert(id, arena_here);


    id
}

pub fn echo_through_copy(id: u32, frame: &[u8], into: &mut [u8]) -> usize {
    let Some(arena) = arena_for_pid(id) else {
        return 0;
    };

    crate::xnu_relay::forward_frame(arena, frame);

    for _ in 0..LONG_ENOUGH {
        if let Some(said) = crate::xnu_relay::take_frame_from_target(arena) {
            let length = said.len().min(into.len());
            into[..length].copy_from_slice(&said[..length]);
            return length;
        }
        crate::kernel::yield_now();
    }

    0
}

pub fn process_id_according_to_copy(id: u32) -> u32 {
    let mut said = [0u8; 4];
    if echo_through_copy(id, b"pid", &mut said) != said.len() {
        return 0;
    }

    u32::from_le_bytes(said)
}

pub fn copy_can_take_memory(id: u32) -> bool {
    let mut said = [0u8; 8];
    echo_through_copy(id, b"mem", &mut said) == said.len() && said[0] == 1
}

pub fn threads_according_to_copy(id: u32) -> u32 {
    let mut said = [0u8; 4];
    if echo_through_copy(id, b"thr", &mut said) != said.len() {
        return 0;
    }

    u32::from_le_bytes(said)
}

pub fn process_is_alive(id: u32) -> bool {
    match process_with_id(id) {
        Some(process) => {
            unsafe { release_process(process.handle) };
            true
        }
        None => false,
    }
}

pub fn arena_for_pid(id: u32) -> Option<u64> {
    unsafe { arenas() }.get(&id).copied()
}

pub fn injected_arenas() -> alloc::vec::Vec<u64> {
    unsafe { arenas() }.values().copied().collect()
}

unsafe fn arenas() -> &'static mut alloc::collections::BTreeMap<u32, u64> {
    unsafe { (&raw mut ARENAS).as_mut().unwrap() }
}

static mut ARENAS: alloc::collections::BTreeMap<u32, u64> = alloc::collections::BTreeMap::new();

fn woke_up(arena: u64) -> bool {
    let is_up = &mut || unsafe { (arena as *const u64).read_volatile() } == crate::xnu_user::AWAKE;

    for _ in 0..MOMENTS_TO_WAIT {
        if is_up() {
            return true;
        }
        crate::kernel::wait(arena as *const u8, Some(A_MOMENT), is_up);
    }

    false
}

const A_MOMENT: u64 = 1000;
const MOMENTS_TO_WAIT: u32 = 30_000;

struct Process {
    handle: *mut c_void,
    task: *mut c_void,
    map: *mut c_void,
}

struct Home {
    code: u64,
    arena: u64,
    arena_here: u64,
    stack: u64,
}

fn process_with_id(id: u32) -> Option<Process> {
    let find = unsafe { _proc_find }?;
    let task_of = unsafe { _proc_task }?;
    let map_of = unsafe { _get_task_map }?;

    let handle = unsafe { find(id as c_int) };
    if handle.is_null() {
        return None;
    }

    let task = unsafe { task_of(handle) };
    Some(Process { handle, task, map: unsafe { map_of(task) } })
}

fn give_the_copy_a_home(map: *mut c_void) -> Option<Home> {
    let (base, size) = crate::own_range();

    let code = take_memory(map, size as u64)?;
    let seen_from_here = share(map, code, size as u64)?;
    lay_out_the_image(base, size, code, seen_from_here);

    let arena = take_memory(map, crate::xnu_relay::ARENA_SIZE)?;
    let arena_here = share(map, arena, crate::xnu_relay::ARENA_SIZE)?;
    unsafe {
        core::ptr::write_bytes(arena_here as *mut u8, 0, crate::xnu_relay::ARENA_SIZE as usize);
        ((arena_here + crate::xnu_relay::IMAGE_BASE) as *mut u64).write(code);
        ((arena_here + crate::xnu_relay::IMAGE_SIZE) as *mut u64).write(size as u64);
        ((arena_here + crate::xnu_relay::PAGE_SIZE) as *mut u64)
            .write(crate::gum::page_size_the_kernel_runs_with() as u64);
    }

    let stack = take_memory(map, STACK)?;

    let protect = unsafe { _mach_vm_protect }?;
    let shared = (crate::writable_half_start() - base) as u64;
    if unsafe { protect(map, code, shared, 0, READ | EXECUTE) } != KERN_SUCCESS {
        return None;
    }
    if unsafe { protect(map, code + shared, size as u64 - shared, 0, READ | WRITE) }
        != KERN_SUCCESS
    {
        return None;
    }

    Some(Home { code: code + crate::xnu_user::entry_offset() as u64, arena, arena_here, stack })
}

fn lay_out_the_image(base: usize, size: usize, code: u64, seen_from_here: u64) {
    let shared = crate::writable_half_start() - base;
    let private = crate::writable_half_size();

    unsafe {
        core::ptr::copy_nonoverlapping(base as *const u8, seen_from_here as *mut u8, shared);
        crate::install_writable_half(code as usize, (seen_from_here as usize) + shared);
        core::ptr::write_bytes(
            (seen_from_here as usize + shared + private) as *mut u8,
            0,
            size - shared - private,
        );
    }
}

fn share(map: *mut c_void, address: u64, size: u64) -> Option<u64> {
    let remap = unsafe { _mach_vm_remap }?;
    let ours = ourselves()?;

    let mut here: u64 = 0;
    let mut may: u32 = 0;
    let mut most: u32 = 0;
    let told = unsafe {
        remap(ours, &mut here as *mut u64, size, 0, ANYWHERE, map, address, SHARED,
            &mut may as *mut u32, &mut most as *mut u32, INHERIT_NONE)
    };
    if told != KERN_SUCCESS {
        return None;
    }

    Some(here)
}

fn take_memory(map: *mut c_void, size: u64) -> Option<u64> {
    let allocate = unsafe { _mach_vm_allocate }?;

    let mut address: u64 = 0;
    if unsafe { allocate(map, &mut address as *mut u64, size, ANYWHERE) } != KERN_SUCCESS {
        return None;
    }

    Some(address)
}

#[allow(dead_code)]
fn put(map: *mut c_void, bytes: &[u8]) -> Option<u64> {
    let copy_in = unsafe { _vm_map_copyin }?;
    let copy_out = unsafe { _vm_map_copyout }?;
    let ours = ourselves()?;

    let held = crate::kernel::alloc(PAGE as usize);
    unsafe {
        core::ptr::write_bytes(held, 0, PAGE as usize);
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), held, bytes.len());
    }

    let mut copy: *mut c_void = core::ptr::null_mut();
    let taken = unsafe { copy_in(ours, held as u64, PAGE, 0, &mut copy as *mut *mut c_void) };
    crate::kernel::free(held, PAGE as usize);
    if taken != KERN_SUCCESS {
        return None;
    }

    let mut landed: u64 = 0;
    if unsafe { copy_out(map, &mut landed as *mut u64, copy) } != KERN_SUCCESS {
        return None;
    }

    Some(landed)
}

fn ourselves() -> Option<*mut c_void> {
    let map_of = unsafe { _get_task_map }?;
    let task_of = unsafe { _current_task }?;

    Some(unsafe { map_of(task_of()) })
}

fn start(task: *mut c_void, home: Home) -> bool {
    start_a_thread(task, home.code, home.stack + STACK - 0x100, home.arena)
}

pub fn serve_thread_requests() {
    for (id, arena) in unsafe { arenas() }.clone() {
        let asked = |at: u64| unsafe { ((arena + at) as *const u64).read_volatile() };
        if asked(crate::xnu_relay::THREAD_WANTED) == crate::xnu_relay::NOTHING_WANTED {
            continue;
        }

        let started = match process_with_id(id) {
            Some(process) => {
                let made = start_a_thread(process.task, asked(crate::xnu_relay::THREAD_WANTED),
                    asked(crate::xnu_relay::THREAD_STACK),
                    asked(crate::xnu_relay::THREAD_ARGUMENT));
                unsafe { release_process(process.handle) };
                made
            }
            None => false,
        };

        unsafe {
            ((arena + crate::xnu_relay::THREAD_WANTED) as *mut u64)
                .write_volatile(crate::xnu_relay::NOTHING_WANTED);
            ((arena + crate::xnu_relay::THREAD_ANSWER) as *mut u64).write_volatile(
                if started { crate::xnu_relay::THREAD_STARTED } else { crate::xnu_relay::THREAD_REFUSED });
        }
    }
}

fn start_a_thread(task: *mut c_void, code: u64, stack: u64, argument: u64) -> bool {
    let create = unsafe { _thread_create };
    let set_state = unsafe { _thread_set_state };
    let resume = unsafe { _thread_resume };
    let (Some(create), Some(set_state), Some(resume)) = (create, set_state, resume) else {
        return false;
    };

    let mut thread: *mut c_void = core::ptr::null_mut();
    if unsafe { create(task, &mut thread as *mut *mut c_void) } != KERN_SUCCESS {
        return false;
    }

    let mut state = [0u32; STATE_WORDS];
    let places = state.as_mut_ptr() as *mut u8;
    unsafe {
        (places.add(STACK_POINTER) as *mut u64).write(stack);
        (places.add(PROGRAM_COUNTER) as *mut u64).write(code);
        (places as *mut u64).write(argument);
        (places.add(FLAGS) as *mut u32).write(PLAIN_ADDRESSES);
    }

    if unsafe { set_state(thread, ARM_THREAD_STATE64, state.as_ptr(), STATE_WORDS as c_int) }
        != KERN_SUCCESS
    {
        return false;
    }

    unsafe { resume(thread) == KERN_SUCCESS }
}

const PAGE: u64 = 0x4000;
const STACK: u64 = 8 * 1024 * 1024;
const KERN_SUCCESS: c_int = 0;
const ANYWHERE: c_int = 1;
const READ: c_int = 1;
const WRITE: c_int = 2;
const EXECUTE: c_int = 4;
const ARM_THREAD_STATE64: c_int = 6;
const SHARED: c_int = 0;
const LONG_ENOUGH: u32 = 100_000;
const INHERIT_NONE: c_int = 2;
const STATE_WORDS: usize = 68;
const STACK_POINTER: usize = 29 * 8 + 16;
const PROGRAM_COUNTER: usize = 29 * 8 + 24;
const FLAGS: usize = 29 * 8 + 36;
const PLAIN_ADDRESSES: u32 = 1;

unsafe fn release_process(handle: *mut c_void) {
    if let Some(release) = unsafe { _proc_rele } {
        unsafe { release(handle) };
    }
}

unsafe extern "C" {
    static _proc_find: Option<unsafe extern "C" fn(c_int) -> *mut c_void>;
    static _proc_rele: Option<unsafe extern "C" fn(*mut c_void)>;
    static _proc_task: Option<unsafe extern "C" fn(*mut c_void) -> *mut c_void>;
    static _current_task: Option<unsafe extern "C" fn() -> *mut c_void>;
    static _get_task_map: Option<unsafe extern "C" fn(*mut c_void) -> *mut c_void>;
    static _mach_vm_allocate: Option<unsafe extern "C" fn(*mut c_void, *mut u64, u64, c_int) -> c_int>;
    static _mach_vm_protect: Option<unsafe extern "C" fn(*mut c_void, u64, u64, c_int, c_int) -> c_int>;
    static _mach_vm_remap: Option<
        unsafe extern "C" fn(*mut c_void, *mut u64, u64, u64, c_int, *mut c_void, u64, c_int,
            *mut u32, *mut u32, c_int) -> c_int,
    >;
    static _vm_map_copyin: Option<unsafe extern "C" fn(*mut c_void, u64, u64, c_int, *mut *mut c_void) -> c_int>;
    static _vm_map_copyout: Option<unsafe extern "C" fn(*mut c_void, *mut u64, *mut c_void) -> c_int>;
    static _thread_create: Option<unsafe extern "C" fn(*mut c_void, *mut *mut c_void) -> c_int>;
    static _thread_set_state: Option<unsafe extern "C" fn(*mut c_void, c_int, *const u32, c_int) -> c_int>;
    static _thread_resume: Option<unsafe extern "C" fn(*mut c_void) -> c_int>;
}
