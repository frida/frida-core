
use core::ffi::{c_int, c_void};

pub fn inject_into_process(id: u32) -> u32 {
    crate::xnu_bell::hang_the_bell();
    crate::xnu_hiding::hide_our_threads();

    let Some(process) = process_with_id(id) else {
        return 0;
    };

    let placed = give_the_copy_a_home(id, process.map);
    unsafe { release_process(process.handle) };

    let Some(home) = placed else {
        return 0;
    };

    let arena_here = home.arena_here;
    let seen_from_here = home.image_here;

    let before = look_at_the_task(process.task);
    let Some(bare_thread) = start(process.task, &home) else {
        return 0;
    };
    learn_where_the_threads_are_counted(&before, &look_at_the_task(process.task));
    crate::xnu_hiding::a_thread_of_ours(bare_thread);


    if !woke_up(id, arena_here) {
        return 0;
    }



    unsafe { arenas() }.insert(id, Placed {
        arena: arena_here,
        image_here: seen_from_here,
        code: home.image,
        in_the_process: home.arena,
        stack: home.stack,
        bare_thread,
    });

    id
}

pub fn a_copy_that_can_start_a_program() -> Option<u64> {
    a_copy_in(THE_ONE_THAT_STARTS_THINGS)
}

pub fn a_copy_that_can_ask_the_system() -> Option<u64> {
    let mut asked = unsafe { ASKED };
    if asked == 0 || !process_is_alive(asked) {
        asked = the_one_that_shows_applications();
        unsafe { ASKED = asked };
    }

    a_copy_in(asked)
}

fn the_one_that_shows_applications() -> u32 {
    let mut found = 0;
    for wanted in [b"backboardd".as_slice(), b"SpringBoard"] {
        crate::xnu_processes::enumerate_processes(&mut |process| {
            if found == 0 && called(process.name, wanted) {
                found = process.id;
            }
        });
        if found != 0 {
            return found;
        }
    }

    found
}

fn called(name: *const u8, wanted: &[u8]) -> bool {
    for (step, byte) in wanted.iter().enumerate() {
        if unsafe { name.add(step).read() } != *byte {
            return false;
        }
    }

    unsafe { name.add(wanted.len()).read() == 0 }
}

fn a_copy_in(id: u32) -> Option<u64> {
    if let Some(arena) = arena_for_pid(id) {
        return Some(arena);
    }

    inject_into_process(id);

    arena_for_pid(id)
}

static mut ASKED: u32 = 0;

const THE_ONE_THAT_STARTS_THINGS: u32 = 1;


pub fn stop_copies() {
    let everywhere: alloc::vec::Vec<u32> = unsafe { arenas() }.keys().copied().collect();
    for id in everywhere {
        detach_from_process(id);
    }
}

pub fn detach_from_process(id: u32) -> bool {
    let Some(placed) = unsafe { arenas() }.remove(&id) else {
        return false;
    };

    tell_it_to_go(id, &placed);
    take_back_what_it_was_given(id, &placed);
    crate::xnu_relay::forget(placed.arena);

    true
}

fn tell_it_to_go(id: u32, placed: &Placed) {
    if !process_is_alive(id) {
        return;
    }

    unsafe {
        ((placed.arena + crate::xnu_relay::STOP_REQUEST) as *mut u32).write_volatile(1)
    };

    wake_the_copy_in(id, placed.arena, placed.in_the_process);

    let has_stopped = &mut || unsafe {
        ((placed.arena + crate::xnu_relay::WORKER_STOPPED) as *const u32).read_volatile()
    } != 0;

    let began = crate::kernel::monotonic_micros();
    while !has_stopped() {
        let waited = (crate::kernel::monotonic_micros() - began) as u64;
        if waited >= LONG_ENOUGH_TO_LEAVE || !process_is_alive(id) {
            return;
        }
        crate::kernel::wait(crate::glib::wakeup_token(), Some(LONG_ENOUGH_TO_LEAVE - waited),
            has_stopped);
    }
}

const LONG_ENOUGH_TO_LEAVE: u64 = 2_000_000;

fn take_back_what_it_was_given(id: u32, placed: &Placed) {
    crate::xnu_hiding::forget_the_threads_of(placed.arena);
    crate::xnu_hiding::no_longer_a_thread_of_ours(placed.bare_thread);

    if let Some(terminate) = unsafe { _thread_terminate } {
        unsafe { terminate(placed.bare_thread) };
    }

    unsafe { give_memory_back(ourselves(), placed.image_here, crate::own_range().1 as u64) };
    unsafe { give_memory_back(ourselves(), placed.arena, crate::xnu_relay::ARENA_SIZE) };

    let Some(process) = process_with_id(id) else {
        return;
    };
    let map = Some(process.map);
    unsafe {
        give_memory_back(map, placed.code, crate::own_range().1 as u64);
        give_memory_back(map, placed.in_the_process, crate::xnu_relay::ARENA_SIZE);
        give_memory_back(map, placed.stack, STACK);
        release_process(process.handle);
    }
}

unsafe fn give_memory_back(map: Option<*mut c_void>, address: u64, size: u64) {
    let (Some(map), Some(deallocate)) = (map, unsafe { _mach_vm_deallocate }) else {
        return;
    };

    unsafe { deallocate(map, address, size) };
}

pub fn echo_through_copy(id: u32, frame: &[u8], into: &mut [u8]) -> usize {
    let Some(arena) = arena_for_pid(id) else {
        return 0;
    };

    crate::xnu_relay::forward_frame(arena, frame);

    let answered = &mut || crate::xnu_relay::holds_a_frame_from_target(arena);
    for _ in 0..LONG_ENOUGH {
        if let Some(said) = crate::xnu_relay::take_frame_from_target(arena) {
            let length = said.len().min(into.len());
            into[..length].copy_from_slice(&said[..length]);
            return length;
        }
        crate::kernel::wait(crate::glib::wakeup_token(), None, answered);
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

pub fn wake_the_copy_at(arena: u64) {
    let Some((id, theirs)) = unsafe { arenas() }.iter()
        .find(|(_, placed)| placed.arena == arena)
        .map(|(id, placed)| (*id, placed.in_the_process))
    else {
        return;
    };

    wake_the_copy_in(id, arena, theirs);
}

fn wake_the_copy_in(id: u32, ours: u64, theirs: u64) {
    let Some(process) = process_with_id(id) else {
        return;
    };

    if let Some(process_of) = unsafe { crate::xnu_spawn::_get_bsdtask_info } {
        crate::xnu_bell::wake_the_copy(unsafe { process_of(process.task) }, ours, theirs);
    }

    unsafe { release_process(process.handle) };
}

pub fn arena_for_pid(id: u32) -> Option<u64> {
    unsafe { arenas() }.get(&id).map(|placed| placed.arena)
}

pub fn a_copy_is_asking_for_something() -> bool {
    unsafe { arenas() }.values().any(|placed| unsafe {
        ((placed.arena + crate::xnu_relay::PROTECT_WANTED) as *const u64).read_volatile()
    } != crate::xnu_relay::NOTHING_WANTED)
}

pub fn injected_arenas() -> alloc::vec::Vec<u64> {
    unsafe { arenas() }.values().map(|placed| placed.arena).collect()
}

unsafe fn arenas() -> &'static mut alloc::collections::BTreeMap<u32, Placed> {
    unsafe { (&raw mut ARENAS).as_mut().unwrap() }
}

static mut ARENAS: alloc::collections::BTreeMap<u32, Placed> = alloc::collections::BTreeMap::new();

fn woke_up(id: u32, arena: u64) -> bool {
    let is_up = &mut || unsafe { (arena as *const u64).read_volatile() } == crate::xnu_user::AWAKE;

    let began = crate::kernel::monotonic_micros();
    while !is_up() {
        let waited = (crate::kernel::monotonic_micros() - began) as u64;
        if waited >= LONG_ENOUGH_TO_COME_UP || !process_is_alive(id) {
            return false;
        }
        crate::kernel::wait(crate::glib::wakeup_token(),
            Some(LONG_ENOUGH_TO_COME_UP - waited), is_up);
    }

    true
}

const LONG_ENOUGH_TO_COME_UP: u64 = 10_000_000;

pub struct Process {
    pub handle: *mut c_void,
    pub task: *mut c_void,
    pub map: *mut c_void,
}

#[derive(Clone)]
struct Placed {
    arena: u64,
    image_here: u64,
    code: u64,
    in_the_process: u64,
    stack: u64,
    bare_thread: *mut c_void,
}

struct Home {
    image: u64,
    image_here: u64,
    code: u64,
    arena: u64,
    arena_here: u64,
    stack: u64,
}

pub fn process_with_id(id: u32) -> Option<Process> {
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

fn give_the_copy_a_home(id: u32, map: *mut c_void) -> Option<Home> {
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
        ((arena_here + crate::xnu_relay::CACHE_SHAPE) as *mut u64)
            .write(crate::xnu::kernel_cache_shape());
        ((arena_here + crate::xnu_relay::HAS_RUN) as *mut u32).write(1);
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

    Some(Home {
        image: code,
        image_here: seen_from_here,
        code: code + crate::xnu_user::entry_offset() as u64,
        arena,
        arena_here,
        stack,
    })
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

fn look_at_the_task(task: *mut c_void) -> alloc::vec::Vec<u32> {
    (0..HOW_FAR_INTO_A_TASK)
        .map(|step| unsafe { ((task as *const u32).add(step)).read_volatile() })
        .collect()
}

fn learn_where_the_threads_are_counted(before: &[u32], after: &[u32]) {
    if unsafe { WHERE_THEY_ARE_COUNTED } != 0 {
        return;
    }

    for step in 0..before.len() - 1 {
        let went_up = |at: usize| after[at] == before[at].wrapping_add(1);
        if before[step] == before[step + 1] && went_up(step) && went_up(step + 1) {
            unsafe { WHERE_THEY_ARE_COUNTED = step * 4 };
            return;
        }
    }
}

pub fn count_only_what_the_process_made(task: *mut c_void) -> Option<(u32, u32)> {
    let at = unsafe { WHERE_THEY_ARE_COUNTED };
    if at == 0 || !any_copy_is_in(task) {
        return None;
    }

    let counted = ((task as usize) + at) as *mut u32;
    let kept = unsafe { (counted.read_volatile(), counted.add(1).read_volatile()) };
    unsafe {
        counted.write_volatile(1);
        counted.add(1).write_volatile(1);
    }

    Some(kept)
}

pub fn count_them_all_again(task: *mut c_void, kept: (u32, u32)) {
    let at = unsafe { WHERE_THEY_ARE_COUNTED };
    if at == 0 {
        return;
    }

    let counted = ((task as usize) + at) as *mut u32;
    unsafe {
        counted.write_volatile(kept.0);
        counted.add(1).write_volatile(kept.1);
    }
}

fn any_copy_is_in(task: *mut c_void) -> bool {
    unsafe { arenas() }.keys().any(|id| {
        match process_with_id(*id) {
            Some(process) => {
                let ours = process.task == task;
                unsafe { release_process(process.handle) };
                ours
            }
            None => false,
        }
    })
}

static mut WHERE_THEY_ARE_COUNTED: usize = 0;

const HOW_FAR_INTO_A_TASK: usize = 0x400;

fn start(task: *mut c_void, home: &Home) -> Option<*mut c_void> {
    start_a_thread(task, home.code, home.stack + STACK - 0x100, home.arena)
}

pub fn serve_what_the_copies_ask() {
    for placed in unsafe { arenas() }.values() {
        crate::xnu_hiding::take_note_of_what_a_copy_says(placed.arena);
    }

    let asked: alloc::vec::Vec<(u32, u64)> = unsafe { arenas() }
        .iter()
        .map(|(id, placed)| (*id, placed.arena))
        .collect();
    for (id, arena) in asked {
        let asked = |at: u64| unsafe { ((arena + at) as *const u64).read_volatile() };
        let wants_protection = asked(crate::xnu_relay::PROTECT_WANTED);
        if wants_protection == crate::xnu_relay::NOTHING_WANTED {
            continue;
        }

        let Some(process) = process_with_id(id) else {
            continue;
        };

        let done = set_protection(process.map, wants_protection,
            asked(crate::xnu_relay::PROTECT_SIZE), asked(crate::xnu_relay::PROTECT_TO) as c_int);
        answer(arena, crate::xnu_relay::PROTECT_WANTED, crate::xnu_relay::PROTECT_ANSWER, done);
        wake_the_copy_at(arena);

        unsafe { release_process(process.handle) };
    }
}

fn set_protection(map: *mut c_void, address: u64, size: u64, may: c_int) -> bool {
    let Some(protect) = (unsafe { _mach_vm_protect }) else {
        return false;
    };

    let asking = if (may & WRITE) != 0 { may | A_COPY_OF_ITS_OWN } else { may };
    if unsafe { protect(map, address, size, 0, asking) } == KERN_SUCCESS {
        return true;
    }

    unsafe { protect(map, address, size, AS_HIGH_AS_IT_GOES, READ | WRITE | EXECUTE) };

    unsafe { protect(map, address, size, 0, asking) == KERN_SUCCESS }
}

fn answer(arena: u64, asked_at: u64, answer_at: u64, went_well: bool) {
    unsafe {
        ((arena + asked_at) as *mut u64).write_volatile(crate::xnu_relay::NOTHING_WANTED);
        ((arena + answer_at) as *mut u64).write_volatile(
            if went_well { crate::xnu_relay::DONE } else { crate::xnu_relay::REFUSED });
    }
}

fn start_a_thread(task: *mut c_void, code: u64, stack: u64, argument: u64) -> Option<*mut c_void> {
    let create = unsafe { _thread_create };
    let set_state = unsafe { _thread_set_state };
    let resume = unsafe { _thread_resume };
    let (Some(create), Some(set_state), Some(resume)) = (create, set_state, resume) else {
        return None;
    };

    let mut thread: *mut c_void = core::ptr::null_mut();
    if unsafe { create(task, &mut thread as *mut *mut c_void) } != KERN_SUCCESS {
        return None;
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
        return None;
    }

    (unsafe { resume(thread) } == KERN_SUCCESS).then_some(thread)
}

const PAGE: u64 = 0x4000;
const STACK: u64 = 8 * 1024 * 1024;
const KERN_SUCCESS: c_int = 0;
const ANYWHERE: c_int = 1;
const AS_HIGH_AS_IT_GOES: c_int = 1;
const A_COPY_OF_ITS_OWN: c_int = 0x10;
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

pub unsafe fn release_process(handle: *mut c_void) {
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
    static _mach_vm_deallocate: Option<unsafe extern "C" fn(*mut c_void, u64, u64) -> c_int>;
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
    static _thread_terminate: Option<unsafe extern "C" fn(*mut c_void) -> c_int>;
}
