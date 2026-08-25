
use core::ffi::{c_char, c_int, c_void};

pub fn learn_where_the_threads_are() {
    if unsafe { THREADS_AT } != 0 {
        return;
    }

    let (Some(this_task), Some(this_thread)) = (unsafe { _current_task }, unsafe { _current_thread })
    else {
        return;
    };
    let (task, thread) = (unsafe { this_task() }, unsafe { this_thread() });
    if task.is_null() || thread.is_null() {
        return;
    }

    let thread = thread as usize;
    for step in 0..(HOW_FAR_INTO_A_TASK / 8) {
        let held = unsafe { ((task as *const usize).add(step)).read_volatile() };
        if held < thread || held >= thread + HOW_FAR_INTO_A_THREAD {
            continue;
        }

        unsafe {
            THREADS_AT = step * 8;
            LINKED_AT = held - thread;
        }
        return;
    }
}

fn each_thread_of(task: *mut c_void, found: &mut dyn FnMut(*mut c_void)) {
    let at = unsafe { THREADS_AT };
    if at == 0 {
        return;
    }

    let list = (task as usize) + at;
    let mut link = unsafe { (list as *const usize).read_volatile() };
    for _ in 0..MOST_THREADS_TO_FOLLOW {
        if link == list || link == 0 {
            return;
        }
        found((link - unsafe { LINKED_AT }) as *mut c_void);
        link = unsafe { (link as *const usize).read_volatile() };
    }
}

static mut THREADS_AT: usize = 0;
static mut LINKED_AT: usize = 0;

const HOW_FAR_INTO_A_TASK: usize = 0x800;
const HOW_FAR_INTO_A_THREAD: usize = 0x800;
const MOST_THREADS_TO_FOLLOW: usize = 64;

pub fn spawn_when_the_loop_can(request_id: u16, words: &[u8]) {
    let asked = each_word_asked_for();
    if words.len() > asked.len() {
        return;
    }
    asked.fill(0);
    asked[..words.len()].copy_from_slice(words);

    unsafe {
        ASKED_BY = request_id;
        ASKED_FOR = true;
    }
}

pub fn start_what_was_asked_for(say: &mut dyn FnMut(u16, u32)) {
    if !unsafe { ASKED_FOR } {
        return;
    }
    unsafe { ASKED_FOR = false };

    say(unsafe { ASKED_BY }, start_a_program());
}

fn start_a_program() -> u32 {
    gate_spawns(true);
    look_for_new_processes();

    let Some(arena) = a_process_that_can_start_one() else {
        return 0;
    };

    let words = each_word_asked_for();
    for (at, byte) in words.iter().enumerate() {
        unsafe { ((arena + crate::xnu_relay::SPAWN_WORDS + at as u64) as *mut u8)
            .write_volatile(*byte) };
    }

    let put = |at: u64, value: u64| unsafe {
        ((arena + at) as *mut u64).write_volatile(value)
    };
    put(crate::xnu_relay::SPAWN_ANSWER, crate::xnu_relay::NOTHING_WANTED);
    put(crate::xnu_relay::SPAWN_WANTED, 1);

    for _ in 0..LONG_ENOUGH_TO_START {
        let said = unsafe {
            ((arena + crate::xnu_relay::SPAWN_ANSWER) as *const u64).read_volatile()
        };
        if said == crate::xnu_relay::NOTHING_WANTED {
            crate::kernel::yield_now();
            continue;
        }

        put(crate::xnu_relay::SPAWN_WANTED, crate::xnu_relay::NOTHING_WANTED);
        if said != crate::xnu_relay::DONE {
            return 0;
        }
        return unsafe {
            ((arena + crate::xnu_relay::SPAWN_ID) as *const u64).read_volatile()
        } as u32;
    }

    0
}

fn a_process_that_can_start_one() -> Option<u64> {
    if let Some(arena) = crate::xnu_injection::arena_for_pid(THE_ONE_THAT_STARTS_THINGS) {
        return Some(arena);
    }

    crate::xnu_injection::inject_into_process(THE_ONE_THAT_STARTS_THINGS);

    crate::xnu_injection::arena_for_pid(THE_ONE_THAT_STARTS_THINGS)
}

fn each_word_asked_for() -> &'static mut [u8; WORD_ROOM] {
    unsafe { (&raw mut ASKED_WORDS).as_mut().unwrap() }
}

static mut ASKED_FOR: bool = false;
static mut ASKED_BY: u16 = 0;
static mut ASKED_WORDS: [u8; WORD_ROOM] = [0; WORD_ROOM];

const WORD_ROOM: usize = crate::xnu_relay::SPAWN_WORDS_ROOM as usize;
const THE_ONE_THAT_STARTS_THINGS: u32 = 1;
const LONG_ENOUGH_TO_START: usize = 20_000_000;

pub fn gate_spawns(on: bool) {
    unsafe { GATING = on };
}

pub fn look_for_new_processes() {
    if unsafe { GATING } {
        learn_where_the_threads_are();
        take_over_the_word_to_go();
    }
}

pub fn is_held(id: u32) -> bool {
    each_held().iter().any(|held| held.waiting && held.id == id)
}

pub fn a_spawn_is_held() -> bool {
    each_held().iter().any(|held| held.waiting && !held.told_of)
}

pub fn tell_of_held_spawns(say: &mut dyn FnMut(u32, &[u8])) {
    for held in each_held().iter_mut() {
        if !held.waiting || held.told_of {
            continue;
        }
        held.told_of = true;
        let length = held.name.iter().position(|byte| *byte == 0).unwrap_or(held.name.len());
        say(held.id, &held.name[..length]);
    }
}

pub fn resume_process(id: u32) -> bool {
    let Some(held) = each_held().iter_mut().find(|held| held.waiting && held.id == id) else {
        return false;
    };
    held.waiting = false;

    if held.holding_its_threads {
        if let Some(start) = unsafe { _thread_resume } {
            for thread in held.threads.iter().take_while(|thread| !thread.is_null()) {
                unsafe { start(*thread) };
            }
        }
        return true;
    }

    say_the_word(held.task, held.flags);

    true
}

fn say_the_word(task: *mut c_void, flags: u32) {
    if let Some(let_it_go) = unsafe { THE_WORD_TO_GO } {
        unsafe { let_it_go(task, flags) };
    }
}

fn take_over_the_word_to_go() {
    if unsafe { TAKEN_OVER } {
        return;
    }
    unsafe { TAKEN_OVER = true };

    let Some(word) = (unsafe { _task_clear_return_wait }) else {
        return;
    };

    unsafe {
        let interceptor = crate::bindings::gum_interceptor_obtain();
        crate::bindings::gum_interceptor_begin_transaction(interceptor);
        crate::bindings::gum_interceptor_replace(interceptor, word as *mut c_void,
            hold_or_let_run as *mut c_void, (&raw mut THE_WORD_TO_GO) as *mut *mut c_void,
            core::ptr::null_mut());
        crate::bindings::gum_interceptor_end_transaction(interceptor);
    }
}

unsafe extern "C" fn hold_or_let_run(task: *mut c_void, flags: u32) {
    if !unsafe { GATING } || (flags & THE_LAST_WORD) == 0 {
        say_the_word(task, flags);
        return;
    }

    let Some(held) = note_it(task, flags) else {
        say_the_word(task, flags);
        return;
    };

    if held.holding_its_threads {
        say_the_word(task, flags);
    }
}

fn note_it(task: *mut c_void, flags: u32) -> Option<&'static Held> {
    let (Some(process_of), Some(number_of), Some(name_of)) =
        (unsafe { _get_bsdtask_info }, unsafe { _proc_pid }, unsafe { _proc_best_name })
    else {
        return None;
    };

    let process = unsafe { process_of(task) };
    if process.is_null() {
        return None;
    }

    let Some(held) = each_held().iter_mut().find(|held| !held.waiting) else {
        return None;
    };

    held.id = unsafe { number_of(process) } as u32;
    held.task = task;
    held.flags = flags;
    held.told_of = false;
    held.name = [0; NAME_ROOM];

    let said = unsafe { name_of(process) } as *const u8;
    for (at, letter) in held.name.iter_mut().enumerate().take(NAME_ROOM - 1) {
        let byte = unsafe { said.add(at).read() };
        if byte == 0 {
            break;
        }
        *letter = byte;
    }

    held.threads = [core::ptr::null_mut(); MOST_THREADS_HELD];
    held.holding_its_threads = false;

    if let Some(stop) = unsafe { _thread_suspend } {
        let mut how_many = 0;
        each_thread_of(task, &mut |thread| {
            if how_many < MOST_THREADS_HELD && unsafe { stop(thread) } == KERN_SUCCESS {
                held.threads[how_many] = thread;
                how_many += 1;
            }
        });
        held.holding_its_threads = how_many != 0;
    }

    held.waiting = true;

    Some(held)
}

fn each_held() -> &'static mut [Held; HOW_MANY_AT_ONCE] {
    unsafe { (&raw mut HELD).as_mut().unwrap() }
}

#[derive(Clone, Copy)]
struct Held {
    id: u32,
    name: [u8; NAME_ROOM],
    task: *mut c_void,
    threads: [*mut c_void; MOST_THREADS_HELD],
    flags: u32,
    waiting: bool,
    told_of: bool,
    holding_its_threads: bool,
}

static mut GATING: bool = false;
static mut TAKEN_OVER: bool = false;
static mut THE_WORD_TO_GO: Option<unsafe extern "C" fn(*mut c_void, u32)> = None;
static mut HELD: [Held; HOW_MANY_AT_ONCE] = [Held {
    id: 0,
    name: [0; NAME_ROOM],
    task: core::ptr::null_mut(),
    threads: [core::ptr::null_mut(); MOST_THREADS_HELD],
    flags: 0,
    waiting: false,
    told_of: false,
    holding_its_threads: false,
}; HOW_MANY_AT_ONCE];

const HOW_MANY_AT_ONCE: usize = 64;
const MOST_THREADS_HELD: usize = 8;
const KERN_SUCCESS: c_int = 0;
const NAME_ROOM: usize = 64;
const THE_LAST_WORD: u32 = 0x2;

unsafe extern "C" {
    static _task_clear_return_wait: Option<unsafe extern "C" fn(*mut c_void, u32)>;
    static _get_bsdtask_info: Option<unsafe extern "C" fn(*mut c_void) -> *mut c_void>;
    static _proc_pid: Option<unsafe extern "C" fn(*mut c_void) -> c_int>;
    static _proc_best_name: Option<unsafe extern "C" fn(*mut c_void) -> *const c_char>;
    static _current_task: Option<unsafe extern "C" fn() -> *mut c_void>;
    static _current_thread: Option<unsafe extern "C" fn() -> *mut c_void>;
    static _thread_suspend: Option<unsafe extern "C" fn(*mut c_void) -> c_int>;
    static _thread_resume: Option<unsafe extern "C" fn(*mut c_void) -> c_int>;
}
