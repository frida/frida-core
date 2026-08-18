// The half of the Win9x agent that runs in ring 3, inside a process the host attached to. It
// reaches nothing of the kernel's, thus it has primitives of its own, which frida_win9x_user_main
// selects before it does anything else.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::sync::atomic::Ordering;

use crate::kernel::ThreadEntry;
use crate::win9x::*;

// No code in this image calls the ring 3 entry point, thus tell the linker to keep it.
#[used]
static USER_ENTRY: extern "C" fn(u32) = frida_win9x_user_main;

// This is the ring 3 half. It has its own copy of the image, thus its data is its own. Only
// the primitives that need the kernel are different.
#[unsafe(no_mangle)]
pub extern "C" fn frida_win9x_user_main(arena: u32) {
    select_user();
    resolve_user_api();
    unsafe { crate::init_gum_without_exceptor() };

    let sleep: unsafe extern "stdcall" fn(u32) =
        unsafe { core::mem::transmute(user_api().sleep as usize) };

    // This thread waits for the host. Do not use yield_now() here, because that rate makes the
    // guest slow.
    unsafe { ((arena + RUNNING_FLAG) as *mut u32).write_volatile(1) };
    while unsafe { ((arena + GO_FLAG) as *const u32).read_volatile() } == 0 {
        unsafe { sleep(PARKED_SLEEP_MS) };
    }

    spawn_thread(user_worker, arena as *mut c_void);

    while unsafe { ((arena + STOP_REQUEST) as *const u32).read_volatile() } == 0 {
        unsafe { sleep(PARKED_SLEEP_MS) };
    }

    // The stub that called this function ends with a loop, thus a return keeps the thread in the
    // arena.
    let exit_thread: unsafe extern "stdcall" fn(u32) -> ! =
        unsafe { core::mem::transmute(user_api().exit_thread as usize) };
    unsafe { ((arena + MAIN_STOPPED) as *mut u32).write_volatile(1) };
    unsafe { exit_thread(0) };
}

// The group that the user-mode half runs on. The order is the order in Primitives.
pub static USER: Primitives = Primitives {
    alloc,
    free,
    alloc_code,
    free_code,
    spawn_thread,
    wait,
    wake,
    yield_now,
    monotonic_micros,
    current_process_id,
    current_thread_id,
    protect,
    protection_at,
    enumerate_ranges,
};

unsafe extern "C" fn user_worker(parameter: *mut c_void, _wait_result: i32) {
    let arena = parameter as u32;
    let context = unsafe { crate::adopt_js_context() };

    unsafe { ((arena + OBSERVED_PID) as *mut u32).write_volatile(current_process_id()) };

    unsafe { crate::route_frames_through(arena as u64) };

    while unsafe { ((arena + STOP_REQUEST) as *const u32).read_volatile() } == 0 {
        if let Some(frame) = take_frame_from_host(arena as u64) {
            crate::on_frame_from_host(frame);
            acknowledge_frame_from_host(arena as u64);
        }

        unsafe { crate::poll_pending_work(context) };
    }

    unsafe { ((arena + WORKER_STOPPED) as *mut u32).write_volatile(1) };
}

unsafe extern "stdcall" fn frida_win9x_user_thread(start: *mut c_void) -> u32 {
    let start = start as *mut UserThreadStart;
    let UserThreadStart { entry, parameter } = unsafe { start.read() };
    free(start as *mut u8, core::mem::size_of::<UserThreadStart>());

    unsafe { entry(parameter, 0) };

    0
}

struct UserThreadStart {
    entry: ThreadEntry,
    parameter: *mut c_void,
}

fn enumerate_ranges(found: &mut dyn FnMut(u64, u64, u32)) {
    let mut address = 0usize;
    loop {
        let Some(region) = describe_region(address) else {
            return;
        };

        if region.protection != 0 {
            found(region.base as u64, region.size as u64, region.protection);
        }

        address = region.base + region.size;
    }
}

fn protection_at(address: usize) -> u32 {
    match describe_region(address) {
        Some(region) => region.protection,
        None => 0,
    }
}

fn describe_region(address: usize) -> Option<Region> {
    let mut info = [0u32; REGION_WORDS];
    let query: extern "stdcall" fn(usize, *mut u32, u32) -> u32 =
        unsafe { core::mem::transmute(user_api().virtual_query) };
    if query(address, info.as_mut_ptr(), (REGION_WORDS * 4) as u32) == 0 {
        return None;
    }

    Some(Region {
        base: info[REGION_BASE] as usize,
        size: info[REGION_SIZE] as usize,
        protection: if info[REGION_STATE] == MEM_COMMIT {
            gum_protection_of(info[REGION_PROTECTION])
        } else {
            0
        },
    })
}

fn gum_protection_of(protection: u32) -> u32 {
    match protection & 0xff {
        PAGE_READONLY | PAGE_EXECUTE_READ => GUM_PAGE_READ | GUM_PAGE_EXECUTE,
        PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY =>
            GUM_PAGE_READ | GUM_PAGE_WRITE | GUM_PAGE_EXECUTE,
        PAGE_EXECUTE => GUM_PAGE_READ | GUM_PAGE_EXECUTE,
        _ => 0,
    }
}

struct Region {
    base: usize,
    size: usize,
    protection: u32,
}

const REGION_WORDS: usize = 7;
const REGION_BASE: usize = 0;
const REGION_SIZE: usize = 3;
const REGION_STATE: usize = 4;
const REGION_PROTECTION: usize = 5;
const MEM_COMMIT: u32 = 0x1000;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_WRITECOPY: u32 = 0x08;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
const GUM_PAGE_READ: u32 = 0x1;
const GUM_PAGE_WRITE: u32 = 0x2;
const GUM_PAGE_EXECUTE: u32 = 0x4;

fn resolve_user_api() {
    unsafe {
        USER_API = UserApi {
            sleep: kernel32_export(b"Sleep"),
            get_tick_count: kernel32_export(b"GetTickCount"),
            get_current_thread_id: kernel32_export(b"GetCurrentThreadId"),
            get_current_process_id: kernel32_export(b"GetCurrentProcessId"),
            get_process_heap: kernel32_export(b"GetProcessHeap"),
            heap_alloc: kernel32_export(b"HeapAlloc"),
            heap_free: kernel32_export(b"HeapFree"),
            virtual_alloc: kernel32_export(b"VirtualAlloc"),
            virtual_free: kernel32_export(b"VirtualFree"),
            virtual_protect: kernel32_export(b"VirtualProtect"),
            virtual_query: kernel32_export(b"VirtualQuery"),
            create_thread: kernel32_export(b"CreateThread"),
            create_process: kernel32_export(b"CreateProcessA"),
            resume_thread: kernel32_export(b"ResumeThread"),
            create_event: kernel32_export(b"CreateEventA"),
            set_event: kernel32_export(b"SetEvent"),
            wait_for_single_object: kernel32_export(b"WaitForSingleObject"),
            exit_thread: kernel32_export(b"ExitThread"),
            close_handle: kernel32_export(b"CloseHandle"),
        };
    }
}

fn user_api() -> &'static UserApi {
    unsafe { &*core::ptr::addr_of!(USER_API) }
}

struct UserApi {
    sleep: u32,
    get_tick_count: u32,
    get_current_thread_id: u32,
    get_current_process_id: u32,
    get_process_heap: u32,
    heap_alloc: u32,
    heap_free: u32,
    virtual_alloc: u32,
    virtual_free: u32,
    virtual_protect: u32,
    virtual_query: u32,
    create_thread: u32,
    create_process: u32,
    resume_thread: u32,
    create_event: u32,
    set_event: u32,
    wait_for_single_object: u32,
    exit_thread: u32,
    close_handle: u32,
}

static mut USER_API: UserApi = UserApi {
    sleep: 0,
    get_tick_count: 0,
    get_current_thread_id: 0,
    get_current_process_id: 0,
    get_process_heap: 0,
    heap_alloc: 0,
    heap_free: 0,
    virtual_alloc: 0,
    virtual_free: 0,
    virtual_protect: 0,
    virtual_query: 0,
    create_thread: 0,
    create_process: 0,
    resume_thread: 0,
    create_event: 0,
    set_event: 0,
    wait_for_single_object: 0,
    exit_thread: 0,
    close_handle: 0,
};

fn event_for(token: *const u8) -> u32 {
    let slot = (token as usize / core::mem::align_of::<usize>()) % EVENTS.len();
    let existing = EVENTS[slot].load(Ordering::Acquire);
    if existing != 0 {
        return existing;
    }

    let create_event: unsafe extern "stdcall" fn(u32, u32, u32, u32) -> u32 =
        unsafe { core::mem::transmute(user_api().create_event as usize) };
    let created = unsafe { create_event(0, 0, 0, 0) };
    match EVENTS[slot].compare_exchange(0, created, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => created,
        Err(raced) => raced,
    }
}

// What a process has mapped is written down where only ring 0 can read it. Thus the kernel half
// hands the list over, and this side only reads it.
pub fn enumerate_modules() -> Vec<LoadedModule> {
    let mut modules = Vec::new();

    let list = unsafe { ((crate::routed_arena() as u32 + MODULE_LIST) as *const u32).read() };
    if list == 0 {
        return modules;
    }

    let mut cursor = list + 4;
    let count = read_word(list);
    for _ in 0..count {
        let base = read_word(cursor);
        let size = read_word(cursor + 4);
        let length = read_word(cursor + 8) as usize;
        let path = unsafe {
            core::slice::from_raw_parts((cursor + 12) as *const u8, length)
        };
        modules.push(LoadedModule {
            path: String::from_utf8_lossy(path).into_owned(),
            base: base as u64,
            size: size as u64,
        });
        cursor += 12 + length as u32;
    }

    modules
}

fn read_word(address: u32) -> u32 {
    unsafe { (address as *const u32).read() }
}

pub struct LoadedModule {
    pub path: String,
    pub base: u64,
    pub size: u64,
}

// A process starts held, thus a caller can attach to it before it runs any of its own code.
// The wide entry points of this system are stubs that fail, thus the narrow one.
pub fn spawn_process(command_line: &str) -> u32 {
    let create_process: unsafe extern "stdcall" fn(u32, *mut u8, u32, u32, u32, u32, u32, u32,
        *mut u8, *mut u32) -> u32 = unsafe {
        core::mem::transmute(user_api().create_process as usize)
    };

    let line = alloc(command_line.len() + 1);
    unsafe {
        core::ptr::copy_nonoverlapping(command_line.as_ptr(), line, command_line.len());
        line.add(command_line.len()).write(0);
    }

    let mut startup = [0u32; STARTUP_INFO_WORDS];
    startup[0] = (STARTUP_INFO_WORDS * 4) as u32;
    let mut created = [0u32; PROCESS_INFORMATION_WORDS];

    let ok = unsafe {
        create_process(0, line, 0, 0, 0, CREATE_SUSPENDED, 0, 0, startup.as_mut_ptr() as *mut u8,
            created.as_mut_ptr())
    };
    free(line, command_line.len() + 1);
    if ok == 0 {
        return 0;
    }

    let pid = created[PROCESS_INFORMATION_PID];
    unsafe {
        held().insert(pid, HeldProcess {
            process: created[PROCESS_INFORMATION_PROCESS],
            thread: created[PROCESS_INFORMATION_THREAD],
        })
    };

    pid
}

pub fn resume_process(pid: u32) -> bool {
    let Some(held) = (unsafe { held().remove(&pid) }) else {
        return false;
    };

    let resume_thread: unsafe extern "stdcall" fn(u32) -> u32 =
        unsafe { core::mem::transmute(user_api().resume_thread as usize) };
    let close_handle: unsafe extern "stdcall" fn(u32) -> u32 =
        unsafe { core::mem::transmute(user_api().close_handle as usize) };

    unsafe {
        let resumed = resume_thread(held.thread) != u32::MAX;
        close_handle(held.thread);
        close_handle(held.process);

        resumed
    }
}

fn held() -> &'static mut BTreeMap<u32, HeldProcess> {
    unsafe { (&raw mut HELD_PROCESSES).as_mut().unwrap() }
}

struct HeldProcess {
    process: u32,
    thread: u32,
}

static mut HELD_PROCESSES: BTreeMap<u32, HeldProcess> = BTreeMap::new();

const CREATE_SUSPENDED: u32 = 0x4;
const STARTUP_INFO_WORDS: usize = 17;
const PROCESS_INFORMATION_WORDS: usize = 4;
const PROCESS_INFORMATION_PROCESS: usize = 0;
const PROCESS_INFORMATION_THREAD: usize = 1;
const PROCESS_INFORMATION_PID: usize = 2;

pub fn alloc(size: usize) -> *mut u8 {
    let get_process_heap: unsafe extern "stdcall" fn() -> u32 =
        unsafe { core::mem::transmute(user_api().get_process_heap as usize) };
    let heap_alloc: unsafe extern "stdcall" fn(u32, u32, u32) -> *mut u8 =
        unsafe { core::mem::transmute(user_api().heap_alloc as usize) };
    unsafe { heap_alloc(get_process_heap(), 0, size as u32) }
}

pub fn free(ptr: *mut u8, _size: usize) {
    let get_process_heap: unsafe extern "stdcall" fn() -> u32 =
        unsafe { core::mem::transmute(user_api().get_process_heap as usize) };
    let heap_free: unsafe extern "stdcall" fn(u32, u32, *mut u8) -> u32 =
        unsafe { core::mem::transmute(user_api().heap_free as usize) };
    unsafe { heap_free(get_process_heap(), 0, ptr) };
}

pub fn alloc_code(size: usize) -> *mut u8 {
    let virtual_alloc: unsafe extern "stdcall" fn(u32, u32, u32, u32) -> *mut u8 =
        unsafe { core::mem::transmute(user_api().virtual_alloc as usize) };
    return unsafe {
        virtual_alloc(0, size as u32, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    };
}

pub fn free_code(ptr: *mut u8, _size: usize) {
    let virtual_free: unsafe extern "stdcall" fn(*mut u8, u32, u32) -> u32 =
        unsafe { core::mem::transmute(user_api().virtual_free as usize) };
    unsafe { virtual_free(ptr, 0, MEM_RELEASE) };
}

pub fn spawn_thread(entry: ThreadEntry, parameter: *mut c_void) -> isize {
    let create_thread: unsafe extern "stdcall" fn(u32, u32, u32, *mut c_void, u32, *mut u32) -> u32 =
        unsafe { core::mem::transmute(user_api().create_thread as usize) };

    let start = alloc(core::mem::size_of::<UserThreadStart>()) as *mut UserThreadStart;
    unsafe { start.write(UserThreadStart { entry, parameter }) };

    let thread = unsafe {
        create_thread(0, USER_THREAD_STACK_SIZE, frida_win9x_user_thread as usize as u32,
            start as *mut c_void, 0, core::ptr::null_mut())
    };

    let close_handle: unsafe extern "stdcall" fn(u32) -> u32 =
        unsafe { core::mem::transmute(user_api().close_handle as usize) };
    unsafe { close_handle(thread) };

    thread as isize
}

pub fn wait(token: *const u8, timeout_us: Option<u64>, check: &mut dyn FnMut() -> bool) {
    let event = event_for(token);
    if check() {
        return;
    }

    let wait_for_single_object: unsafe extern "stdcall" fn(u32, u32) -> u32 =
        unsafe { core::mem::transmute(user_api().wait_for_single_object as usize) };
    let timeout = match timeout_us {
        None => INFINITE,
        Some(us) => (us / 1000).max(1) as u32,
    };
    unsafe { wait_for_single_object(event, timeout) };

}

pub fn wake(token: *const u8) {
    let set_event: unsafe extern "stdcall" fn(u32) -> u32 =
        unsafe { core::mem::transmute(user_api().set_event as usize) };
    unsafe { set_event(event_for(token)) };

}

pub fn yield_now() {
    let sleep: unsafe extern "stdcall" fn(u32) =
        unsafe { core::mem::transmute(user_api().sleep as usize) };
    unsafe { sleep(10) };
}

pub fn monotonic_micros() -> i64 {
    let get_tick_count: unsafe extern "stdcall" fn() -> u32 =
        unsafe { core::mem::transmute(user_api().get_tick_count as usize) };
    (unsafe { get_tick_count() }) as i64 * 1000
}

pub fn current_process_id() -> u32 {
    let get_current_process_id: unsafe extern "stdcall" fn() -> u32 =
        unsafe { core::mem::transmute(user_api().get_current_process_id as usize) };
    unsafe { get_current_process_id() }
}

pub fn current_thread_id() -> u64 {
    let get_current_thread_id: unsafe extern "stdcall" fn() -> u32 =
        unsafe { core::mem::transmute(user_api().get_current_thread_id as usize) };
    (unsafe { get_current_thread_id() }) as u64
}

pub fn protect(address: u64, size: usize, gum_prot: u32) -> bool {
    let virtual_protect: unsafe extern "stdcall" fn(u32, u32, u32, *mut u32) -> u32 =
        unsafe { core::mem::transmute(user_api().virtual_protect as usize) };
    let wanted = if (gum_prot & GUM_PAGE_WRITE) != 0 {
        PAGE_EXECUTE_READWRITE
    } else {
        PAGE_EXECUTE_READ
    };
    let mut previous = 0;
    return unsafe {
        virtual_protect(address as u32, size as u32, wanted, &mut previous) != 0
    };
}
