// The half of the Win9x agent that runs in ring 3, inside a process the host attached to. It
// reaches nothing of the kernel's, thus it has primitives of its own, which frida_win9x_user_main
// selects before it does anything else.

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
            create_thread: kernel32_export(b"CreateThread"),
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
    create_thread: u32,
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
    create_thread: 0,
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
