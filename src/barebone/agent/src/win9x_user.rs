// The half of the Win9x agent that runs in ring 3, inside a process the host attached to. It
// reaches nothing of the kernel's, thus it has primitives of its own, which frida_win9x_user_main
// selects before it does anything else.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};

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
    enumerate_threads,
};

unsafe extern "C" fn user_worker(parameter: *mut c_void, _wait_result: i32) {
    let arena = parameter as u32;
    let context = unsafe { crate::adopt_js_context() };

    unsafe { ((arena + OBSERVED_PID) as *mut u32).write_volatile(current_process_id()) };

    unsafe { crate::route_frames_through(arena as u64) };

    crate::gum_windows::watch_the_loader();

    while unsafe { ((arena + STOP_REQUEST) as *const u32).read_volatile() } == 0 {
        if let Some(frame) = take_frame_from_host(arena as u64) {
            crate::on_frame_from_host(frame);
            acknowledge_frame_from_host(arena as u64);
        }

        pump_frames_to_host();

        let wanted = unsafe { ((arena + GATING) as *const u32).read_volatile() } != 0;
        if wanted != unsafe { GATING_HERE } {
            unsafe { GATING_HERE = wanted };
            gate_spawns(wanted);
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

fn enumerate_threads(found: &mut dyn FnMut(crate::kernel::ThreadInfo)) {
    crate::win9x::enumerate_threads_of(current_process_id(), found)
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

pub unsafe extern "stdcall" fn on_module_load(name: *const u8) -> u32 {
    let original: extern "stdcall" fn(*const u8) -> u32 =
        unsafe { core::mem::transmute(crate::gum_windows::loader_load()) };

    let handle = original(name);
    note_module(handle, name);

    handle
}

pub unsafe extern "stdcall" fn on_module_load_with_flags(name: *const u8, file: u32,
        flags: u32) -> u32 {
    let original: extern "stdcall" fn(*const u8, u32, u32) -> u32 =
        unsafe { core::mem::transmute(crate::gum_windows::loader_load_with_flags()) };

    let handle = original(name, file, flags);
    note_module(handle, name);

    handle
}

pub unsafe extern "stdcall" fn on_module_unload(handle: u32) -> u32 {
    let original: extern "stdcall" fn(u32) -> u32 =
        unsafe { core::mem::transmute(crate::gum_windows::loader_unload()) };

    let base = handle;
    let left = original(handle);
    if left != 0 {
        crate::gum_windows::module_left(base as u64);
    }

    left
}

pub fn loader_entry_points() -> Option<LoaderEntryPoints> {
    let load = kernel32_export(b"LoadLibraryA") as usize;
    let unload = kernel32_export(b"FreeLibrary") as usize;
    if load == 0 || unload == 0 {
        return None;
    }

    Some(LoaderEntryPoints {
        load,
        load_with_flags: kernel32_export(b"LoadLibraryExA") as usize,
        unload,
    })
}

pub struct LoaderEntryPoints {
    pub load: usize,
    pub load_with_flags: usize,
    pub unload: usize,
}

fn note_module(handle: u32, name: *const u8) {
    if handle == 0 {
        return;
    }

    crate::gum_windows::module_arrived(handle as u64, &text_at(name));
}

fn text_at(name: *const u8) -> alloc::string::String {
    let mut text = alloc::string::String::new();
    let mut cursor = name;
    loop {
        let byte = unsafe { cursor.read() };
        if byte == 0 {
            return text;
        }
        text.push(byte as char);
        cursor = unsafe { cursor.add(1) };
    }
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
            virtual_query: kernel32_export(b"VirtualQuery"),
            create_thread: kernel32_export(b"CreateThread"),
            create_process: kernel32_export(b"CreateProcessA"),
            get_thread_context: kernel32_export(b"GetThreadContext"),
            suspend_thread: kernel32_export(b"SuspendThread"),
            resume_thread: kernel32_export(b"ResumeThread"),
            create_event: kernel32_export(b"CreateEventA"),
            set_event: kernel32_export(b"SetEvent"),
            wait_for_single_object: kernel32_export(b"WaitForSingleObject"),
            exit_thread: kernel32_export(b"ExitThread"),
            close_handle: kernel32_export(b"CloseHandle"),
            set_file_pointer: kernel32_export(b"SetFilePointer"),
            create_file: kernel32_export(b"CreateFileA"),
            read_file: kernel32_export(b"ReadFile"),
            find_first_file: kernel32_export(b"FindFirstFileA"),
            find_next_file: kernel32_export(b"FindNextFileA"),
            find_close: kernel32_export(b"FindClose"),
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
    get_thread_context: u32,
    suspend_thread: u32,
    resume_thread: u32,
    create_event: u32,
    set_event: u32,
    wait_for_single_object: u32,
    exit_thread: u32,
    close_handle: u32,
    set_file_pointer: u32,
    create_file: u32,
    read_file: u32,
    find_first_file: u32,
    find_next_file: u32,
    find_close: u32,
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
    get_thread_context: 0,
    suspend_thread: 0,
    resume_thread: 0,
    create_event: 0,
    set_event: 0,
    wait_for_single_object: 0,
    exit_thread: 0,
    close_handle: 0,
    set_file_pointer: 0,
    create_file: 0,
    read_file: 0,
    find_first_file: 0,
    find_next_file: 0,
    find_close: 0,
};

fn slot_for_token(token: *const u8) -> usize {
    let start = (token as usize / core::mem::align_of::<usize>()) % EVENTS.len();
    for step in 0..EVENTS.len() {
        let slot = (start + step) % EVENTS.len();

        let owner = EVENT_OWNERS[slot].load(Ordering::Acquire);
        if owner == token as usize {
            return slot;
        }
        if owner == 0
                && EVENT_OWNERS[slot].compare_exchange(0, token as usize, Ordering::AcqRel,
                    Ordering::Acquire).is_ok() {
            return slot;
        }
    }

    0
}

fn event_in(slot: usize) -> u32 {
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

    let process = created[PROCESS_INFORMATION_PROCESS];
    let thread = created[PROCESS_INFORMATION_THREAD];
    let pid = created[PROCESS_INFORMATION_PID];
    if hold_at_entry_point(pid, thread).is_none() {
        return 0;
    }

    unsafe { held().insert(pid, HeldProcess { process, thread }) };

    pid
}

fn gate_spawns(on: bool) {
    let create_process = user_api().create_process as *mut c_void;
    if create_process.is_null() {
        return;
    }

    unsafe {
        let interceptor = crate::bindings::gum_interceptor_obtain();
        crate::bindings::gum_interceptor_begin_transaction(interceptor);
        if on {
            crate::bindings::gum_interceptor_replace(interceptor, create_process,
                on_create_process as *mut c_void, &raw mut ORIGINAL_CREATE_PROCESS,
                core::ptr::null());
        } else {
            crate::bindings::gum_interceptor_revert(interceptor, create_process);
        }
        crate::bindings::gum_interceptor_end_transaction(interceptor);
    }
}

unsafe extern "stdcall" fn on_create_process(application: u32, command_line: *const u8,
        process_attributes: u32, thread_attributes: u32, inherit: u32, flags: u32,
        environment: u32, directory: u32, startup: *mut u8, information: *mut u32) -> u32 {
    let original: unsafe extern "stdcall" fn(u32, *const u8, u32, u32, u32, u32, u32, u32,
        *mut u8, *mut u32) -> u32 = unsafe {
        core::mem::transmute((&raw const ORIGINAL_CREATE_PROCESS).read())
    };

    let ok = unsafe {
        original(application, command_line, process_attributes, thread_attributes, inherit,
            flags | CREATE_SUSPENDED, environment, directory, startup, information)
    };
    if ok == 0 {
        return ok;
    }

    let process = unsafe { information.add(PROCESS_INFORMATION_PROCESS).read() };
    let thread = unsafe { information.add(PROCESS_INFORMATION_THREAD).read() };
    let pid = unsafe { information.add(PROCESS_INFORMATION_PID).read() };

    let held_ok = hold_at_entry_point(pid, thread).is_some();
    unsafe {
        let arena = crate::routed_arena() as u32;
        ((arena + 0xa0) as *mut u32).write_volatile(if held_ok { 1 } else { 2 });
    }
    unsafe { held().insert(pid, HeldProcess { process, thread }) };

    crate::tell_the_host_of_a_spawn(pid, command_line);

    ok
}

static mut ORIGINAL_CREATE_PROCESS: *mut c_void = core::ptr::null_mut();
static mut GATING_HERE: bool = false;

struct Image {
    handle: u32,
}

impl crate::icons::Image for Image {
    fn read_at(&self, position: u32, buffer: &mut [u8]) -> u32 {
        let set_pointer: unsafe extern "stdcall" fn(u32, u32, u32, u32) -> u32 =
            unsafe { core::mem::transmute(user_api().set_file_pointer as usize) };
        let read_file: unsafe extern "stdcall" fn(u32, *mut u8, u32, *mut u32, u32) -> u32 =
            unsafe { core::mem::transmute(user_api().read_file as usize) };

        unsafe { set_pointer(self.handle, position, 0, 0) };

        let mut taken = 0u32;
        if unsafe { read_file(self.handle, buffer.as_mut_ptr(), buffer.len() as u32,
                &raw mut taken, 0) } == 0 {
            return 0;
        }

        taken
    }
}

impl Image {
    fn open(path: &[u8]) -> Option<Image> {
        let create_file: unsafe extern "stdcall" fn(*const u8, u32, u32, u32, u32, u32, u32)
            -> u32 = unsafe { core::mem::transmute(user_api().create_file as usize) };

        let handle = unsafe {
            create_file(path.as_ptr(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0)
        };
        if handle == INVALID_HANDLE {
            return None;
        }

        Some(Image { handle })
    }
}

impl Drop for Image {
    fn drop(&mut self) {
        let close_handle: unsafe extern "stdcall" fn(u32) -> u32 =
            unsafe { core::mem::transmute(user_api().close_handle as usize) };
        unsafe { close_handle(self.handle) };
    }
}

fn identity_of(target: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut asciiz = Vec::new();
    asciiz.extend_from_slice(target);
    asciiz.push(0);

    let Some(image) = Image::open(&asciiz) else {
        return (Vec::new(), Vec::new());
    };

    let mut identity = [0u8; 128];
    let mut description = [0u8; 128];
    let named = crate::icons::identify(&image, &mut identity);
    let described = crate::icons::describe(&image, &mut description);

    (identity[..named].to_vec(), description[..described].to_vec())
}

pub fn enumerate_shortcuts(found: &mut dyn FnMut(&str, &str, &str, &str)) {
    let mut menu = Vec::new();
    menu.extend_from_slice(windows_directory().as_bytes());
    menu.extend_from_slice(b"\\Start Menu");

    walk_for_shortcuts(&menu, 0, found);
}

fn walk_for_shortcuts(directory: &[u8], depth: u32,
        found: &mut dyn FnMut(&str, &str, &str, &str)) {
    if depth == MAX_MENU_DEPTH {
        return;
    }

    let find_first: unsafe extern "stdcall" fn(*const u8, *mut u8) -> u32 =
        unsafe { core::mem::transmute(user_api().find_first_file as usize) };
    let find_next: unsafe extern "stdcall" fn(u32, *mut u8) -> u32 =
        unsafe { core::mem::transmute(user_api().find_next_file as usize) };
    let find_close: unsafe extern "stdcall" fn(u32) -> u32 =
        unsafe { core::mem::transmute(user_api().find_close as usize) };

    let mut pattern = Vec::new();
    pattern.extend_from_slice(directory);
    pattern.extend_from_slice(b"\\*.*\0");

    let mut entry = [0u8; FIND_DATA_SIZE];
    let search = unsafe { find_first(pattern.as_ptr(), entry.as_mut_ptr()) };
    if search == INVALID_HANDLE {
        return;
    }

    loop {
        let attributes = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
        let name = text_in(&entry[FIND_DATA_NAME..]);

        if name != b"." && name != b".." {
            let mut path = Vec::new();
            path.extend_from_slice(directory);
            path.push(b'\\');
            path.extend_from_slice(name);

            if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                walk_for_shortcuts(&path, depth + 1, found);
            } else if ends_with_ignoring_case(name, b".lnk") {
                if let Some(target) = target_of_shortcut(&path)
                        .filter(|target| ends_with_ignoring_case(target, b".exe")) {
                    let shown = &name[..name.len() - 4];
                    let (identity, description) = identity_of(&target);
                    found(text_as_str(&identity), text_as_str(&target), text_as_str(shown),
                        text_as_str(&description));
                }
            }
        }

        if unsafe { find_next(search, entry.as_mut_ptr()) } == 0 {
            break;
        }
    }

    unsafe { find_close(search) };
}

fn target_of_shortcut(path: &[u8]) -> Option<Vec<u8>> {
    let mut asciiz = Vec::new();
    asciiz.extend_from_slice(path);
    asciiz.push(0);

    let blob = read_whole_file(&asciiz)?;
    if blob.len() < SHELL_LINK_HEADER || blob[0] != SHELL_LINK_HEADER as u8 {
        return None;
    }

    let flags = u32::from_le_bytes([blob[0x14], blob[0x15], blob[0x16], blob[0x17]]);
    let mut at = SHELL_LINK_HEADER;

    if flags & HAS_TARGET_ID_LIST != 0 {
        if at + 2 > blob.len() {
            return None;
        }
        at += 2 + u16::from_le_bytes([blob[at], blob[at + 1]]) as usize;
    }

    if flags & HAS_LINK_INFO == 0 || at + 0x1c > blob.len() {
        return None;
    }

    let word = |offset: usize| {
        u32::from_le_bytes([blob[offset], blob[offset + 1], blob[offset + 2], blob[offset + 3]])
    };
    if word(at + 8) & VOLUME_ID_AND_LOCAL_BASE_PATH == 0 {
        return None;
    }

    let base = at + word(at + 0x10) as usize;
    let suffix = at + word(at + 0x18) as usize;
    if base >= blob.len() || suffix >= blob.len() {
        return None;
    }

    let mut target = Vec::new();
    target.extend_from_slice(text_in(&blob[base..]));
    target.extend_from_slice(text_in(&blob[suffix..]));

    Some(target)
}

fn read_whole_file(path: &[u8]) -> Option<Vec<u8>> {
    let create_file: unsafe extern "stdcall" fn(*const u8, u32, u32, u32, u32, u32, u32) -> u32 =
        unsafe { core::mem::transmute(user_api().create_file as usize) };
    let read_file: unsafe extern "stdcall" fn(u32, *mut u8, u32, *mut u32, u32) -> u32 =
        unsafe { core::mem::transmute(user_api().read_file as usize) };
    let close_handle: unsafe extern "stdcall" fn(u32) -> u32 =
        unsafe { core::mem::transmute(user_api().close_handle as usize) };

    let file = unsafe {
        create_file(path.as_ptr(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0)
    };
    if file == INVALID_HANDLE {
        return None;
    }

    let mut blob = alloc::vec![0u8; MAX_SHORTCUT];
    let mut taken = 0u32;
    let ok = unsafe {
        read_file(file, blob.as_mut_ptr(), blob.len() as u32, &raw mut taken, 0)
    };
    unsafe { close_handle(file) };

    if ok == 0 {
        return None;
    }
    blob.truncate(taken as usize);

    Some(blob)
}

fn windows_directory() -> &'static str {
    "C:\\WINDOWS"
}

fn text_in(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());

    &bytes[..end]
}

fn text_as_str(bytes: &[u8]) -> &str {
    core::str::from_utf8(bytes).unwrap_or("")
}

fn ends_with_ignoring_case(name: &[u8], suffix: &[u8]) -> bool {
    if name.len() < suffix.len() {
        return false;
    }

    name[name.len() - suffix.len()..]
        .iter()
        .zip(suffix)
        .all(|(a, b)| a.to_ascii_lowercase() == *b)
}

const MAX_MENU_DEPTH: u32 = 4;
const MAX_SHORTCUT: usize = 4096;
const FIND_DATA_SIZE: usize = 0x140;
const FIND_DATA_NAME: usize = 0x2c;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const INVALID_HANDLE: u32 = 0xffff_ffff;
const GENERIC_READ: u32 = 0x8000_0000;
const FILE_SHARE_READ: u32 = 0x1;
const OPEN_EXISTING: u32 = 3;
const SHELL_LINK_HEADER: usize = 0x4c;
const HAS_TARGET_ID_LIST: u32 = 0x1;
const HAS_LINK_INFO: u32 = 0x2;
const VOLUME_ID_AND_LOCAL_BASE_PATH: u32 = 0x1;

fn hold_at_entry_point(pid: u32, thread: u32) -> Option<()> {
    let (entry_point, prologue) = patch(pid, 0, HOLD_INSTRUCTION)?;
    if entry_point == NOTHING_TO_HOLD {
        return Some(());
    }
    if entry_point == 0 {
        return None;
    }

    resume_thread(thread);
    let arrived = wait_for_entry_point(thread, entry_point);

    patch(pid, entry_point, prologue)?;

    arrived
}

pub fn take_writes_on(first_page: *mut u8, pages: u32) -> *mut u8 {
    let span = pages as usize * PAGE_SIZE as usize;
    if !in_shared_library(first_page as u32) {
        protect(first_page as u64, span, GUM_PAGE_READ | GUM_PAGE_WRITE | GUM_PAGE_EXECUTE);
        return first_page;
    }

    let scratch = alloc_code(span);
    if scratch.is_null() {
        return scratch;
    }
    unsafe { core::ptr::copy_nonoverlapping(first_page, scratch, span) };

    let mut before = Vec::with_capacity(span);
    before.extend_from_slice(unsafe { core::slice::from_raw_parts(first_page, span) });
    unsafe { (&raw mut REMAPPED).as_mut().unwrap() }.push(Remapped {
        scratch: scratch as u32,
        first_page: first_page as u32,
        before,
    });

    scratch
}

pub fn make_the_writes(writable: *mut u8, pages: u32) {
    let remapped = unsafe { (&raw mut REMAPPED).as_mut().unwrap() };
    let Some(index) = remapped.iter().position(|known| known.scratch == writable as u32) else {
        return;
    };
    let taken = remapped.remove(index);

    let span = pages as usize * PAGE_SIZE as usize;
    let written = unsafe { core::slice::from_raw_parts(taken.scratch as *const u8, span) };

    let mut offset = 0;
    while offset != span {
        if written[offset] == taken.before[offset] {
            offset += 1;
            continue;
        }

        let start = offset;
        while offset != span && written[offset] != taken.before[offset] {
            offset += 1;
        }

        ask_for_a_guard(taken.first_page + start as u32, &written[start..offset]);
    }

    free_code(taken.scratch as *mut u8, span);
}

struct Remapped {
    scratch: u32,
    first_page: u32,
    before: Vec<u8>,
}

static mut REMAPPED: Vec<Remapped> = Vec::new();

fn in_shared_library(address: u32) -> bool {
    let address = address as u64;

    enumerate_modules().iter().any(|module| {
        module.base >= SHARED_ARENA_BASE
            && address >= module.base
            && address < module.base + module.size
    })
}

fn ask_for_a_guard(address: u32, bytes: &[u8]) {
    let sleep: unsafe extern "stdcall" fn(u32) =
        unsafe { core::mem::transmute(user_api().sleep as usize) };
    let arena = crate::routed_arena() as u32;

    if bytes.len() > PATCH_CODE_MAX {
        return;
    }

    take_the_slot();

    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), (arena + PATCH_CODE) as *mut u8,
            bytes.len());
        ((arena + PATCH_ADDRESS) as *mut u32).write_volatile(address);
        ((arena + PATCH_LENGTH) as *mut u32).write_volatile(bytes.len() as u32);
        ((arena + PATCH_REQUEST) as *mut u32).write_volatile(HOOK_ASKED);
    }

    for _ in 0..PATCH_ATTEMPTS {
        if unsafe { ((arena + PATCH_REQUEST) as *const u32).read_volatile() } == PATCH_ANSWERED {
            unsafe { ((arena + PATCH_REQUEST) as *mut u32).write_volatile(0) };
            give_the_slot_back();
            return;
        }

        unsafe { sleep(HOLD_SLICE_MS) };
    }

    give_the_slot_back();
}

const SHARED_ARENA_BASE: u64 = 0x8000_0000;

fn take_the_slot() {
    let sleep: unsafe extern "stdcall" fn(u32) =
        unsafe { core::mem::transmute(user_api().sleep as usize) };

    while ASKING.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
        unsafe { sleep(1) };
    }
}

fn give_the_slot_back() {
    ASKING.store(false, Ordering::Release);
}

static ASKING: AtomicBool = AtomicBool::new(false);

fn patch(pid: u32, address: u32, code: u32) -> Option<(u32, u32)> {
    let sleep: unsafe extern "stdcall" fn(u32) =
        unsafe { core::mem::transmute(user_api().sleep as usize) };
    let arena = crate::routed_arena() as u32;

    take_the_slot();

    unsafe {
        ((arena + PATCH_PROCESS) as *mut u32).write_volatile(pid);
        ((arena + PATCH_ADDRESS) as *mut u32).write_volatile(address);
        ((arena + PATCH_BYTES) as *mut u32).write_volatile(code);
        ((arena + PATCH_REQUEST) as *mut u32).write_volatile(PATCH_ASKED);
    }

    for _ in 0..PATCH_ATTEMPTS {
        if unsafe { ((arena + PATCH_REQUEST) as *const u32).read_volatile() } == PATCH_ANSWERED {
            let at = unsafe { ((arena + PATCH_ADDRESS) as *const u32).read_volatile() };
            let previous = unsafe { ((arena + PATCH_BYTES) as *const u32).read_volatile() };
            unsafe { ((arena + PATCH_REQUEST) as *mut u32).write_volatile(0) };
            give_the_slot_back();

            return Some((at, previous));
        }

        unsafe { sleep(HOLD_SLICE_MS) };
    }

    give_the_slot_back();

    None
}

fn wait_for_entry_point(thread: u32, entry_point: u32) -> Option<()> {
    let sleep: unsafe extern "stdcall" fn(u32) =
        unsafe { core::mem::transmute(user_api().sleep as usize) };

    for _ in 0..HOLD_ATTEMPTS {
        if register_of(thread, CONTEXT_CONTROL, CONTEXT_EIP) == Some(entry_point) {
            suspend_thread(thread);
            if register_of(thread, CONTEXT_CONTROL, CONTEXT_EIP) == Some(entry_point) {
                return Some(());
            }
            resume_thread(thread);
        }

        unsafe { sleep(HOLD_SLICE_MS) };
    }

    None
}

fn register_of(thread: u32, flags: u32, offset: usize) -> Option<u32> {
    let get_thread_context: unsafe extern "stdcall" fn(u32, *mut u8) -> u32 =
        unsafe { core::mem::transmute(user_api().get_thread_context as usize) };

    let mut context = [0u32; CONTEXT_WORDS];
    context[0] = flags;
    let asked = unsafe { get_thread_context(thread, context.as_mut_ptr() as *mut u8) };

    (asked != 0).then(|| context[offset / 4])
}

fn suspend_thread(thread: u32) {
    let suspend: unsafe extern "stdcall" fn(u32) -> u32 =
        unsafe { core::mem::transmute(user_api().suspend_thread as usize) };

    unsafe { suspend(thread) };
}

fn resume_thread(thread: u32) {
    let resume: unsafe extern "stdcall" fn(u32) -> u32 =
        unsafe { core::mem::transmute(user_api().resume_thread as usize) };

    unsafe { resume(thread) };
}

pub fn resume_process(pid: u32) -> bool {
    let Some(held) = (unsafe { held().remove(&pid) }) else {
        return false;
    };

    let close_handle: unsafe extern "stdcall" fn(u32) -> u32 =
        unsafe { core::mem::transmute(user_api().close_handle as usize) };

    resume_thread(held.thread);
    unsafe {
        close_handle(held.thread);
        close_handle(held.process);
    }

    true
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
const CONTEXT_WORDS: usize = 179;
const CONTEXT_CONTROL: u32 = 0x0001_0001;
const CONTEXT_INTEGER: u32 = 0x0001_0002;
const CONTEXT_EAX: usize = 0xb0;
const CONTEXT_EIP: usize = 0xb8;
const HOLD_INSTRUCTION: u32 = 0xfeeb;
const PATCH_ATTEMPTS: u32 = 5000;
const HOLD_ATTEMPTS: u32 = 5000;
const HOLD_SLICE_MS: u32 = 1;
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
    let slot = slot_for_token(token);
    let event = event_in(slot);
    if check() {
        return;
    }

    let wait_for_single_object: unsafe extern "stdcall" fn(u32, u32) -> u32 =
        unsafe { core::mem::transmute(user_api().wait_for_single_object as usize) };
    let timeout = match timeout_us {
        None => INFINITE,
        Some(us) => (us / 1000).max(1) as u32,
    };
    EVENT_SLEEPERS[slot].fetch_add(1, Ordering::AcqRel);
    unsafe { wait_for_single_object(event, timeout) };
    EVENT_SLEEPERS[slot].fetch_sub(1, Ordering::AcqRel);
}

pub fn wake(token: *const u8) {
    let set_event: unsafe extern "stdcall" fn(u32) -> u32 =
        unsafe { core::mem::transmute(user_api().set_event as usize) };

    let slot = slot_for_token(token);
    let event = event_in(slot);

    let mut sleepers = EVENT_SLEEPERS[slot].load(Ordering::Acquire).max(1);
    while sleepers != 0 {
        unsafe { set_event(event) };
        sleepers -= 1;
    }
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
