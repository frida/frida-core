// The half of the NT agent that runs in ring 3, inside a process the host attached to. It reaches
// nothing of the kernel's, thus it has primitives of its own, which frida_winnt_user_main selects
// before it does anything else.

use alloc::collections::BTreeMap;
use core::ffi::c_void;

use crate::winnt::{
    BLOCK_PROCESS_ID, BLOCK_THREAD_ID, CURRENT_PROCESS, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    OBSERVED_PID, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, Primitives, STOP_REQUEST,
    BOOTSTRAP_CLIENT_ID, BOOTSTRAP_CONTEXT, BOOTSTRAP_CREATE_THREAD, BOOTSTRAP_HANDLE,
    BOOTSTRAP_INITIAL_TEB, BOOTSTRAP_TERMINATE_THREAD, TARGET_WAKE_HANDLE,
    USER_SHARED_DATA, AGENT_WAKE_HANDLE, PEB_PARAMETERS_OFFSET, POINTER_SIZE, export,
    module_base, read_pointer,
    acknowledge_frame_from_host, select_user, take_frame_from_host, windows_fn,
};

// No code in this image calls the ring 3 entry point, thus tell the linker to keep it.
#[used]
static USER_ENTRY: extern "C" fn(usize) = frida_winnt_user_main;

// This is the half that runs in a process. It has its own copy of the image, thus its data is
// its own. The ring selects which primitives it uses.
// The thread that descends has no block of its own, thus it can only make syscalls: ntdll's
// stubs need none. It asks for a real thread, which the kernel gives a block, and then retires.
#[used]
static BOOTSTRAP_ENTRY: extern "C" fn(usize) -> ! = frida_winnt_user_bootstrap;

#[unsafe(no_mangle)]
pub extern "C" fn frida_winnt_user_bootstrap(arena: usize) -> ! {
    unsafe {
        let create: windows_fn!(
            *mut *mut c_void, u32, *mut c_void, *mut c_void, *mut c_void, *mut u8, *mut c_void,
            u8, => i32) = core::mem::transmute(read_pointer(arena + BOOTSTRAP_CREATE_THREAD as usize));
        let terminate: windows_fn!(*mut c_void, i32 => i32) =
            core::mem::transmute(read_pointer(arena + BOOTSTRAP_TERMINATE_THREAD as usize));

        let status = create(
            (arena + BOOTSTRAP_HANDLE as usize) as *mut *mut c_void,
            THREAD_ALL_ACCESS,
            core::ptr::null_mut(),
            CURRENT_PROCESS,
            (arena + BOOTSTRAP_CLIENT_ID as usize) as *mut c_void,
            read_pointer(arena + BOOTSTRAP_CONTEXT as usize) as *mut u8,
            read_pointer(arena + BOOTSTRAP_INITIAL_TEB as usize) as *mut c_void,
            0,
        );

        let _ = status;

        terminate(CURRENT_THREAD, 0);
    }

    loop {}
}

const THREAD_ALL_ACCESS: u32 = 0x1f_03ff;
const CURRENT_THREAD: *mut c_void = -2isize as *mut c_void;
const IDLE_SLICE_US: u64 = 50_000;

#[unsafe(no_mangle)]
pub extern "C" fn frida_winnt_user_main(arena: usize) {
    select_user();

    unsafe {
        ARENA = arena as u64;
    }
    resolve_user_api();

    unsafe { crate::init_gum_without_exceptor() };
    let context = unsafe { crate::adopt_js_context() };

    unsafe {
        ((arena + OBSERVED_PID as usize) as *mut u32).write_volatile(current_client_id(BLOCK_PROCESS_ID));

        crate::route_frames_through(arena as u64);
    }

    while unsafe { ((arena + STOP_REQUEST as usize) as *const u32).read_volatile() } == 0 {
        while let Some(frame) = take_frame_from_host(arena as u64) {
            crate::on_frame_from_host(frame);
            acknowledge_frame_from_host(arena as u64);
        }

        unsafe { crate::poll_pending_work(context) };

        // The kernel half sets this on its way in. Nothing else here comes around on a clock,
        // and the wait ends early whenever a frame arrives.
        let due_time = -((IDLE_SLICE_US as i64) * 10);
        unsafe { (user_api().wait_for_object)(target_wake_handle(), 0, &due_time) };
    }

    unsafe { (user_api().exit_thread)(0) };
}

// The group that the ring 3 half runs on. The order is the order in Primitives.
pub static USER: Primitives = Primitives {
    log,
    alloc,
    free,
    alloc_code,
    free_code,
    protect,
    protection_at,
    enumerate_ranges,
    wait,
    wake,
    yield_now,
    current_process_id,
    current_thread_id,
    shared_data,
};

fn resolve_user_api() {
    let ntdll = module_base(peb(), b"ntdll.dll");

    unsafe {
        USER_API = Some(UserApi {
            allocate_heap: core::mem::transmute(export(ntdll, b"RtlAllocateHeap")),
            free_heap: core::mem::transmute(export(ntdll, b"RtlFreeHeap")),
            allocate_memory: core::mem::transmute(export(ntdll, b"NtAllocateVirtualMemory")),
            free_memory: core::mem::transmute(export(ntdll, b"NtFreeVirtualMemory")),
            protect_memory: core::mem::transmute(export(ntdll, b"NtProtectVirtualMemory")),
            query_memory: core::mem::transmute(export(ntdll, b"NtQueryVirtualMemory")),
            yield_execution: core::mem::transmute(export(ntdll, b"NtYieldExecution")),
            wait_for_object: core::mem::transmute(export(ntdll, b"NtWaitForSingleObject")),
            set_event: core::mem::transmute(export(ntdll, b"NtSetEvent")),
            exit_thread: core::mem::transmute(export(ntdll, b"RtlExitUserThread")),
        });

        SPAWN_API = Some(SpawnApi {
            create_process_parameters: core::mem::transmute(
                export(ntdll, b"RtlCreateProcessParameters")),
            create_user_process: core::mem::transmute(export(ntdll, b"RtlCreateUserProcess")),
            destroy_process_parameters: core::mem::transmute(
                export(ntdll, b"RtlDestroyProcessParameters")),
            resume_thread: core::mem::transmute(export(ntdll, b"NtResumeThread")),
            close: core::mem::transmute(export(ntdll, b"NtClose")),
        });
    }
}

// Making a process is the work of the loader's own entry points. They ask for wide strings and
// they leave the first thread of the new process held, which is what a caller wants.
pub fn spawn_process(command_line: &str) -> u32 {
    let api = unsafe { (*core::ptr::addr_of!(SPAWN_API)).as_ref().unwrap() };

    let mut image = WideText::of(&native_path_of(command_line));
    let mut line = WideText::of(command_line);
    let mut desktop = our_desktop();

    let mut parameters: *mut c_void = core::ptr::null_mut();
    let created = unsafe {
        (api.create_process_parameters)(&mut parameters, image.text(), core::ptr::null_mut(),
            core::ptr::null_mut(), line.text(), core::ptr::null_mut(), core::ptr::null_mut(),
            desktop.as_mut_ptr(), core::ptr::null_mut(), core::ptr::null_mut())
    };
    if created < 0 {
        return 0;
    }

    let mut information = [0u8; PROCESS_INFORMATION_SIZE];
    let status = unsafe {
        (api.create_user_process)(image.text(), OBJ_CASE_INSENSITIVE, parameters,
            core::ptr::null_mut(), core::ptr::null_mut(), CURRENT_PROCESS, 0,
            core::ptr::null_mut(), core::ptr::null_mut(), information.as_mut_ptr())
    };
    unsafe { (api.destroy_process_parameters)(parameters) };
    if status < 0 {
        return 0;
    }

    let pid = read_handle(&information, PROCESS_INFORMATION_PID) as usize as u32;
    unsafe {
        held().insert(pid, HeldProcess {
            process: read_handle(&information, PROCESS_INFORMATION_PROCESS),
            thread: read_handle(&information, PROCESS_INFORMATION_THREAD),
        })
    };

    pid
}

pub fn resume_process(pid: u32) -> bool {
    let Some(held) = (unsafe { held().remove(&pid) }) else {
        return false;
    };
    let api = unsafe { (*core::ptr::addr_of!(SPAWN_API)).as_ref().unwrap() };

    unsafe {
        let resumed = (api.resume_thread)(held.thread, core::ptr::null_mut()) >= 0;
        (api.close)(held.thread);
        (api.close)(held.process);

        resumed
    }
}

// The loader takes the path the way the object manager spells it.
fn native_path_of(command_line: &str) -> alloc::string::String {
    let program = command_line.split(' ').next().unwrap_or(command_line);

    alloc::format!("\\??\\{}", program.trim_matches('"'))
}

// A new process draws on the desktop that this one draws on.
fn our_desktop() -> [u8; UNICODE_STRING_SIZE] {
    let parameters = unsafe { read_pointer(peb() + PEB_PARAMETERS_OFFSET) };
    let mut desktop = [0u8; UNICODE_STRING_SIZE];
    unsafe {
        core::ptr::copy_nonoverlapping((parameters + PARAMETERS_DESKTOP_OFFSET) as *const u8,
            desktop.as_mut_ptr(), UNICODE_STRING_SIZE);
    }

    desktop
}

fn read_handle(information: &[u8; PROCESS_INFORMATION_SIZE], offset: usize) -> *mut c_void {
    let mut bytes = [0u8; POINTER_SIZE];
    bytes.copy_from_slice(&information[offset..offset + POINTER_SIZE]);

    usize::from_le_bytes(bytes) as *mut c_void
}

fn held() -> &'static mut BTreeMap<u32, HeldProcess> {
    unsafe { (&raw mut HELD_PROCESSES).as_mut().unwrap() }
}

// A wide string and the record that names it travel together, the record pointing into it.
struct WideText {
    characters: alloc::vec::Vec<u16>,
    record: [u8; UNICODE_STRING_SIZE],
}

impl WideText {
    fn of(text: &str) -> WideText {
        let mut characters: alloc::vec::Vec<u16> = text.encode_utf16().collect();
        characters.push(0);

        let bytes = ((characters.len() - 1) * 2) as u16;
        let mut record = [0u8; UNICODE_STRING_SIZE];
        record[..2].copy_from_slice(&bytes.to_le_bytes());
        record[2..4].copy_from_slice(&(bytes + 2).to_le_bytes());

        WideText { characters, record }
    }

    fn text(&mut self) -> *mut u8 {
        let buffer = self.characters.as_ptr() as usize;
        self.record[UNICODE_STRING_BUFFER..].copy_from_slice(&buffer.to_le_bytes());

        self.record.as_mut_ptr()
    }
}

struct SpawnApi {
    create_process_parameters: windows_fn!(*mut *mut c_void, *mut u8, *mut u8, *mut u8, *mut u8,
        *mut u8, *mut u8, *mut u8, *mut u8, *mut u8 => i32),
    create_user_process: windows_fn!(*mut u8, u32, *mut c_void, *mut c_void, *mut c_void,
        *mut c_void, u8, *mut c_void, *mut c_void, *mut u8 => i32),
    destroy_process_parameters: windows_fn!(*mut c_void => i32),
    resume_thread: windows_fn!(*mut c_void, *mut u32 => i32),
    close: windows_fn!(*mut c_void => i32),
}

struct HeldProcess {
    process: *mut c_void,
    thread: *mut c_void,
}

static mut SPAWN_API: Option<SpawnApi> = None;
static mut HELD_PROCESSES: BTreeMap<u32, HeldProcess> = BTreeMap::new();

const OBJ_CASE_INSENSITIVE: u32 = 0x40;

#[cfg(target_arch = "x86")]
const UNICODE_STRING_SIZE: usize = 8;
#[cfg(target_arch = "x86")]
const UNICODE_STRING_BUFFER: usize = 4;
#[cfg(target_arch = "x86")]
const PARAMETERS_DESKTOP_OFFSET: usize = 0x78;
#[cfg(target_arch = "x86")]
const PROCESS_INFORMATION_SIZE: usize = 128;
#[cfg(target_arch = "x86")]
const PROCESS_INFORMATION_PROCESS: usize = 0x04;
#[cfg(target_arch = "x86")]
const PROCESS_INFORMATION_THREAD: usize = 0x08;
#[cfg(target_arch = "x86")]
const PROCESS_INFORMATION_PID: usize = 0x0c;

#[cfg(target_arch = "x86_64")]
const UNICODE_STRING_SIZE: usize = 16;
#[cfg(target_arch = "x86_64")]
const UNICODE_STRING_BUFFER: usize = 8;
#[cfg(target_arch = "x86_64")]
const PARAMETERS_DESKTOP_OFFSET: usize = 0xc0;
#[cfg(target_arch = "x86_64")]
const PROCESS_INFORMATION_SIZE: usize = 192;
#[cfg(target_arch = "x86_64")]
const PROCESS_INFORMATION_PROCESS: usize = 0x08;
#[cfg(target_arch = "x86_64")]
const PROCESS_INFORMATION_THREAD: usize = 0x10;
#[cfg(target_arch = "x86_64")]
const PROCESS_INFORMATION_PID: usize = 0x18;

fn user_api() -> &'static UserApi {
    unsafe { (*core::ptr::addr_of!(USER_API)).as_ref().unwrap() }
}

struct UserApi {
    allocate_heap: windows_fn!(usize, u32, usize => *mut u8),
    free_heap: windows_fn!(usize, u32, *mut u8 => u8),
    allocate_memory: windows_fn!(*mut c_void, *mut *mut u8, usize, *mut usize, u32, u32 => i32),
    free_memory: windows_fn!(*mut c_void, *mut *mut u8, *mut usize, u32 => i32),
    protect_memory: windows_fn!(*mut c_void, *mut *mut u8, *mut usize, u32, *mut u32 => i32),
    query_memory: windows_fn!(*mut c_void, *mut u8, u32, *mut u8, usize, *mut usize => i32),
    yield_execution: windows_fn!( => i32),
    wait_for_object: windows_fn!(*mut c_void, u8, *const i64 => i32),
    set_event: windows_fn!(*mut c_void, *mut u32 => i32),
    exit_thread: windows_fn!(u32 => !),
}

static mut USER_API: Option<UserApi> = None;





fn process_heap() -> usize {
    unsafe { read_pointer(peb() + PEB_PROCESS_HEAP_OFFSET) }
}

fn target_wake_handle() -> *mut c_void {
    unsafe { ((ARENA + TARGET_WAKE_HANDLE) as *const u64).read() as *mut c_void }
}

fn agent_wake_handle() -> *mut c_void {
    unsafe { ((ARENA + AGENT_WAKE_HANDLE) as *const u64).read() as *mut c_void }
}

static mut ARENA: u64 = 0;



#[cfg(target_arch = "x86")]
fn current_client_id(offset: u32) -> u32 {
    let id: u32;
    unsafe {
        core::arch::asm!("mov {0:e}, fs:[{1:e}]", out(reg) id, in(reg) offset,
            options(nomem, nostack, preserves_flags));
    }
    id
}

#[cfg(target_arch = "x86_64")]
fn current_client_id(offset: u32) -> u32 {
    let id: u64;
    unsafe {
        core::arch::asm!("mov {0}, gs:[{1:e}]", out(reg) id, in(reg) offset,
            options(nomem, nostack, preserves_flags));
    }
    id as u32
}

#[cfg(target_arch = "x86")]
fn peb() -> usize {
    let peb: usize;
    unsafe {
        core::arch::asm!("mov {0:e}, fs:[0x30]", out(reg) peb,
            options(nomem, nostack, preserves_flags));
    }
    peb
}

#[cfg(target_arch = "x86_64")]
fn peb() -> usize {
    let peb: usize;
    unsafe {
        core::arch::asm!("mov {0}, gs:[0x60]", out(reg) peb,
            options(nomem, nostack, preserves_flags));
    }
    peb
}

#[cfg(target_arch = "x86")]
const PEB_PROCESS_HEAP_OFFSET: usize = 0x18;

#[cfg(target_arch = "x86_64")]
const PEB_PROCESS_HEAP_OFFSET: usize = 0x30;




const MEMORY_BASIC_INFORMATION: u32 = 0;
const MEMORY_BASE: usize = 0x00;
const MEMORY_REGION_SIZE: usize = if core::mem::size_of::<usize>() == 8 { 0x18 } else { 0x0c };
const MEMORY_STATE: usize = if core::mem::size_of::<usize>() == 8 { 0x20 } else { 0x10 };
const MEMORY_PROTECT: usize = if core::mem::size_of::<usize>() == 8 { 0x24 } else { 0x14 };
const MEMORY_INFORMATION_SIZE: usize = if core::mem::size_of::<usize>() == 8 { 0x30 } else { 0x1c };
const PAGE_PROTECTION_MASK: u32 = 0xff;
const PAGE_WRITECOPY: u32 = 0x08;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
const PAGE_READONLY: u32 = 0x02;
const PAGE_EXECUTE_READ: u32 = 0x20;
const GUM_PAGE_READ: u32 = 0x1;
const GUM_PAGE_WRITE: u32 = 0x2;
const GUM_PAGE_EXECUTE: u32 = 0x4;

// Only ring 0 can write to a port.
fn log(_msg: &str) {}

fn alloc(size: usize) -> *mut u8 {
    unsafe { (user_api().allocate_heap)(process_heap(), 0, size) }
}

fn free(ptr: *mut u8, _size: usize) {
    unsafe { (user_api().free_heap)(process_heap(), 0, ptr) };
}

fn alloc_code(size: usize) -> *mut u8 {
    let mut address: *mut u8 = core::ptr::null_mut();
    let mut region = size;

    unsafe {
        (user_api().allocate_memory)(CURRENT_PROCESS, &mut address, 0, &mut region,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    address
}

fn free_code(ptr: *mut u8, _size: usize) {
    let mut address = ptr;
    let mut region = 0usize;

    unsafe { (user_api().free_memory)(CURRENT_PROCESS, &mut address, &mut region, MEM_RELEASE) };
}

fn protect(address: u64, size: usize, gum_prot: u32) -> bool {
    let mut base = address as *mut u8;
    let mut region = size;
    let mut previous = 0u32;

    unsafe {
        (user_api().protect_memory)(CURRENT_PROCESS, &mut base, &mut region,
            page_protection_of(gum_prot), &mut previous) >= 0
    }
}

fn page_protection_of(gum_prot: u32) -> u32 {
    match (gum_prot & GUM_PAGE_WRITE != 0, gum_prot & GUM_PAGE_EXECUTE != 0) {
        (true, true) => PAGE_EXECUTE_READWRITE,
        (true, false) => PAGE_READWRITE,
        (false, true) => PAGE_EXECUTE_READ,
        (false, false) => PAGE_READONLY,
    }
}

// Only the kernel half can read the page tables. The copy asks the memory manager.
fn protection_at(address: usize) -> u32 {
    let mut region = [0u8; MEMORY_INFORMATION_SIZE];
    if !query_region(address as u64, &mut region) {
        return 0;
    }

    gum_protection_of(&region)
}

fn enumerate_ranges(found: &mut dyn FnMut(u64, u64, u32)) {
    let mut address = 0u64;
    let mut region = [0u8; MEMORY_INFORMATION_SIZE];

    while query_region(address, &mut region) {
        let size = read_field(&region, MEMORY_REGION_SIZE);
        if size == 0 {
            return;
        }

        let protection = gum_protection_of(&region);
        if protection != 0 {
            found(read_field(&region, MEMORY_BASE), size, protection);
        }

        address = address.wrapping_add(size);
    }
}

fn wait(_token: *const u8, timeout_us: Option<u64>, check: &mut dyn FnMut() -> bool) {
    if check() {
        return;
    }

    let due_time = timeout_us.map(|us| -((us as i64) * 10));
    unsafe {
        (user_api().wait_for_object)(target_wake_handle(), 0,
            due_time.as_ref().map_or(core::ptr::null(), |t| t))
    };
}

fn wake(_token: *const u8) {
    unsafe { (user_api().set_event)(target_wake_handle(), core::ptr::null_mut()) };
}

fn yield_now() {
    unsafe { (user_api().yield_execution)() };
}

fn current_process_id() -> u32 {
    current_client_id(BLOCK_PROCESS_ID)
}

fn current_thread_id() -> u64 {
    current_client_id(BLOCK_THREAD_ID) as u64
}

fn shared_data() -> usize {
    USER_SHARED_DATA
}

fn query_region(address: u64, region: &mut [u8; MEMORY_INFORMATION_SIZE]) -> bool {
    let mut written = 0usize;

    unsafe {
        (user_api().query_memory)(CURRENT_PROCESS, address as *mut u8, MEMORY_BASIC_INFORMATION,
            region.as_mut_ptr(), MEMORY_INFORMATION_SIZE, &mut written) >= 0
    }
}

fn gum_protection_of(region: &[u8; MEMORY_INFORMATION_SIZE]) -> u32 {
    if read_field(region, MEMORY_STATE) as u32 != MEM_COMMIT {
        return 0;
    }

    match (read_field(region, MEMORY_PROTECT) as u32) & PAGE_PROTECTION_MASK {
        PAGE_READONLY => GUM_PAGE_READ,
        PAGE_READWRITE | PAGE_WRITECOPY => GUM_PAGE_READ | GUM_PAGE_WRITE,
        PAGE_EXECUTE => GUM_PAGE_EXECUTE,
        PAGE_EXECUTE_READ => GUM_PAGE_READ | GUM_PAGE_EXECUTE,
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY =>
            GUM_PAGE_READ | GUM_PAGE_WRITE | GUM_PAGE_EXECUTE,
        _ => 0,
    }
}

fn read_field(region: &[u8; MEMORY_INFORMATION_SIZE], offset: usize) -> u64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(&region[offset..offset + 8]);
    u64::from_le_bytes(value)
}

// The kernel half waits for an event, thus set the event after you write the frame.
pub(crate) fn signal_kernel_half() {
    unsafe { (user_api().set_event)(agent_wake_handle(), core::ptr::null_mut()) };
}
