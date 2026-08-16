// The half of the NT agent that runs in ring 3, inside a process the host attached to. It reaches
// nothing of the kernel's, thus it has primitives of its own, which frida_winnt_user_main selects
// before it does anything else.

use core::ffi::c_void;

use crate::winnt::{
    BLOCK_PROCESS_ID, BLOCK_THREAD_ID, CURRENT_PROCESS, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    OBSERVED_PID, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, Primitives, STOP_REQUEST,
    TARGET_WAKE_HANDLE, UNICODE_STRING_BUFFER_OFFSET, USER_SHARED_DATA, AGENT_WAKE_HANDLE,
    acknowledge_frame_from_host, select_user, take_frame_from_host, windows_fn,
};

// No code in this image calls the ring 3 entry point, thus tell the linker to keep it.
#[used]
static USER_ENTRY: extern "C" fn(usize) = frida_winnt_user_main;

// This is the half that runs in a process. It has its own copy of the image, thus its data is
// its own. The ring selects which primitives it uses.
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

        unsafe { crate::dispatch_pending_work(context) };
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
    current_thread_id,
    shared_data,
};

fn resolve_user_api() {
    let ntdll = module_base(b"ntdll.dll");

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
    }
}

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

fn module_base(wanted: &[u8]) -> usize {
    unsafe {
        let head = read_pointer(peb() + PEB_LDR_OFFSET) + LDR_IN_LOAD_ORDER_OFFSET;

        let mut entry = read_pointer(head);
        while entry != head {
            let name = read_pointer(entry + ENTRY_BASE_NAME_OFFSET + UNICODE_STRING_BUFFER_OFFSET);
            if name_matches(name, wanted) {
                return read_pointer(entry + ENTRY_DLL_BASE_OFFSET);
            }
            entry = read_pointer(entry);
        }
    }

    0
}

// The loader writes the names as wide characters, and the letter case can be different.
fn name_matches(name: usize, wanted: &[u8]) -> bool {
    for (index, expected) in wanted.iter().enumerate() {
        let actual = unsafe { ((name + index * 2) as *const u16).read() };
        if actual == 0 || (actual as u8).to_ascii_lowercase() != expected.to_ascii_lowercase() {
            return false;
        }
    }

    unsafe { ((name + wanted.len() * 2) as *const u16).read() == 0 }
}

fn export(base: usize, wanted: &[u8]) -> usize {
    unsafe {
        let headers = base + read_u32(base + PE_HEADERS_OFFSET) as usize;
        let magic = (headers + OPTIONAL_HEADER_OFFSET) as *const u16;
        let directories = headers
            + OPTIONAL_HEADER_OFFSET
            + if magic.read() == PE32_PLUS_MAGIC {
                DATA_DIRECTORIES_OFFSET_64
            } else {
                DATA_DIRECTORIES_OFFSET_32
            };

        let exports = base + read_u32(directories) as usize;
        let count = read_u32(exports + EXPORT_NAME_COUNT_OFFSET) as usize;
        let functions = base + read_u32(exports + EXPORT_FUNCTIONS_OFFSET) as usize;
        let names = base + read_u32(exports + EXPORT_NAMES_OFFSET) as usize;
        let ordinals = base + read_u32(exports + EXPORT_ORDINALS_OFFSET) as usize;

        for index in 0..count {
            let name = base + read_u32(names + index * 4) as usize;
            if name_is(name, wanted) {
                let ordinal = ((ordinals + index * 2) as *const u16).read() as usize;
                return base + read_u32(functions + ordinal * 4) as usize;
            }
        }
    }

    0
}

fn name_is(name: usize, wanted: &[u8]) -> bool {
    for (index, expected) in wanted.iter().enumerate() {
        if unsafe { ((name + index) as *const u8).read() } != *expected {
            return false;
        }
    }

    unsafe { ((name + wanted.len()) as *const u8).read() == 0 }
}

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

unsafe fn read_pointer(address: usize) -> usize {
    unsafe { (address as *const usize).read() }
}

unsafe fn read_u32(address: usize) -> u32 {
    unsafe { (address as *const u32).read() }
}

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
const PEB_LDR_OFFSET: usize = 0x0c;
#[cfg(target_arch = "x86")]
const PEB_PROCESS_HEAP_OFFSET: usize = 0x18;
#[cfg(target_arch = "x86")]
const LDR_IN_LOAD_ORDER_OFFSET: usize = 0x0c;
#[cfg(target_arch = "x86")]
const ENTRY_DLL_BASE_OFFSET: usize = 0x18;
#[cfg(target_arch = "x86")]
const ENTRY_BASE_NAME_OFFSET: usize = 0x2c;

#[cfg(target_arch = "x86_64")]
const PEB_LDR_OFFSET: usize = 0x18;
#[cfg(target_arch = "x86_64")]
const PEB_PROCESS_HEAP_OFFSET: usize = 0x30;
#[cfg(target_arch = "x86_64")]
const LDR_IN_LOAD_ORDER_OFFSET: usize = 0x10;
#[cfg(target_arch = "x86_64")]
const ENTRY_DLL_BASE_OFFSET: usize = 0x30;
#[cfg(target_arch = "x86_64")]
const ENTRY_BASE_NAME_OFFSET: usize = 0x58;



const PE_HEADERS_OFFSET: usize = 0x3c;
const OPTIONAL_HEADER_OFFSET: usize = 0x18;
const PE32_PLUS_MAGIC: u16 = 0x20b;
const DATA_DIRECTORIES_OFFSET_32: usize = 0x60;
const DATA_DIRECTORIES_OFFSET_64: usize = 0x70;
const EXPORT_NAME_COUNT_OFFSET: usize = 0x18;
const EXPORT_FUNCTIONS_OFFSET: usize = 0x1c;
const EXPORT_NAMES_OFFSET: usize = 0x20;
const EXPORT_ORDINALS_OFFSET: usize = 0x24;

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
