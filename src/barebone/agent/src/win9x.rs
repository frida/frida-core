// The VMM side of the blob flavor. Reached the way XNU is: the host fills in a
// slot per service before calling _start, so nothing here is a link-time import.
//
// The signatures follow the VxD service documentation; none of them has been
// exercised against a running kernel yet.

use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::kernel::ThreadEntry;

const PAGE_SIZE: u32 = 4096;

const PG_SYS: u32 = 1;
const PAGE_FLAGS_CODE: u32 = PAGE_FIXED | PAGE_LOCKED | PAGE_ZERO_INIT;
const PAGE_FIXED: u32 = 0x8;
const PAGE_LOCKED: u32 = 0x80;
const PAGE_ZERO_INIT: u32 = 0x1;

const PAGE_PRESENT: u32 = 0x1;
const PAGE_WRITEABLE: u32 = 0x2;
const GUM_PAGE_WRITE: u32 = 0x2;

const BLOCK_SVC_INTS: u32 = 1 << 0;

const DEBUG_CONSOLE_PORT: u16 = 0xe9;

pub fn log(msg: &str) {
    for byte in msg.bytes() {
        if byte == 0 {
            break;
        }
        write_debug_byte(byte);
    }
}

pub fn log_hex(value: u32) {
    let mut shift = 32;
    while shift != 0 {
        shift -= 4;
        let digit = ((value >> shift) & 0xf) as u8;
        write_debug_byte(if digit < 10 { b'0' + digit } else { b'a' + digit - 10 });
    }
    write_debug_byte(b'\n');
}

fn write_debug_byte(byte: u8) {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") DEBUG_CONSOLE_PORT, in("al") byte,
            options(nomem, nostack, preserves_flags));
    }
}

pub fn panic(msg: &str) {
    log(msg);
    unsafe {
        fatal_error_handler(msg.as_ptr(), 0);
    }
}

pub fn alloc(size: usize) -> *mut u8 {
    unsafe { __HeapAllocate(size as u32, 0) }
}

pub fn free(ptr: *mut u8, _size: usize) {
    unsafe {
        __HeapFree(ptr, 0);
    }
}

pub fn alloc_code(size: usize) -> *mut u8 {
    let pages = size.div_ceil(PAGE_SIZE as usize) as u32;
    unsafe { __PageAllocate(pages, PG_SYS, 0, 0, 0, 0, core::ptr::null_mut(), PAGE_FLAGS_CODE) }
}

pub fn free_code(ptr: *mut u8, _size: usize) {
    unsafe {
        __PageFree(ptr, 0);
    }
}

pub fn spawn_thread(entry: ThreadEntry, parameter: *mut c_void) -> isize {
    unsafe {
        THREAD_ENTRY = Some(entry);
        THREAD_PARAMETER = parameter;

        vwin32_create_ring0_thread(
            THREAD_STACK_SIZE as u32,
            0,
            frida_win9x_thread_thunk as u32,
            0,
        ) as isize
    }
}

// VMM refuses to build a thread from the borrowed context the host enters us on, and only
// says so by never returning, so hand the work to a point where VMM is between jobs.
pub fn run_when_ready(action: fn()) {
    unsafe {
        READY_ACTION = Some(action);
        schedule_global_event(frida_win9x_event_thunk);
    }
}

#[unsafe(no_mangle)]
extern "C" fn frida_win9x_on_event() {
    if let Some(action) = unsafe { READY_ACTION } {
        action();
    }
}

static mut READY_ACTION: Option<fn()> = None;

#[unsafe(no_mangle)]
extern "C" fn frida_win9x_thread_start() {
    unsafe {
        if let Some(entry) = THREAD_ENTRY {
            entry(THREAD_PARAMETER, 0);
        }
    }
}

static mut THREAD_ENTRY: Option<ThreadEntry> = None;
static mut THREAD_PARAMETER: *mut c_void = core::ptr::null_mut();

const THREAD_STACK_SIZE: usize = 64 * 1024;



pub fn wait(token: *const u8, timeout_us: Option<u64>, check: &mut dyn FnMut() -> bool) {
    let semaphore = semaphore_for(token);
    if check() {
        return;
    }

    match timeout_us {
        None => unsafe { wait_semaphore(semaphore, BLOCK_SVC_INTS) },
        Some(us) => block_until_signalled_or_timed_out(semaphore, us),
    }
}

fn block_until_signalled_or_timed_out(semaphore: u32, timeout_us: u64) {
    let timeout_ms = (timeout_us / 1000).max(1) as u32;
    let timeout = unsafe { set_global_time_out(timeout_ms, semaphore) };
    unsafe {
        wait_semaphore(semaphore, BLOCK_SVC_INTS);
    }
    if timeout != 0 {
        unsafe {
            cancel_time_out(timeout);
        }
    }
}

pub fn wake(token: *const u8) {
    unsafe {
        signal_semaphore(semaphore_for(token));
    }
}

pub fn yield_now() {
    unsafe {
        _Release_Time_Slice();
    }
}

pub fn monotonic_micros() -> i64 {
    unsafe { _Get_System_Time() as i64 * 1000 }
}

pub fn wall_clock_micros() -> (u32, u32) {
    let micros = monotonic_micros() as u64;
    ((micros / 1_000_000) as u32, (micros % 1_000_000) as u32)
}

pub fn current_thread_id() -> u64 {
    unsafe { get_cur_thread_handle() as u64 }
}

pub fn protect(address: u64, size: usize, gum_prot: u32) -> bool {
    let first_page = address / PAGE_SIZE as u64;
    let pages = size.div_ceil(PAGE_SIZE as usize) as u32;

    let mut set = PAGE_PRESENT;
    if (gum_prot & GUM_PAGE_WRITE) != 0 {
        set |= PAGE_WRITEABLE;
    }
    let clear = PAGE_WRITEABLE & !set;

    unsafe { __PageModifyPermissions(first_page as u32, pages, !clear, set) != 0xffff_ffff }
}

pub fn map_io(phys_addr: u64, size: u64) -> *mut c_void {
    let pages = (size as usize).div_ceil(PAGE_SIZE as usize) as u32;
    unsafe { __MapPhysToLinear(phys_addr as u32, pages * PAGE_SIZE, 0) as *mut c_void }
}

pub fn virt_to_phys(vaddr: u64) -> u64 {
    let mut entry: u32 = 0;
    let page = (vaddr / PAGE_SIZE as u64) as u32;
    unsafe {
        __CopyPageTable(page, 1, &mut entry, 0);
    }
    ((entry & !(PAGE_SIZE - 1)) as u64) | (vaddr & (PAGE_SIZE - 1) as u64)
}

pub fn install_interrupt_handler(
    irq: u32,
    target: *mut c_void,
    handler: InterruptHandler,
    refcon: *mut c_void,
) -> i32 {
    unsafe {
        HW_INT_HANDLER = Some(handler);
        HW_INT_TARGET = target;
        HW_INT_REFCON = refcon;
    }

    unsafe {
        IRQ_DESCRIPTOR = VpicdIrqDescriptor {
            irq_number: irq as u16,
            options: VPICD_OPT_REF_DATA | VPICD_OPT_CAN_SHARE,
            hw_int_proc: frida_win9x_hw_int_thunk,
            virt_int_proc: 0,
            eoi_proc: 0,
            mask_change_proc: 0,
            iret_proc: 0,
            iret_time_out: VPICD_DEFAULT_IRET_TIME_OUT,
            hw_int_ref: 0,
        };
    }

    let handle = unsafe { vpicd_virtualize_irq(core::ptr::addr_of_mut!(IRQ_DESCRIPTOR)) };
    if handle != 0 {
        unsafe {
            IRQ_HANDLE = handle;
            vpicd_physically_unmask(handle);
        }
    }
    if handle == 0 { -1 } else { 0 }
}

pub struct ProcessInfo {
    pub id: u32,
    pub path: *const u8,
}

// Win32 threads carry the process they belong to in VWIN32's per-thread block, so the
// process list is the deduplicated set of those, and the image path is where the command
// line starts.
pub fn enumerate_processes(found: &mut dyn FnMut(ProcessInfo)) {
    let slot = unsafe { (0xc00211ccu32 as *const u32).read() };
    let vm = unsafe { get_sys_vm_handle() };
    let first = unsafe { get_initial_thread_handle(vm) };

    let mut seen: [u32; 64] = [0; 64];
    let mut count = 0usize;
    let mut thread = first;
    while thread != 0 && count < seen.len() {
        if unsafe { (thread as *const u32).add(0x2c / 4).read() } == WIN32_THREAD {
            let block = unsafe { (thread as *const u32).byte_add(slot as usize).read() };
            let pdb = unsafe { (block as *const u32).add(1).read() };
            if !seen[..count].contains(&pdb) {
                seen[count] = pdb;
                count += 1;
                found(ProcessInfo {
                    id: process_id(pdb),
                    path: image_path(pdb),
                });
            }
        }

        let next = unsafe { get_next_thread_handle(thread) };
        thread = if next == first { 0 } else { next };
    }
}

// KERNEL32 hands out its process database pointer XOR a per-boot value, and so must we.
fn process_id(pdb: u32) -> u32 {
    let slot = unsafe { core::ptr::addr_of!(_KERNEL32_ProcessIdObfuscator).read() };
    if slot == 0 {
        return pdb;
    }

    pdb ^ unsafe { (slot as *const u32).read() }
}

// The command line would do for most processes, but it is empty for the ones Windows starts
// itself and can carry arguments besides. KERNEL32 names a module the way GetModuleFileName
// does: the process's own MODREF, indexed into the module table.
fn image_path(pdb: u32) -> *const u8 {
    let slot = unsafe { core::ptr::addr_of!(_KERNEL32_ModuleTable).read() };
    if slot == 0 {
        return core::ptr::null();
    }

    let table = unsafe { (slot as *const u32).read() };
    let modref = unsafe { (pdb as *const u32).byte_add(PDB_MODREF_OFFSET).read() };
    if table < ARENA_FLOOR || modref < ARENA_FLOOR {
        return core::ptr::null();
    }

    let index = unsafe { (modref as *const u16).byte_add(MODREF_MTE_INDEX_OFFSET).read() };
    let entry = unsafe { (table as *const u32).add(index as usize).read() };
    if entry < ARENA_FLOOR {
        return core::ptr::null();
    }

    let path = unsafe { (entry as *const u32).byte_add(IMTE_FILE_NAME_OFFSET).read() };
    if path < ARENA_FLOOR {
        return core::ptr::null();
    }

    path as *const u8
}

const WIN32_THREAD: u32 = 0x2a;
const ARENA_FLOOR: u32 = 0x10000;
const PDB_MODREF_OFFSET: usize = 0x94;
const MODREF_MTE_INDEX_OFFSET: usize = 0x10;
const IMTE_FILE_NAME_OFFSET: usize = 0x0c;

pub fn enumerate_icons(path: *const u8, found: &mut dyn FnMut(&[u8])) {
    let file = match File::open(path) {
        Some(file) => file,
        None => return,
    };

    let resources = match file.resource_directory() {
        Some(resources) => resources,
        None => return,
    };

    let group = match resources.first_leaf(RT_GROUP_ICON) {
        Some(group) => group,
        None => return,
    };

    let count = file.read_u16(group.offset + GROUP_COUNT_OFFSET);
    for index in 0..count as u32 {
        let entry = group.offset + GROUP_ENTRIES_OFFSET + index * GROUP_ENTRY_SIZE;
        let id = file.read_u16(entry + GROUP_ENTRY_ID_OFFSET);
        if let Some(icon) = resources.leaf(RT_ICON, id) {
            if let Some(bytes) = file.read_blob(icon.offset, icon.size) {
                found(bytes);
            }
        }
    }
}

struct File {
    handle: u32,
}

impl File {
    fn open(path: *const u8) -> Option<File> {
        let handle = unsafe {
            ifsmgr_ring0_file_io(
                R0_OPENCREATFILE,
                0,
                0,
                ACTION_OPENEXISTING,
                path as u32,
                ACCESS_READONLY | SHARE_DENYNONE,
            )
        };
        if handle == 0 {
            return None;
        }

        Some(File { handle })
    }

    fn resource_directory(&self) -> Option<ResourceDirectory> {
        let headers = self.read_u32(DOS_HEADERS_OFFSET);
        if self.read_u32(headers) != PE_SIGNATURE {
            return None;
        }

        let optional = headers + OPTIONAL_HEADER_OFFSET;
        let directory_rva = self.read_u32(optional + RESOURCE_DIRECTORY_OFFSET);
        if directory_rva == 0 {
            return None;
        }

        let sections = optional + self.read_u16(headers + OPTIONAL_HEADER_SIZE_OFFSET) as u32;
        let section_count = self.read_u16(headers + SECTION_COUNT_OFFSET) as u32;
        for index in 0..section_count {
            let section = sections + index * SECTION_SIZE;
            let virtual_address = self.read_u32(section + SECTION_RVA_OFFSET);
            let virtual_size = self.read_u32(section + SECTION_VIRTUAL_SIZE_OFFSET);
            if directory_rva >= virtual_address && directory_rva < virtual_address + virtual_size {
                let raw_data = self.read_u32(section + SECTION_RAW_DATA_OFFSET);
                return Some(ResourceDirectory {
                    file: self,
                    rva: directory_rva,
                    offset: directory_rva - virtual_address + raw_data,
                });
            }
        }

        None
    }

    fn read_u32(&self, position: u32) -> u32 {
        let mut bytes = [0u8; 4];
        self.read_at(position, &mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn read_u16(&self, position: u32) -> u16 {
        let mut bytes = [0u8; 2];
        self.read_at(position, &mut bytes);
        u16::from_le_bytes(bytes)
    }

    fn read_blob(&self, position: u32, size: u32) -> Option<&'static [u8]> {
        let blob = unsafe { &mut *core::ptr::addr_of_mut!(ICON_BUFFER) };
        if size as usize > blob.len() {
            return None;
        }

        let read = self.read_at(position, &mut blob[..size as usize]);
        if read != size {
            return None;
        }

        Some(&blob[..size as usize])
    }

    fn read_at(&self, position: u32, buffer: &mut [u8]) -> u32 {
        unsafe {
            ifsmgr_ring0_file_io(
                R0_READFILE,
                self.handle,
                buffer.len() as u32,
                position,
                buffer.as_mut_ptr() as u32,
                0,
            )
        }
    }
}

impl Drop for File {
    fn drop(&mut self) {
        unsafe { ifsmgr_ring0_file_io(R0_CLOSEFILE, self.handle, 0, 0, 0, 0) };
    }
}

struct ResourceDirectory<'f> {
    file: &'f File,
    rva: u32,
    offset: u32,
}

struct Resource {
    offset: u32,
    size: u32,
}

impl ResourceDirectory<'_> {
    fn first_leaf(&self, kind: u16) -> Option<Resource> {
        let by_name = self.subdirectory(self.offset, kind)?;
        let by_language = self.first_subdirectory(by_name)?;

        self.leaf_at(self.first_subdirectory(by_language)?)
    }

    fn leaf(&self, kind: u16, name: u16) -> Option<Resource> {
        let by_name = self.subdirectory(self.offset, kind)?;
        let by_language = self.subdirectory(by_name, name)?;

        self.leaf_at(self.first_subdirectory(by_language)?)
    }

    fn subdirectory(&self, directory: u32, id: u16) -> Option<u32> {
        for entry in self.entries(directory) {
            if self.file.read_u32(entry) == id as u32 {
                return Some(self.child(entry));
            }
        }

        None
    }

    fn first_subdirectory(&self, directory: u32) -> Option<u32> {
        self.entries(directory).next().map(|e| self.child(e))
    }

    fn entries(&self, directory: u32) -> impl Iterator<Item = u32> + '_ {
        let named = self.file.read_u16(directory + NAMED_ENTRY_COUNT_OFFSET) as u32;
        let identified = self.file.read_u16(directory + ID_ENTRY_COUNT_OFFSET) as u32;
        let first = directory + DIRECTORY_HEADER_SIZE + named * DIRECTORY_ENTRY_SIZE;

        (0..identified).map(move |index| first + index * DIRECTORY_ENTRY_SIZE)
    }

    fn child(&self, entry: u32) -> u32 {
        let value = self.file.read_u32(entry + DIRECTORY_ENTRY_CHILD_OFFSET);
        self.offset + (value & !SUBDIRECTORY_FLAG)
    }

    fn leaf_at(&self, data_entry: u32) -> Option<Resource> {
        let data_rva = self.file.read_u32(data_entry);

        Some(Resource {
            offset: self.offset + data_rva - self.rva,
            size: self.file.read_u32(data_entry + DATA_ENTRY_SIZE_OFFSET),
        })
    }
}

static mut ICON_BUFFER: [u8; MAX_ICON_SIZE] = [0; MAX_ICON_SIZE];

const MAX_ICON_SIZE: usize = 16 * 1024;

const R0_OPENCREATFILE: u32 = 0xd500;
const R0_READFILE: u32 = 0xd600;
const R0_CLOSEFILE: u32 = 0xd700;
const ACCESS_READONLY: u32 = 0x0000;
const SHARE_DENYNONE: u32 = 0x0040;
const ACTION_OPENEXISTING: u32 = 0x01;

const DOS_HEADERS_OFFSET: u32 = 0x3c;
const PE_SIGNATURE: u32 = 0x00004550;
const SECTION_COUNT_OFFSET: u32 = 0x06;
const OPTIONAL_HEADER_SIZE_OFFSET: u32 = 0x14;
const OPTIONAL_HEADER_OFFSET: u32 = 0x18;
const RESOURCE_DIRECTORY_OFFSET: u32 = 0x70;
const SECTION_SIZE: u32 = 0x28;
const SECTION_VIRTUAL_SIZE_OFFSET: u32 = 0x08;
const SECTION_RVA_OFFSET: u32 = 0x0c;
const SECTION_RAW_DATA_OFFSET: u32 = 0x14;

const RT_ICON: u16 = 3;
const RT_GROUP_ICON: u16 = 14;
const NAMED_ENTRY_COUNT_OFFSET: u32 = 0x0c;
const ID_ENTRY_COUNT_OFFSET: u32 = 0x0e;
const DIRECTORY_HEADER_SIZE: u32 = 0x10;
const DIRECTORY_ENTRY_SIZE: u32 = 0x08;
const DIRECTORY_ENTRY_CHILD_OFFSET: u32 = 0x04;
const SUBDIRECTORY_FLAG: u32 = 0x8000_0000;
const DATA_ENTRY_SIZE_OFFSET: u32 = 0x04;
const GROUP_COUNT_OFFSET: u32 = 0x04;
const GROUP_ENTRIES_OFFSET: u32 = 0x06;
const GROUP_ENTRY_SIZE: u32 = 0x0e;
const GROUP_ENTRY_ID_OFFSET: u32 = 0x0c;

pub fn install_fault_reporter() {
    unsafe {
        FAULT_CHAIN[INVALID_OPCODE as usize] = hook_vmm_fault(INVALID_OPCODE, frida_win9x_fault_thunk_ud);
        FAULT_CHAIN[GENERAL_PROTECTION as usize] =
            hook_vmm_fault(GENERAL_PROTECTION, frida_win9x_fault_thunk_gp);
        FAULT_CHAIN[PAGE_FAULT as usize] = hook_vmm_fault(PAGE_FAULT, frida_win9x_fault_thunk_pf);
    }
}

#[unsafe(no_mangle)]
extern "C" fn frida_win9x_on_fault(fault: u32, frame: *mut u32) -> u32 {
    let mut cpu_context = unsafe {
        crate::bindings::_GumIA32CpuContext {
            eip: frame.add(fault_frame_eip_slot(fault)).read(),
            edi: frame.read(),
            esi: frame.add(1).read(),
            ebp: frame.add(2).read(),
            esp: frame.add(3).read(),
            ebx: frame.add(4).read(),
            edx: frame.add(5).read(),
            ecx: frame.add(6).read(),
            eax: frame.add(7).read(),
            xmm: core::ptr::null_mut(),
        }
    };

    let handled = unsafe {
        crate::bindings::gum_barebone_handle_exception(
            exception_type_for(fault),
            cpu_context.eip as *mut c_void,
            faulting_address() as *mut c_void,
            &mut cpu_context,
        )
    };
    if handled == 0 {
        return unsafe { FAULT_CHAIN[fault as usize] };
    }

    unsafe {
        frida_win9x_resume = [
            cpu_context.eip,
            cpu_context.edi,
            cpu_context.esi,
            cpu_context.ebp,
            cpu_context.esp,
            cpu_context.ebx,
            cpu_context.edx,
            cpu_context.ecx,
            cpu_context.eax,
        ];
    }

    0
}

#[unsafe(no_mangle)]
static mut frida_win9x_resume: [u32; 9] = [0; 9];

fn exception_type_for(fault: u32) -> crate::bindings::GumExceptionType {
    use crate::bindings::*;

    match fault {
        DIVIDE_ERROR | OVERFLOW | BOUND_RANGE_EXCEEDED | X87_FLOATING_POINT
        | SIMD_FLOATING_POINT => _GumExceptionType_GUM_EXCEPTION_ARITHMETIC,
        DEBUG => _GumExceptionType_GUM_EXCEPTION_SINGLE_STEP,
        BREAKPOINT => _GumExceptionType_GUM_EXCEPTION_BREAKPOINT,
        INVALID_OPCODE => _GumExceptionType_GUM_EXCEPTION_ILLEGAL_INSTRUCTION,
        STACK_SEGMENT_FAULT => _GumExceptionType_GUM_EXCEPTION_STACK_OVERFLOW,
        GENERAL_PROTECTION | PAGE_FAULT => _GumExceptionType_GUM_EXCEPTION_ACCESS_VIOLATION,
        _ => _GumExceptionType_GUM_EXCEPTION_SYSTEM,
    }
}

const DIVIDE_ERROR: u32 = 0;
const DEBUG: u32 = 1;
const BREAKPOINT: u32 = 3;
const OVERFLOW: u32 = 4;
const BOUND_RANGE_EXCEEDED: u32 = 5;
const STACK_SEGMENT_FAULT: u32 = 12;
const X87_FLOATING_POINT: u32 = 16;
const SIMD_FLOATING_POINT: u32 = 19;

fn fault_frame_eip_slot(fault: u32) -> usize {
    const PUSHED_REGISTERS: usize = 8;
    const VECTOR: usize = 1;

    let error_code = match fault {
        8 | 10 | 11 | 12 | 13 | 14 | 17 | 21 => 1,
        _ => 0,
    };

    PUSHED_REGISTERS + VECTOR + error_code
}

fn faulting_address() -> u32 {
    let address: u32;
    unsafe { core::arch::asm!("mov {0:e}, cr2", out(reg) address, options(nomem, nostack, preserves_flags)) };
    address
}

static mut FAULT_CHAIN: [u32; 32] = [0; 32];

#[unsafe(no_mangle)]
static mut frida_win9x_fault_chain: u32 = 0;

const INVALID_OPCODE: u32 = 6;
const GENERAL_PROTECTION: u32 = 13;
const PAGE_FAULT: u32 = 14;

#[unsafe(no_mangle)]
extern "C" fn frida_win9x_on_hw_int(_ref_data: *mut c_void) {
    unsafe {
        if let Some(handler) = HW_INT_HANDLER {
            handler(HW_INT_TARGET, HW_INT_REFCON, core::ptr::null_mut(), 0);
        }
        vpicd_phys_eoi(IRQ_HANDLE);
    }
}

static mut IRQ_HANDLE: u32 = 0;

static mut IRQ_DESCRIPTOR: VpicdIrqDescriptor = VpicdIrqDescriptor {
    irq_number: 0,
    options: 0,
    hw_int_proc: frida_win9x_hw_int_thunk,
    virt_int_proc: 0,
    eoi_proc: 0,
    mask_change_proc: 0,
    iret_proc: 0,
    iret_time_out: 0,
    hw_int_ref: 0,
};

static mut HW_INT_HANDLER: Option<InterruptHandler> = None;
static mut HW_INT_TARGET: *mut c_void = core::ptr::null_mut();
static mut HW_INT_REFCON: *mut c_void = core::ptr::null_mut();

#[repr(C)]
struct VpicdIrqDescriptor {
    irq_number: u16,
    options: u16,
    hw_int_proc: unsafe extern "C" fn(),
    virt_int_proc: u32,
    eoi_proc: u32,
    mask_change_proc: u32,
    iret_proc: u32,
    iret_time_out: u32,
    hw_int_ref: u32,
}

const VPICD_OPT_CAN_SHARE: u16 = 0x02;
const VPICD_OPT_REF_DATA: u16 = 0x04;
const VPICD_DEFAULT_IRET_TIME_OUT: u32 = 500;

pub type InterruptHandler =
    unsafe extern "C" fn(target: *mut c_void, refcon: *mut c_void, nub: *mut c_void, source: i32);

pub fn get_kernel_base() -> u64 {
    KERNEL_BASE.load(Ordering::Relaxed) as u64
}

pub fn set_kernel_base(base: u64) {
    KERNEL_BASE.store(base as u32, Ordering::Relaxed);
}

static KERNEL_BASE: AtomicU32 = AtomicU32::new(0);

// One semaphore per waited-on address, created on first use. VMM has no
// futex-alike, so the token has to be mapped onto something it does have.
fn semaphore_for(token: *const u8) -> u32 {
    let slot = (token as usize / core::mem::align_of::<usize>()) % SEMAPHORES.len();
    let existing = SEMAPHORES[slot].load(Ordering::Acquire);
    if existing != 0 {
        return existing;
    }

    let created = unsafe { create_semaphore(0) };
    match SEMAPHORES[slot].compare_exchange(0, created, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => created,
        Err(raced) => raced,
    }
}

const NUM_SEMAPHORES: usize = 64;
static SEMAPHORES: [AtomicU32; NUM_SEMAPHORES] = [const { AtomicU32::new(0) }; NUM_SEMAPHORES];

unsafe extern "C" {
    fn wait_semaphore(semaphore: u32, flags: u32);
    fn signal_semaphore(semaphore: u32);
    fn create_semaphore(token_count: u32) -> u32;
    fn get_cur_thread_handle() -> u32;
    fn fatal_error_handler(message: *const u8, flags: u32);
    fn vpicd_virtualize_irq(descriptor: *mut VpicdIrqDescriptor) -> u32;
    fn vpicd_physically_unmask(handle: u32);
    fn vpicd_phys_eoi(handle: u32);
    fn set_global_time_out(milliseconds: u32, semaphore: u32) -> u32;
    fn cancel_time_out(timeout: u32);
    fn hook_vmm_fault(fault: u32, handler: unsafe extern "C" fn()) -> u32;
    fn frida_win9x_fault_thunk_ud();
    fn frida_win9x_fault_thunk_gp();
    fn frida_win9x_fault_thunk_pf();
    fn frida_win9x_time_out_thunk();
    fn get_cur_vm_handle() -> u32;
    fn get_sys_vm_handle() -> u32;
    fn schedule_global_event(callback: unsafe extern "C" fn()) -> u32;
    fn frida_win9x_event_thunk();
    fn get_next_vm_handle(vm: u32) -> u32;
    fn get_initial_thread_handle(vm: u32) -> u32;
    fn get_next_thread_handle(thread: u32) -> u32;
    fn ifsmgr_ring0_file_io(function: u32, ebx: u32, ecx: u32, edx: u32, esi: u32, edi: u32) -> u32;
    fn vwin32_create_ring0_thread(stack_size: u32, parameter: u32, entry: u32, event: u32) -> u32;
    fn frida_win9x_hw_int_thunk();
    fn frida_win9x_thread_thunk();
}

core::arch::global_asm!(
    r#"
.intel_syntax noprefix

.global wait_semaphore
wait_semaphore:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    mov eax, [ebp + 8]
    mov ecx, [ebp + 12]
    call dword ptr [_Wait_Semaphore]
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.global signal_semaphore
signal_semaphore:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    mov eax, [ebp + 8]
    call dword ptr [_Signal_Semaphore]
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.global create_semaphore
create_semaphore:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    mov ecx, [ebp + 8]
    call dword ptr [_Create_Semaphore]
    cmc
    sbb ecx, ecx
    and eax, ecx
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.global get_cur_thread_handle
get_cur_thread_handle:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    call dword ptr [_Get_Cur_Thread_Handle]
    mov eax, edi
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.global fatal_error_handler
fatal_error_handler:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    mov esi, [ebp + 8]
    mov eax, [ebp + 12]
    call dword ptr [_Fatal_Error_Handler]
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.global schedule_global_event
schedule_global_event:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    mov esi, [ebp + 8]
    call dword ptr [_Schedule_Global_Event]
    mov eax, ebx
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.global frida_win9x_event_thunk
frida_win9x_event_thunk:
    pushad
    call frida_win9x_on_event
    popad
    ret

.global get_sys_vm_handle
get_sys_vm_handle:
    push ebx
    call dword ptr [_Get_Sys_VM_Handle]
    mov eax, ebx
    pop ebx
    ret

.global get_next_vm_handle
get_next_vm_handle:
    push ebp
    mov ebp, esp
    push ebx
    mov ebx, [ebp + 8]
    call dword ptr [_Get_Next_VM_Handle]
    mov eax, ebx
    pop ebx
    pop ebp
    ret

.global get_initial_thread_handle
get_initial_thread_handle:
    push ebp
    mov ebp, esp
    push ebx
    push edi
    mov ebx, [ebp + 8]
    call dword ptr [_Get_Initial_Thread_Handle]
    mov eax, edi
    pop edi
    pop ebx
    pop ebp
    ret

.global get_next_thread_handle
get_next_thread_handle:
    push ebp
    mov ebp, esp
    push ebx
    push edi
    mov edi, [ebp + 8]
    call dword ptr [_Get_Next_Thread_Handle]
    mov eax, edi
    pop edi
    pop ebx
    pop ebp
    ret

.global vwin32_create_ring0_thread
vwin32_create_ring0_thread:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    mov ecx, [ebp + 8]
    mov edx, [ebp + 12]
    mov ebx, [ebp + 16]
    mov esi, [ebp + 20]
    call dword ptr [__VWIN32_CreateRing0Thread]
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.global ifsmgr_ring0_file_io
ifsmgr_ring0_file_io:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    mov eax, [ebp + 8]
    mov ebx, [ebp + 12]
    mov ecx, [ebp + 16]
    mov edx, [ebp + 20]
    mov esi, [ebp + 24]
    mov edi, [ebp + 28]
    call dword ptr [_IFSMgr_Ring0_FileIO]
    jnc 1f
    xor eax, eax
1:
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.global get_cur_vm_handle
get_cur_vm_handle:
    push ebx
    call dword ptr [_Get_Cur_VM_Handle]
    mov eax, ebx
    pop ebx
    ret

.global hook_vmm_fault
hook_vmm_fault:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    mov eax, [ebp + 8]
    mov esi, [ebp + 12]
    call dword ptr [_Hook_VMM_Fault]
    mov eax, esi
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.global frida_win9x_fault_thunk_ud
frida_win9x_fault_thunk_ud:
    push 6
    jmp frida_win9x_fault_common

.global frida_win9x_fault_thunk_gp
frida_win9x_fault_thunk_gp:
    push 13
    jmp frida_win9x_fault_common

.global frida_win9x_fault_thunk_pf
frida_win9x_fault_thunk_pf:
    push 14
    jmp frida_win9x_fault_common

frida_win9x_fault_common:
    pushad
    mov eax, [esp + 32]
    push esp
    push eax
    call frida_win9x_on_fault
    add esp, 8
    mov [frida_win9x_fault_chain], eax
    popad
    add esp, 4
    cmp dword ptr [frida_win9x_fault_chain], 0
    je frida_win9x_fault_resume
    jmp dword ptr [frida_win9x_fault_chain]
frida_win9x_fault_resume:
    mov esp, [frida_win9x_resume + 16]
    mov edi, [frida_win9x_resume + 4]
    mov esi, [frida_win9x_resume + 8]
    mov ebp, [frida_win9x_resume + 12]
    mov ebx, [frida_win9x_resume + 20]
    mov edx, [frida_win9x_resume + 24]
    mov ecx, [frida_win9x_resume + 28]
    mov eax, [frida_win9x_resume + 32]
    push dword ptr [frida_win9x_resume]
    ret

.global set_global_time_out
set_global_time_out:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    mov eax, [ebp + 8]
    mov edx, [ebp + 12]
    lea esi, [frida_win9x_time_out_thunk]
    call dword ptr [_Set_Global_Time_Out]
    mov eax, esi
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.global cancel_time_out
cancel_time_out:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    mov esi, [ebp + 8]
    call dword ptr [_Cancel_Time_Out]
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.global frida_win9x_time_out_thunk
frida_win9x_time_out_thunk:
    pushad
    mov eax, edx
    call dword ptr [_Signal_Semaphore]
    popad
    ret

.global vpicd_phys_eoi
vpicd_phys_eoi:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    mov eax, [ebp + 8]
    call dword ptr [_VPICD_Phys_EOI]
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.global vpicd_physically_unmask
vpicd_physically_unmask:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    mov eax, [ebp + 8]
    call dword ptr [_VPICD_Physically_Unmask]
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.global vpicd_virtualize_irq
vpicd_virtualize_irq:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    call dword ptr [_Get_Cur_VM_Handle]
    mov edi, [ebp + 8]
    call dword ptr [_VPICD_Virtualize_IRQ]
    cmc
    sbb ecx, ecx
    and eax, ecx
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

.global frida_win9x_thread_thunk
frida_win9x_thread_thunk:
    call frida_win9x_thread_start
1:
    jmp 1b

.global frida_win9x_hw_int_thunk
frida_win9x_hw_int_thunk:
    pushad
    push edx
    call frida_win9x_on_hw_int
    add esp, 4
    popad
    clc
    ret
"#
);

unsafe extern "C" {
    static _Get_Cur_VM_Handle: unsafe extern "C" fn();
    static _Get_Sys_VM_Handle: unsafe extern "C" fn();
    static _Schedule_Global_Event: unsafe extern "C" fn();
    static _Create_Semaphore: unsafe extern "C" fn();
    static _Wait_Semaphore: unsafe extern "C" fn();
    static _Signal_Semaphore: unsafe extern "C" fn();
    static _Get_Next_VM_Handle: unsafe extern "C" fn();
    static _Release_Time_Slice: unsafe extern "C" fn();
    static _Set_Global_Time_Out: unsafe extern "C" fn();
    static _Cancel_Time_Out: unsafe extern "C" fn();
    static _Get_System_Time: unsafe extern "C" fn() -> u32;
    static __HeapAllocate: unsafe extern "C" fn(u32, u32) -> *mut u8;
    static __HeapFree: unsafe extern "C" fn(*mut u8, u32);
    static __PageAllocate:
        unsafe extern "C" fn(u32, u32, u32, u32, u32, u32, *mut c_void, u32) -> *mut u8;
    static __PageFree: unsafe extern "C" fn(*mut u8, u32);
    static __CopyPageTable: unsafe extern "C" fn(u32, u32, *mut u32, u32) -> u32;
    static __MapPhysToLinear: unsafe extern "C" fn(u32, u32, u32) -> u32;
    static _Hook_VMM_Fault: unsafe extern "C" fn();
    static _Fatal_Error_Handler: unsafe extern "C" fn();
    static _Get_Cur_Thread_Handle: unsafe extern "C" fn();
    static _Get_Initial_Thread_Handle: unsafe extern "C" fn();
    static _Get_Next_Thread_Handle: unsafe extern "C" fn();
    static __Debug_Printf_Service: unsafe extern "C" fn(*const u8, ...);
    static __ContextSwitch: unsafe extern "C" fn(u32);
    static __PageModifyPermissions: unsafe extern "C" fn(u32, u32, u32, u32) -> u32;
    static __GetCurrentContext: unsafe extern "C" fn() -> u32;
    static _VPICD_Virtualize_IRQ: unsafe extern "C" fn();
    static _VPICD_Phys_EOI: unsafe extern "C" fn();
    static _VPICD_Physically_Unmask: unsafe extern "C" fn();
    static __VWIN32_CreateRing0Thread: unsafe extern "C" fn();
    static _IFSMgr_Ring0_FileIO: unsafe extern "C" fn();
    static _KERNEL32_ProcessIdObfuscator: u32;
    static _KERNEL32_ModuleTable: u32;
}
