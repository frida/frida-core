// The agent injected from the outside: the host resolves the kernel functions
// below and patches their addresses into .kernel_addrs, the same way it does
// for XNU and Windows. Everything the kernel would otherwise have to lend us --
// its symbol table, its module list, the right to write to its pages -- comes
// from the host instead, over the hostlink.

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::ptr;
use core::ptr::read_volatile;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::kernel::ThreadEntry;

#[cfg(target_arch = "x86")]
pub fn log(msg: &str) {
    unsafe { frida_k_log(msg.as_ptr() as *const c_char) };
}

#[cfg(not(target_arch = "x86"))]
pub fn log(msg: &str) {
    unsafe {
        if let Some(f) = __printk {
            f(msg.as_ptr() as *const c_char)
        } else {
            _printk.unwrap()(msg.as_ptr() as *const c_char)
        }
    };
}

pub fn panic(msg: &str) -> ! {
    unsafe { _panic(msg.as_ptr() as *const c_char) }
}

pub fn run_when_ready(action: fn()) {
    waiters();

    action();
}

// A fault in the agent goes to the kernel as it is, which prints the register
// dump and the backtrace this would otherwise have to reproduce.
pub fn install_fault_reporter() {}

pub fn release_fault_reporter() {}

pub fn send_signal(signal: c_int, task: usize) {
    unsafe { _send_sig(signal, task as *mut c_void, 1) };
}

pub fn release_interrupt() {
    let Some(interrupt) = (unsafe { (&raw mut INTERRUPT).as_mut().unwrap().take() }) else {
        return;
    };

    unsafe { _free_irq(interrupt.irq, interrupt.target) };
}

pub fn take_the_file(descriptor: u32) -> *mut c_void {
    unsafe { _fget(descriptor) }
}

pub fn let_the_file_go(file: *mut c_void) {
    unsafe { super::processes::let_go_of(file) };
}

pub fn wait_for_a_word(file: *mut c_void) -> bool {
    let mut byte = 0u8;
    let mut at = 0i64;

    unsafe { _kernel_read(file, &mut byte, 1, &mut at) == 1 }
}

pub fn leave_a_word(file: *mut c_void) {
    let byte = 0u8;
    let mut at = 0i64;

    unsafe { _kernel_write(file, &byte, 1, &mut at) };
}

pub fn spawn_thread(entry: ThreadEntry, parameter: *mut c_void) -> isize {
    let trampoline = alloc(size_of::<Trampoline>()) as *mut Trampoline;
    unsafe {
        trampoline.write(Trampoline { entry, parameter });

        let task = _kthread_create_on_node(
            THREAD_ENTRY,
            trampoline as *mut c_void,
            NUMA_NO_NODE,
            c"frida".as_ptr(),
        );
        _wake_up_process(task);
    }
    0
}

#[cfg(target_arch = "x86")]
pub fn alloc(size: usize) -> *mut u8 {
    unsafe { frida_k_alloc(size, GFP_KERNEL as usize) }
}

#[cfg(not(target_arch = "x86"))]
pub fn alloc(size: usize) -> *mut u8 {
    unsafe {
        if let Some(f) = ___kmalloc_noprof {
            f(size, GFP_KERNEL)
        } else {
            _kmalloc.unwrap()(size, GFP_KERNEL)
        }
    }
}

pub fn free(ptr: *mut u8, _size: usize) {
    unsafe { _kfree(ptr) };
}

#[cfg(target_arch = "x86")]
pub fn alloc_code(size: usize) -> *mut u8 {
    unsafe {
        frida_k_alloc_code(EXECMEM_MODULE_TEXT as usize, size, size.div_ceil(PAGE_SIZE))
    }
}

#[cfg(not(target_arch = "x86"))]
pub fn alloc_code(size: usize) -> *mut u8 {
    unsafe {
        let code = if let Some(f) = _execmem_alloc {
            f(EXECMEM_MODULE_TEXT, size)
        } else {
            _module_alloc.unwrap()(size)
        };

        if let Some(f) = _set_memory_rw {
            f(code as usize, size.div_ceil(PAGE_SIZE) as c_int);
        }

        code
    }
}

#[cfg(target_arch = "x86")]
pub fn free_code(ptr: *mut u8, _size: usize) {
    unsafe { frida_k_free_code(ptr) };
}

#[cfg(not(target_arch = "x86"))]
pub fn free_code(ptr: *mut u8, _size: usize) {
    unsafe {
        if let Some(f) = _execmem_free {
            f(ptr);
        } else {
            _module_memfree.unwrap()(ptr);
        }
    }
}

pub fn page_size() -> usize {
    crate::gum::page_size_the_kernel_runs_with()
}

pub fn protect(address: u64, size: usize, protection: u32) -> bool {
    crate::gum_injected::ask_the_host_to_protect(address, size, protection)
}

pub fn current_process_id() -> u32 {
    KERNEL_PROCESS
}

pub fn alloc_dma(size: usize) -> *mut u8 {
    alloc(size)
}

pub fn free_dma(ptr: *mut u8, size: usize) {
    free(ptr, size);
}

pub fn wait(_token: *const u8, timeout_us: Option<u64>, check: &mut dyn FnMut() -> bool) {
    let waiters = waiters();

    let mut waiter = [0usize; WAIT_ENTRY_WORDS];
    let waiter = queue_this_thread(&mut waiter);

    unsafe { _prepare_to_wait_event(waiters, waiter, TASK_INTERRUPTIBLE) };

    if !check() {
        match timeout_us {
            Some(us) => {
                let mut until = (us as i64) * 1000;
                unsafe { _schedule_hrtimeout_range(&mut until, WAKE_SLACK_NS, HRTIMER_MODE_REL) };
            }
            None => unsafe { _schedule() },
        }
    }

    unsafe { _finish_wait(waiters, waiter) };
}

pub fn wake(_token: *const u8) {
    unsafe { ___wake_up(waiters(), TASK_NORMAL, WAKE_EVERY_WAITER, ptr::null_mut()) };
}

fn queue_this_thread(entry: &mut [usize; WAIT_ENTRY_WORDS]) -> *mut c_void {
    let entry = entry.as_mut_ptr();

    unsafe {
        entry.add(WAIT_ENTRY_THREAD).write(current_task() as usize);
        entry.add(WAIT_ENTRY_WAKE).write(_autoremove_wake_function as usize);

        let queued = entry.add(WAIT_ENTRY_QUEUED);
        queued.write(queued as usize);
        queued.add(1).write(queued as usize);
    }

    entry as *mut c_void
}

fn waiters() -> *mut c_void {
    let queue = (&raw mut WAITERS) as *mut c_void;


    if !WAITERS_CLAIMED.swap(true, Ordering::AcqRel) {
        unsafe {
            ___init_waitqueue_head(queue, c"frida".as_ptr(), (&raw mut WAITERS_KEY) as *mut c_void)
        };
        WAITERS_READY.store(true, Ordering::Release);
    }
    while !WAITERS_READY.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }

    queue
}

static mut WAITERS: [usize; WAIT_QUEUE_WORDS] = [0; WAIT_QUEUE_WORDS];
static mut WAITERS_KEY: [usize; LOCK_KEY_WORDS] = [0; LOCK_KEY_WORDS];
static WAITERS_CLAIMED: AtomicBool = AtomicBool::new(false);
static WAITERS_READY: AtomicBool = AtomicBool::new(false);

pub fn pci_interrupt(bus: u8, devfn: u8) -> Option<u32> {
    let device = unsafe { _pci_get_domain_bus_and_slot(0, bus as c_uint, devfn as c_uint) };
    if device.is_null() {
        return None;
    }

    let line = unsafe { _pci_irq_vector(device, 0) };
    unsafe { _pci_dev_put(device) };

    if line < 0 {
        return None;
    }

    Some(line as u32)
}

pub fn yield_now() {
    unsafe { _schedule() };
}

pub fn monotonic_micros() -> i64 {
    (unsafe { _ktime_get_mono_fast_ns() } / 1000) as i64
}

pub fn wall_clock_micros() -> (u32, u32) {
    let mut now = Timespec64 { tv_sec: 0, tv_nsec: 0 };
    unsafe { _ktime_get_real_ts64(&mut now) };
    (now.tv_sec as u32, (now.tv_nsec / 1000) as u32)
}

// Linux keeps the running task where the architecture puts it: in a register
// of its own on arm64, and behind the per-CPU segment elsewhere, at an offset
// the host resolves along with everything else.
pub fn current_thread_id() -> u64 {
    current_task() & JS_SAFE_THREAD_ID_MASK
}

#[cfg(target_arch = "arm")]
pub fn current_task() -> u64 {
    let task: u32;
    unsafe {
        core::arch::asm!("mrc p15, 0, {}, c13, c0, 3", out(reg) task, options(nomem, nostack));
    }
    task as u64
}

#[cfg(target_arch = "aarch64")]
pub fn current_task() -> u64 {
    let task: u64;
    unsafe {
        core::arch::asm!("mrs {}, sp_el0", out(reg) task, options(nomem, nostack));
    }
    task
}

#[cfg(target_arch = "x86_64")]
pub fn current_task() -> u64 {
    let task: u64;
    unsafe {
        core::arch::asm!("mov {}, gs:[{}]", out(reg) task, in(reg) _current_task, options(nostack));
    }
    task
}

#[cfg(target_arch = "x86_64")]
pub fn top_of_stack() -> usize {
    let top: usize;
    unsafe {
        core::arch::asm!("mov {}, gs:[{}]", out(reg) top, in(reg) _cpu_current_top_of_stack, options(nostack));
    }
    top
}

#[cfg(target_arch = "x86")]
pub fn current_task() -> u64 {
    let task: u32;
    unsafe {
        core::arch::asm!("mov {}, fs:[{}]", out(reg) task, in(reg) _current_task as u32, options(nostack));
    }
    task as u64
}

pub fn get_kernel_base() -> u64 {
    KERNEL_BASE.load(Ordering::Relaxed)
}

pub fn set_kernel_base(base: u64) {
    KERNEL_BASE.store(base, Ordering::Relaxed);
}

pub type IOInterruptHandler =
    extern "C" fn(target: *mut c_void, refcon: *mut c_void, nub: *mut c_void, source: i32);

// The transport's interrupt arrives on a thread of the kernel's choosing, so
// what it carries -- the token to wake, and the handler that wakes it -- is put
// somewhere the trampoline can find it again.
pub fn install_interrupt_handler(
    irq: u32,
    target: *mut c_void,
    handler: IOInterruptHandler,
    refcon: *mut c_void,
) -> i32 {
    unsafe {
        INTERRUPT = Some(Interrupt { irq, target, handler, refcon });

        _request_threaded_irq(
            irq,
            INTERRUPT_ENTRY,
            None,
            IRQF_SHARED,
            c"frida".as_ptr(),
            target,
        )
    }
}

#[cfg(target_arch = "arm")]
pub fn map_io(phys_addr: u64, size: u64) -> *mut c_void {
    unsafe { _ioremap(phys_addr as u32, size as usize) }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn map_io(phys_addr: u64, size: u64) -> *mut c_void {
    unsafe { _ioremap(phys_addr as usize, size as usize) }
}

#[cfg(not(any(target_arch = "arm", target_arch = "x86", target_arch = "x86_64")))]
pub fn map_io(phys_addr: u64, size: u64) -> *mut c_void {
    unsafe { _generic_ioremap_prot(phys_addr, size as usize, page_of(DEVICE_MEMORY) as usize) }
}

pub fn map_pages(pages: *mut c_void, count: usize) -> *mut c_void {
    unsafe { _vmap(pages, count as u32, VM_MAP as usize, page_of(ORDINARY_MEMORY) as usize) }
}

// Which attribute a page carries is an index into a register the kernel filled in, and what it
// put where differs between versions, so the register itself is asked.
#[cfg(target_arch = "arm")]
fn page_of(_memory: u64) -> u64 {
    unsafe { read_volatile(_pgprot_kernel) as u64 }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn page_of(_memory: u64) -> u64 {
    PAGE_KERNEL & unsafe { read_volatile(___default_kernel_pte_mask) } as u64
}

#[cfg(target_arch = "x86_64")]
const PAGE_KERNEL: u64 = 0x8000_0000_0000_0163;
#[cfg(target_arch = "x86")]
const PAGE_KERNEL: u64 = 0x163;

#[cfg(target_arch = "aarch64")]
fn page_of(memory: u64) -> u64 {
    PTE_TYPE_PAGE | PTE_AF | PTE_SHARED | PTE_WRITE | PTE_PXN | PTE_UXN | (attribute_of(memory) << 2)
}

#[cfg(target_arch = "aarch64")]
fn attribute_of(memory: u64) -> u64 {
    let attributes: u64;
    unsafe {
        core::arch::asm!("mrs {}, mair_el1", out(reg) attributes, options(nomem, nostack));
    }

    let mut index = 0;
    while index != ATTRIBUTES_KEPT {
        if (attributes >> (index * 8)) & 0xff == memory {
            break;
        }
        index += 1;
    }

    index
}

#[cfg(target_arch = "aarch64")]
pub fn virt_to_phys(vaddr: u64) -> u64 {
    let memstart = unsafe { read_volatile(_memstart_addr) };
    vaddr - linear_map_base() + memstart
}

#[cfg(target_arch = "aarch64")]
fn linear_map_base() -> u64 {
    let tcr_el1: u64;
    unsafe {
        core::arch::asm!("mrs {}, tcr_el1", out(reg) tcr_el1, options(nomem, nostack));
    }
    let kernel_address_bits = 64 - ((tcr_el1 >> TCR_T1SZ_SHIFT) & TCR_T1SZ_MASK);
    u64::MAX << kernel_address_bits
}

#[cfg(target_arch = "arm")]
pub fn virt_to_phys(vaddr: u64) -> u64 {
    vaddr.wrapping_add(unsafe { read_volatile(___pv_offset) })
}

#[cfg(target_arch = "x86_64")]
pub fn virt_to_phys(vaddr: u64) -> u64 {
    vaddr.wrapping_sub(unsafe { read_volatile(_page_offset_base) })
}

#[cfg(target_arch = "x86")]
pub fn virt_to_phys(vaddr: u64) -> u64 {
    vaddr.wrapping_sub(page_offset())
}

#[cfg(target_arch = "x86")]
fn page_offset() -> u64 {
    get_kernel_base() & !(SPLIT_GRANULARITY - 1)
}

#[cfg(target_arch = "x86")]
const SPLIT_GRANULARITY: u64 = 1 << 30;

struct Trampoline {
    entry: ThreadEntry,
    parameter: *mut c_void,
}

struct Interrupt {
    irq: u32,
    target: *mut c_void,
    handler: IOInterruptHandler,
    refcon: *mut c_void,
}

static mut INTERRUPT: Option<Interrupt> = None;

// Linux hands its handler the cookie it was registered with and expects to hear
// whether the interrupt was ours; the agent's handler takes the four arguments
// XNU's interrupt controller passes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn frida_cb_interrupt(_irq: c_int, _cookie: *mut c_void) -> c_int {
    let Some(interrupt) = (unsafe { &*core::ptr::addr_of!(INTERRUPT) }) else {
        return IRQ_NONE;
    };

    (interrupt.handler)(interrupt.target, interrupt.refcon, core::ptr::null_mut(), 0);

    IRQ_HANDLED
}

// kthread hands its worker one argument and expects an exit code back, whereas
// the agent's threads take the pair that XNU's continuations do.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn frida_cb_thread(data: *mut c_void) -> c_int {
    let trampoline = data as *mut Trampoline;
    unsafe {
        let Trampoline { entry, parameter } = trampoline.read();
        free(trampoline as *mut u8, size_of::<Trampoline>());
        entry(parameter, 0);
    }
    0
}

// The thread pointer is exposed to JavaScript as a GumThreadId, so it must fit
// in a double without losing precision; the low bits keep it unique per thread.
const KERNEL_PROCESS: u32 = 0;
const JS_SAFE_THREAD_ID_MASK: u64 = (1 << 48) - 1;

const GFP_KERNEL: u32 = 0xcc0;
const NUMA_NO_NODE: c_int = -1;
const EXECMEM_MODULE_TEXT: u32 = 1;
const PAGE_SIZE: usize = 4096;
#[cfg(target_arch = "aarch64")]
const TCR_T1SZ_SHIFT: u64 = 16;
#[cfg(target_arch = "aarch64")]
const TCR_T1SZ_MASK: u64 = 0x3f;
const TASK_INTERRUPTIBLE: c_uint = 1;
const TASK_NORMAL: c_uint = 3;
const WAKE_EVERY_WAITER: c_int = 0;
const WAKE_SLACK_NS: u64 = 50_000;
const HRTIMER_MODE_REL: c_int = 1;
const WAIT_ENTRY_WORDS: usize = 8;
const WAIT_ENTRY_THREAD: usize = 1;
const WAIT_ENTRY_WAKE: usize = 2;
const WAIT_ENTRY_QUEUED: usize = 3;
const WAIT_QUEUE_WORDS: usize = 16;
const LOCK_KEY_WORDS: usize = 8;
const DEVICE_MEMORY: u64 = 0x04;
const ORDINARY_MEMORY: u64 = 0xff;
const ATTRIBUTES_KEPT: u64 = 8;
const VM_MAP: u64 = 0x4;
const PTE_TYPE_PAGE: u64 = 0x3;
const PTE_SHARED: u64 = 3 << 8;
const PTE_AF: u64 = 1 << 10;
const PTE_WRITE: u64 = 1 << 51;
const PTE_PXN: u64 = 1 << 53;
const PTE_UXN: u64 = 1 << 54;
const IRQF_SHARED: usize = 0x80;
const IRQ_NONE: c_int = 0;
const IRQ_HANDLED: c_int = 1;

static KERNEL_BASE: AtomicU64 = AtomicU64::new(0);

#[repr(C)]
struct Timespec64 {
    tv_sec: i64,
    tv_nsec: i64,
}

type KthreadFn = unsafe extern "C" fn(data: *mut c_void) -> c_int;
type IrqHandlerFn = unsafe extern "C" fn(irq: c_int, cookie: *mut c_void) -> c_int;

unsafe extern "C" {
    // Kernels built before the printk rework export the name without the
    // underscore; the host fills in whichever this one has.
    static __printk: Option<unsafe extern "C" fn(*const c_char)>;
    static _printk: Option<unsafe extern "C" fn(*const c_char)>;
    #[cfg(not(target_arch = "x86"))]
    static _panic: unsafe extern "C" fn(*const c_char) -> !;
    static _kthread_create_on_node:
        unsafe extern "C" fn(KthreadFn, *mut c_void, c_int, *const c_char) -> *mut c_void;
    #[cfg(not(target_arch = "x86"))]
    static _wake_up_process: unsafe extern "C" fn(*mut c_void) -> c_int;
    #[cfg(not(target_arch = "x86"))]
    static _fget: unsafe extern "C" fn(c_uint) -> *mut c_void;
    #[cfg(not(target_arch = "x86"))]
    static _kernel_read: unsafe extern "C" fn(*mut c_void, *mut u8, usize, *mut i64) -> isize;
    #[cfg(not(target_arch = "x86"))]
    static _kernel_write: unsafe extern "C" fn(*mut c_void, *const u8, usize, *mut i64) -> isize;
    // Allocation profiling renamed the entry points in 6.10; before that the
    // size-plus-flags pair went to __kmalloc.
    static ___kmalloc_noprof: Option<unsafe extern "C" fn(usize, u32) -> *mut u8>;
    static _kmalloc: Option<unsafe extern "C" fn(usize, u32) -> *mut u8>;
    #[cfg(not(target_arch = "x86"))]
    static _kfree: unsafe extern "C" fn(*mut u8);
    // Executable memory moved out of the module loader in 6.12.
    static _execmem_alloc: Option<unsafe extern "C" fn(u32, usize) -> *mut u8>;
    static _set_memory_rw: Option<unsafe extern "C" fn(usize, c_int) -> c_int>;
    static _execmem_free: Option<unsafe extern "C" fn(*mut u8)>;
    static _module_alloc: Option<unsafe extern "C" fn(usize) -> *mut u8>;
    static _module_memfree: Option<unsafe extern "C" fn(*mut u8)>;
    #[cfg(not(target_arch = "x86"))]
    static ___init_waitqueue_head: unsafe extern "C" fn(*mut c_void, *const c_char, *mut c_void);
    #[cfg(not(target_arch = "x86"))]
    static _prepare_to_wait_event: unsafe extern "C" fn(*mut c_void, *mut c_void, c_uint) -> c_int;
    #[cfg(not(target_arch = "x86"))]
    static _finish_wait: unsafe extern "C" fn(*mut c_void, *mut c_void);
    #[cfg(not(target_arch = "x86"))]
    static ___wake_up: unsafe extern "C" fn(*mut c_void, c_uint, c_int, *mut c_void);
    static _autoremove_wake_function: *const c_void;
    #[cfg(not(target_arch = "x86"))]
    static _schedule_hrtimeout_range: unsafe extern "C" fn(*mut i64, u64, c_int) -> c_int;
    #[cfg(not(target_arch = "x86"))]
    static _pci_get_domain_bus_and_slot: unsafe extern "C" fn(c_int, c_uint, c_uint) -> *mut c_void;
    #[cfg(not(target_arch = "x86"))]
    static _pci_irq_vector: unsafe extern "C" fn(*mut c_void, c_uint) -> c_int;
    #[cfg(not(target_arch = "x86"))]
    static _pci_dev_put: unsafe extern "C" fn(*mut c_void);
    #[cfg(not(target_arch = "x86"))]
    static _schedule: unsafe extern "C" fn();
    #[cfg(not(target_arch = "x86"))]
    static _ktime_get_mono_fast_ns: unsafe extern "C" fn() -> u64;
    #[cfg(not(target_arch = "x86"))]
    static _ktime_get_real_ts64: unsafe extern "C" fn(*mut Timespec64);
    #[cfg(not(target_arch = "x86"))]
    static _send_sig: unsafe extern "C" fn(c_int, *mut c_void, c_int) -> c_int;
    #[cfg(not(target_arch = "x86"))]
    static _free_irq: unsafe extern "C" fn(u32, *mut c_void) -> *mut c_void;
    #[cfg(not(target_arch = "x86"))]
    static _request_threaded_irq: unsafe extern "C" fn(
        u32,
        IrqHandlerFn,
        Option<IrqHandlerFn>,
        usize,
        *const c_char,
        *mut c_void,
    ) -> c_int;    static _generic_ioremap_prot: unsafe extern "C" fn(u64, usize, usize) -> *mut c_void;
    #[cfg(not(target_arch = "x86"))]
    static _vmap: unsafe extern "C" fn(*mut c_void, u32, usize, usize) -> *mut c_void;
    #[cfg(target_arch = "aarch64")]
    static _memstart_addr: *const u64;
    #[cfg(target_arch = "x86_64")]
    static _page_offset_base: *const u64;
    #[cfg(not(any(target_arch = "aarch64", target_arch = "arm")))]
    static _current_task: usize;
    #[cfg(target_arch = "x86_64")]
    static _cpu_current_top_of_stack: usize;
    #[cfg(target_arch = "arm")]
    static ___pv_offset: *const u64;
    #[cfg(target_arch = "arm")]
    static _pgprot_kernel: *const u32;
    #[cfg(target_arch = "arm")]
    static _ioremap: unsafe extern "C" fn(u32, usize) -> *mut c_void;
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[cfg(not(target_arch = "x86"))]
    static _ioremap: unsafe extern "C" fn(usize, usize) -> *mut c_void;
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    static ___default_kernel_pte_mask: *const usize;
}


#[cfg(target_arch = "x86")]
unsafe extern "C" {
    fn frida_k_log(message: *const c_char);
    fn frida_k_alloc(size: usize, flags: usize) -> *mut u8;
    fn frida_k_alloc_code(kind: usize, size: usize, pages: usize) -> *mut u8;
    fn frida_k_free_code(code: *mut u8);
}

#[cfg(target_arch = "x86")]
unsafe extern "C" {
    #[link_name = "frida_k_panic"]
    fn _panic(a0: *const c_char) -> !;
    #[link_name = "frida_k_wake_up_process"]
    fn _wake_up_process(a0: *mut c_void) -> c_int;
    #[link_name = "frida_k_fget"]
    fn _fget(a0: c_uint) -> *mut c_void;
    #[link_name = "frida_k_kernel_read"]
    fn _kernel_read(a0: *mut c_void, a1: *mut u8, a2: usize, a3: *mut i64) -> isize;
    #[link_name = "frida_k_kernel_write"]
    fn _kernel_write(a0: *mut c_void, a1: *const u8, a2: usize, a3: *mut i64) -> isize;
    #[link_name = "frida_k_kfree"]
    fn _kfree(a0: *mut u8);
    #[link_name = "frida_k___init_waitqueue_head"]
    fn ___init_waitqueue_head(a0: *mut c_void, a1: *const c_char, a2: *mut c_void);
    #[link_name = "frida_k_prepare_to_wait_event"]
    fn _prepare_to_wait_event(a0: *mut c_void, a1: *mut c_void, a2: c_uint) -> c_int;
    #[link_name = "frida_k_finish_wait"]
    fn _finish_wait(a0: *mut c_void, a1: *mut c_void);
    #[link_name = "frida_k___wake_up"]
    fn ___wake_up(a0: *mut c_void, a1: c_uint, a2: c_int, a3: *mut c_void);
    #[link_name = "frida_k_schedule_hrtimeout_range"]
    fn _schedule_hrtimeout_range(a0: *mut i64, a1: u64, a2: c_int) -> c_int;
    #[link_name = "frida_k_pci_get_domain_bus_and_slot"]
    fn _pci_get_domain_bus_and_slot(a0: c_int, a1: c_uint, a2: c_uint) -> *mut c_void;
    #[link_name = "frida_k_pci_irq_vector"]
    fn _pci_irq_vector(a0: *mut c_void, a1: c_uint) -> c_int;
    #[link_name = "frida_k_pci_dev_put"]
    fn _pci_dev_put(a0: *mut c_void);
    #[link_name = "frida_k_schedule"]
    fn _schedule();
    #[link_name = "frida_k_ktime_get_mono_fast_ns"]
    fn _ktime_get_mono_fast_ns() -> u64;
    #[link_name = "frida_k_ktime_get_real_ts64"]
    fn _ktime_get_real_ts64(a0: *mut Timespec64);
    #[link_name = "frida_k_send_sig"]
    fn _send_sig(a0: c_int, a1: *mut c_void, a2: c_int) -> c_int;
    #[link_name = "frida_k_free_irq"]
    fn _free_irq(a0: u32, a1: *mut c_void) -> *mut c_void;
    #[link_name = "frida_k_vmap"]
    fn _vmap(a0: *mut c_void, a1: u32, a2: usize, a3: usize) -> *mut c_void;
    #[link_name = "frida_k_ioremap"]
    fn _ioremap(a0: usize, a1: usize) -> *mut c_void;
}

#[cfg(target_arch = "x86")]
unsafe extern "C" {
    #[link_name = "frida_k_request_threaded_irq"]
    fn _request_threaded_irq(
        a0: u32,
        a1: IrqHandlerFn,
        a2: Option<IrqHandlerFn>,
        a3: usize,
        a4: *const c_char,
        a5: *mut c_void,
    ) -> c_int;
    fn frida_kcb_thread(data: *mut c_void) -> c_int;
    fn frida_kcb_interrupt(irq: c_int, cookie: *mut c_void) -> c_int;
}

#[cfg(target_arch = "x86")]
const THREAD_ENTRY: unsafe extern "C" fn(*mut c_void) -> c_int = frida_kcb_thread;
#[cfg(not(target_arch = "x86"))]
const THREAD_ENTRY: unsafe extern "C" fn(*mut c_void) -> c_int = frida_cb_thread;

#[cfg(target_arch = "x86")]
const INTERRUPT_ENTRY: unsafe extern "C" fn(c_int, *mut c_void) -> c_int = frida_kcb_interrupt;
#[cfg(not(target_arch = "x86"))]
const INTERRUPT_ENTRY: unsafe extern "C" fn(c_int, *mut c_void) -> c_int = frida_cb_interrupt;
