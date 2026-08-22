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
            enter_thread,
            trampoline as *mut c_void,
            NUMA_NO_NODE,
            c"frida".as_ptr(),
        );
        _wake_up_process(task);
    }
    0
}

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
        core::arch::asm!("mov {}, gs:[{}]", out(reg) task, in(reg) &_current_task as *const _ as u64, options(nostack));
    }
    task
}

#[cfg(target_arch = "x86")]
pub fn current_task() -> u64 {
    let task: u32;
    unsafe {
        core::arch::asm!("mov {}, fs:[{}]", out(reg) task, in(reg) &_current_task as *const _ as u32, options(nostack));
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
            enter_interrupt,
            None,
            IRQF_SHARED,
            c"frida".as_ptr(),
            target,
        )
    }
}

pub fn map_io(phys_addr: u64, size: u64) -> *mut c_void {
    unsafe { _generic_ioremap_prot(phys_addr, size as usize, page_of(DEVICE_MEMORY)) }
}

pub fn map_pages(pages: *mut c_void, count: usize) -> *mut c_void {
    unsafe { _vmap(pages, count as u32, VM_MAP, page_of(ORDINARY_MEMORY)) }
}

// Which attribute a page carries is an index into a register the kernel filled in, and what it
// put where differs between versions, so the register itself is asked.
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

#[cfg(not(target_arch = "aarch64"))]
pub fn virt_to_phys(vaddr: u64) -> u64 {
    unsafe { _virt_to_phys(vaddr) }
}

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
unsafe extern "C" fn enter_interrupt(_irq: c_int, _cookie: *mut c_void) -> c_int {
    let Some(interrupt) = (unsafe { &*core::ptr::addr_of!(INTERRUPT) }) else {
        return IRQ_NONE;
    };

    (interrupt.handler)(interrupt.target, interrupt.refcon, core::ptr::null_mut(), 0);

    IRQ_HANDLED
}

// kthread hands its worker one argument and expects an exit code back, whereas
// the agent's threads take the pair that XNU's continuations do.
unsafe extern "C" fn enter_thread(data: *mut c_void) -> c_int {
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
const IRQF_SHARED: u64 = 0x80;
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
    static _panic: unsafe extern "C" fn(*const c_char) -> !;
    static _kthread_create_on_node:
        unsafe extern "C" fn(KthreadFn, *mut c_void, c_int, *const c_char) -> *mut c_void;
    static _wake_up_process: unsafe extern "C" fn(*mut c_void) -> c_int;
    static _fget: unsafe extern "C" fn(c_uint) -> *mut c_void;
    static _kernel_read: unsafe extern "C" fn(*mut c_void, *mut u8, usize, *mut i64) -> isize;
    static _kernel_write: unsafe extern "C" fn(*mut c_void, *const u8, usize, *mut i64) -> isize;
    // Allocation profiling renamed the entry points in 6.10; before that the
    // size-plus-flags pair went to __kmalloc.
    static ___kmalloc_noprof: Option<unsafe extern "C" fn(usize, u32) -> *mut u8>;
    static _kmalloc: Option<unsafe extern "C" fn(usize, u32) -> *mut u8>;
    static _kfree: unsafe extern "C" fn(*mut u8);
    // Executable memory moved out of the module loader in 6.12.
    static _execmem_alloc: Option<unsafe extern "C" fn(u32, usize) -> *mut u8>;
    static _set_memory_rw: Option<unsafe extern "C" fn(usize, c_int) -> c_int>;
    static _execmem_free: Option<unsafe extern "C" fn(*mut u8)>;
    static _module_alloc: Option<unsafe extern "C" fn(usize) -> *mut u8>;
    static _module_memfree: Option<unsafe extern "C" fn(*mut u8)>;
    static ___init_waitqueue_head: unsafe extern "C" fn(*mut c_void, *const c_char, *mut c_void);
    static _prepare_to_wait_event: unsafe extern "C" fn(*mut c_void, *mut c_void, c_uint) -> c_int;
    static _finish_wait: unsafe extern "C" fn(*mut c_void, *mut c_void);
    static ___wake_up: unsafe extern "C" fn(*mut c_void, c_uint, c_int, *mut c_void);
    static _autoremove_wake_function: *const c_void;
    static _schedule_hrtimeout_range: unsafe extern "C" fn(*mut i64, u64, c_int) -> c_int;
    static _pci_get_domain_bus_and_slot: unsafe extern "C" fn(c_int, c_uint, c_uint) -> *mut c_void;
    static _pci_irq_vector: unsafe extern "C" fn(*mut c_void, c_uint) -> c_int;
    static _pci_dev_put: unsafe extern "C" fn(*mut c_void);
    static _schedule: unsafe extern "C" fn();
    static _ktime_get_mono_fast_ns: unsafe extern "C" fn() -> u64;
    static _ktime_get_real_ts64: unsafe extern "C" fn(*mut Timespec64);
    static _free_irq: unsafe extern "C" fn(u32, *mut c_void) -> *mut c_void;
    static _request_threaded_irq: unsafe extern "C" fn(
        u32,
        IrqHandlerFn,
        Option<IrqHandlerFn>,
        u64,
        *const c_char,
        *mut c_void,
    ) -> c_int;
    static _generic_ioremap_prot: unsafe extern "C" fn(u64, usize, u64) -> *mut c_void;
    static _vmap: unsafe extern "C" fn(*mut c_void, u32, u64, u64) -> *mut c_void;
    #[cfg(target_arch = "aarch64")]
    static _memstart_addr: *const u64;
    #[cfg(not(target_arch = "aarch64"))]
    static _virt_to_phys: unsafe extern "C" fn(u64) -> u64;
    #[cfg(not(target_arch = "aarch64"))]
    static _current_task: usize;
}
