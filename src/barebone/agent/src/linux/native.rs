// The agent injected from the outside: the host resolves the kernel functions
// below and patches their addresses into .kernel_addrs, the same way it does
// for XNU and Windows. Everything the kernel would otherwise have to lend us --
// its symbol table, its module list, the right to write to its pages -- comes
// from the host instead, over the hostlink.

use core::ffi::{c_char, c_int, c_void};
use core::sync::atomic::{AtomicU64, Ordering};

use crate::kernel::ThreadEntry;

pub fn log(msg: &str) {
    unsafe { printk(c"%s".as_ptr(), msg.as_ptr() as *const c_char) };
}

pub fn panic(msg: &str) -> ! {
    unsafe { _panic(c"%s".as_ptr(), msg.as_ptr() as *const c_char) }
}

pub fn run_when_ready(action: fn()) {
    action();
}

// A fault in the agent goes to the kernel as it is, which prints the register
// dump and the backtrace this would otherwise have to reproduce.
pub fn install_fault_reporter() {}

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
        if let Some(f) = _kmalloc_noprof {
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
        if let Some(f) = _execmem_alloc {
            f(EXECMEM_MODULE_TEXT, size)
        } else {
            _module_alloc.unwrap()(size)
        }
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

// The kernel's own wait queues live behind macros and per-version struct
// layouts, so the wait is spelled out here instead: sleep in short hops, and
// let the condition itself say when to stop.
pub fn wait(_token: *const u8, timeout_us: Option<u64>, check: &mut dyn FnMut() -> bool) {
    let deadline = timeout_us.map(|us| monotonic_micros() + us as i64);

    while !check() {
        if deadline.is_some_and(|deadline| monotonic_micros() >= deadline) {
            return;
        }
        unsafe { _msleep(WAIT_INTERVAL_MS) };
    }
}

pub fn wake(_token: *const u8) {}

pub fn yield_now() {
    unsafe { _schedule() };
}

pub fn monotonic_micros() -> i64 {
    (unsafe { _ktime_get_ns() } / 1000) as i64
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
fn current_task() -> u64 {
    let task: u64;
    unsafe {
        core::arch::asm!("mrs {}, sp_el0", out(reg) task, options(nomem, nostack));
    }
    task
}

#[cfg(target_arch = "x86_64")]
fn current_task() -> u64 {
    let task: u64;
    unsafe {
        core::arch::asm!("mov {}, gs:[{}]", out(reg) task, in(reg) &_current_task as *const _ as u64, options(nostack));
    }
    task
}

#[cfg(target_arch = "x86")]
fn current_task() -> u64 {
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
        INTERRUPT = Some(Interrupt { target, handler, refcon });

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
    unsafe { _ioremap(phys_addr, size as usize) }
}

pub fn virt_to_phys(vaddr: u64) -> u64 {
    unsafe { _virt_to_phys(vaddr) }
}

struct Trampoline {
    entry: ThreadEntry,
    parameter: *mut c_void,
}

struct Interrupt {
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
const JS_SAFE_THREAD_ID_MASK: u64 = (1 << 48) - 1;

const GFP_KERNEL: u32 = 0xcc0;
const NUMA_NO_NODE: c_int = -1;
const EXECMEM_MODULE_TEXT: u32 = 1;
const WAIT_INTERVAL_MS: u32 = 1;
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
    #[link_name = "_printk"]
    static _printk: Option<unsafe extern "C" fn(*const c_char, ...)>;
    static _panic: unsafe extern "C" fn(*const c_char, ...) -> !;
    static _kthread_create_on_node:
        unsafe extern "C" fn(KthreadFn, *mut c_void, c_int, *const c_char) -> *mut c_void;
    static _wake_up_process: unsafe extern "C" fn(*mut c_void) -> c_int;
    // Allocation profiling renamed the entry points in 6.10; before that the
    // size-plus-flags pair went to __kmalloc.
    static _kmalloc_noprof: Option<unsafe extern "C" fn(usize, u32) -> *mut u8>;
    static _kmalloc: Option<unsafe extern "C" fn(usize, u32) -> *mut u8>;
    static _kfree: unsafe extern "C" fn(*mut u8);
    // Executable memory moved out of the module loader in 6.12.
    static _execmem_alloc: Option<unsafe extern "C" fn(u32, usize) -> *mut u8>;
    static _execmem_free: Option<unsafe extern "C" fn(*mut u8)>;
    static _module_alloc: Option<unsafe extern "C" fn(usize) -> *mut u8>;
    static _module_memfree: Option<unsafe extern "C" fn(*mut u8)>;
    static _msleep: unsafe extern "C" fn(u32);
    static _schedule: unsafe extern "C" fn();
    static _ktime_get_ns: unsafe extern "C" fn() -> u64;
    static _ktime_get_real_ts64: unsafe extern "C" fn(*mut Timespec64);
    static _request_threaded_irq: unsafe extern "C" fn(
        u32,
        IrqHandlerFn,
        Option<IrqHandlerFn>,
        u64,
        *const c_char,
        *mut c_void,
    ) -> c_int;
    static _ioremap: unsafe extern "C" fn(u64, usize) -> *mut c_void;
    static _virt_to_phys: unsafe extern "C" fn(u64) -> u64;
    #[cfg(not(target_arch = "aarch64"))]
    static _current_task: usize;
}

unsafe fn printk(format: *const c_char, message: *const c_char) {
    unsafe { _printk.unwrap()(format, message) };
}
