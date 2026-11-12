use alloc::vec;
use core::ffi::{c_int, c_long, c_void};
use core::mem::size_of;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use super::layout::field_offset;
use super::{cloak, native, process_memory, user_threads};

pub fn open() {
    cloak::install_hooks();

    let Some(arguments) = describe_arguments() else {
        return;
    };
    let target = unsafe { SYS_PRCTL_TARGET };
    if target == 0 {
        return;
    }
    unsafe { ARGUMENTS = Some(arguments) };

    let interceptor = unsafe { crate::bindings::gum_interceptor_obtain() };
    unsafe {
        crate::bindings::gum_interceptor_begin_transaction(interceptor);
        crate::bindings::gum_interceptor_replace(interceptor, target as *mut c_void,
            frida_cb_sys_prctl as *mut c_void, (&raw mut SYS_PRCTL) as *mut *mut c_void, ptr::null_mut());
        crate::bindings::gum_interceptor_end_transaction(interceptor);
    }
}

pub fn close() {
    if unsafe { (*(&raw const ARGUMENTS)).is_some() } {
        let interceptor = unsafe { crate::bindings::gum_interceptor_obtain() };
        unsafe {
            crate::bindings::gum_interceptor_begin_transaction(interceptor);
            crate::bindings::gum_interceptor_revert(interceptor, SYS_PRCTL_TARGET as *mut c_void);
            crate::bindings::gum_interceptor_end_transaction(interceptor);
        }
    }

    cloak::remove_hooks();
}

pub fn an_operation_waits() -> bool {
    !PENDING.load(Ordering::Acquire).is_null()
}

pub fn carry_out_operations() {
    let operation = PENDING.swap(ptr::null_mut(), Ordering::AcqRel);
    if operation.is_null() {
        return;
    }

    unsafe {
        (*operation).result = match (*operation).request {
            Request::Allocate { id, size, protection } => process_memory::allocate(id, size, protection) as c_long,
            Request::Release { id, address, size } => process_memory::release(id, address, size) as c_long,
            Request::StartThread { id, entry, stack, argument, tls } => {
                user_threads::start_in_process(id, entry, stack, argument, tls) as c_long
            }
        };
        (*operation).done.store(true, Ordering::Release);
    }

    native::wake(wake_token());
}

unsafe extern "C" fn frida_cb_sys_prctl(regs: *const c_void) -> c_long {
    let argument = |index: usize| read_word(regs as usize + unsafe { arguments().at[index] });

    if argument(0) as c_int != CONTROL_MAGIC || argument(4) as u64 != CONTROL_TOKEN {
        let original: unsafe extern "C" fn(*const c_void) -> c_long = unsafe { core::mem::transmute(SYS_PRCTL) };
        return unsafe { original(regs) };
    }

    let op = argument(1) as u32;
    let (first, second) = (argument(2), argument(3));

    if op == OP_PING {
        return CONTROL_MAGIC as c_long;
    }

    if op >= OP_ALLOC && !unsafe { _capable(CAP_SYS_ADMIN) } {
        return -(EPERM as c_long);
    }

    let tgid = read_i32(native::current_task() as usize + unsafe { arguments().task_tgid });
    match op {
        OP_ADD_THREAD => cloak::add_thread(tgid, first as i32),
        OP_REMOVE_THREAD => cloak::remove_thread(tgid, first as i32),
        OP_ADD_RANGE => cloak::add_range(tgid, first, second),
        OP_REMOVE_RANGE => cloak::remove_range(tgid, first, second),
        OP_ADD_FD => cloak::add_fd(tgid, first as i32),
        OP_REMOVE_FD => cloak::remove_fd(tgid, first as i32),
        OP_ALLOC => return allocate(first),
        OP_FREE => return release(first),
        OP_WRITE => return write(first),
        OP_READ => return read(first),
        OP_SPAWN => return start_thread(first),
        OP_CLOAK_THREAD => return cloak_thread(first),
        OP_CLOAK_RANGE => return cloak_range(first),
        _ => return -(EINVAL as c_long),
    }

    0
}

fn allocate(arguments: usize) -> c_long {
    let Some(args) = arguments_at::<AllocArgs>(arguments) else {
        return -(EFAULT as c_long);
    };

    hand_to_the_worker(Request::Allocate { id: args.pid, size: args.size as usize, protection: args.prot as usize })
}

fn release(arguments: usize) -> c_long {
    let Some(args) = arguments_at::<FreeArgs>(arguments) else {
        return -(EFAULT as c_long);
    };

    hand_to_the_worker(Request::Release { id: args.pid, address: args.address as usize, size: args.size as usize })
}

fn write(arguments: usize) -> c_long {
    let Some(args) = arguments_at::<RwArgs>(arguments) else {
        return -(EFAULT as c_long);
    };

    let mut bounce = vec![0u8; args.size as usize];
    if !process_memory::read_own(args.buffer as usize, &mut bounce) {
        return -(EFAULT as c_long);
    }

    process_memory::write(args.pid, args.address as usize, &bounce) as c_long
}

fn read(arguments: usize) -> c_long {
    let Some(args) = arguments_at::<RwArgs>(arguments) else {
        return -(EFAULT as c_long);
    };

    let mut bounce = vec![0u8; args.size as usize];
    let transferred = process_memory::read(args.pid, args.address as usize, &mut bounce);

    if !process_memory::write_own(args.buffer as usize, &bounce) {
        return -(EFAULT as c_long);
    }

    transferred as c_long
}

fn start_thread(arguments: usize) -> c_long {
    let Some(args) = arguments_at::<SpawnArgs>(arguments) else {
        return -(EFAULT as c_long);
    };

    hand_to_the_worker(Request::StartThread {
        id: args.pid,
        entry: args.entry as usize,
        stack: args.stack as usize,
        argument: args.arg as usize,
        tls: args.tls as usize,
    })
}

fn cloak_thread(arguments: usize) -> c_long {
    let Some(args) = arguments_at::<CloakThreadArgs>(arguments) else {
        return -(EFAULT as c_long);
    };

    cloak::add_thread(args.tgid as i32, args.tid as i32);

    0
}

fn cloak_range(arguments: usize) -> c_long {
    let Some(args) = arguments_at::<CloakRangeArgs>(arguments) else {
        return -(EFAULT as c_long);
    };

    cloak::add_range(args.tgid as i32, args.base as usize, args.size as usize);

    0
}

fn arguments_at<T: Default>(address: usize) -> Option<T> {
    let mut value = T::default();
    let raw = unsafe { core::slice::from_raw_parts_mut(&mut value as *mut T as *mut u8, size_of::<T>()) };

    process_memory::read_own(address, raw).then_some(value)
}

fn hand_to_the_worker(request: Request) -> c_long {
    let token = wake_token();

    while BUSY.swap(true, Ordering::Acquire) {
        native::wait(token, None, &mut || !BUSY.load(Ordering::Acquire));
    }

    let mut operation = Operation { request, result: 0, done: AtomicBool::new(false) };
    PENDING.store(&mut operation, Ordering::Release);
    crate::nudge_the_loop(token);

    while !operation.done.load(Ordering::Acquire) {
        native::wait(token, None, &mut || operation.done.load(Ordering::Acquire));
    }

    BUSY.store(false, Ordering::Release);
    native::wake(token);

    operation.result
}

fn wake_token() -> *const u8 {
    (&raw const crate::glib::WAKEUP_TOKEN) as *const u8
}

struct Operation {
    request: Request,
    result: c_long,
    done: AtomicBool,
}

enum Request {
    Allocate { id: u32, size: usize, protection: usize },
    Release { id: u32, address: usize, size: usize },
    StartThread { id: u32, entry: usize, stack: usize, argument: usize, tls: usize },
}

static PENDING: AtomicPtr<Operation> = AtomicPtr::new(ptr::null_mut());
static BUSY: AtomicBool = AtomicBool::new(false);

#[repr(C)]
#[derive(Default)]
struct AllocArgs {
    size: u64,
    pid: u32,
    prot: u32,
}

#[repr(C)]
#[derive(Default)]
struct FreeArgs {
    address: u64,
    size: u64,
    pid: u32,
}

#[repr(C)]
#[derive(Default)]
struct RwArgs {
    address: u64,
    buffer: u64,
    size: u64,
    pid: u32,
}

#[repr(C)]
#[derive(Default)]
struct SpawnArgs {
    entry: u64,
    stack: u64,
    arg: u64,
    tls: u64,
    pid: u32,
}

#[repr(C)]
#[derive(Default)]
struct CloakThreadArgs {
    tgid: u32,
    tid: u32,
}

#[repr(C)]
#[derive(Default)]
struct CloakRangeArgs {
    base: u64,
    size: u64,
    tgid: u32,
}

struct ArgumentLayout {
    at: [usize; 5],
    task_tgid: usize,
}

#[cfg(target_arch = "aarch64")]
fn describe_arguments() -> Option<ArgumentLayout> {
    let regs = field_offset("pt_regs", "regs")?;

    Some(ArgumentLayout {
        at: core::array::from_fn(|index| regs + index * size_of::<usize>()),
        task_tgid: field_offset("task_struct", "tgid")?,
    })
}

#[cfg(target_arch = "x86_64")]
fn describe_arguments() -> Option<ArgumentLayout> {
    Some(ArgumentLayout {
        at: [
            field_offset("pt_regs", "di")?,
            field_offset("pt_regs", "si")?,
            field_offset("pt_regs", "dx")?,
            field_offset("pt_regs", "r10")?,
            field_offset("pt_regs", "r8")?,
        ],
        task_tgid: field_offset("task_struct", "tgid")?,
    })
}

unsafe fn arguments() -> &'static ArgumentLayout {
    unsafe { (*(&raw const ARGUMENTS)).as_ref().unwrap() }
}

static mut ARGUMENTS: Option<ArgumentLayout> = None;
static mut SYS_PRCTL: usize = 0;

fn read_word(address: usize) -> usize {
    unsafe { (address as *const usize).read() }
}

fn read_i32(address: usize) -> i32 {
    unsafe { (address as *const i32).read() }
}

const CONTROL_MAGIC: c_int = 0x4652_4944;
const CONTROL_TOKEN: u64 = 0x1d5f_9e6b_2c7a_4038;

const OP_ADD_THREAD: u32 = 1;
const OP_REMOVE_THREAD: u32 = 2;
const OP_ADD_RANGE: u32 = 3;
const OP_REMOVE_RANGE: u32 = 4;
const OP_ADD_FD: u32 = 5;
const OP_REMOVE_FD: u32 = 6;
const OP_PING: u32 = 32;
const OP_ALLOC: u32 = 64;
const OP_FREE: u32 = 65;
const OP_WRITE: u32 = 66;
const OP_READ: u32 = 67;
const OP_SPAWN: u32 = 68;
const OP_CLOAK_THREAD: u32 = 69;
const OP_CLOAK_RANGE: u32 = 70;

const CAP_SYS_ADMIN: c_int = 21;

const EPERM: c_int = 1;
const EFAULT: c_int = 14;
const EINVAL: c_int = 22;

#[cfg(target_arch = "aarch64")]
use self::___arm64_sys_prctl as SYS_PRCTL_TARGET;
#[cfg(target_arch = "x86_64")]
use self::___x64_sys_prctl as SYS_PRCTL_TARGET;

unsafe extern "C" {
    #[cfg(target_arch = "aarch64")]
    static ___arm64_sys_prctl: usize;
    #[cfg(target_arch = "x86_64")]
    static ___x64_sys_prctl: usize;
    static _capable: unsafe extern "C" fn(c_int) -> bool;
}
