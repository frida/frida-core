
pub fn entry_offset() -> usize {
    (frida_xnu_user_entry as usize) - crate::own_range().0
}

pub extern "C" fn frida_xnu_user_entry(arena: usize) -> ! {
    let arena = arena as u64;
    unsafe { ARENA = arena };

    crate::xnu_user_calls::told_the_cache_shape(word_at(arena + crate::xnu_relay::CACHE_SHAPE));
    crate::xnu_user_calls::told_the_page_size(
        word_at(arena + crate::xnu_relay::PAGE_SIZE) as usize);
    crate::xnu::select_user();
    crate::gthread::use_thread_slots(&crate::xnu_user_calls::SLOTS);

    unsafe {
        crate::set_own_range(word_at(arena + crate::xnu_relay::IMAGE_BASE),
            word_at(arena + crate::xnu_relay::IMAGE_SIZE));
        crate::run_constructors();
        crate::init_gum_without_exceptor();
    }

    let has_run = unsafe { ((arena + crate::xnu_relay::HAS_RUN) as *const u32).read_volatile() };
    let served = has_run != 0 && become_a_thread_the_system_knows(arena);

    unsafe { ((arena + crate::xnu_relay::AWAKE_AT) as *mut u64).write_volatile(AWAKE) };

    if !served {
        unsafe { user_worker(arena as *mut core::ffi::c_void, 0) };
    }

    wait_for_something_that_never_comes();
}

fn wait_for_something_that_never_comes() -> ! {
    if let Some(wait) = crate::xnu_libsystem::function_named(b"/libsystem_kernel.dylib",
        b"_mach_msg")
    {
        type Wait = unsafe extern "C" fn(*mut u8, i32, u32, u32, u32, u32, u32) -> i32;
        let wait: Wait = unsafe { core::mem::transmute(wait) };

        let listening_on = crate::xnu_user_calls::a_port_to_answer_on();
        let mut nothing = [0u8; 1024];
        loop {
            unsafe {
                wait(nothing.as_mut_ptr(), ONLY_LISTEN, 0, nothing.len() as u32, listening_on,
                    NO_TIMEOUT, NO_ONE_TO_TELL)
            };
        }
    }

    loop {
        crate::kernel::yield_now();
    }
}

const ONLY_LISTEN: i32 = 2;
const NO_TIMEOUT: u32 = 0;
const NO_ONE_TO_TELL: u32 = 0;

fn become_a_thread_the_system_knows(arena: u64) -> bool {
    let Some(making) = crate::xnu_libsystem::making_threads() else {
        return false;
    };
    let Some(out_of_a_bare_one) = making.out_of_a_bare_one else {
        return false;
    };

    let start = crate::xnu_libsystem::signed_to_begin_at(serve_from_a_proper_thread);
    let mut made = 0u64;

    unsafe {
        out_of_a_bare_one(&mut made, core::ptr::null(), start, arena as *mut core::ffi::c_void) == 0
    }
}

unsafe extern "C" fn serve_from_a_proper_thread(arena: *mut core::ffi::c_void)
    -> *mut core::ffi::c_void
{
    unsafe { user_worker(arena, 0) };

    core::ptr::null_mut()
}

unsafe extern "C" fn user_worker(parameter: *mut core::ffi::c_void, _wait_result: i32) {
    let arena = parameter as u64;
    unsafe { ARENA = arena };

    let context = unsafe { crate::adopt_js_context() };
    unsafe { crate::route_frames_through(arena) };
    crate::glib::own_the_loop();
    crate::watch_for_work(context, copy_has_work, serve_the_copy);

    while word_at(arena + crate::xnu_relay::STOP_REQUEST) == 0 {
        unsafe { crate::dispatch_pending_work(context) };
    }

    unsafe { ((arena + crate::xnu_relay::WORKER_STOPPED) as *mut u32).write_volatile(1) };
}

fn copy_has_work() -> bool {
    let arena = unsafe { ARENA };

    crate::xnu_relay::holds_a_frame_from_host(arena)
        || word_at(arena + crate::xnu_relay::STOP_REQUEST) != 0
}

fn serve_the_copy() {
    let arena = unsafe { ARENA };

    while let Some(frame) = crate::xnu_relay::take_frame_from_host(arena) {
        crate::on_frame_from_host(&frame);
    }
}

pub fn ask_for_protection(address: u64, size: usize, may: u32) -> bool {
    ask_the_other_half(&[(crate::xnu_relay::PROTECT_SIZE, size as u64),
        (crate::xnu_relay::PROTECT_TO, may as u64)],
        crate::xnu_relay::PROTECT_WANTED, address, crate::xnu_relay::PROTECT_ANSWER)
}

fn ask_the_other_half(along_with: &[(u64, u64)], asked_at: u64, asking: u64, answer_at: u64)
    -> bool
{
    let arena = unsafe { ARENA };
    if arena == 0 {
        return false;
    }

    let put = |at: u64, value: u64| unsafe { ((arena + at) as *mut u64).write_volatile(value) };
    put(answer_at, crate::xnu_relay::NOTHING_WANTED);
    for (at, value) in along_with {
        put(*at, *value);
    }
    put(asked_at, asking);

    loop {
        let said = unsafe { ((arena + answer_at) as *const u64).read_volatile() };
        if said != crate::xnu_relay::NOTHING_WANTED {
            return said == crate::xnu_relay::DONE;
        }
        crate::kernel::yield_now();
    }
}

fn word_at(at: u64) -> u64 {
    unsafe { (at as *const u64).read_volatile() }
}

static mut ARENA: u64 = 0;

pub const AWAKE: u64 = 0x6672_6964_6100_0001;
