#![no_std]

#[cfg(not(any(feature = "xnu", feature = "linux")))]
compile_error!("pick a flavour: --features xnu or --features linux");

#[cfg(all(feature = "xnu", feature = "linux"))]
compile_error!("pick one flavour, not both");

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::ffi::{CStr, c_void};
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

use bindings::{
    GAsyncResult, GBytes, GError, GMainContext, GObject, GVariant, GumMemoryRange,
    GumScript, GumScriptBackend, g_error_free, g_free, g_main_context_iteration,
    g_main_context_push_thread_default, g_memdup2, g_object_unref, g_variant_check_format_string,
    g_variant_get, g_variant_get_data, g_variant_get_size, g_variant_get_string,
    g_variant_get_uint32, g_variant_new, g_variant_new_from_data, g_variant_new_string,
    g_variant_new_tuple, g_variant_new_uint32, g_variant_type_free, g_variant_type_new,
    g_variant_unref, gchar, gpointer, gsize, gum_script_backend_create,
    gum_script_backend_create_finish, gum_script_backend_get_scheduler,
    gum_script_backend_obtain_qjs, gum_script_get_stalker, gum_script_load,
    gum_script_load_finish, gum_script_post, gum_script_scheduler_disable_background_thread,
    gum_script_scheduler_get_js_context, gum_script_set_message_handler, gum_script_unload,
    gum_script_unload_finish, gum_stalker_exclude,
};

mod ffi;
mod glib;
mod gthread;
mod gum;
mod libc;

pub mod kernel;

#[cfg(feature = "linux")]
mod gum_linux;
#[cfg(feature = "linux")]
mod hostlink_chardev;
#[cfg(feature = "linux")]
mod linux;

#[cfg(feature = "xnu")]
mod gum_xnu;
#[cfg(feature = "xnu")]
mod hostlink_virtio;
#[cfg(feature = "xnu")]
mod hostlink_vsock;
#[cfg(feature = "xnu")]
mod pac;
#[cfg(feature = "xnu")]
mod symbols;
#[cfg(feature = "xnu")]
mod xnu;

mod bindings {
    #![allow(
        dead_code,
        improper_ctypes,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals,
        unused_imports
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[repr(u8)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum FridaCommand {
    CreateScript = 1,
    LoadScript = 2,
    DestroyScript = 3,
    PostScriptMessage = 4,
    RemapWritablePages = 5,
    MemoryProtect = 6,
    PatchCode = 7,

    Reply = 128,
    ScriptMessage = 129,
}

impl core::fmt::Display for FridaCommand {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FridaCommand::CreateScript => write!(f, "CreateScript"),
            FridaCommand::LoadScript => write!(f, "LoadScript"),
            FridaCommand::DestroyScript => write!(f, "DestroyScript"),
            FridaCommand::PostScriptMessage => write!(f, "PostScriptMessage"),
            FridaCommand::RemapWritablePages => write!(f, "RemapWritablePages"),
            FridaCommand::MemoryProtect => write!(f, "MemoryProtect"),
            FridaCommand::PatchCode => write!(f, "PatchCode"),
            FridaCommand::Reply => write!(f, "Reply"),
            FridaCommand::ScriptMessage => write!(f, "ScriptMessage"),
        }
    }
}

#[derive(Debug)]
struct HandlerResponse {
    variant: *mut GVariant,
}

impl HandlerResponse {
    fn success(variant: *mut GVariant) -> Self {
        Self {
            variant: unsafe { g_variant_new(c"(bv)".as_ptr(), 1, variant) },
        }
    }

    fn success_empty() -> Self {
        Self::success(unsafe { g_variant_new_tuple(ptr::null(), 0) })
    }

    fn error(message: &str) -> Self {
        let mut c_message = String::from(message);
        c_message.push('\0');

        Self {
            variant: unsafe {
                g_variant_new(
                    c"(bv)".as_ptr(),
                    0,
                    g_variant_new_string(c_message.as_ptr()),
                )
            },
        }
    }
}

#[cfg(feature = "xnu")]
mod entrypoint_xnu {
    use super::*;
    use crate::symbols::SymbolTable;

    static mut CONFIG_DATA: &'static [u8] = &[];
    pub static mut MODULE_INFO: Vec<ModuleInfo> = Vec::new();
    pub static mut SYMBOL_TABLE: SymbolTable = SymbolTable::empty();

    #[derive(Debug, Clone)]
    pub struct ModuleInfo {
        pub name: String,
        pub version: String,
        pub offset: u32,
        pub size: u32,
        pub start_func_offset: u32,
        pub stop_func_offset: u32,
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn _start(config_data: *const u8, config_size: usize) {
        unsafe {
            kernel::log("frida: _start entry\n\0");
            CONFIG_DATA = core::slice::from_raw_parts(config_data, config_size);
            kernel::log("frida: _start config stored\n\0");

            let _r = kernel::spawn_thread(worker, 12345usize as *mut c_void);
        }
    }

    // KNOWN ISSUE (vphone research kernel): the worker panics during gum_init_embedded with
    // "debug exceptions enabled in kernel mode". The worker itself is healthy — it runs with
    // PSTATE.D=1 (debug masked) throughout. The panic is the research kernel's synchronous-
    // exception handler reacting to ANY exception the agent takes in kernel mode while the VZ
    // debug stub is active. Two confirmed sources: (1) the host's breakpoint-based Callbacks
    // patch BRK at gum_try_mprotect/remap, and the BRK is a debug exception; (2) a stray jump
    // into the agent's data region during GObject init (instruction abort) — looks like a
    // misapplied relocation for a function pointer stored in .data/.rodata.
    unsafe extern "C" fn worker(_parameter: *mut c_void, _wait_result: i32) {
        unsafe {
            kernel::log("frida: worker entry\n\0");
            init_gum();

            let (transport_config, kernel_base, module_info, symbol_table, own_range) =
                parse_config(core::ptr::addr_of!(CONFIG_DATA).read());
            kernel::set_kernel_base(kernel_base);
            MODULE_INFO = module_info;
            SYMBOL_TABLE = symbol_table;
            OWN_RANGE = own_range;
            kernel::log("frida: config parsed, init transport\n\0");

            let wake_token = ptr::addr_of_mut!(glib::WAKEUP_TOKEN) as *const u8;
            let transport = match transport_config {
                TransportConfig::Virtio { mmio, irq } => Transport::Virtio(
                    hostlink_virtio::Hostlink::init(
                        mmio,
                        irq,
                        Some(on_frame_from_host),
                        wake_token,
                    )
                    .unwrap(),
                ),
                TransportConfig::Vsock { host_port } => Transport::Vsock(
                    hostlink_vsock::Hostlink::init(host_port, Some(on_frame_from_host), wake_token)
                        .unwrap(),
                ),
            };
            transport_set(transport);
            kernel::log("frida: transport up, entering main loop\n\0");

            run_main_loop(adopt_js_context());
        }
    }

    unsafe fn parse_config(
        config: &[u8],
    ) -> (
        TransportConfig,
        u64,
        Vec<ModuleInfo>,
        SymbolTable,
        GumMemoryRange,
    ) {
        use crate::bindings::{
            GVariantIter, g_variant_get_byte, g_variant_get_child_value, g_variant_get_uint64,
            g_variant_get_variant, g_variant_iter_init, g_variant_iter_next,
        };

        unsafe {
            let type_string = c"((tt)yvta(ssuuuu)ay)".as_ptr() as *const gchar;
            let variant_type = g_variant_type_new(type_string);

            let root_variant = g_variant_new_from_data(
                variant_type,
                config.as_ptr() as *const c_void,
                config.len() as gsize,
                1,
                None,
                ptr::null_mut(),
            );

            let transport_kind_variant = g_variant_get_child_value(root_variant, 1);
            let transport_kind = g_variant_get_byte(transport_kind_variant);

            let transport_cfg_outer = g_variant_get_child_value(root_variant, 2);
            let transport_cfg_inner = g_variant_get_variant(transport_cfg_outer);
            let transport_config = match transport_kind {
                0 => {
                    let mmio_variant = g_variant_get_child_value(transport_cfg_inner, 0);
                    let mmio = g_variant_get_uint64(mmio_variant);
                    let irq_variant = g_variant_get_child_value(transport_cfg_inner, 1);
                    let irq = g_variant_get_uint32(irq_variant);
                    g_variant_unref(irq_variant);
                    g_variant_unref(mmio_variant);
                    TransportConfig::Virtio { mmio, irq }
                }
                1 => {
                    let host_port = g_variant_get_uint32(transport_cfg_inner);
                    TransportConfig::Vsock { host_port }
                }
                _ => panic!("Unsupported transport kind: {}", transport_kind),
            };
            g_variant_unref(transport_cfg_inner);
            g_variant_unref(transport_cfg_outer);
            g_variant_unref(transport_kind_variant);

            let kernel_base_variant = g_variant_get_child_value(root_variant, 3);
            let kernel_base = g_variant_get_uint64(kernel_base_variant);
            kernel::set_kernel_base(kernel_base);

            let module_info_variant = g_variant_get_child_value(root_variant, 4);
            let mut iter: GVariantIter = core::mem::zeroed();
            g_variant_iter_init(&mut iter as *mut GVariantIter, module_info_variant);

            let mut module_info: Vec<ModuleInfo> = Vec::new();
            let mut raw_name: *mut gchar = ptr::null_mut();
            let mut raw_version: *mut gchar = ptr::null_mut();
            let mut offset: u32 = 0;
            let mut size: u32 = 0;
            let mut start_func_offset: u32 = 0;
            let mut stop_func_offset: u32 = 0;
            while g_variant_iter_next(
                &mut iter as *mut GVariantIter,
                c"(&s&suuuu)".as_ptr(),
                &mut raw_name,
                &mut raw_version,
                &mut offset,
                &mut size,
                &mut start_func_offset,
                &mut stop_func_offset,
            ) != 0
            {
                module_info.push(ModuleInfo {
                    name: String::from(CStr::from_ptr(raw_name).to_str().unwrap()),
                    version: String::from(CStr::from_ptr(raw_version).to_str().unwrap()),
                    offset,
                    size,
                    start_func_offset,
                    stop_func_offset,
                });
            }

            let symbol_array_variant = g_variant_get_child_value(root_variant, 5);
            let symbol_data_ptr = g_variant_get_data(symbol_array_variant) as *const u8;
            let symbol_data_size = g_variant_get_size(symbol_array_variant) as usize;
            let symbol_table = SymbolTable::new(core::slice::from_raw_parts(
                symbol_data_ptr,
                symbol_data_size,
            ));

            let own_range_variant = g_variant_get_child_value(root_variant, 0);
            let mut own_base: u64 = 0;
            let mut own_size: u64 = 0;
            g_variant_get(
                own_range_variant,
                c"(tt)".as_ptr(),
                &mut own_base,
                &mut own_size,
            );
            let own_range = GumMemoryRange {
                base_address: own_base,
                size: own_size as gsize,
            };

            g_variant_unref(own_range_variant);
            g_variant_unref(symbol_array_variant);
            g_variant_unref(module_info_variant);
            g_variant_unref(kernel_base_variant);
            g_variant_unref(root_variant);
            g_variant_type_free(variant_type);

            (
                transport_config,
                kernel_base,
                module_info,
                symbol_table,
                own_range,
            )
        }
    }
}

#[cfg(feature = "linux")]
mod entrypoint_linux {
    use super::*;
    use core::ffi::c_int;
    use core::sync::atomic::AtomicBool;

    static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
    static WORKER_EXITED: AtomicBool = AtomicBool::new(false);

    /// Called from the module's init path. Everything interesting happens on our
    /// own kernel thread: `insmod` runs with the module mutex held, and bringing
    /// up Gum plus connecting to the host both block.
    #[unsafe(no_mangle)]
    pub extern "C" fn frida_agent_start() -> c_int {
        kernel::log("frida: agent starting\n\0");

        if kernel::spawn_thread(worker, ptr::null_mut()) != 0 {
            kernel::log("frida: failed to spawn worker\n\0");
            return -1;
        }

        0
    }

    /// Called from the module's exit path, which must not return until the worker
    /// is off our text — the module's pages go away right after.
    #[unsafe(no_mangle)]
    pub extern "C" fn frida_agent_stop() {
        kernel::log("frida: agent stopping\n\0");

        STOP_REQUESTED.store(true, Ordering::Release);

        while !WORKER_EXITED.load(Ordering::Acquire) {
            kernel::wake(ptr::addr_of!(glib::WAKEUP_TOKEN) as *const u8);
            kernel::wait(
                ptr::addr_of!(glib::WAKEUP_TOKEN) as *const u8,
                Some(10_000),
                &mut || WORKER_EXITED.load(Ordering::Acquire),
            );
        }

        kernel::log("frida: agent stopped\n\0");
    }

    pub fn stop_requested() -> bool {
        STOP_REQUESTED.load(Ordering::Acquire)
    }

    unsafe extern "C" fn worker(_parameter: *mut c_void, _wait_result: i32) {
        unsafe {
            kernel::log("frida: worker entry\n\0");

            init_gum();

            kernel::install_hooks();

            let (own_base, own_size) = kernel::own_range();
            OWN_RANGE = GumMemoryRange {
                base_address: own_base,
                size: own_size as gsize,
            };

            match hostlink_chardev::Hostlink::init(Some(on_frame_from_host)) {
                Ok(hostlink) => transport_set(Transport::CharDevice(hostlink)),
                Err(_) => {
                    kernel::log("frida: failed to connect to peer\n\0");
                    WORKER_EXITED.store(true, Ordering::Release);
                    return;
                }
            }
            kernel::log("frida: transport up, entering main loop\n\0");

            let main_context = adopt_js_context();

            run_main_loop(main_context);

            destroy_all_scripts(main_context);
            transport_teardown();

            WORKER_EXITED.store(true, Ordering::Release);
            kernel::wake(ptr::addr_of!(glib::WAKEUP_TOKEN) as *const u8);
        }
    }
}

#[cfg(feature = "linux")]
pub use entrypoint_linux::{frida_agent_start, frida_agent_stop};
#[cfg(feature = "xnu")]
pub use entrypoint_xnu::{MODULE_INFO, ModuleInfo, SYMBOL_TABLE, _start};

pub enum Transport {
    #[cfg(feature = "xnu")]
    Virtio(hostlink_virtio::Hostlink),
    #[cfg(feature = "xnu")]
    Vsock(hostlink_vsock::Hostlink),
    #[cfg(feature = "linux")]
    CharDevice(hostlink_chardev::Hostlink),
}

impl Transport {
    pub fn send(&self, payload: &[u8]) {
        match self {
            #[cfg(feature = "xnu")]
            Transport::Virtio(h) => h.send(payload),
            #[cfg(feature = "xnu")]
            Transport::Vsock(h) => h.send(payload),
            #[cfg(feature = "linux")]
            Transport::CharDevice(h) => h.send(payload),
        }
    }

    pub fn process(&self) {
        match self {
            #[cfg(feature = "xnu")]
            Transport::Virtio(h) => h.process(),
            #[cfg(feature = "xnu")]
            Transport::Vsock(h) => h.process(),
            #[cfg(feature = "linux")]
            Transport::CharDevice(h) => h.process(),
        }
    }
}

#[cfg(feature = "xnu")]
pub enum TransportConfig {
    Virtio { mmio: u64, irq: u32 },
    Vsock { host_port: u32 },
}

static mut TRANSPORT_DRIVER: *mut Transport = core::ptr::null_mut();

#[inline(always)]
fn transport_set(driver: Transport) {
    unsafe {
        let boxed = Box::into_raw(Box::new(driver));
        TRANSPORT_DRIVER = boxed;
    }
}

#[inline(always)]
fn transport_get_unchecked() -> &'static Transport {
    unsafe {
        debug_assert!(!TRANSPORT_DRIVER.is_null());
        &*TRANSPORT_DRIVER
    }
}

// Only the XNU backend has to cope with Gum asking for memory work before the
// hostlink that performs it exists.
#[cfg(feature = "xnu")]
#[inline(always)]
fn transport_is_up() -> bool {
    unsafe { !TRANSPORT_DRIVER.is_null() }
}

static mut SCRIPTS: BTreeMap<u32, *mut GumScript> = BTreeMap::new();
static NEXT_SCRIPT_ID: AtomicU32 = AtomicU32::new(1);
static mut OWN_RANGE: GumMemoryRange = GumMemoryRange {
    base_address: 0,
    size: 0,
};

static NEXT_REQUEST_ID: AtomicU32 = AtomicU32::new(1);
static mut PENDING_REPLIES: BTreeMap<u16, *mut GVariant> = BTreeMap::new();

unsafe fn init_gum() {
    unsafe {
        bindings::g_set_panic_handler(Some(frida_panic_handler), ptr::null_mut());
        bindings::gum_init_embedded();
        kernel::log("frida: gum_init_embedded done\n\0");
        bindings::g_log_set_default_handler(Some(frida_log_handler), ptr::null_mut());

        gum_script_scheduler_disable_background_thread(gum_script_backend_get_scheduler());

    }
}

fn on_frame_from_host(frame: &[u8]) {
    if let Some(variant) = deserialize_message(&frame) {
        process_incoming_message(variant);
        unsafe {
            g_variant_unref(variant);
        }
    }
}

unsafe fn adopt_js_context() -> *mut GMainContext {
    unsafe {
        let context = gum_script_scheduler_get_js_context(gum_script_backend_get_scheduler());

        // Acquires the context as well, which is what lets this thread run the jobs the
        // asynchronous script calls queue on it. Being the thread default is what makes
        // a script created here deliver its messages here too.
        g_main_context_push_thread_default(context);

        context
    }
}

const IDLE_SLICE_US: u64 = 50_000;

fn run_main_loop(main_context: *mut GMainContext) {
    unsafe {
        loop {
            transport_get_unchecked().process();

            #[cfg(feature = "linux")]
            if entrypoint_linux::stop_requested() {
                return;
            }

            g_main_context_iteration(main_context, 0);

            kernel::wait(
                ptr::addr_of!(glib::WAKEUP_TOKEN) as *const u8,
                Some(IDLE_SLICE_US),
                &mut || false,
            );

            kernel::yield_now();
        }
    }
}

#[cfg(feature = "linux")]
fn destroy_all_scripts(main_context: *mut GMainContext) {
    unsafe {
        let scripts = core::mem::take(core::ptr::addr_of_mut!(SCRIPTS).as_mut().unwrap());
        for (_, script) in scripts {
            UNLOADS_IN_FLIGHT.fetch_add(1, Ordering::Relaxed);
            gum_script_unload(script, ptr::null_mut(), Some(on_script_unloaded), ptr::null_mut());
        }

        while UNLOADS_IN_FLIGHT.load(Ordering::Relaxed) != 0 {
            g_main_context_iteration(main_context, 0);
            kernel::yield_now();
        }
    }
}

#[cfg(feature = "linux")]
unsafe extern "C" fn on_script_unloaded(
    source_object: *mut GObject,
    result: *mut GAsyncResult,
    _user_data: gpointer,
) {
    unsafe {
        let script = source_object as *mut GumScript;

        gum_script_unload_finish(script, result);
        g_object_unref(script as *mut c_void);

        UNLOADS_IN_FLIGHT.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(feature = "linux")]
static UNLOADS_IN_FLIGHT: AtomicU32 = AtomicU32::new(0);

#[cfg(feature = "linux")]
fn transport_teardown() {
    unsafe {
        let driver = TRANSPORT_DRIVER;
        TRANSPORT_DRIVER = ptr::null_mut();
        drop(Box::from_raw(driver));
    }
}

unsafe fn serialize_message(variant: *mut GVariant) -> Option<Vec<u8>> {
    unsafe {
        let size = g_variant_get_size(variant) as usize;
        if size == 0 {
            return None;
        }

        let data_ptr = g_variant_get_data(variant) as *const u8;
        let mut result = Vec::with_capacity(size);
        result.resize(size, 0);
        core::ptr::copy_nonoverlapping(data_ptr, result.as_mut_ptr(), size);

        Some(result)
    }
}

fn deserialize_message(data: &[u8]) -> Option<*mut GVariant> {
    unsafe {
        if data.is_empty() {
            return None;
        }

        let variant_type = g_variant_type_new(c"(yqv)".as_ptr());
        let data_copy = g_memdup2(data.as_ptr() as *const c_void, data.len() as u64);
        let variant = g_variant_new_from_data(
            variant_type,
            data_copy,
            data.len() as u64,
            0,
            Some(g_free),
            data_copy,
        );
        g_variant_type_free(variant_type);

        if variant.is_null() {
            None
        } else {
            Some(variant)
        }
    }
}

fn process_incoming_message(variant: *mut GVariant) {
    {
        let mut cmd_value: u8 = 0;
        let mut request_id: u16 = 0;
        let mut payload_variant: *mut GVariant = ptr::null_mut();

        let cmd = unsafe {
            g_variant_get(
                variant,
                c"(yqv)".as_ptr(),
                &mut cmd_value,
                &mut request_id,
                &mut payload_variant,
            );

            core::mem::transmute::<u8, FridaCommand>(cmd_value)
        };

        if cmd == FridaCommand::Reply {
            unsafe {
                core::ptr::addr_of_mut!(PENDING_REPLIES)
                    .as_mut()
                    .unwrap()
                    .insert(request_id, payload_variant);
            }
            return;
        }

        let response = match cmd {
            FridaCommand::CreateScript => handle_create_script(payload_variant, request_id),
            FridaCommand::LoadScript => handle_load_script(payload_variant, request_id),
            FridaCommand::DestroyScript => handle_destroy_script(payload_variant, request_id),
            FridaCommand::PostScriptMessage => Some(handle_post_script_message(payload_variant)),
            _ => Some(HandlerResponse::error("Unknown command")),
        };

        if let Some(response) = response {
            send_command_reply(request_id, response);
        }

        unsafe { g_variant_unref(payload_variant) };
    }
}

fn send_command_reply(request_id: u16, response: HandlerResponse) {
    unsafe {
        let message = g_variant_new(
            c"(yqv)".as_ptr(),
            FridaCommand::Reply as u8 as u32,
            request_id as u32,
            response.variant,
        );

        if let Some(serialized) = serialize_message(message) {
            transport_get_unchecked().send(&serialized);
        }

        g_variant_unref(message);
    }
}

pub fn host_rpc(command: FridaCommand, payload: *mut GVariant) -> *mut GVariant {
    unsafe {
        let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed) as u16;
        let message = g_variant_new(
            c"(yqv)".as_ptr(),
            command as u8 as u32,
            request_id as u32,
            payload,
        );
        let transport = transport_get_unchecked();
        transport.send(&serialize_message(message).unwrap());
        g_variant_unref(message);

        let wait_event = ptr::addr_of_mut!(glib::WAKEUP_TOKEN) as *const u8;
        loop {
            let mut reply: Option<*mut GVariant> = None;
            kernel::wait(wait_event, None, &mut || {
                transport.process();
                reply = take_pending_reply(request_id);
                reply.is_some()
            });
            if let Some(reply) = reply {
                return reply;
            }
        }
    }
}

fn take_pending_reply(request_id: u16) -> Option<*mut GVariant> {
    unsafe {
        core::ptr::addr_of_mut!(PENDING_REPLIES)
            .as_mut()
            .unwrap()
            .remove(&request_id)
    }
}

fn handle_create_script(payload_variant: *mut GVariant, request_id: u16) -> Option<HandlerResponse> {
    unsafe {
        if g_variant_check_format_string(payload_variant, c"s".as_ptr(), 0) == 0 {
            return Some(HandlerResponse::error("Invalid payload format: expected string"));
        }
        let source = g_variant_get_string(payload_variant, core::ptr::null_mut());

        gum_script_backend_create(
            gum_script_backend_obtain_qjs(),
            c"agent.js".as_ptr(),
            source,
            ptr::null_mut(),
            ptr::null_mut(),
            Some(on_script_created),
            Box::into_raw(Box::new(request_id)) as *mut c_void,
        );

        None
    }
}

unsafe extern "C" fn on_script_created(
    source_object: *mut GObject,
    result: *mut GAsyncResult,
    user_data: gpointer,
) {
    unsafe {
        let request_id = *Box::from_raw(user_data as *mut u16);

        let mut error: *mut GError = ptr::null_mut();
        let script = gum_script_backend_create_finish(
            source_object as *mut GumScriptBackend,
            result,
            &mut error,
        );

        if !error.is_null() {
            let message = String::from(CStr::from_ptr((*error).message).to_str().unwrap());
            g_error_free(error);
            send_command_reply(request_id, HandlerResponse::error(&message));
            return;
        }

        exclude_own_range_from_stalker(script);

        let script_id = NEXT_SCRIPT_ID.fetch_add(1, Ordering::Relaxed);

        gum_script_set_message_handler(
            script,
            Some(frida_message_handler),
            Box::into_raw(Box::new(script_id)) as *mut c_void,
            None,
        );

        core::ptr::addr_of_mut!(SCRIPTS)
            .as_mut()
            .unwrap()
            .insert(script_id, script);

        send_command_reply(request_id, HandlerResponse::success(g_variant_new_uint32(script_id)));
    }
}

// Stalker must not instrument our own runtime: when it follows the current
// thread into the hostlink transport it would deadlock on the locks that the
// RPC it depends on is holding. On XNU the host injected the image, so it tells
// us our range as part of the config; on Linux we ask the module loader.
unsafe fn exclude_own_range_from_stalker(script: *mut GumScript) {
    unsafe {
        gum_stalker_exclude(gum_script_get_stalker(script), core::ptr::addr_of!(OWN_RANGE));
    }
}

unsafe extern "C" fn frida_message_handler(
    message: *const gchar,
    _data: *mut GBytes,
    user_data: gpointer,
) {
    unsafe {
        let script_id = *(user_data as *const u32);

        let message_variant = g_variant_new(
            c"(yqv)".as_ptr(),
            FridaCommand::ScriptMessage as u8 as u32,
            0u32,
            g_variant_new(c"(us)".as_ptr(), script_id, message),
        );

        if let Some(serialized) = serialize_message(message_variant) {
            transport_get_unchecked().send(&serialized);
        }

        g_variant_unref(message_variant);
    }
}

fn handle_load_script(payload_variant: *mut GVariant, request_id: u16) -> Option<HandlerResponse> {
    unsafe {
        if g_variant_check_format_string(payload_variant, c"u".as_ptr(), 0) == 0 {
            return Some(HandlerResponse::error("Invalid payload format: expected uint32"));
        }
        let script_id = g_variant_get_uint32(payload_variant);

        let Some(script) = get_script_by_id(script_id) else {
            return Some(HandlerResponse::error(&format!("Script with ID {} not found", script_id)));
        };

        gum_script_load(
            script,
            ptr::null_mut(),
            Some(on_script_loaded),
            Box::into_raw(Box::new(request_id)) as *mut c_void,
        );

        None
    }
}

unsafe extern "C" fn on_script_loaded(
    source_object: *mut GObject,
    result: *mut GAsyncResult,
    user_data: gpointer,
) {
    unsafe {
        let request_id = *Box::from_raw(user_data as *mut u16);

        gum_script_load_finish(source_object as *mut GumScript, result);

        send_command_reply(request_id, HandlerResponse::success_empty());
    }
}

fn handle_destroy_script(payload_variant: *mut GVariant, request_id: u16) -> Option<HandlerResponse> {
    unsafe {
        if g_variant_check_format_string(payload_variant, c"u".as_ptr(), 0) == 0 {
            return Some(HandlerResponse::error("Invalid payload format: expected uint32"));
        }
        let script_id = g_variant_get_uint32(payload_variant);

        let scripts = core::ptr::addr_of_mut!(SCRIPTS).as_mut().unwrap();
        let Some(script) = scripts.remove(&script_id) else {
            return Some(HandlerResponse::error(&format!("Script with ID {} not found", script_id)));
        };

        gum_script_unload(
            script,
            ptr::null_mut(),
            Some(on_script_destroyed),
            Box::into_raw(Box::new(request_id)) as *mut c_void,
        );

        None
    }
}

unsafe extern "C" fn on_script_destroyed(
    source_object: *mut GObject,
    result: *mut GAsyncResult,
    user_data: gpointer,
) {
    unsafe {
        let request_id = *Box::from_raw(user_data as *mut u16);
        let script = source_object as *mut GumScript;

        gum_script_unload_finish(script, result);
        g_object_unref(script as *mut c_void);

        send_command_reply(request_id, HandlerResponse::success_empty());
    }
}

fn handle_post_script_message(payload_variant: *mut GVariant) -> HandlerResponse {
    unsafe {
        if g_variant_check_format_string(payload_variant, c"(us)".as_ptr(), 0) == 0 {
            return HandlerResponse::error("Invalid payload format: expected (uint32, string)");
        }
        let mut script_id: u32 = 0;
        let mut message: *const gchar = ptr::null();
        g_variant_get(
            payload_variant,
            c"(u&s)".as_ptr(),
            &mut script_id,
            &mut message,
        );

        let Some(script) = get_script_by_id(script_id) else {
            return HandlerResponse::error(&format!("Script with ID {} not found", script_id));
        };

        gum_script_post(script, message, ptr::null_mut());

        HandlerResponse::success_empty()
    }
}

unsafe fn get_script_by_id(script_id: u32) -> Option<*mut GumScript> {
    unsafe {
        let scripts = core::ptr::addr_of_mut!(SCRIPTS).as_mut().unwrap();
        scripts.get(&script_id).copied()
    }
}

unsafe extern "C" fn frida_panic_handler(message: *const u8, _user_data: *mut c_void) {
    let msg = unsafe { CStr::from_ptr(message).to_str().unwrap() };
    panic!("[Frida] {}", msg);
}

unsafe extern "C" fn frida_log_handler(
    _log_domain: *const core::ffi::c_char,
    _log_level: i32,
    message: *const core::ffi::c_char,
    _user_data: *mut c_void,
) {
    let msg = unsafe { CStr::from_ptr(message).to_str().unwrap() };
    kprintln!("[Frida] {}", msg);
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    let mut s = format!("{}", info);
    s.push('\0');
    kernel::panic(s.as_str());
    #[allow(unreachable_code)]
    loop {}
}

pub struct KernelAllocator;

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        kernel::alloc(layout.size())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        kernel::free(ptr, layout.size());
    }
}

#[global_allocator]
static GLOBAL: KernelAllocator = KernelAllocator;
extern crate alloc;

#[macro_export]
macro_rules! kprintln {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let mut buf = alloc::string::String::new();
        write!(&mut buf, $($arg)*).unwrap();
        buf.push('\n');
        buf.push('\0');
        $crate::kernel::log(&buf)
    }};
}
