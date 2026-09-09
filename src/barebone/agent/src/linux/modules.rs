use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::{c_int, c_long, c_void};
use core::ptr;

use super::layout::field_offset;
use super::{LoadedModule, ModuleEvent};

pub fn enumerate_modules() -> Vec<LoadedModule> {
    let Some(layout) = module_layout() else {
        return Vec::new();
    };

    let head = unsafe { _modules } as usize;
    if head == 0 {
        return Vec::new();
    }

    let mut modules = Vec::new();
    let mut node = word_at(head);
    let mut left = MAX_MODULES;
    while node != head && node != 0 && left != 0 {
        let module = node - layout.list;
        if is_live(module, &layout) {
            modules.push(describe(module, &layout));
        }

        node = word_at(node);
        left -= 1;
    }

    modules
}

pub fn watch_modules(on_event: fn(ModuleEvent, LoadedModule)) {
    if module_layout().is_none() {
        return;
    }

    unsafe {
        if _register_module_notifier.is_none() {
            return;
        }

        WATCHER = Some(on_event);
        NOTIFIER = Box::into_raw(Box::new(NotifierBlock {
            notifier_call: Some(NOTIFIER_CALL),
            next: ptr::null_mut(),
            priority: 0,
        }));

        register_notifier(NOTIFIER as *mut c_void);
    }
}

pub fn unwatch_modules() {
    unsafe {
        if (&raw const WATCHER).read().is_none() {
            return;
        }

        if _unregister_module_notifier.is_some() {
            unregister_notifier(NOTIFIER as *mut c_void);
        }

        drop(Box::from_raw(NOTIFIER));
        NOTIFIER = ptr::null_mut();
        WATCHER = None;
    }
}

#[cfg(not(target_arch = "x86"))]
unsafe fn register_notifier(block: *mut c_void) {
    unsafe {
        if let Some(register) = _register_module_notifier {
            register(block);
        }
    }
}

#[cfg(not(target_arch = "x86"))]
unsafe fn unregister_notifier(block: *mut c_void) {
    unsafe {
        if let Some(unregister) = _unregister_module_notifier {
            unregister(block);
        }
    }
}

#[cfg(target_arch = "x86")]
unsafe fn register_notifier(block: *mut c_void) {
    unsafe { frida_k_register_module_notifier(block) };
}

#[cfg(target_arch = "x86")]
unsafe fn unregister_notifier(block: *mut c_void) {
    unsafe { frida_k_unregister_module_notifier(block) };
}

#[cfg(not(target_arch = "x86"))]
const NOTIFIER_CALL: unsafe extern "C" fn(*mut NotifierBlock, c_long, *mut c_void) -> c_int =
    on_module_state;

#[cfg(target_arch = "x86")]
const NOTIFIER_CALL: unsafe extern "C" fn(*mut NotifierBlock, c_long, *mut c_void) -> c_int =
    frida_kcb_module_state;

#[cfg(target_arch = "x86")]
#[unsafe(no_mangle)]
unsafe extern "C" fn frida_cb_module_state(
    block: *mut NotifierBlock,
    action: c_long,
    module: *mut c_void,
) -> c_int {
    unsafe { on_module_state(block, action, module) }
}

unsafe extern "C" fn on_module_state(
    _block: *mut NotifierBlock,
    action: c_long,
    module: *mut c_void,
) -> c_int {
    let kind = match action {
        MODULE_STATE_LIVE => ModuleEvent::Loaded,
        MODULE_STATE_GOING => ModuleEvent::Unloaded,
        _ => return NOTIFY_DONE,
    };

    let Some(on_event) = (unsafe { WATCHER }) else {
        return NOTIFY_DONE;
    };
    let Some(layout) = module_layout() else {
        return NOTIFY_DONE;
    };

    on_event(kind, describe(module as usize, &layout));

    NOTIFY_DONE
}

fn describe(module: usize, layout: &Layout) -> LoadedModule {
    let (base, size) = match layout.memory {
        Memory::Described { at, base, size } => (word_at(module + at + base), word_at(module + at + size)),
        Memory::Split { base, size } => (word_at(module + base), word_at(module + size)),
    };

    LoadedModule {
        name: text_at(module + layout.name),
        version: layout
            .version
            .map(|at| text_at(word_at(module + at)))
            .unwrap_or_default(),
        base: base as u64,
        size: (size & 0xffff_ffff) as u64,
    }
}

fn is_live(module: usize, layout: &Layout) -> bool {
    let Some(at) = layout.state else {
        return true;
    };

    let state = unsafe { ((module + at) as *const u32).read_volatile() };

    state == MODULE_STATE_LIVE as u32
}

fn module_layout() -> Option<&'static Layout> {
    unsafe {
        let known = (&raw mut LAYOUT).as_mut().unwrap();
        if known.is_none() {
            *known = discover_layout();
        }
        known.as_ref()
    }
}

static mut LAYOUT: Option<Layout> = None;

struct Layout {
    list: usize,
    name: usize,
    version: Option<usize>,
    state: Option<usize>,
    memory: Memory,
}

enum Memory {
    Described { at: usize, base: usize, size: usize },
    Split { base: usize, size: usize },
}

fn discover_layout() -> Option<Layout> {
    layout_from_types().or_else(layout_from_probing)
}

fn layout_from_types() -> Option<Layout> {
    let memory = match field_offset("module", "mem") {
        Some(at) => Memory::Described {
            at,
            base: field_offset("module_memory", "base")?,
            size: field_offset("module_memory", "size")?,
        },
        None => match field_offset("module", "core_layout") {
            Some(at) => Memory::Described {
                at,
                base: field_offset("module_layout", "base")?,
                size: field_offset("module_layout", "size")?,
            },
            None => Memory::Split {
                base: field_offset("module", "module_core")?,
                size: field_offset("module", "core_size")?,
            },
        },
    };

    Some(Layout {
        list: field_offset("module", "list")?,
        name: field_offset("module", "name")?,
        version: field_offset("module", "version"),
        state: field_offset("module", "state"),
        memory,
    })
}

fn layout_from_probing() -> Option<Layout> {
    let list = WORD;
    let name = list + 2 * WORD;
    let (at, size) = probe_memory(list, name + MODULE_NAME_LEN)?;

    Some(Layout {
        list,
        name,
        version: None,
        state: Some(0),
        memory: Memory::Described { at, base: 0, size },
    })
}

fn probe_memory(list: usize, after_name: usize) -> Option<(usize, usize)> {
    let head = unsafe { _modules } as usize;
    if head == 0 {
        return None;
    }

    let start = (after_name + WORD - 1) & !(WORD - 1);
    for at in (start..PROBE_SPAN).step_by(WORD) {
        for size in (WORD..=MAX_SIZE_DISTANCE).step_by(WORD) {
            if each_module(head, list, |module| describes_memory(module, at, size)) {
                return Some((at, size));
            }
        }
    }

    None
}

fn describes_memory(module: usize, at: usize, size: usize) -> bool {
    let base = word_at(module + at);
    let size = unsafe { ((module + at + size) as *const u32).read_volatile() } as usize;

    base != 0
        && base & (PAGE_SIZE - 1) == 0
        && size != 0
        && size & (PAGE_SIZE - 1) == 0
        && size <= MAX_MODULE_SIZE
        && base.abs_diff(module) <= MODULE_REACH
}

fn each_module(head: usize, list: usize, is_sane: impl Fn(usize) -> bool) -> bool {
    let mut node = word_at(head);
    let mut seen = 0;
    let mut left = MAX_MODULES;
    while node != head && node != 0 && left != 0 {
        if !is_sane(node - list) {
            return false;
        }
        seen += 1;

        node = word_at(node);
        left -= 1;
    }

    seen != 0
}

fn word_at(address: usize) -> usize {
    unsafe { (address as *const usize).read_volatile() }
}

fn text_at(address: usize) -> String {
    if address == 0 {
        return String::new();
    }

    let mut text = String::new();
    for i in 0..MAX_NAME {
        let byte = unsafe { ((address + i) as *const u8).read_volatile() };
        if byte == 0 {
            break;
        }
        text.push(byte as char);
    }

    text
}

static mut WATCHER: Option<fn(ModuleEvent, LoadedModule)> = None;

static mut NOTIFIER: *mut NotifierBlock = ptr::null_mut();

#[repr(C)]
struct NotifierBlock {
    notifier_call:
        Option<unsafe extern "C" fn(*mut NotifierBlock, c_long, *mut c_void) -> c_int>,
    next: *mut NotifierBlock,
    priority: c_int,
}

const MODULE_STATE_LIVE: c_long = 0;
const MODULE_STATE_GOING: c_long = 2;
const NOTIFY_DONE: c_int = 0;
const MAX_MODULES: usize = 4096;
const WORD: usize = core::mem::size_of::<usize>();
const MODULE_NAME_LEN: usize = 64 - WORD;
const PAGE_SIZE: usize = 4096;
const PROBE_SPAN: usize = 1024;
const MAX_MODULE_SIZE: usize = 256 * 1024 * 1024;
const MODULE_REACH: usize = 512 * 1024 * 1024;
const MAX_SIZE_DISTANCE: usize = 3 * WORD;
const MAX_NAME: usize = 64;

#[cfg(target_arch = "x86")]
unsafe extern "C" {
    fn frida_kcb_module_state(
        block: *mut NotifierBlock,
        action: c_long,
        module: *mut c_void,
    ) -> c_int;
    fn frida_k_register_module_notifier(block: *mut c_void) -> c_int;
    fn frida_k_unregister_module_notifier(block: *mut c_void) -> c_int;
}

unsafe extern "C" {
    static _modules: *const c_void;
    static _register_module_notifier: Option<unsafe extern "C" fn(*mut c_void) -> c_int>;
    #[allow(dead_code)]
    static _unregister_module_notifier: Option<unsafe extern "C" fn(*mut c_void) -> c_int>;
}
