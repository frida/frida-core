// Gum's platform backend for an agent the host injected into a kernel that
// keeps its page tables and its executable regions to itself. Memory
// permissions and kernel-text writes go out over the hostlink, because the
// guest cannot perform them itself: the host owns the page tables and the
// physical-memory bridge.

use crate::{
    FridaCommand,
    bindings::{
        _GumPageProtection_GUM_PAGE_EXECUTE, _GumPageProtection_GUM_PAGE_READ,
        _GumPageProtection_GUM_PAGE_WRITE, _GumRwxSupport_GUM_RWX_FULL,
        _GumRwxSupport_GUM_RWX_NONE, GArray,
        GumDebugSymbolDetails, GumFoundRangeFunc, GumFoundThreadFunc, GumMemoryRange,
        GumModuleRegistry, GumPageProtection, GumRangeDetails, GumRwxSupport, GumThreadDetails,
        GumThreadId, GumThreadRegistry, gum_barebone_register_thread,
        gum_barebone_unregister_thread,
        g_array_append_vals, g_array_new, g_object_unref, g_strdup, g_variant_get_boolean,
        g_variant_get_uint64, g_variant_new, g_variant_new_fixed_array, g_variant_type_free,
        g_variant_type_new, g_variant_unref, gboolean, gchar, gconstpointer, gpointer, gsize, guint,
        gum_barebone_register_module,
        gum_barebone_try_remap_writable_pages as _gum_barebone_try_remap_writable_pages,
        gum_mprotect, gum_query_page_size,
    },
    gum::{self, FoundExportCallback},
    host_rpc, kernel, libc,
};
use alloc::format;
use alloc::vec::Vec;
use core::ffi::CStr;
use core::mem::size_of;
use core::ptr;

// Where the guest's kernel keeps itself and its modules, which is what Gum
// reports as the path of each one.
#[cfg(feature = "xnu-core")]
const KERNEL_PATH: &str = "/System/Library/Kernels/kernel";
#[cfg(feature = "xnu-core")]
const MODULE_DIRECTORY: &str = "/System/Library/Extensions/";
#[cfg(feature = "xnu-core")]
const MODULE_SUFFIX: &str = ".kext";

#[cfg(feature = "linux-injected")]
const KERNEL_PATH: &str = "/boot/vmlinux";
#[cfg(feature = "linux-injected")]
const MODULE_DIRECTORY: &str = "/lib/modules/";
#[cfg(feature = "linux-injected")]
const MODULE_SUFFIX: &str = ".ko";

const SHADOW_MAGIC: u64 = 0x4644_4f48_5341_4853;
const SHADOW_HEADER: usize = 24;
const SHADOW_MIN_ADDRESS: u64 = 0xffff_f000_0000_0000;

#[cfg(feature = "xnu-core")]
#[unsafe(no_mangle)]
pub extern "C" fn gum_barebone_query_platform() -> *const crate::bindings::gchar {
    c"darwin".as_ptr() as *const crate::bindings::gchar
}

#[cfg(feature = "linux-injected")]
#[unsafe(no_mangle)]
pub extern "C" fn gum_barebone_query_platform() -> *const crate::bindings::gchar {
    c"linux".as_ptr() as *const crate::bindings::gchar
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_query_rwx_support() -> GumRwxSupport {
    #[cfg(feature = "linux-injected")]
    if kernel::in_copy() {
        return _GumRwxSupport_GUM_RWX_FULL;
    }

    _GumRwxSupport_GUM_RWX_NONE
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_memory_can_remap_writable() -> gboolean {
    #[cfg(feature = "linux-injected")]
    if kernel::in_copy() {
        return 0;
    }

    #[cfg(feature = "xnu-core")]
    if crate::xnu::in_copy() {
        return 0;
    }

    1
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_memory_try_remap_writable_pages(
    first_page: gpointer,
    n_pages: guint,
) -> gpointer {
    if gum::is_agent_slab(first_page as u64) {
        return remap_agent_pages(first_page, n_pages);
    }

    shadow_kernel_pages(first_page, n_pages)
}

#[cfg(feature = "xnu-kext")]
fn remap_agent_pages(first_page: gpointer, _n_pages: guint) -> gpointer {
    first_page
}

#[cfg(not(feature = "xnu-kext"))]
fn remap_agent_pages(first_page: gpointer, n_pages: guint) -> gpointer {
    unsafe {
        let page_size = gum_query_page_size() as usize;
        let mut virtual_addrs = Vec::with_capacity(n_pages as usize);

        let mut current_page = first_page as u64;
        for _ in 0..n_pages {
            virtual_addrs.push(current_page as gpointer);
            current_page += page_size as u64;
        }

        _gum_barebone_try_remap_writable_pages(
            virtual_addrs.as_ptr() as *mut *const core::ffi::c_void,
            virtual_addrs.len() as guint,
        )
    }
}

fn shadow_kernel_pages(first_page: gpointer, n_pages: guint) -> gpointer {
    unsafe {
        let total = n_pages as usize * gum_query_page_size() as usize;
        let buffer = kernel::alloc(SHADOW_HEADER + total);
        *(buffer as *mut u64) = SHADOW_MAGIC;
        *(buffer.add(8) as *mut u64) = first_page as u64;
        *(buffer.add(16) as *mut u32) = n_pages;

        let body = buffer.add(SHADOW_HEADER);
        core::ptr::copy_nonoverlapping(first_page as *const u8, body, total);
        body as gpointer
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_memory_dispose_writable_pages(writable: gpointer, _n_pages: guint) {
    if (writable as u64) < SHADOW_MIN_ADDRESS {
        return;
    }
    unsafe {
        let buffer = (writable as *mut u8).sub(SHADOW_HEADER);
        if *(buffer as *const u64) != SHADOW_MAGIC {
            return;
        }
        let first_page = *(buffer.add(8) as *const u64);
        let n_pages = *(buffer.add(16) as *const u32);
        let total = n_pages as usize * gum_query_page_size() as usize;

        commit_kernel_patch(first_page, writable as *const u8, total);
        libc::__clear_cache(first_page as *const u8, (first_page + total as u64) as *const u8);

        kernel::free(buffer, SHADOW_HEADER + total);
    }
}

#[cfg(feature = "xnu-kext")]
unsafe fn commit_kernel_patch(address: u64, data: *const u8, len: usize) {
    crate::xnu::write_through_a_writable_alias(address, data, len);
}

#[cfg(not(feature = "xnu-kext"))]
unsafe fn commit_kernel_patch(address: u64, data: *const u8, len: usize) {
    unsafe {
        let element_type = g_variant_type_new(c"y".as_ptr());
        let bytes = g_variant_new_fixed_array(element_type, data as gconstpointer, len as gsize, 1);
        g_variant_type_free(element_type);

        let payload = g_variant_new(c"(t@ay)".as_ptr(), address, bytes);
        let reply = host_rpc(FridaCommand::PatchCode, payload);
        g_variant_unref(reply);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_barebone_try_remap_writable_pages(
    addrs: *const gpointer,
    n_addrs: guint,
) -> gpointer {
    if !crate::transport_is_up() {
        return ptr::null_mut();
    }
    unsafe {
        let element_type = g_variant_type_new(c"t".as_ptr());
        let payload = g_variant_new_fixed_array(
            element_type,
            addrs as gconstpointer,
            n_addrs as gsize,
            size_of::<u64>() as gsize,
        );
        g_variant_type_free(element_type);

        let reply = host_rpc(FridaCommand::RemapWritablePages, payload);
        let virtual_address = g_variant_get_uint64(reply);
        g_variant_unref(reply);

        virtual_address as gpointer
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_try_mprotect(
    address: gpointer,
    size: gsize,
    prot: GumPageProtection,
) -> gboolean {
    protect_here(address as u64, size as usize, prot as u32) as gboolean
}

// Where the agent has a half that runs in a process of the target, the protection is that
// half's own business: it has an address space it may change itself.
#[cfg(feature = "linux-injected")]
fn protect_here(address: u64, size: usize, prot: u32) -> bool {
    kernel::protect(address, size, prot)
}

#[cfg(feature = "xnu-kext")]
fn protect_here(address: u64, size: usize, prot: u32) -> bool {
    if crate::xnu::in_copy() {
        return kernel::protect(address, size, prot);
    }

    true
}

#[cfg(all(feature = "xnu-core", not(feature = "xnu-kext")))]
fn protect_here(address: u64, size: usize, prot: u32) -> bool {
    if crate::xnu::in_copy() {
        return kernel::protect(address, size, prot);
    }

    ask_the_host_to_protect(address, size, prot)
}

#[cfg(not(any(feature = "linux-injected", feature = "xnu-core")))]
fn protect_here(address: u64, size: usize, prot: u32) -> bool {
    ask_the_host_to_protect(address, size, prot)
}

pub fn ask_the_host_to_protect(address: u64, size: usize, prot: u32) -> bool {
    if !crate::transport_is_up() {
        return true;
    }

    let granted = the_host_grants_it(address, size, prot);

    #[cfg(feature = "xnu-core")]
    if granted {
        crate::kernel::make_the_machine_agree();
    }

    granted
}

fn the_host_grants_it(address: u64, size: usize, prot: u32) -> bool {
    unsafe {
        let payload = g_variant_new(c"(ttu)".as_ptr(), address, size as u64, prot);

        let reply = host_rpc(FridaCommand::MemoryProtect, payload);
        let success = g_variant_get_boolean(reply) != 0;
        g_variant_unref(reply);

        if success {
            flush_tlb_range(address, size as u64);
        }

        success
    }
}

// The host rewrites our page-table descriptors through the physical-memory
// bridge, which leaves this CPU's TLB holding the stale translation. Stalker
// flips a slab page RW then RX in place, so without this the freeze never takes
// effect and executing the page faults with a permission abort.
unsafe fn flush_tlb_range(address: u64, size: u64) {
    let page_size = unsafe { gum_query_page_size() } as u64;
    let start = address & !(page_size - 1);
    let end = (address + size + page_size - 1) & !(page_size - 1);

    unsafe { flush_pages(start, end, page_size) };
}

#[cfg(target_arch = "aarch64")]
unsafe fn flush_pages(start: u64, end: u64, page_size: u64) {
    unsafe {
        core::arch::asm!("dsb ish", options(nostack, preserves_flags));
        let mut va = start;
        while va < end {
            core::arch::asm!("tlbi vaae1is, {operand}", operand = in(reg) va >> 12,
                options(nostack, preserves_flags));
            va += page_size;
        }
        core::arch::asm!("dsb ish", "isb", options(nostack, preserves_flags));
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn flush_pages(start: u64, end: u64, page_size: u64) {
    unsafe {
        let mut va = start;
        while va < end {
            core::arch::asm!("invlpg [{operand}]", operand = in(reg) va as usize,
                options(nostack, preserves_flags));
            va += page_size;
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_memory_allocate(
    address: gpointer,
    size: gsize,
    _alignment: gsize,
    prot: GumPageProtection,
) -> gpointer {
    #[cfg(feature = "xnu-core")]
    let ptr = if crate::xnu::in_copy() {
        crate::xnu_user_calls::code_memory_near(address as u64, size as usize)
    } else {
        kernel::alloc_code(size as usize)
    };
    #[cfg(not(feature = "xnu-core"))]
    let ptr = kernel::alloc_code(size as usize);
    #[cfg(not(feature = "xnu-core"))]
    let _ = address;
    unsafe {
        core::ptr::write_bytes(ptr, 0, size as usize);
        if (prot & _GumPageProtection_GUM_PAGE_EXECUTE) != 0 {
            gum::register_slab(ptr as u64, size as usize);
            gum_mprotect(ptr as gpointer, size, prot);
        }
    }
    ptr as gpointer
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_memory_free(address: gpointer, size: gsize) -> gboolean {
    // Executable slabs were flipped to RX in the page tables; restore RW before returning them to
    // the allocator, otherwise the reclaimed pages stay non-writable and the next consumer faults.
    if gum::is_agent_slab(address as u64) {
        unsafe {
            gum_mprotect(
                address,
                size,
                (_GumPageProtection_GUM_PAGE_READ | _GumPageProtection_GUM_PAGE_WRITE)
                    as GumPageProtection,
            );
        }
        gum::unregister_slab(address as u64);
    }
    kernel::free_code(address as *mut u8, size as usize);
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_barebone_on_registry_activating(registry: *mut GumModuleRegistry) {
    #[cfg(feature = "linux-injected")]
    if kernel::in_copy() {
        kernel::register_what_the_copy_lives_among(registry);
        kernel::watch_the_loader();
        return;
    }

    #[cfg(feature = "xnu-core")]
    if crate::xnu::in_copy() {
        crate::xnu_mapped::register_what_the_copy_lives_among(registry);
        return;
    }

    let kernel_base = kernel::get_kernel_base();

    unsafe {
        let module_infos = core::ptr::addr_of!(crate::MODULE_INFO);
        let module_infos = &*module_infos;

        let mut i = 0;
        for module_info in module_infos.iter() {
            let module_base = kernel_base + module_info.offset as u64;

            let module_path = if i == 0 {
                KERNEL_PATH
            } else {
                &format!(
                    "{}{}{}",
                    MODULE_DIRECTORY, module_info.name, MODULE_SUFFIX
                )
            };
            let module_range = GumMemoryRange {
                base_address: module_base,
                size: module_info.size as gsize,
            };

            let module = gum::gum_native_module_new(&module_path, &module_info.version, &module_range);
            gum_barebone_register_module(registry, module);
            g_object_unref(module as gpointer);

            i += 1;
        }
    }
}

#[cfg(any(feature = "linux-injected", feature = "xnu-core"))]
#[unsafe(no_mangle)]
pub extern "C" fn gum_barebone_on_thread_registry_activating(registry: *mut GumThreadRegistry) {
    unsafe { THREAD_REGISTRY = registry };

    kernel::enumerate_threads(&mut |thread| announce_thread(thread.id));
}

#[cfg(any(feature = "linux-injected", feature = "xnu-core"))]
#[unsafe(no_mangle)]
pub extern "C" fn gum_barebone_on_thread_registry_deactivating(_registry: *mut GumThreadRegistry) {
    unsafe { THREAD_REGISTRY = ptr::null_mut() };
}

#[cfg(any(feature = "linux-injected", feature = "xnu-core"))]
pub(crate) fn thread_appeared(id: u32) {
    announce_thread(id);
}

#[cfg(any(feature = "linux-injected", feature = "xnu-core"))]
pub(crate) fn thread_vanished(id: u32) {
    let registry = unsafe { THREAD_REGISTRY };
    if registry.is_null() {
        return;
    }

    unsafe { gum_barebone_unregister_thread(registry, id as GumThreadId) };
}

#[cfg(any(feature = "linux-injected", feature = "xnu-core"))]
fn announce_thread(id: u32) {
    let registry = unsafe { THREAD_REGISTRY };
    if registry.is_null() {
        return;
    }

    let mut details: GumThreadDetails = unsafe { core::mem::zeroed() };
    details.id = id as GumThreadId;

    unsafe { gum_barebone_register_thread(registry, &details) };
}

#[cfg(any(feature = "linux-injected", feature = "xnu-core"))]
static mut THREAD_REGISTRY: *mut GumThreadRegistry = ptr::null_mut();

#[cfg(any(feature = "linux-injected", feature = "xnu-core"))]
#[unsafe(no_mangle)]
pub extern "C" fn gum_barebone_enumerate_threads(func: GumFoundThreadFunc, user_data: gpointer) {
    let Some(emit) = func else {
        return;
    };

    kernel::enumerate_threads(&mut |thread| {
        let mut details: GumThreadDetails = unsafe { core::mem::zeroed() };
        details.id = thread.id as GumThreadId;

        unsafe { emit(&details, user_data) };
    });
}

#[cfg(any(feature = "linux-injected", feature = "xnu-core"))]
#[unsafe(no_mangle)]
pub extern "C" fn _gum_process_enumerate_ranges(
    prot: GumPageProtection,
    func: GumFoundRangeFunc,
    user_data: gpointer,
) {
    let Some(emit) = func else {
        return;
    };

    kernel::enumerate_ranges(&mut |base, size, protection| {
        if (protection & prot as u32) != prot as u32 {
            return;
        }

        let range = GumMemoryRange {
            base_address: base,
            size: size as gsize,
        };
        let details = GumRangeDetails {
            range: &range,
            protection: protection as GumPageProtection,
            file: ptr::null(),
        };

        unsafe { emit(&details, user_data) };
    });
}

#[cfg(any(feature = "linux-injected", feature = "xnu-core"))]
#[unsafe(no_mangle)]
pub extern "C" fn gum_memory_query_protection(
    address: gpointer,
    prot: *mut GumPageProtection,
) -> gboolean {
    let protection = kernel::protection_at(address as u64);
    if protection == 0 {
        return 0;
    }

    unsafe { *prot = protection as GumPageProtection };
    1
}

pub(crate) unsafe fn enumerate_exports_in_range(
    start_address: u64,
    end_address: u64,
    callback: &mut FoundExportCallback<'_>,
) {
    #[cfg(feature = "linux-injected")]
    if kernel::in_copy() {
        kernel::enumerate_exports_in_range(start_address, end_address, callback);
        return;
    }

    #[cfg(feature = "xnu-core")]
    if crate::xnu::in_copy() {
        crate::xnu_mapped::enumerate_exports_in_range(start_address, end_address, callback);
        return;
    }

    unsafe {
        let symbol_table = core::ptr::addr_of!(crate::SYMBOL_TABLE);
        let symbol_table = &*symbol_table;

        const N_EXT: u8 = 0x01; // External symbol flag
        const N_TYPE: u8 = 0x0e; // Type mask
        const N_SECT: u8 = 0x0e; // Defined in section

        for symbol_ref in symbol_table.iter_symbols_in_range(start_address, end_address) {
            let is_external = (symbol_ref.symbol_type() & N_EXT) != 0;
            let is_defined = (symbol_ref.symbol_type() & N_TYPE) == N_SECT;
            if !is_external || !is_defined {
                continue;
            }

            if !callback(symbol_ref.name_ptr(), symbol_ref.address()) {
                break;
            }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_load_symbols(_path: *const gchar) -> gboolean {
    0
}
