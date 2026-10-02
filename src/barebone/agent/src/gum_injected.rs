// Gum's platform backend for an agent the host injected into a kernel that
// keeps its page tables and its executable regions to itself. Memory
// permissions and kernel-text writes go out over the hostlink, because the
// guest cannot perform them itself: the host owns the page tables and the
// physical-memory bridge.

use crate::{
    FridaCommand,
    bindings::{
        _GumPageProtection_GUM_PAGE_EXECUTE, _GumPageProtection_GUM_PAGE_READ,
        _GumPageProtection_GUM_PAGE_WRITE, _GumRwxSupport_GUM_RWX_NONE,
        GumFoundRangeFunc, GumFoundThreadFunc, GumMemoryRange,
        GumCpuContext, GumModuleRegistry, GumPageProtection, GumRangeDetails, GumRwxSupport,
        GumThreadDetails, GumThreadFlags, GumThreadFlags_GUM_THREAD_FLAGS_CPU_CONTEXT,
        GumThreadFlags_GUM_THREAD_FLAGS_STATE, GumThreadId,
        GumThreadRegistry, gum_barebone_register_thread, g_variant_get_uint64,
        g_variant_new_fixed_array, g_variant_type_free, g_variant_type_new, g_variant_unref,
        gboolean, gchar, gconstpointer, gpointer, gsize, guint, gum_mprotect, gum_query_page_size,
    },
    gum::{self, FoundExportCallback},
    host_rpc, kernel, libc,
};
#[cfg(feature = "xnu-core")]
use crate::bindings::{g_object_unref, gum_barebone_register_module};
#[cfg(feature = "linux-injected")]
use crate::bindings::gum_barebone_unregister_thread;
#[cfg(not(feature = "xnu-kext"))]
use crate::bindings::{
    g_variant_get_boolean, g_variant_new,
    gum_barebone_try_remap_writable_pages as _gum_barebone_try_remap_writable_pages,
};
use alloc::collections::{BTreeMap, BTreeSet};
#[cfg(feature = "xnu-core")]
use alloc::format;
use alloc::vec::Vec;
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

const SHADOW_HEADER: usize = 24;

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

#[cfg(feature = "linux-injected")]
#[unsafe(no_mangle)]
pub extern "C" fn gum_barebone_query_stack_size() -> crate::bindings::gsize {
    if kernel::in_copy() {
        return if crate::on_js_thread() { crate::linux::STACK_SIZE as crate::bindings::gsize } else { 0 };
    }

    crate::linux::stack_headroom() as crate::bindings::gsize
}

#[cfg(feature = "xnu-core")]
#[unsafe(no_mangle)]
pub extern "C" fn gum_barebone_query_stack_size() -> crate::bindings::gsize {
    if crate::on_js_thread() {
        crate::xnu_injection::STACK as crate::bindings::gsize
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_query_rwx_support() -> GumRwxSupport {
    #[cfg(feature = "linux-injected")]
    return _GumRwxSupport_GUM_RWX_NONE;

    #[cfg(not(feature = "linux-injected"))]
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
    #[cfg(feature = "xnu-kext")]
    if crate::xnu::the_writable_view_of(first_page as u64) != 0 {
        return remap_agent_pages(first_page, n_pages);
    }

    #[cfg(all(feature = "linux-injected", not(target_arch = "arm")))]
    if writable_in_place(first_page, n_pages) {
        return first_page;
    }

    #[cfg(not(feature = "xnu-kext"))]
    if gum::is_agent_slab(first_page as u64) {
        return remap_agent_pages(first_page, n_pages);
    }

    shadow_kernel_pages(first_page, n_pages)
}

#[cfg(feature = "xnu-kext")]
fn remap_agent_pages(first_page: gpointer, _n_pages: guint) -> gpointer {
    crate::xnu::the_writable_view_of(first_page as u64) as gpointer
}

#[cfg(all(feature = "linux-injected", not(target_arch = "arm")))]
fn writable_in_place(first_page: gpointer, n_pages: guint) -> bool {
    let size = n_pages as usize * unsafe { gum_query_page_size() } as usize;

    kernel::set_protection(first_page as u64, size, GUM_PAGE_RWX)
}

#[cfg(not(feature = "xnu-kext"))]
fn remap_agent_pages(first_page: gpointer, n_pages: guint) -> gpointer {
    let alias = remap_agent_pages_through_host(first_page, n_pages);
    if !alias.is_null() {
        aliases().insert(alias as u64, first_page as u64);
    }

    alias
}

fn aliases() -> &'static mut BTreeMap<u64, u64> {
    unsafe { core::ptr::addr_of_mut!(ALIASES).as_mut().unwrap() }
}

static mut ALIASES: BTreeMap<u64, u64> = BTreeMap::new();

#[cfg(not(feature = "xnu-kext"))]
fn remap_agent_pages_through_host(first_page: gpointer, n_pages: guint) -> gpointer {
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

#[cfg(all(feature = "linux-injected", not(target_arch = "arm")))]
const GUM_PAGE_RWX: u32 = 7;

unsafe fn what_changed(first_page: u64, shadow: *const u8, total: usize) -> Option<(usize, usize)> {
    let live = unsafe { core::slice::from_raw_parts(first_page as *const u8, total) };
    let ours = unsafe { core::slice::from_raw_parts(shadow, total) };

    let first = live.iter().zip(ours).position(|(a, b)| a != b)?;
    let last = total - live.iter().zip(ours).rev().position(|(a, b)| a != b).unwrap();

    let start = first & !(WORD_SIZE - 1);
    let end = (last + WORD_SIZE - 1) & !(WORD_SIZE - 1);

    Some((start, end - start))
}

const WORD_SIZE: usize = 4;

fn shadow_kernel_pages(first_page: gpointer, n_pages: guint) -> gpointer {
    unsafe {
        let total = n_pages as usize * gum_query_page_size() as usize;
        let buffer = kernel::alloc(SHADOW_HEADER + total);
        *(buffer.add(8) as *mut u64) = first_page as u64;
        *(buffer.add(16) as *mut u32) = n_pages;

        let body = buffer.add(SHADOW_HEADER);
        core::ptr::copy_nonoverlapping(first_page as *const u8, body, total);

        shadows().insert(body as u64);

        body as gpointer
    }
}

fn shadows() -> &'static mut BTreeSet<u64> {
    unsafe { core::ptr::addr_of_mut!(SHADOWS).as_mut().unwrap() }
}

static mut SHADOWS: BTreeSet<u64> = BTreeSet::new();

#[unsafe(no_mangle)]
pub extern "C" fn gum_memory_dispose_writable_pages(writable: gpointer, _n_pages: guint) {

    #[cfg(feature = "xnu-kext")]
    if let Some(base) = crate::xnu::the_page_behind(writable as u64) {
        let size = _n_pages as usize * unsafe { gum_query_page_size() } as usize;
        libc::__clear_cache(base as *const u8, (base + size as u64) as *const u8);
        return;
    }

    if let Some(executable) = aliases().remove(&(writable as u64)) {
        let size = _n_pages as usize * unsafe { gum_query_page_size() } as usize;
        libc::__clear_cache(executable as *const u8, (executable + size as u64) as *const u8);
        return;
    }

    if !shadows().remove(&(writable as u64)) {
        #[cfg(all(feature = "linux-injected", not(target_arch = "arm")))]
        {
            let size = _n_pages as usize * unsafe { gum_query_page_size() } as usize;
            libc::__clear_cache(writable as *const u8,
                (writable as u64 + size as u64) as *const u8);
        }

        return;
    }
    unsafe {
        let buffer = (writable as *mut u8).sub(SHADOW_HEADER);
        let first_page = *(buffer.add(8) as *const u64);
        let n_pages = *(buffer.add(16) as *const u32);
        let total = n_pages as usize * gum_query_page_size() as usize;

        if let Some((offset, len)) = what_changed(first_page, writable as *const u8, total) {
            commit_kernel_patch(first_page + offset as u64, (writable as *const u8).add(offset),
                len);
            libc::__clear_cache((first_page + offset as u64) as *const u8,
                (first_page + (offset + len) as u64) as *const u8);
        }

        kernel::free(buffer, SHADOW_HEADER + total);
    }
}

#[cfg(feature = "xnu-kext")]
unsafe fn commit_kernel_patch(address: u64, data: *const u8, len: usize) {
    crate::xnu::write_through_a_writable_alias(address, data, len);
}

#[cfg(all(feature = "linux-injected", not(target_arch = "arm")))]
unsafe fn commit_kernel_patch(address: u64, data: *const u8, len: usize) {
    if kernel::patch_text(address, data, len) {
        return;
    }

    unsafe { ask_the_host_to_patch(address, data, len) };
}

#[cfg(all(not(feature = "xnu-kext"), any(not(feature = "linux-injected"), target_arch = "arm")))]
unsafe fn commit_kernel_patch(address: u64, data: *const u8, len: usize) {
    unsafe { ask_the_host_to_patch(address, data, len) };
}

#[cfg(not(feature = "xnu-kext"))]
unsafe fn ask_the_host_to_patch(address: u64, data: *const u8, len: usize) {
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
        let mut wide = Vec::with_capacity(n_addrs as usize);
        for i in 0..n_addrs as usize {
            wide.push(*addrs.add(i) as u64);
        }

        let element_type = g_variant_type_new(c"t".as_ptr());
        let payload = g_variant_new_fixed_array(
            element_type,
            wide.as_ptr() as gconstpointer,
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

#[cfg(not(feature = "xnu-kext"))]
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

#[cfg(not(feature = "xnu-kext"))]
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
#[cfg(not(feature = "xnu-kext"))]
unsafe fn flush_tlb_range(address: u64, size: u64) {
    let page_size = unsafe { gum_query_page_size() } as u64;
    let start = address & !(page_size - 1);
    let end = (address + size + page_size - 1) & !(page_size - 1);

    unsafe { flush_pages(start, end, page_size) };
}

#[cfg(all(not(feature = "xnu-kext"), target_arch = "arm"))]
unsafe fn flush_pages(start: u64, end: u64, page_size: u64) {
    unsafe {
        core::arch::asm!("dsb ish", options(nostack, preserves_flags));
        let mut va = start;
        while va < end {
            core::arch::asm!("mcr p15, 0, {operand}, c8, c3, 3", operand = in(reg) va as u32,
                options(nostack, preserves_flags));
            va += page_size;
        }
        core::arch::asm!("dsb ish", "isb", options(nostack, preserves_flags));
    }
}

#[cfg(all(not(feature = "xnu-kext"), target_arch = "aarch64"))]
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

#[cfg(feature = "xnu-kext")]
#[unsafe(no_mangle)]
pub extern "C" fn gum_memory_allocate_near(
    spec: gconstpointer,
    size: gsize,
    alignment: gsize,
    prot: GumPageProtection,
) -> gpointer {
    if spec.is_null() {
        return gum_memory_allocate(ptr::null_mut(), size, alignment, prot);
    }

    let (wanted, reach) = unsafe {
        (
            (*(spec as *const GumAddressSpec)).near_address as u64,
            (*(spec as *const GumAddressSpec)).max_distance as u64,
        )
    };

    let within_reach = |at: gpointer| {
        !at.is_null()
            && (at as u64).abs_diff(wanted).max((at as u64 + size - 1).abs_diff(wanted)) <= reach
    };

    let close = crate::xnu::kernel_alloc_code_above(wanted.saturating_sub(reach), size as usize)
        as gpointer;
    if within_reach(close) {
        remember_slab_of(close, size);
        return close;
    }
    if !close.is_null() {
        release_pages_now(close, size);
    }

    let got = gum_memory_allocate(ptr::null_mut(), size, alignment, prot);
    if within_reach(got) {
        return got;
    }
    if !got.is_null() {
        release_pages_now(got, size);
    }

    ptr::null_mut()
}

#[cfg(feature = "xnu-kext")]
fn release_pages_now(at: gpointer, size: gsize) {
    gum::unregister_slab(at as u64);
    crate::xnu::forget_what_we_took(at as u64);
    kernel::free_code(at as *mut u8, size as usize);
}

#[cfg(feature = "xnu-kext")]
fn remember_slab_of(at: gpointer, size: gsize) {
    gum::register_slab(at as u64, size as usize);
    crate::xnu::remember_what_we_took(at as u64, size as usize, true);
}

#[cfg(feature = "xnu-kext")]
#[repr(C)]
struct GumAddressSpec {
    near_address: gpointer,
    max_distance: gsize,
}

#[cfg(feature = "xnu-kext")]
#[unsafe(no_mangle)]
pub extern "C" fn gum_memory_allocate_bookkeeping(size: gsize, _alignment: gsize) -> gpointer {
    let ptr = crate::xnu::kernel_alloc_pages(size as usize);
    if !ptr.is_null() {
        unsafe { core::ptr::write_bytes(ptr, 0, size as usize) };
    }

    ptr as gpointer
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_memory_allocate(
    address: gpointer,
    size: gsize,
    _alignment: gsize,
    prot: GumPageProtection,
) -> gpointer {
    let may_run = (prot & _GumPageProtection_GUM_PAGE_EXECUTE) != 0;

    #[cfg(feature = "xnu-kext")]
    let ptr = kernel::alloc_code(size as usize);
    #[cfg(feature = "xnu-kext")]
    let _ = address;

    #[cfg(all(feature = "xnu-core", not(feature = "xnu-kext")))]
    let ptr = if crate::xnu::in_copy() {
        crate::xnu_user_calls::code_memory_near(address as u64, size as usize)
    } else {
        kernel::alloc_code(size as usize)
    };
    #[cfg(all(not(feature = "xnu-core"), not(feature = "linux-injected")))]
    let ptr = kernel::alloc_code(size as usize);
    #[cfg(feature = "linux-injected")]
    let ptr = kernel::alloc_heap(size as usize);
    #[cfg(not(feature = "xnu-core"))]
    let _ = address;
    #[cfg(not(feature = "xnu-kext"))]
    unsafe { core::ptr::write_bytes(ptr, 0, size as usize) };

    if may_run {
        gum::register_slab(ptr as u64, size as usize);
    }

    #[cfg(not(feature = "xnu-kext"))]
    if may_run {
        unsafe { gum_mprotect(ptr as gpointer, size, prot) };
    }

    #[cfg(feature = "xnu-kext")]
    crate::xnu::remember_what_we_took(ptr as u64, size as usize, may_run);

    ptr as gpointer
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_memory_free(address: gpointer, size: gsize) -> gboolean {
    #[cfg(feature = "xnu-kext")]
    if gum::is_agent_slab(address as u64) {
        return 1;
    }

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
    #[cfg(feature = "xnu-kext")]
    crate::xnu::forget_what_we_took(address as u64);

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

    #[cfg(feature = "linux-injected")]
    {
        crate::gum_modules::publish(registry);
        return;
    }

    #[cfg(not(feature = "linux-injected"))]
    {
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
                    &format!("{}{}{}", MODULE_DIRECTORY, module_info.name, MODULE_SUFFIX)
                };
                let module_range = GumMemoryRange {
                    base_address: module_base,
                    size: module_info.size as gsize,
                };

                let module =
                    gum::gum_native_module_new(&module_path, &module_info.version, &module_range);
                gum_barebone_register_module(registry, module);
                g_object_unref(module as gpointer);

                i += 1;
            }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gum_barebone_on_registry_deactivating(_registry: *mut GumModuleRegistry) {
    #[cfg(feature = "linux-injected")]
    crate::gum_modules::unpublish();
}

#[cfg(any(feature = "linux-injected", feature = "xnu-core"))]
#[unsafe(no_mangle)]
pub extern "C" fn gum_barebone_on_thread_registry_activating(registry: *mut GumThreadRegistry) {
    unsafe { THREAD_REGISTRY = registry };

    kernel::enumerate_threads(&mut |thread| announce_thread(thread.id), false);
}

#[cfg(any(feature = "linux-injected", feature = "xnu-core"))]
#[unsafe(no_mangle)]
pub extern "C" fn gum_barebone_on_thread_registry_deactivating(_registry: *mut GumThreadRegistry) {
    unsafe { THREAD_REGISTRY = ptr::null_mut() };
}

#[cfg(feature = "linux-injected")]
pub(crate) fn thread_appeared(id: u32) {
    announce_thread(id);
}

#[cfg(feature = "linux-injected")]
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
pub extern "C" fn gum_barebone_enumerate_threads(func: GumFoundThreadFunc, user_data: gpointer,
        flags: GumThreadFlags) {
    let Some(emit) = func else {
        return;
    };

    let with_registers = (flags & GumThreadFlags_GUM_THREAD_FLAGS_CPU_CONTEXT) != 0;
    kernel::enumerate_threads(&mut |thread| {
        let mut details: GumThreadDetails = unsafe { core::mem::zeroed() };
        details.id = thread.id as GumThreadId;

        if let Some(state) = thread.state {
            details.flags |= GumThreadFlags_GUM_THREAD_FLAGS_STATE;
            details.state = state;
        }

        if let Some(cpu) = thread.cpu_state {
            details.flags |= GumThreadFlags_GUM_THREAD_FLAGS_CPU_CONTEXT;
            details.cpu_context = cpu_context_from(&cpu);
        }

        unsafe { emit(&details, user_data) };
    }, with_registers);
}

#[cfg(target_arch = "aarch64")]
fn cpu_context_from(state: &kernel::CpuState) -> GumCpuContext {
    GumCpuContext {
        pc: state.pc,
        sp: state.sp,
        nzcv: state.nzcv,
        x: state.x,
        fp: state.fp,
        lr: state.lr,
    }
}

#[cfg(target_arch = "x86_64")]
fn cpu_context_from(state: &kernel::CpuState) -> GumCpuContext {
    GumCpuContext {
        rip: state.rip,
        r15: state.r15,
        r14: state.r14,
        r13: state.r13,
        r12: state.r12,
        r11: state.r11,
        r10: state.r10,
        r9: state.r9,
        r8: state.r8,
        rdi: state.rdi,
        rsi: state.rsi,
        rbp: state.rbp,
        rsp: state.rsp,
        rbx: state.rbx,
        rdx: state.rdx,
        rcx: state.rcx,
        rax: state.rax,
        xmm: ptr::null_mut(),
    }
}

#[cfg(target_arch = "x86")]
fn cpu_context_from(state: &kernel::CpuState) -> GumCpuContext {
    GumCpuContext {
        eip: state.eip,
        edi: state.edi,
        esi: state.esi,
        ebp: state.ebp,
        esp: state.esp,
        ebx: state.ebx,
        edx: state.edx,
        ecx: state.ecx,
        eax: state.eax,
        xmm: ptr::null_mut(),
    }
}

#[cfg(target_arch = "arm")]
fn cpu_context_from(state: &kernel::CpuState) -> GumCpuContext {
    GumCpuContext {
        cpsr: state.cpsr,
        pc: state.pc,
        sp: state.sp,
        r8: state.r8,
        r9: state.r9,
        r10: state.r10,
        r11: state.r11,
        r12: state.r12,
        lr: state.lr,
        r: state.r,
        ..unsafe { core::mem::zeroed() }
    }
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

    let report = |base: u64, size: u64, protection: u32| {
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
    };

    #[cfg(feature = "linux-injected")]
    if !kernel::in_copy() {
        each_kernel_module_range(|base, size| report(base, size, KERNEL_RANGE_PROTECTION));
        return;
    }

    kernel::enumerate_ranges(&mut |base, size, protection| report(base, size as u64, protection));
}

#[cfg(feature = "linux-injected")]
const KERNEL_RANGE_PROTECTION: u32 = 1 | 2 | 4;

#[cfg(feature = "linux-injected")]
fn each_kernel_module_range(mut visit: impl FnMut(u64, u64)) {
    let kernel_base = kernel::get_kernel_base();
    let module_infos = unsafe { &*core::ptr::addr_of!(crate::MODULE_INFO) };
    for module_info in module_infos.iter() {
        visit(kernel_base + module_info.offset, module_info.size);
    }
}

#[cfg(any(feature = "linux-injected", feature = "xnu-core"))]
#[unsafe(no_mangle)]
pub extern "C" fn gum_memory_query_region(
    address: gconstpointer,
    range: *mut GumMemoryRange,
    prot: *mut GumPageProtection,
) -> gboolean {
    let Some(region) = region_at(address as u64).filter(|region| region.protection != 0) else {
        return 0;
    };

    unsafe {
        *range = GumMemoryRange {
            base_address: region.base,
            size: region.size as gsize,
        };
        *prot = region.protection as GumPageProtection;
    }
    1
}

#[cfg(any(feature = "linux-injected", feature = "xnu-core"))]
fn region_at(address: u64) -> Option<kernel::MemoryRegion> {
    #[cfg(feature = "linux-injected")]
    if !kernel::in_copy() {
        return kernel_module_region_at(address);
    }

    kernel::region_at(address)
}

#[cfg(feature = "linux-injected")]
fn kernel_module_region_at(address: u64) -> Option<kernel::MemoryRegion> {
    let mut found = None;
    each_kernel_module_range(|base, size| {
        if address >= base && address < base + size {
            found = Some(kernel::MemoryRegion {
                base,
                size,
                protection: KERNEL_RANGE_PROTECTION,
            });
        }
    });

    found
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

    #[cfg(feature = "linux-injected")]
    if crate::gum_modules::enumerate_exports_in_module(start_address, callback) {
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
