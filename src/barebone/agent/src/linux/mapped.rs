use alloc::string::String;
use alloc::vec::Vec;

use core::ffi::c_void;
use core::ptr;

use crate::bindings::{
    GumMemoryRange, GumModuleRegistry, g_object_unref, gpointer, gsize, gum_barebone_register_module,
    gum_barebone_unregister_module, gum_interceptor_begin_transaction,
    gum_interceptor_end_transaction, gum_interceptor_obtain, gum_interceptor_replace,
};
use crate::gum;

use super::user::{EXECUTABLE, READABLE, WRITABLE, contents_of};

pub fn register_what_the_copy_lives_among(registry: *mut GumModuleRegistry) {
    unsafe { REGISTRY = registry };

    for image in mapped_images() {
        announce(&image);
        unsafe { known() }.push(image);
    }
}

// The loader calls the same empty function every time it has changed what is mapped -- that is
// what a debugger watches -- so the copy asks again from there.
pub fn watch_the_loader() {
    let Some(rendezvous) = where_the_loader_says_so() else {
        return;
    };

    unsafe {
        let interceptor = gum_interceptor_obtain();
        gum_interceptor_begin_transaction(interceptor);
        gum_interceptor_replace(interceptor, rendezvous as gpointer,
            the_loader_changed_something as gpointer, &raw mut LOADER_SAYS_SO,
            ptr::null_mut());
        gum_interceptor_end_transaction(interceptor);
    }
}

unsafe extern "C" fn the_loader_changed_something() {
    let said_so: unsafe extern "C" fn() = unsafe { core::mem::transmute(LOADER_SAYS_SO) };
    unsafe { said_so() };

    look_again();
}

fn look_again() {
    let registry = unsafe { REGISTRY };
    if registry.is_null() {
        return;
    }

    let mapped = mapped_images();
    let known = unsafe { known() };

    for image in &mapped {
        if !known.iter().any(|seen| seen.base == image.base) {
            announce(image);
        }
    }
    for seen in known.iter() {
        if !mapped.iter().any(|image| image.base == seen.base) {
            unsafe { gum_barebone_unregister_module(registry, seen.base) };
        }
    }

    *known = mapped;
}

fn announce(image: &Image) {
    let range = GumMemoryRange {
        base_address: image.base,
        size: image.size as gsize,
    };

    let module = gum::gum_native_module_new(&image.path, "", &range);
    unsafe {
        gum_barebone_register_module(unsafe { REGISTRY }, module);
        g_object_unref(module as gpointer);
    }
}

fn where_the_loader_says_so() -> Option<u64> {
    let mut found = 0u64;
    for image in mapped_images() {
        let mut on_export = |name: *const crate::bindings::gchar, address: u64| {
            if unsafe { core::ffi::CStr::from_ptr(name) } == c"_dl_debug_state" {
                found = address;
            }

            found == 0
        };
        super::symbols::enumerate_exports_in_range(image.base, image.base + image.size,
            &mut on_export);
        if found != 0 {
            return Some(found);
        }
    }

    None
}

unsafe fn known() -> &'static mut Vec<Image> {
    unsafe { (&raw mut KNOWN).as_mut().unwrap() }
}

static mut KNOWN: Vec<Image> = Vec::new();
static mut REGISTRY: *mut GumModuleRegistry = ptr::null_mut();
static mut LOADER_SAYS_SO: *mut c_void = ptr::null_mut();

pub fn enumerate_ranges(found: &mut dyn FnMut(u64, u64, u32)) {
    let listed = contents_of(c"/proc/self/maps");

    for line in listed.split(|byte| *byte == b'\n') {
        let Some(mapping) = mapping_in(line) else {
            continue;
        };

        found(mapping.start, mapping.end - mapping.start, mapping.protection);
    }
}

pub fn protection_at(address: u64) -> u32 {
    let listed = contents_of(c"/proc/self/maps");

    for line in listed.split(|byte| *byte == b'\n') {
        let Some(mapping) = mapping_in(line) else {
            continue;
        };

        if address >= mapping.start && address < mapping.end {
            return mapping.protection;
        }
    }

    0
}

fn mapped_images() -> Vec<Image> {
    let listed = contents_of(c"/proc/self/maps");

    let mut images: Vec<Image> = Vec::new();
    for line in listed.split(|byte| *byte == b'\n') {
        let Some(mapping) = mapping_in(line) else {
            continue;
        };
        if mapping.path.is_empty() {
            continue;
        }

        let holds_code = mapping.protection & EXECUTABLE as u32 != 0;
        match images.last_mut() {
            Some(image) if image.path.as_bytes() == mapping.path => {
                image.size = mapping.end - image.base;
                image.holds_code |= holds_code;
            }
            _ => images.push(Image {
                path: String::from_utf8_lossy(mapping.path).into_owned(),
                base: mapping.start,
                size: mapping.end - mapping.start,
                holds_code,
            }),
        }
    }

    images.retain(|image| image.holds_code);

    images
}

fn mapping_in(line: &[u8]) -> Option<Mapping<'_>> {
    let boundary = line.iter().position(|byte| *byte == b'-')?;
    let start = number_in(&line[..boundary])?;

    let rest = &line[boundary + 1..];
    let mut fields = rest.split(|byte| *byte == b' ');
    let end = number_in(fields.next()?)?;
    let how = fields.next()?;

    Some(Mapping {
        path: line[..].iter().position(|byte| *byte == b'/').map_or(&[], |at| &line[at..]),
        start,
        end,
        protection: protection_of(how),
    })
}

fn protection_of(how: &[u8]) -> u32 {
    let mut protection = 0;
    if how[0] == b'r' {
        protection |= READABLE as u32;
    }
    if how[1] == b'w' {
        protection |= WRITABLE as u32;
    }
    if how[2] == b'x' {
        protection |= EXECUTABLE as u32;
    }

    protection
}

fn number_in(digits: &[u8]) -> Option<u64> {
    let mut value = 0u64;
    for digit in digits {
        value = (value << 4) | (digit.to_ascii_lowercase() as char).to_digit(16)? as u64;
    }

    Some(value)
}

struct Image {
    path: String,
    base: u64,
    size: u64,
    holds_code: bool,
}

struct Mapping<'a> {
    path: &'a [u8],
    start: u64,
    end: u64,
    protection: u32,
}
