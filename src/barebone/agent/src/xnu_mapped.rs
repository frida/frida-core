
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::bindings::{GumMemoryRange, GumModuleRegistry, g_object_unref, gpointer, gsize};
use crate::gum;

pub fn register_what_the_copy_lives_among(registry: *mut GumModuleRegistry) {
    for image in what_is_loaded() {
        let range = GumMemoryRange { base_address: image.base, size: image.size as gsize };
        let module = gum::gum_native_module_new(&image.path, "", &range);
        unsafe {
            crate::bindings::gum_barebone_register_module(registry, module);
            g_object_unref(module as gpointer);
        }
    }
}

pub fn enumerate_exports_in_range(from: u64, to: u64,
    found: &mut crate::gum::FoundExportCallback<'_>)
{
    let _ = to;
    let Some(image) = what_is_loaded().into_iter().find(|image| image.base == from) else {
        return;
    };

    crate::xnu_libsystem::each_export(image.base, &mut |name, address| {
        let said = alloc::ffi::CString::new(name).unwrap();
        found(said.as_ptr(), address);
    });
}

pub fn export_named(wanted: &str) -> u64 {
    let Some(ask_the_loader) = crate::xnu_libsystem::function_named(b"/libdyld.dylib", b"_dlsym")
    else {
        return 0;
    };

    type AskTheLoader = unsafe extern "C" fn(*const core::ffi::c_void, *const u8) -> u64;
    let ask_the_loader: AskTheLoader = unsafe { core::mem::transmute(ask_the_loader) };

    let Ok(asked) = alloc::ffi::CString::new(wanted) else {
        return 0;
    };

    let signed = unsafe { ask_the_loader(WHEREVER_IT_IS, asked.as_ptr() as *const u8) };

    unsafe { crate::pac::ptrauth_strip_data(signed as *const u8) as u64 }
}

const WHEREVER_IT_IS: *const core::ffi::c_void = -2isize as *const core::ffi::c_void;

struct Image {
    base: u64,
    size: u64,
    path: String,
}

fn what_is_loaded() -> Vec<Image> {
    let mut found = Vec::new();
    let Some(list) = where_the_loader_keeps_its_list() else {
        return found;
    };

    let images = read_word(list + HOW_MANY_IMAGES) as usize;
    let at = read_long(list + WHERE_THE_IMAGES_ARE);
    for step in 0..images.min(MOST_IMAGES) {
        let each = at + (step * AN_IMAGE) as u64;
        let base = read_long(each);
        let path = read_long(each + WHAT_IT_CAME_FROM);
        if base == 0 || path == 0 {
            continue;
        }

        found.push(Image { base, size: how_much_of_it_there_is(base), path: text_at(path) });
    }

    found
}

fn where_the_loader_keeps_its_list() -> Option<u64> {
    let asking = crate::xnu_libsystem::asking_about_threads()?;
    let about: unsafe extern "C" fn(u32, u32, *mut u32, *mut u32) -> i32 =
        unsafe { core::mem::transmute(crate::xnu_libsystem::function_named(
            b"/libsystem_kernel.dylib", b"_task_info")?) };

    let task = unsafe { (asking.this_task as *const u32).read_volatile() };
    let mut said = [0u32; ABOUT_THE_LOADER_WORDS];
    let mut room = said.len() as u32;
    let told = unsafe { about(task, ABOUT_THE_LOADER, said.as_mut_ptr(), &mut room) };
    if told != 0 {
        return None;
    }

    let list = (said[0] as u64) | ((said[1] as u64) << 32);

    (list != 0).then_some(list)
}

fn how_much_of_it_there_is(image: u64) -> u64 {
    let commands = read_word(image + HOW_MANY_COMMANDS);
    let mut at = image + PAST_THE_HEADER;

    for _ in 0..commands {
        let kind = read_word(at);
        let length = read_word(at + 4) as u64;
        if kind == A_SEGMENT && name_is(at + 8, b"__TEXT") {
            return read_long(at + HOW_BIG_A_SEGMENT_IS);
        }
        at += length;
    }

    0
}

fn name_is(at: u64, wanted: &[u8]) -> bool {
    for (step, byte) in wanted.iter().enumerate() {
        if unsafe { ((at as *const u8).add(step)).read_volatile() } != *byte {
            return false;
        }
    }

    let past = unsafe { ((at as *const u8).add(wanted.len())).read_volatile() };

    past == 0
}

fn text_at(at: u64) -> String {
    let mut said = Vec::new();
    for step in 0..LONGEST_NAME {
        let byte = unsafe { ((at as *const u8).add(step)).read_volatile() };
        if byte == 0 {
            break;
        }
        said.push(byte);
    }

    core::str::from_utf8(&said).unwrap_or("?").to_string()
}

fn read_word(at: u64) -> u32 {
    unsafe { (at as *const u32).read_volatile() }
}

fn read_long(at: u64) -> u64 {
    unsafe { (at as *const u64).read_volatile() }
}

const ABOUT_THE_LOADER: u32 = 17;
const ABOUT_THE_LOADER_WORDS: usize = 8;
const HOW_MANY_IMAGES: u64 = 4;
const WHERE_THE_IMAGES_ARE: u64 = 8;
const AN_IMAGE: usize = 24;
const WHAT_IT_CAME_FROM: u64 = 8;
const MOST_IMAGES: usize = 4096;

const HOW_MANY_COMMANDS: u64 = 16;
const PAST_THE_HEADER: u64 = 32;
const A_SEGMENT: u32 = 0x19;
const WHERE_A_SEGMENT_GOES: u64 = 24;
const HOW_BIG_A_SEGMENT_IS: u64 = 32;
const LONGEST_NAME: usize = 1024;
