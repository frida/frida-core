
use crate::kernel;

pub fn enumerate_ranges(found: &mut dyn FnMut(u64, usize, u32)) {
    for_each_segment(&mut |base, size, protection| found(base, size, protection));
}

pub fn protection_at(address: u64) -> u32 {
    let mut answer = 0;

    for_each_segment(&mut |base, size, protection| {
        if address >= base && address < base + size as u64 {
            answer = protection;
        }
    });

    answer
}

fn for_each_segment(found: &mut dyn FnMut(u64, usize, u32)) {
    let kernel_base = kernel::get_kernel_base();
    if kernel_base == 0 {
        return;
    }

    let modules = unsafe { &*core::ptr::addr_of!(crate::MODULE_INFO) };
    for module in modules.iter() {
        segments_of(kernel_base + module.offset as u64, found);
    }
}

fn segments_of(image: u64, found: &mut dyn FnMut(u64, usize, u32)) {
    if read_u32(image) != MACH_HEADER_MAGIC {
        return;
    }

    let commands = read_u32(image + COMMAND_COUNT);
    let mut command = image + MACH_HEADER_SIZE;
    let mut slide: Option<u64> = None;

    for _ in 0..commands {
        if read_u32(command) == LC_SEGMENT_64 {
            let linked_at = read_u64(command + SEGMENT_ADDRESS);
            let size = read_u64(command + SEGMENT_SIZE);
            let protection = read_u32(command + SEGMENT_PROTECTION);

            let moved_by = *slide.get_or_insert(image.wrapping_sub(linked_at));
            if size != 0 && protection != 0 {
                found(linked_at.wrapping_add(moved_by), size as usize, protection);
            }
        }

        command += read_u32(command + COMMAND_SIZE) as u64;
    }
}

fn read_u32(at: u64) -> u32 {
    unsafe { (at as *const u32).read_unaligned() }
}

fn read_u64(at: u64) -> u64 {
    unsafe { (at as *const u64).read_unaligned() }
}

const MACH_HEADER_MAGIC: u32 = 0xfeed_facf;
const MACH_HEADER_SIZE: u64 = 32;
const COMMAND_COUNT: u64 = 16;
const COMMAND_SIZE: u64 = 4;
const LC_SEGMENT_64: u32 = 0x19;
const SEGMENT_ADDRESS: u64 = 24;
const SEGMENT_SIZE: u64 = 32;
const SEGMENT_PROTECTION: u64 = 60;
