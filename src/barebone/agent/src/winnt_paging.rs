// Windows maps the page tables into themselves. Thus the entry for a page is at an address
// that you calculate from the page, and no kernel export is necessary. The two word sizes
// differ only in the address of the self-map and the number of levels.

pub fn protect(address: u64, size: usize, gum_prot: u32) -> bool {
    let first_page = (address / PAGE_SIZE as u64) as usize;
    let pages = (size + (address as usize & (PAGE_SIZE - 1))).div_ceil(PAGE_SIZE);

    for page in first_page..first_page + pages {
        let address = page * PAGE_SIZE;
        if !maps_small_page(address) {
            continue;
        }

        reprotect_page(address, gum_prot);
        invalidate_page(address);
    }

    true
}

// Read the page tables and join adjacent pages that have the same permissions. Report only
// the kernel half of the address space, because the other half belongs to the process that
// is current.
pub fn enumerate_ranges(found: &mut dyn FnMut(u64, u64, u32)) {
    let mut ranges = Ranges {
        found,
        base: 0,
        size: 0,
        protection: 0,
    };

    walk_kernel_space(&mut ranges);

    ranges.flush();
}

struct Ranges<'f> {
    found: &'f mut dyn FnMut(u64, u64, u32),
    base: usize,
    size: usize,
    protection: u32,
}

impl Ranges<'_> {
    fn add(&mut self, address: usize, size: usize, protection: u32) {
        if protection != self.protection || self.base.wrapping_add(self.size) != address {
            self.flush();
            self.base = address;
            self.protection = protection;
        }
        self.size += size;
    }

    fn flush(&mut self) {
        if self.protection != 0 {
            (self.found)(self.base as u64, self.size as u64, self.protection);
        }
        self.size = 0;
        self.protection = 0;
    }
}

#[cfg(target_arch = "x86")]
mod arch {
    use super::*;

    // A 32-bit kernel can use PAE. The two forms differ in the width of an entry, in the address
    // of the directory, and in the availability of the non-executable bit.
    pub fn protection_at(address: usize) -> u32 {
        unsafe {
            if pae_enabled() {
                let pde = ((PAE_PDE_BASE + (address >> 21) * 8) as *const u64).read_volatile();
                if (pde & PAGE_PRESENT as u64) == 0 {
                    return 0;
                }
                if (pde & PAGE_LARGE as u64) != 0 {
                    return protection_of(pde, PAGE_NO_EXECUTE);
                }
                let pte = ((PTE_BASE + (address >> 12) * 8) as *const u64).read_volatile();
                if (pte & PAGE_PRESENT as u64) == 0 {
                    return 0;
                }
                protection_of(pte, PAGE_NO_EXECUTE)
            } else {
                let pde = ((PDE_BASE + (address >> 22) * 4) as *const u32).read_volatile();
                if (pde & PAGE_PRESENT) == 0 {
                    return 0;
                }
                if (pde & PAGE_LARGE) != 0 {
                    return protection_of(pde as u64, 0);
                }
                let pte = ((PTE_BASE + (address >> 12) * 4) as *const u32).read_volatile();
                if (pte & PAGE_PRESENT) == 0 {
                    return 0;
                }
                protection_of(pte as u64, 0)
            }
        }
    }

    // Two gigabytes contain sufficiently few pages to examine each one.
    pub fn walk_kernel_space(ranges: &mut Ranges) {
        let mut address = KERNEL_SPACE_START;
        while address != 0 {
            let protection = protection_at(address);
            if protection != 0 {
                ranges.add(address, PAGE_SIZE, protection);
            }
            address = address.wrapping_add(PAGE_SIZE);
        }
    }

    pub fn reprotect_page(address: usize, gum_prot: u32) {
        unsafe {
            if pae_enabled() {
                let entry = (PTE_BASE + (address >> 12) * 8) as *mut u64;
                let value = apply_protection(entry.read_volatile(), gum_prot as u64,
                    PAGE_WRITEABLE as u64, PAGE_NO_EXECUTE);
                entry.write_volatile(value);
            } else {
                let entry = (PTE_BASE + (address >> 12) * 4) as *mut u32;
                let value = apply_protection(entry.read_volatile() as u64, gum_prot as u64,
                    PAGE_WRITEABLE as u64, 0);
                entry.write_volatile(value as u32);
            }
        }
    }

    // The kernel maps its pool with large pages, which have no page table. Thus the self-map has
    // no entry to change. Such a mapping is already writable and executable.
    pub fn maps_small_page(address: usize) -> bool {
        unsafe {
            if pae_enabled() {
                let pde = ((PAE_PDE_BASE + (address >> 21) * 8) as *const u64).read_volatile();
                (pde & PAGE_PRESENT as u64) != 0 && (pde & PAGE_LARGE as u64) == 0
            } else {
                let pde = ((PDE_BASE + (address >> 22) * 4) as *const u32).read_volatile();
                (pde & PAGE_PRESENT) != 0 && (pde & PAGE_LARGE) == 0
            }
        }
    }

    fn pae_enabled() -> bool {
        let cr4: u32;
        unsafe {
            core::arch::asm!("mov {0:e}, cr4", out(reg) cr4,
                options(nomem, nostack, preserves_flags));
        }
        (cr4 & CR4_PAE) != 0
    }

    const KERNEL_SPACE_START: usize = 0x8000_0000;
    const PTE_BASE: usize = 0xc000_0000;
    const PDE_BASE: usize = 0xc030_0000;
    const PAE_PDE_BASE: usize = 0xc060_0000;
    const CR4_PAE: u32 = 1 << 5;
}

#[cfg(target_arch = "x86_64")]
mod arch {
    use super::*;

    pub fn protection_at(address: usize) -> u32 {
        for level in TOP_LEVEL..TABLE_LEVEL {
            let entry = entry_at(level, address);
            if (entry & PAGE_PRESENT as u64) == 0 {
                return 0;
            }
            if (entry & PAGE_LARGE as u64) != 0 {
                return protection_of(entry, PAGE_NO_EXECUTE);
            }
        }

        let entry = entry_at(TABLE_LEVEL, address);
        if (entry & PAGE_PRESENT as u64) == 0 {
            return 0;
        }

        protection_of(entry, PAGE_NO_EXECUTE)
    }

    // Half of a 48-bit space contains too many pages to examine each one. Thus the walk goes down
    // the levels, and an absent table costs nothing.
    pub fn walk_kernel_space(ranges: &mut Ranges) {
        for index in ENTRIES_PER_TABLE / 2..ENTRIES_PER_TABLE {
            descend(sign_extend(index << LEVEL_SHIFTS[TOP_LEVEL]), TOP_LEVEL, ranges);
        }
    }

    fn descend(address: usize, level: usize, ranges: &mut Ranges) {
        let entry = entry_at(level, address);
        if (entry & PAGE_PRESENT as u64) == 0 {
            return;
        }

        let span = 1usize << LEVEL_SHIFTS[level];
        if level == TABLE_LEVEL || (entry & PAGE_LARGE as u64) != 0 {
            ranges.add(address, span, protection_of(entry, PAGE_NO_EXECUTE));
            return;
        }

        let child_span = span / ENTRIES_PER_TABLE;
        for index in 0..ENTRIES_PER_TABLE {
            descend(address.wrapping_add(index * child_span), level + 1, ranges);
        }
    }

    pub fn reprotect_page(address: usize, gum_prot: u32) {
        let entry = entry_pointer(TABLE_LEVEL, address);
        unsafe {
            let value = apply_protection(entry.read_volatile(), gum_prot as u64,
                PAGE_WRITEABLE as u64, PAGE_NO_EXECUTE);
            entry.write_volatile(value);
        }
    }

    // The kernel maps its pool with large pages, which have no page table. Thus the self-map has
    // no entry to change. Such a mapping is already writable and executable.
    pub fn maps_small_page(address: usize) -> bool {
        for level in TOP_LEVEL..TABLE_LEVEL {
            let entry = entry_at(level, address);
            if (entry & PAGE_PRESENT as u64) == 0 || (entry & PAGE_LARGE as u64) != 0 {
                return false;
            }
        }

        true
    }

    fn entry_at(level: usize, address: usize) -> u64 {
        unsafe { entry_pointer(level, address).read_volatile() }
    }

    fn entry_pointer(level: usize, address: usize) -> *mut u64 {
        let index = (address >> LEVEL_SHIFTS[level]) & LEVEL_INDEX_MASKS[level];
        (LEVEL_BASES[level] + index * 8) as *mut u64
    }

    fn sign_extend(address: usize) -> usize {
        (((address << CANONICAL_SPARE_BITS) as isize) >> CANONICAL_SPARE_BITS) as usize
    }

    const TOP_LEVEL: usize = 0;
    const TABLE_LEVEL: usize = 3;
    const ENTRIES_PER_TABLE: usize = 512;
    const CANONICAL_SPARE_BITS: usize = 16;

    const LEVEL_SHIFTS: [usize; 4] = [39, 30, 21, 12];
    const LEVEL_INDEX_MASKS: [usize; 4] = [0x1ff, 0x3_ffff, 0x7ff_ffff, 0xf_ffff_ffff];
    const LEVEL_BASES: [usize; 4] = [
        0xffff_f6fb_7dbe_d000,
        0xffff_f6fb_7da0_0000,
        0xffff_f6fb_4000_0000,
        0xffff_f680_0000_0000,
    ];
}

pub use arch::protection_at;

use arch::{maps_small_page, reprotect_page, walk_kernel_space};

fn protection_of(entry: u64, no_execute: u64) -> u32 {
    let mut prot = GUM_PAGE_READ;
    if (entry & PAGE_WRITEABLE as u64) != 0 {
        prot |= GUM_PAGE_WRITE;
    }
    if no_execute == 0 || (entry & no_execute) == 0 {
        prot |= GUM_PAGE_EXECUTE;
    }
    prot
}

fn apply_protection(entry: u64, gum_prot: u64, writeable: u64, no_execute: u64) -> u64 {
    let mut value = entry;

    if (gum_prot & GUM_PAGE_WRITE as u64) != 0 {
        value |= writeable;
    } else {
        value &= !writeable;
    }

    if no_execute != 0 {
        if (gum_prot & GUM_PAGE_EXECUTE as u64) != 0 {
            value &= !no_execute;
        } else {
            value |= no_execute;
        }
    }

    value
}

fn invalidate_page(address: usize) {
    unsafe {
        core::arch::asm!("invlpg [{0}]", in(reg) address, options(nostack, preserves_flags));
    }
}

const PAGE_SIZE: usize = 4096;
const PAGE_PRESENT: u32 = 0x1;
const PAGE_WRITEABLE: u32 = 0x2;
const PAGE_LARGE: u32 = 0x80;
const PAGE_NO_EXECUTE: u64 = 1 << 63;

pub(crate) const GUM_PAGE_READ: u32 = 0x1;
pub(crate) const GUM_PAGE_WRITE: u32 = 0x2;
pub(crate) const GUM_PAGE_EXECUTE: u32 = 0x4;
