
use crate::kernel::{self, MemoryRegion};

pub fn region_at(address: u64) -> Option<MemoryRegion> {
    kernel::noted_mappings()
        .iter()
        .find(|(base, size, _)| address >= *base && address < *base + *size as u64)
        .map(|&(base, size, protection)| MemoryRegion {
            base,
            size: size as u64,
            protection,
        })
}

pub fn enumerate_ranges(found: &mut dyn FnMut(u64, usize, u32)) {
    for (address, size, protection) in kernel::noted_mappings() {
        found(*address, *size, *protection);
    }
}
