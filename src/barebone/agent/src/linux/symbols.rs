use core::mem::size_of;

use crate::bindings::gchar;
use crate::gum::FoundExportCallback;

pub fn enumerate_exports_in_range(start: u64, end: u64, callback: &mut FoundExportCallback<'_>) {
    let Some(image) = Image::mapped_at(start) else {
        return;
    };

    for index in 0..image.symbol_count {
        let symbol = unsafe { &*((image.symbols + (index * size_of::<Symbol>()) as u64) as *const Symbol) };
        if symbol.section == UNDEFINED || symbol.value == 0 {
            continue;
        }
        if symbol.binding() != GLOBAL && symbol.binding() != WEAK {
            continue;
        }

        let address = image.slide + symbol.value;
        if address < start || address >= end {
            continue;
        }

        if !callback((image.names + symbol.name as u64) as *const gchar, address) {
            break;
        }
    }
}

struct Image {
    slide: u64,
    symbols: u64,
    names: u64,
    symbol_count: usize,
}

impl Image {
    fn mapped_at(base: u64) -> Option<Image> {
        let header = unsafe { &*(base as *const Header) };
        if header.magic != MAGIC || header.class != SIXTY_FOUR_BIT {
            return None;
        }

        let slide = if header.kind == SHARED_OBJECT { base } else { 0 };
        let describing = describing_segment(base, header)?;

        let mut symbols = 0;
        let mut names = 0;
        let mut hashes = 0;
        let mut gnu_hashes = 0;
        let mut at = slide + describing.address;
        loop {
            let entry = unsafe { &*(at as *const DynamicEntry) };
            at += size_of::<DynamicEntry>() as u64;

            match entry.tag {
                DYNAMIC_END => break,
                DYNAMIC_HASHES => hashes = with_slide(entry.value, base),
                DYNAMIC_NAMES => names = with_slide(entry.value, base),
                DYNAMIC_SYMBOLS => symbols = with_slide(entry.value, base),
                DYNAMIC_GNU_HASHES => gnu_hashes = with_slide(entry.value, base),
                _ => continue,
            }
        }
        if symbols == 0 || names == 0 {
            return None;
        }

        let symbol_count = if hashes != 0 {
            unsafe { (hashes as *const u32).add(1).read() as usize }
        } else {
            symbols_behind(gnu_hashes)?
        };

        Some(Image {
            slide,
            symbols,
            names,
            symbol_count,
        })
    }
}

fn describing_segment(base: u64, header: &Header) -> Option<&'static Segment> {
    for index in 0..header.segment_count as u64 {
        let segment = unsafe {
            &*((base + header.segments_at + (index * header.segment_size as u64)) as *const Segment)
        };
        if segment.kind == DESCRIBES_THE_IMAGE {
            return Some(segment);
        }
    }

    None
}

// GNU's table says where its buckets and chains are, and the last chain says how many symbols
// the image has: the walk ends on the entry that has its lowest bit set.
fn symbols_behind(gnu_hashes: u64) -> Option<usize> {
    if gnu_hashes == 0 {
        return None;
    }

    let table = gnu_hashes as *const u32;
    let (bucket_count, first_hashed, bloom_size) = unsafe {
        (table.read() as usize, table.add(1).read() as usize, table.add(2).read() as usize)
    };

    let buckets = unsafe { table.add(4).cast::<u64>().add(bloom_size).cast::<u32>() };
    let mut last = 0;
    for index in 0..bucket_count {
        last = last.max(unsafe { buckets.add(index).read() } as usize);
    }
    if last < first_hashed {
        return Some(first_hashed);
    }

    let chains = unsafe { buckets.add(bucket_count) };
    let mut at = last - first_hashed;
    while unsafe { chains.add(at).read() } & 1 == 0 {
        at += 1;
    }

    Some(first_hashed + at + 1)
}

fn with_slide(value: u64, base: u64) -> u64 {
    if value < base { base + value } else { value }
}

#[repr(C)]
struct Header {
    magic: u32,
    class: u8,
    rest_of_identity: [u8; 11],
    kind: u16,
    machine: u16,
    version: u32,
    entry: u64,
    segments_at: u64,
    sections_at: u64,
    flags: u32,
    header_size: u16,
    segment_size: u16,
    segment_count: u16,
}

#[repr(C)]
struct Segment {
    kind: u32,
    flags: u32,
    offset: u64,
    address: u64,
    physical_address: u64,
    size_in_file: u64,
    size_in_memory: u64,
    alignment: u64,
}

#[repr(C)]
struct DynamicEntry {
    tag: u64,
    value: u64,
}

#[repr(C)]
struct Symbol {
    name: u32,
    info: u8,
    other: u8,
    section: u16,
    value: u64,
    size: u64,
}

impl Symbol {
    fn binding(&self) -> u8 {
        self.info >> 4
    }
}

const MAGIC: u32 = 0x464c_457f;
const SIXTY_FOUR_BIT: u8 = 2;
const SHARED_OBJECT: u16 = 3;
const DESCRIBES_THE_IMAGE: u32 = 2;
const DYNAMIC_END: u64 = 0;
const DYNAMIC_HASHES: u64 = 4;
const DYNAMIC_NAMES: u64 = 5;
const DYNAMIC_SYMBOLS: u64 = 6;
const DYNAMIC_GNU_HASHES: u64 = 0x6fff_fef5;
const UNDEFINED: u16 = 0;
const GLOBAL: u8 = 1;
const WEAK: u8 = 2;
