use core::ffi::c_void;

pub fn field_offset(container: &str, field: &str) -> Option<usize> {
    let types = described_types()?;

    let mut described = types.first()?;
    loop {
        if described.kind == KIND_STRUCT && types.name_of(described.name) == container {
            return described.member(&types, field).map(|bits| bits / 8);
        }

        described = types.after(&described)?;
    }
}

pub fn struct_size(container: &str) -> Option<usize> {
    let types = described_types()?;

    let mut described = types.first()?;
    loop {
        if described.kind == KIND_STRUCT && types.name_of(described.name) == container {
            return Some(described.size as usize);
        }

        described = types.after(&described)?;
    }
}

struct DescribedTypes {
    types: &'static [u8],
    names: &'static [u8],
}

impl DescribedTypes {
    fn first(&self) -> Option<Described> {
        self.at(0)
    }

    fn after(&self, described: &Described) -> Option<Described> {
        self.at(described.body + described.body_size)
    }

    fn at(&self, offset: usize) -> Option<Described> {
        if offset + DESCRIPTION_SIZE > self.types.len() {
            return None;
        }

        let name = word_at(self.types, offset);
        let info = word_at(self.types, offset + 4);
        let size = word_at(self.types, offset + 8);

        let kind = (info >> 24) & 0x1f;
        let members = (info & 0xffff) as usize;
        let members_carry_bitfields = (info >> 31) != 0;

        Some(Described {
            name,
            kind,
            size,
            members,
            members_carry_bitfields,
            body: offset + DESCRIPTION_SIZE,
            body_size: body_size_of(kind, members),
        })
    }

    fn name_of(&self, offset: u32) -> &'static str {
        let start = offset as usize;
        let end = self.names[start..]
            .iter()
            .position(|letter| *letter == 0)
            .map(|length| start + length)
            .unwrap_or(self.names.len());

        core::str::from_utf8(&self.names[start..end]).unwrap_or("")
    }
}

struct Described {
    name: u32,
    kind: u32,
    size: u32,
    members: usize,
    members_carry_bitfields: bool,
    body: usize,
    body_size: usize,
}

impl Described {
    fn member(&self, types: &DescribedTypes, field: &str) -> Option<usize> {
        for index in 0..self.members {
            let member = self.body + (index * MEMBER_SIZE);
            if types.name_of(word_at(types.types, member)) != field {
                continue;
            }

            let placement = word_at(types.types, member + 8);
            let bits = if self.members_carry_bitfields {
                placement & 0x00ff_ffff
            } else {
                placement
            };

            return Some(bits as usize);
        }

        None
    }
}

fn described_types() -> Option<DescribedTypes> {
    let start = unsafe { ___start_BTF } as usize;
    let stop = unsafe { ___stop_BTF } as usize;
    if start == 0 || stop <= start {
        return None;
    }

    let described = unsafe { core::slice::from_raw_parts(start as *const u8, stop - start) };
    if u16::from_ne_bytes([described[0], described[1]]) != DESCRIPTION_MAGIC {
        return None;
    }

    let header_size = word_at(described, 4) as usize;
    let types = header_size + word_at(described, 8) as usize;
    let types_size = word_at(described, 12) as usize;
    let names = header_size + word_at(described, 16) as usize;
    let names_size = word_at(described, 20) as usize;
    if names + names_size > described.len() {
        return None;
    }

    Some(DescribedTypes {
        types: &described[types..types + types_size],
        names: &described[names..names + names_size],
    })
}

fn body_size_of(kind: u32, members: usize) -> usize {
    match kind {
        KIND_INT | KIND_VARIABLE | KIND_TAG => 4,
        KIND_ARRAY => 12,
        KIND_STRUCT | KIND_UNION => members * MEMBER_SIZE,
        KIND_ENUM | KIND_SIGNATURE => members * 8,
        KIND_SECTION | KIND_WIDE_ENUM => members * 12,
        _ => 0,
    }
}

fn word_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

const DESCRIPTION_MAGIC: u16 = 0xeb9f;
const DESCRIPTION_SIZE: usize = 12;
const MEMBER_SIZE: usize = 12;

const KIND_INT: u32 = 1;
const KIND_ARRAY: u32 = 3;
const KIND_STRUCT: u32 = 4;
const KIND_UNION: u32 = 5;
const KIND_ENUM: u32 = 6;
const KIND_SIGNATURE: u32 = 13;
const KIND_VARIABLE: u32 = 14;
const KIND_SECTION: u32 = 15;
const KIND_TAG: u32 = 17;
const KIND_WIDE_ENUM: u32 = 19;

unsafe extern "C" {
    static ___start_BTF: *const c_void;
    static ___stop_BTF: *const c_void;
}
