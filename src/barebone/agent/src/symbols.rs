use alloc::string::{String, ToString};

#[derive(Debug, Clone)]
pub struct DarwinSymbolDetails {
    pub name: String,
    pub address: u64,
    pub symbol_type: u8,
    pub section: u8,
    pub description: u16,
}

pub struct SymbolTable {
    data: &'static [u8],
    symbol_count: usize,
}

impl SymbolTable {
    pub const fn empty() -> Self {
        Self {
            data: &[],
            symbol_count: 0,
        }
    }

    pub fn new(data: &'static [u8]) -> Self {
        if data.len() < 4 {
            return Self::empty();
        }
        let symbol_count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        Self { data, symbol_count }
    }

    pub fn is_empty(&self) -> bool {
        self.symbol_count == 0
    }

    pub fn symbol_count(&self) -> usize {
        self.symbol_count
    }

    pub fn find_symbol_by_name(&self, name: &str) -> Option<DarwinSymbolDetails> {
        if self.is_empty() {
            return None;
        }

        let kernel_base = crate::xnu::get_kernel_base();

        let mut left = 0;
        let mut right = self.symbol_count;

        while left < right {
            let mid = left + (right - left) / 2;
            let symbol_offset = self.get_symbol_offset_by_name_index(mid);
            let symbol_name = self.parse_symbol_name(symbol_offset);

            match symbol_name.as_str().cmp(name) {
                core::cmp::Ordering::Equal => {
                    let (name, addr_offset, symbol_type, section, description) =
                        self.parse_full_symbol(symbol_offset);
                    return Some(DarwinSymbolDetails {
                        name,
                        address: kernel_base + addr_offset as u64,
                        symbol_type,
                        section,
                        description,
                    });
                }
                core::cmp::Ordering::Less => left = mid + 1,
                core::cmp::Ordering::Greater => right = mid,
            }
        }

        None
    }

    pub fn find_symbol_by_address(&self, address: u64) -> Option<DarwinSymbolDetails> {
        if self.is_empty() {
            return None;
        }

        let kernel_base = crate::xnu::get_kernel_base();
        let target_offset = (address - kernel_base) as u32;

        let mut left = 0;
        let mut right = self.symbol_count;

        while left < right {
            let mid = left + (right - left) / 2;
            let symbol_offset = self.get_symbol_offset_by_address_index(mid);
            let symbol_addr_offset = self.parse_symbol_address(symbol_offset);

            match symbol_addr_offset.cmp(&target_offset) {
                core::cmp::Ordering::Equal => {
                    let (name, _, symbol_type, section, description) =
                        self.parse_full_symbol(symbol_offset);
                    return Some(DarwinSymbolDetails {
                        name,
                        address,
                        symbol_type,
                        section,
                        description,
                    });
                }
                core::cmp::Ordering::Less => left = mid + 1,
                core::cmp::Ordering::Greater => right = mid,
            }
        }

        None
    }

    pub fn find_closest_symbol_by_address(&self, address: u64) -> Option<DarwinSymbolDetails> {
        if self.is_empty() {
            return None;
        }

        let kernel_base = crate::xnu::get_kernel_base();
        let target_offset = (address - kernel_base) as u32;

        let mut left = 0;
        let mut right = self.symbol_count;
        let mut best_match: Option<usize> = None;

        while left < right {
            let mid = left + (right - left) / 2;
            let symbol_offset = self.get_symbol_offset_by_address_index(mid);
            let symbol_addr_offset = self.parse_symbol_address(symbol_offset);

            if symbol_addr_offset <= target_offset {
                best_match = Some(mid);
                left = mid + 1;
            } else {
                right = mid;
            }
        }

        if let Some(index) = best_match {
            let symbol_offset = self.get_symbol_offset_by_address_index(index);
            let (name, addr_offset, symbol_type, section, description) =
                self.parse_full_symbol(symbol_offset);
            return Some(DarwinSymbolDetails {
                name,
                address: kernel_base + addr_offset as u64,
                symbol_type,
                section,
                description,
            });
        }

        None
    }

    fn name_index_start(&self) -> usize {
        4
    }

    fn address_index_start(&self) -> usize {
        4 + self.symbol_count * 4
    }

    fn get_symbol_offset_by_name_index(&self, index: usize) -> usize {
        let offset = self.name_index_start() + index * 4;
        u32::from_le_bytes([
            self.data[offset], self.data[offset+1],
            self.data[offset+2], self.data[offset+3]
        ]) as usize
    }

    fn get_symbol_offset_by_address_index(&self, index: usize) -> usize {
        let offset = self.address_index_start() + index * 4;
        u32::from_le_bytes([
            self.data[offset], self.data[offset+1],
            self.data[offset+2], self.data[offset+3]
        ]) as usize
    }

    fn parse_symbol_name(&self, offset: usize) -> String {
        let name_len = u16::from_le_bytes([self.data[offset], self.data[offset+1]]) as usize;
        unsafe {
            core::str::from_utf8_unchecked(&self.data[offset+2..offset+2+name_len]).to_string()
        }
    }

    fn parse_symbol_address(&self, offset: usize) -> u32 {
        let name_len = u16::from_le_bytes([self.data[offset], self.data[offset+1]]) as usize;
        let meta_start = offset + 2 + name_len;
        u32::from_le_bytes([
            self.data[meta_start], self.data[meta_start+1],
            self.data[meta_start+2], self.data[meta_start+3]
        ])
    }

    fn parse_full_symbol(&self, offset: usize) -> (String, u32, u8, u8, u16) {
        let name_len = u16::from_le_bytes([self.data[offset], self.data[offset+1]]) as usize;
        let name = unsafe {
            core::str::from_utf8_unchecked(&self.data[offset+2..offset+2+name_len]).to_string()
        };

        let meta_start = offset + 2 + name_len;
        let symbol_offset = u32::from_le_bytes([
            self.data[meta_start], self.data[meta_start+1],
            self.data[meta_start+2], self.data[meta_start+3]
        ]);
        let symbol_type = self.data[meta_start + 4];
        let section = self.data[meta_start + 5];
        let description = u16::from_le_bytes([self.data[meta_start+6], self.data[meta_start+7]]);

        (name, symbol_offset, symbol_type, section, description)
    }
}
