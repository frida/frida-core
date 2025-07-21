use alloc::string::{String, ToString};
use crate::bindings::{g_pattern_spec_new, g_pattern_spec_free, g_pattern_spec_match_string, GPatternSpec};

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
        let index = self.binary_search_by_name(name)?;
        let kernel_base = crate::xnu::get_kernel_base();
        let symbol_offset = self.get_symbol_offset_by_name_index(index);
        let (name, addr_offset, symbol_type, section, description) = self.parse_full_symbol(symbol_offset);

        Some(DarwinSymbolDetails {
            name,
            address: kernel_base + addr_offset as u64,
            symbol_type,
            section,
            description,
        })
    }

    pub fn find_symbol_by_address(&self, address: u64) -> Option<DarwinSymbolDetails> {
        let kernel_base = crate::xnu::get_kernel_base();
        let target_offset = (address - kernel_base) as u32;
        let index = self.binary_search_by_address(target_offset)?;
        let symbol_offset = self.get_symbol_offset_by_address_index(index);
        let (name, _, symbol_type, section, description) = self.parse_full_symbol(symbol_offset);

        Some(DarwinSymbolDetails {
            name,
            address,
            symbol_type,
            section,
            description,
        })
    }

    pub fn find_symbol_name_ptr_by_address(&self, address: u64) -> *const core::ffi::c_char {
        let kernel_base = crate::xnu::get_kernel_base();
        let target_offset = (address - kernel_base) as u32;

        if let Some(index) = self.binary_search_by_address(target_offset) {
            let symbol_offset = self.get_symbol_offset_by_address_index(index);
            unsafe { (self.data.as_ptr().add(symbol_offset + 2)) as *const core::ffi::c_char }
        } else {
            core::ptr::null()
        }
    }

    pub fn find_closest_symbol_by_address(&self, address: u64) -> Option<DarwinSymbolDetails> {
        let kernel_base = crate::xnu::get_kernel_base();
        let target_offset = (address - kernel_base) as u32;
        let index = self.binary_search_closest_by_address(target_offset)?;
        let symbol_offset = self.get_symbol_offset_by_address_index(index);
        let (name, addr_offset, symbol_type, section, description) = self.parse_full_symbol(symbol_offset);

        Some(DarwinSymbolDetails {
            name,
            address: kernel_base + addr_offset as u64,
            symbol_type,
            section,
            description,
        })
    }

    pub fn find_symbols_by_name(&self, name: &str) -> alloc::vec::Vec<DarwinSymbolDetails> {
        let mut results = alloc::vec::Vec::new();

        if self.is_empty() {
            return results;
        }

        let kernel_base = crate::xnu::get_kernel_base();

        let mut left = 0;
        let mut right = self.symbol_count;
        let mut found_index = None;

        while left < right {
            let mid = left + (right - left) / 2;
            let symbol_offset = self.get_symbol_offset_by_name_index(mid);
            let symbol_name = self.parse_symbol_name(symbol_offset);

            match symbol_name.as_str().cmp(name) {
                core::cmp::Ordering::Equal => {
                    found_index = Some(mid);
                    break;
                }
                core::cmp::Ordering::Less => left = mid + 1,
                core::cmp::Ordering::Greater => right = mid,
            }
        }

        if let Some(index) = found_index {
            let mut start = index;
            let mut end = index;

            while start > 0 {
                let symbol_offset = self.get_symbol_offset_by_name_index(start - 1);
                let symbol_name = self.parse_symbol_name(symbol_offset);
                if symbol_name == name {
                    start -= 1;
                } else {
                    break;
                }
            }

            while end + 1 < self.symbol_count {
                let symbol_offset = self.get_symbol_offset_by_name_index(end + 1);
                let symbol_name = self.parse_symbol_name(symbol_offset);
                if symbol_name == name {
                    end += 1;
                } else {
                    break;
                }
            }

            for i in start..=end {
                let symbol_offset = self.get_symbol_offset_by_name_index(i);
                let (name, addr_offset, symbol_type, section, description) =
                    self.parse_full_symbol(symbol_offset);
                results.push(DarwinSymbolDetails {
                    name,
                    address: kernel_base + addr_offset as u64,
                    symbol_type,
                    section,
                    description,
                });
            }
        }

        results
    }

    pub fn find_symbols_matching_glob(&self, pattern: &str) -> alloc::vec::Vec<DarwinSymbolDetails> {
        let mut results = alloc::vec::Vec::new();

        if self.is_empty() {
            return results;
        }

        let kernel_base = crate::xnu::get_kernel_base();

        let pattern_cstr = alloc::ffi::CString::new(pattern).unwrap();
        let pspec = unsafe { g_pattern_spec_new(pattern_cstr.as_ptr()) };

        if pspec.is_null() {
            return results;
        }

        for i in 0..self.symbol_count {
            let symbol_offset = self.get_symbol_offset_by_name_index(i);

            if self.symbol_matches_pattern(symbol_offset, pspec) {
                let (name, addr_offset, symbol_type, section, description) =
                    self.parse_full_symbol(symbol_offset);
                results.push(DarwinSymbolDetails {
                    name,
                    address: kernel_base + addr_offset as u64,
                    symbol_type,
                    section,
                    description,
                });
            }
        }

        unsafe { g_pattern_spec_free(pspec) };
        results
    }

    fn symbol_matches_pattern(&self, offset: usize, pspec: *mut GPatternSpec) -> bool {
        let name_start = offset + 2;
        unsafe {
            g_pattern_spec_match_string(pspec, self.data[name_start..].as_ptr() as *const core::ffi::c_char) != 0
        }
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
        let meta_start = offset + 2 + name_len + 1;
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

        let meta_start = offset + 2 + name_len + 1;
        let symbol_offset = u32::from_le_bytes([
            self.data[meta_start], self.data[meta_start+1],
            self.data[meta_start+2], self.data[meta_start+3]
        ]);
        let symbol_type = self.data[meta_start + 4];
        let section = self.data[meta_start + 5];
        let description = u16::from_le_bytes([self.data[meta_start+6], self.data[meta_start+7]]);

        (name, symbol_offset, symbol_type, section, description)
    }

    fn binary_search_by_name(&self, name: &str) -> Option<usize> {
        if self.is_empty() {
            return None;
        }

        let mut left = 0;
        let mut right = self.symbol_count;

        while left < right {
            let mid = left + (right - left) / 2;
            let symbol_offset = self.get_symbol_offset_by_name_index(mid);
            let symbol_name = self.parse_symbol_name(symbol_offset);

            match symbol_name.as_str().cmp(name) {
                core::cmp::Ordering::Equal => return Some(mid),
                core::cmp::Ordering::Less => left = mid + 1,
                core::cmp::Ordering::Greater => right = mid,
            }
        }

        None
    }

    fn binary_search_by_address(&self, target_offset: u32) -> Option<usize> {
        if self.is_empty() {
            return None;
        }

        let mut left = 0;
        let mut right = self.symbol_count;

        while left < right {
            let mid = left + (right - left) / 2;
            let symbol_offset = self.get_symbol_offset_by_address_index(mid);
            let symbol_addr_offset = self.parse_symbol_address(symbol_offset);

            match symbol_addr_offset.cmp(&target_offset) {
                core::cmp::Ordering::Equal => return Some(mid),
                core::cmp::Ordering::Less => left = mid + 1,
                core::cmp::Ordering::Greater => right = mid,
            }
        }

        None
    }

    fn binary_search_closest_by_address(&self, target_offset: u32) -> Option<usize> {
        if self.is_empty() {
            return None;
        }

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

        best_match
    }
}
