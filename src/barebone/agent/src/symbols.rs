use crate::bindings::{
    GPatternSpec, g_pattern_spec_free, g_pattern_spec_match_string, g_pattern_spec_new,
};
use crate::xnu::get_kernel_base;
use alloc::borrow::ToOwned;
use alloc::ffi::CString;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::ffi::{CStr, c_char};
use core::mem::size_of;
use core::ptr;

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
        let symbol_count = unsafe { *(data.as_ptr() as *const u32) as usize };
        Self { data, symbol_count }
    }

    pub fn is_empty(&self) -> bool {
        self.symbol_count == 0
    }

    pub fn symbol_count(&self) -> usize {
        self.symbol_count
    }

    pub fn find_symbol_by_name(&self, name: &str) -> Option<DarwinSymbolDetails> {
        let (_, entry) = self.binary_search_by_name(name)?;
        let symbol_name = entry.name(self);

        Some(DarwinSymbolDetails {
            name: symbol_name.to_owned(),
            address: get_kernel_base() + entry.address_offset as u64,
            symbol_type: entry.symbol_type,
            section: entry.section,
            description: entry.description,
        })
    }

    pub fn find_symbols_by_name(&self, name: &str) -> Vec<DarwinSymbolDetails> {
        let mut results = Vec::new();

        let (found_index, _) = match self.binary_search_by_name(name) {
            Some(result) => result,
            None => return results,
        };

        let mut start = found_index;
        let mut end = found_index;

        while start > 0 {
            let entry = self.get_symbol_entry_by_name_index(start - 1);
            let symbol_name = entry.name(self);
            if symbol_name == name {
                start -= 1;
            } else {
                break;
            }
        }

        while end + 1 < self.symbol_count {
            let entry = self.get_symbol_entry_by_name_index(end + 1);
            let symbol_name = entry.name(self);
            if symbol_name == name {
                end += 1;
            } else {
                break;
            }
        }

        let kernel_base = get_kernel_base();

        for i in start..=end {
            let entry = self.get_symbol_entry_by_name_index(i);
            let symbol_name = entry.name(self);
            results.push(DarwinSymbolDetails {
                name: symbol_name.to_owned(),
                address: kernel_base + entry.address_offset as u64,
                symbol_type: entry.symbol_type,
                section: entry.section,
                description: entry.description,
            });
        }

        results
    }

    pub fn find_symbol_by_address(&self, address: u64) -> Option<DarwinSymbolDetails> {
        let target_offset = (address - get_kernel_base()) as u32;
        let (_, entry) = self.binary_search_by_address(target_offset)?;
        let symbol_name = entry.name(self);

        Some(DarwinSymbolDetails {
            name: symbol_name.to_owned(),
            address,
            symbol_type: entry.symbol_type,
            section: entry.section,
            description: entry.description,
        })
    }

    pub fn find_symbol_name_ptr_by_address(&self, address: u64) -> *const c_char {
        let target_offset = (address - get_kernel_base()) as u32;
        if let Some((_, entry)) = self.binary_search_by_address(target_offset) {
            entry.name_ptr(self)
        } else {
            ptr::null()
        }
    }

    pub fn find_closest_symbol_by_address(&self, address: u64) -> Option<DarwinSymbolDetails> {
        let kernel_base = get_kernel_base();
        let target_offset = (address - kernel_base) as u32;
        let (_, entry) = self.binary_search_closest_by_address(target_offset)?;
        let symbol_name = entry.name(self);

        Some(DarwinSymbolDetails {
            name: symbol_name.to_owned(),
            address: kernel_base + entry.address_offset as u64,
            symbol_type: entry.symbol_type,
            section: entry.section,
            description: entry.description,
        })
    }

    pub fn find_symbols_matching_glob(&self, pattern: &str) -> Vec<DarwinSymbolDetails> {
        let mut results = Vec::new();

        if self.is_empty() {
            return results;
        }

        let pattern_cstr = CString::new(pattern).unwrap();
        let pspec = unsafe { g_pattern_spec_new(pattern_cstr.as_ptr()) };

        let kernel_base = get_kernel_base();

        for i in 0..self.symbol_count {
            let entry = self.get_symbol_entry_by_name_index(i);

            if self.symbol_matches_pattern(entry, pspec) {
                let symbol_name = entry.name(self);
                results.push(DarwinSymbolDetails {
                    name: symbol_name.to_owned(),
                    address: kernel_base + entry.address_offset as u64,
                    symbol_type: entry.symbol_type,
                    section: entry.section,
                    description: entry.description,
                });
            }
        }

        unsafe { g_pattern_spec_free(pspec) };

        results
    }

    fn symbol_matches_pattern(&self, entry: &SymbolEntry, pspec: *mut GPatternSpec) -> bool {
        unsafe { g_pattern_spec_match_string(pspec, entry.name_ptr(self)) != 0 }
    }

    fn get_symbol_entry_by_name_index(&self, index: usize) -> &SymbolEntry {
        let offset = self.name_index_start() + index * 4;
        let symbol_offset = unsafe { *(self.data.as_ptr().add(offset) as *const u32) as usize };
        self.symbol_entry_at(symbol_offset)
    }

    fn get_symbol_entry_by_address_index(&self, index: usize) -> &SymbolEntry {
        let offset = self.address_index_start() + index * 4;
        let symbol_offset = unsafe { *(self.data.as_ptr().add(offset) as *const u32) as usize };
        self.symbol_entry_at(symbol_offset)
    }

    fn symbol_entry_at(&self, offset: usize) -> &SymbolEntry {
        unsafe { &*(self.data.as_ptr().add(offset) as *const SymbolEntry) }
    }

    fn name_index_start(&self) -> usize {
        4
    }

    fn address_index_start(&self) -> usize {
        4 + self.symbol_count * 4
    }

    fn binary_search_by_name(&self, name: &str) -> Option<(usize, &SymbolEntry)> {
        self.binary_search(
            |table, mid| table.get_symbol_entry_by_name_index(mid),
            |entry| entry.name(self).cmp(name),
            false,
        )
    }

    fn binary_search_by_address(&self, target_offset: u32) -> Option<(usize, &SymbolEntry)> {
        self.binary_search(
            |table, mid| table.get_symbol_entry_by_address_index(mid),
            |entry| entry.address_offset.cmp(&target_offset),
            false,
        )
    }

    fn binary_search_closest_by_address(
        &self,
        target_offset: u32,
    ) -> Option<(usize, &SymbolEntry)> {
        self.binary_search(
            |table, mid| table.get_symbol_entry_by_address_index(mid),
            |entry| entry.address_offset.cmp(&target_offset),
            true,
        )
    }

    fn binary_search<F, C>(
        &self,
        get_entry_fn: F,
        compare_fn: C,
        find_closest: bool,
    ) -> Option<(usize, &SymbolEntry)>
    where
        F: Fn(&Self, usize) -> &SymbolEntry,
        C: Fn(&SymbolEntry) -> Ordering,
    {
        if self.is_empty() {
            return None;
        }

        let mut left = 0;
        let mut right = self.symbol_count;
        let mut best_match: Option<(usize, &SymbolEntry)> = None;

        while left < right {
            let mid = left + (right - left) / 2;
            let entry = get_entry_fn(self, mid);

            match compare_fn(entry) {
                Ordering::Equal => return Some((mid, entry)),
                Ordering::Less => {
                    if find_closest {
                        best_match = Some((mid, entry));
                    }
                    left = mid + 1;
                }
                Ordering::Greater => right = mid,
            }
        }

        best_match
    }

    pub fn iter_symbols(&self) -> SymbolIterator {
        SymbolIterator {
            symbol_table: self,
            index: 0,
        }
    }
}

#[repr(C)]
struct SymbolEntry {
    address_offset: u32,
    symbol_type: u8,
    section: u8,
    description: u16,
}

impl SymbolEntry {
    fn name<'a>(&self, symbol_table: &'a SymbolTable) -> &'a str {
        unsafe {
            CStr::from_ptr(self.name_ptr(symbol_table))
                .to_str()
                .unwrap()
        }
    }

    fn name_ptr(&self, symbol_table: &SymbolTable) -> *const c_char {
        let entry_ptr = self as *const SymbolEntry as *const u8;
        let data_start = symbol_table.data.as_ptr();
        let entry_offset = unsafe { entry_ptr.offset_from(data_start) as usize };
        let name_start = entry_offset + size_of::<SymbolEntry>();

        unsafe { symbol_table.data.as_ptr().add(name_start) as *const c_char }
    }
}

pub struct SymbolIterator<'a> {
    symbol_table: &'a SymbolTable,
    index: usize,
}

impl<'a> Iterator for SymbolIterator<'a> {
    type Item = DarwinSymbolDetails;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.symbol_table.symbol_count {
            return None;
        }

        let entry = self.symbol_table.get_symbol_entry_by_name_index(self.index);
        let symbol_name = entry.name(self.symbol_table);
        let kernel_base = get_kernel_base();
        let details = DarwinSymbolDetails {
            name: symbol_name.to_owned(),
            address: kernel_base + entry.address_offset as u64,
            symbol_type: entry.symbol_type,
            section: entry.section,
            description: entry.description,
        };

        self.index += 1;

        Some(details)
    }
}
