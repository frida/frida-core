use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::bindings::gpointer;
use crate::gum;
use crate::xnu;

pub unsafe fn allocate_shared_transport(page_size: usize) -> (*mut SharedTransport, usize) {
    unsafe {
        let transport_ptr = xnu::kalloc(page_size) as *mut SharedTransport;

        core::ptr::write(
            transport_ptr,
            SharedTransport {
                magic: 0x44495246,
                page_size: page_size as u32,
                h2g_head: AtomicU32::new(0),
                h2g_tail: AtomicU32::new(0),
                g2h_head: AtomicU32::new(0),
                g2h_tail: AtomicU32::new(0),
                next_fragment_id: AtomicU32::new(1),
                reserved: [0; 3],
                data: [],
            },
        );

        let physical_addr =
            gum::gum_barebone_virtual_to_physical(transport_ptr as gpointer) as usize;
        (transport_ptr, physical_addr)
    }
}

#[repr(C)]
pub struct SharedTransport {
    pub magic: u32,
    pub page_size: u32,

    pub h2g_head: AtomicU32,
    pub h2g_tail: AtomicU32,

    pub g2h_head: AtomicU32,
    pub g2h_tail: AtomicU32,

    pub next_fragment_id: AtomicU32,

    pub reserved: [u32; 3],

    pub data: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MessageHeader {
    pub size: u16,
    pub fragment_id: u16,
    pub fragment_count: u16,
    pub flags: u8,
    pub _reserved: [u8; 9],
}

const MSG_FLAG_COMPLETE: u8 = 0x01;
const MSG_FLAG_FRAGMENT: u8 = 0x02;

#[derive(Debug, Clone)]
struct PendingFragment {
    data: Vec<u8>,
    next_fragment_index: usize,
    fragment_id: u16,
    total_fragments: usize,
}

static mut PENDING_FRAGMENTS: VecDeque<PendingFragment> = VecDeque::new();
static mut FRAGMENT_CACHE: BTreeMap<u16, Vec<u8>> = BTreeMap::new();

pub struct TransportBuffers {
    pub page_size: usize,
    pub header_size: usize,
    pub buffer_size: usize,
    pub max_message_size: usize,
}

impl TransportBuffers {
    pub fn new(page_size: usize) -> Self {
        let header_size = core::mem::size_of::<SharedTransport>();
        let available_data = page_size - header_size;
        let buffer_size = available_data / 2;
        let max_message_size = buffer_size - core::mem::size_of::<MessageHeader>() - 16;

        Self {
            page_size,
            header_size,
            buffer_size,
            max_message_size,
        }
    }
}

impl SharedTransport {
    unsafe fn get_buffer_sizes(&self) -> TransportBuffers {
        TransportBuffers::new(self.page_size as usize)
    }

    unsafe fn h2g_buffer(&self) -> *mut u8 {
        let base = self.data.as_ptr() as *mut u8;
        base
    }

    unsafe fn g2h_buffer(&self) -> *mut u8 {
        unsafe {
            let sizes = self.get_buffer_sizes();
            let base = self.data.as_ptr() as *mut u8;
            base.add(sizes.buffer_size)
        }
    }

    pub unsafe fn try_write_message_g2h(&mut self, data: &[u8]) -> bool {
        unsafe {
            let sizes = self.get_buffer_sizes();
            let data_len = data.len();

            if data_len > sizes.max_message_size {
                return self.try_write_fragmented_g2h(data);
            }

            let header = MessageHeader {
                size: data_len as u16,
                fragment_id: 0,
                fragment_count: 0,
                flags: MSG_FLAG_COMPLETE,
                _reserved: [0; 9],
            };

            let total_size = core::mem::size_of::<MessageHeader>() + data_len;

            // TODO: Queue! But lots of duplicated logic between this and try_write_fragmented_g2h.
            if !self.has_space_g2h(total_size) {
                return false;
            }

            self.write_bytes_g2h(
                &header as *const MessageHeader as *const u8,
                core::mem::size_of::<MessageHeader>(),
            );

            self.write_bytes_g2h(data.as_ptr(), data_len);

            true
        }
    }

    unsafe fn try_write_fragmented_g2h(&mut self, data: &[u8]) -> bool {
        unsafe {
            let sizes = self.get_buffer_sizes();
            let chunk_size = sizes.max_message_size;
            let total_fragments = (data.len() + chunk_size - 1) / chunk_size;

            if total_fragments > u16::MAX as usize {
                return false;
            }

            let fragment_id = self.next_fragment_id.fetch_add(1, Ordering::Relaxed) as u16;

            for (fragment_index, chunk) in data.chunks(chunk_size).enumerate() {
                let header = MessageHeader {
                    size: chunk.len() as u16,
                    fragment_id,
                    fragment_count: total_fragments as u16,
                    flags: MSG_FLAG_FRAGMENT,
                    _reserved: [0; 9],
                };

                let total_size = core::mem::size_of::<MessageHeader>() + chunk.len();

                if !self.has_space_g2h(total_size) {
                    let remaining_data = &data[(fragment_index * chunk_size)..];
                    let pending = PendingFragment {
                        data: remaining_data.to_vec(),
                        next_fragment_index: fragment_index,
                        fragment_id,
                        total_fragments,
                    };

                    let pending_queue =
                        core::ptr::addr_of_mut!(PENDING_FRAGMENTS).as_mut().unwrap();
                    pending_queue.push_back(pending);

                    return true;
                }

                self.write_bytes_g2h(
                    &header as *const MessageHeader as *const u8,
                    core::mem::size_of::<MessageHeader>(),
                );
                self.write_bytes_g2h(chunk.as_ptr(), chunk.len());
            }

            true
        }
    }

    pub unsafe fn try_read_message_h2g(&mut self) -> Option<Vec<u8>> {
        unsafe {
            if self.available_bytes_h2g() < core::mem::size_of::<MessageHeader>() {
                return None;
            }

            let header = self.peek_header_h2g()?;

            let total_size = core::mem::size_of::<MessageHeader>() + header.size as usize;
            if self.available_bytes_h2g() < total_size {
                return None;
            }

            self.advance_tail_h2g(core::mem::size_of::<MessageHeader>());

            let mut data = Vec::with_capacity(header.size as usize);
            data.resize(header.size as usize, 0);
            if !self.read_bytes_h2g(data.as_mut_ptr(), header.size as usize) {
                return None;
            }

            if header.flags & MSG_FLAG_FRAGMENT != 0 {
                return self.handle_fragment_h2g(header, data);
            }

            Some(data)
        }
    }

    unsafe fn handle_fragment_h2g(
        &mut self,
        header: MessageHeader,
        data: Vec<u8>,
    ) -> Option<Vec<u8>> {
        unsafe {
            let fragment_cache = core::ptr::addr_of_mut!(FRAGMENT_CACHE).as_mut().unwrap();

            let entry = fragment_cache
                .entry(header.fragment_id)
                .or_insert_with(Vec::new);
            entry.extend_from_slice(&data);

            let expected_total_size = header.fragment_count as usize * header.size as usize;
            if entry.len() >= expected_total_size {
                let complete_data = fragment_cache.remove(&header.fragment_id).unwrap();
                Some(complete_data)
            } else {
                None
            }
        }
    }

    pub unsafe fn process_pending_fragments(&mut self) {
        unsafe {
            let pending_queue = core::ptr::addr_of_mut!(PENDING_FRAGMENTS).as_mut().unwrap();

            while let Some(mut pending) = pending_queue.pop_front() {
                let sizes = self.get_buffer_sizes();
                let chunk_size = sizes.max_message_size;
                let remaining_data = &pending.data;

                let mut fragments_sent = 0;
                for (_local_index, chunk) in remaining_data.chunks(chunk_size).enumerate() {
                    let header = MessageHeader {
                        size: chunk.len() as u16,
                        fragment_id: pending.fragment_id,
                        fragment_count: pending.total_fragments as u16,
                        flags: MSG_FLAG_FRAGMENT,
                        _reserved: [0; 9],
                    };

                    let total_size = core::mem::size_of::<MessageHeader>() + chunk.len();

                    if !self.has_space_g2h(total_size) {
                        let remaining_offset = fragments_sent * chunk_size;
                        pending.data = remaining_data[remaining_offset..].to_vec();
                        pending.next_fragment_index += fragments_sent;
                        pending_queue.push_front(pending);
                        return;
                    }

                    self.write_bytes_g2h(
                        &header as *const MessageHeader as *const u8,
                        core::mem::size_of::<MessageHeader>(),
                    );
                    self.write_bytes_g2h(chunk.as_ptr(), chunk.len());
                    fragments_sent += 1;
                }
            }
        }
    }

    unsafe fn has_space_g2h(&self, size: usize) -> bool {
        unsafe {
            let sizes = self.get_buffer_sizes();
            let head = self.g2h_head.load(Ordering::Acquire);
            let tail = self.g2h_tail.load(Ordering::Acquire);
            let available = if head >= tail {
                sizes.buffer_size - (head - tail) as usize - 1
            } else {
                (tail - head) as usize - 1
            };
            available >= size
        }
    }

    unsafe fn write_bytes_g2h(&mut self, data: *const u8, size: usize) {
        unsafe {
            let sizes = self.get_buffer_sizes();
            let head = self.g2h_head.load(Ordering::Acquire);
            let buffer = self.g2h_buffer();
            let head_pos = head as usize % sizes.buffer_size;

            if head_pos + size <= sizes.buffer_size {
                core::ptr::copy_nonoverlapping(data, buffer.add(head_pos), size);
            } else {
                let first_chunk = sizes.buffer_size - head_pos;
                let second_chunk = size - first_chunk;

                core::ptr::copy_nonoverlapping(data, buffer.add(head_pos), first_chunk);
                core::ptr::copy_nonoverlapping(data.add(first_chunk), buffer, second_chunk);
            }

            self.g2h_head.store(
                (head + size as u32) % sizes.buffer_size as u32,
                Ordering::Release,
            );
        }
    }

    unsafe fn peek_header_h2g(&self) -> Option<MessageHeader> {
        unsafe {
            let available = self.available_bytes_h2g();
            if available < core::mem::size_of::<MessageHeader>() {
                return None;
            }

            let sizes = self.get_buffer_sizes();
            let tail = self.h2g_tail.load(Ordering::Acquire);
            let buffer = self.h2g_buffer();
            let tail_pos = tail as usize % sizes.buffer_size;
            let header_size = core::mem::size_of::<MessageHeader>();

            let mut header: MessageHeader = core::mem::zeroed();
            let header_ptr = &mut header as *mut MessageHeader as *mut u8;

            if tail_pos + header_size <= sizes.buffer_size {
                core::ptr::copy_nonoverlapping(buffer.add(tail_pos), header_ptr, header_size);
            } else {
                let first_chunk = sizes.buffer_size - tail_pos;
                let second_chunk = header_size - first_chunk;

                core::ptr::copy_nonoverlapping(buffer.add(tail_pos), header_ptr, first_chunk);
                core::ptr::copy_nonoverlapping(buffer, header_ptr.add(first_chunk), second_chunk);
            }

            Some(header)
        }
    }

    unsafe fn advance_tail_h2g(&mut self, size: usize) {
        unsafe {
            let sizes = self.get_buffer_sizes();
            let tail = self.h2g_tail.load(Ordering::Acquire);
            self.h2g_tail.store(
                (tail + size as u32) % sizes.buffer_size as u32,
                Ordering::Release,
            );
        }
    }

    unsafe fn read_bytes_h2g(&mut self, dest: *mut u8, size: usize) -> bool {
        unsafe {
            if self.available_bytes_h2g() < size {
                return false;
            }

            let sizes = self.get_buffer_sizes();
            let tail = self.h2g_tail.load(Ordering::Acquire);
            let buffer = self.h2g_buffer();
            let tail_pos = tail as usize % sizes.buffer_size;

            if tail_pos + size <= sizes.buffer_size {
                core::ptr::copy_nonoverlapping(buffer.add(tail_pos), dest, size);
            } else {
                let first_chunk = sizes.buffer_size - tail_pos;
                let second_chunk = size - first_chunk;

                core::ptr::copy_nonoverlapping(buffer.add(tail_pos), dest, first_chunk);
                core::ptr::copy_nonoverlapping(buffer, dest.add(first_chunk), second_chunk);
            }

            self.h2g_tail.store(
                (tail + size as u32) % sizes.buffer_size as u32,
                Ordering::Release,
            );
            true
        }
    }

    unsafe fn available_bytes_h2g(&self) -> usize {
        unsafe {
            let head = self.h2g_head.load(Ordering::Acquire);
            let tail = self.h2g_tail.load(Ordering::Acquire);
            let sizes = self.get_buffer_sizes();

            if head >= tail {
                (head - tail) as usize
            } else {
                sizes.buffer_size - (tail - head) as usize
            }
        }
    }
}
