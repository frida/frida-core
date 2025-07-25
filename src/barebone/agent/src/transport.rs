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
                channel_a_head: AtomicU32::new(0),
                channel_a_tail: AtomicU32::new(0),
                channel_b_head: AtomicU32::new(0),
                channel_b_tail: AtomicU32::new(0),
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

    pub channel_a_head: AtomicU32,
    pub channel_a_tail: AtomicU32,

    pub channel_b_head: AtomicU32,
    pub channel_b_tail: AtomicU32,

    pub next_fragment_id: AtomicU32,

    pub reserved: [u32; 3],

    pub data: [u8; 0],
}

#[derive(Debug, Clone, Copy)]
pub enum TransportRole {
    Primary,
    Secondary,
}

pub struct TransportView<'a> {
    transport: &'a mut SharedTransport,
    role: TransportRole,
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
    pub unsafe fn as_view(&mut self, role: TransportRole) -> TransportView {
        TransportView {
            transport: self,
            role,
        }
    }

    unsafe fn get_buffer_sizes(&self) -> TransportBuffers {
        TransportBuffers::new(self.page_size as usize)
    }

    unsafe fn channel_a_buffer(&self) -> *mut u8 {
        let base = self.data.as_ptr() as *mut u8;
        base
    }

    unsafe fn channel_b_buffer(&self) -> *mut u8 {
        unsafe {
            let sizes = self.get_buffer_sizes();
            let base = self.data.as_ptr() as *mut u8;
            base.add(sizes.buffer_size)
        }
    }
}

impl<'a> TransportView<'a> {
    unsafe fn tx_buffer(&self) -> *mut u8 {
        unsafe {
            match self.role {
                TransportRole::Primary => self.transport.channel_a_buffer(),
                TransportRole::Secondary => self.transport.channel_b_buffer(),
            }
        }
    }

    unsafe fn rx_buffer(&self) -> *mut u8 {
        unsafe {
            match self.role {
                TransportRole::Primary => self.transport.channel_b_buffer(),
                TransportRole::Secondary => self.transport.channel_a_buffer(),
            }
        }
    }

    unsafe fn tx_pointers(&self) -> (&AtomicU32, &AtomicU32) {
        match self.role {
            TransportRole::Primary => (&self.transport.channel_a_head, &self.transport.channel_a_tail),
            TransportRole::Secondary => (&self.transport.channel_b_head, &self.transport.channel_b_tail),
        }
    }

    unsafe fn rx_pointers(&self) -> (&AtomicU32, &AtomicU32) {
        match self.role {
            TransportRole::Primary => (&self.transport.channel_b_head, &self.transport.channel_b_tail),
            TransportRole::Secondary => (&self.transport.channel_a_head, &self.transport.channel_a_tail),
        }
    }

    pub unsafe fn try_write_message(&mut self, data: &[u8]) -> bool {
        unsafe {
            let sizes = self.transport.get_buffer_sizes();
            let fragment_id = self.transport.next_fragment_id.fetch_add(1, Ordering::Relaxed) as u16;

            let total_fragments = if data.len() <= sizes.max_message_size {
                1
            } else {
                let chunk_size = sizes.max_message_size;
                let fragments = (data.len() + chunk_size - 1) / chunk_size;
                if fragments > u16::MAX as usize {
                    return false;
                }
                fragments
            };

            let pending = PendingFragment {
                data: data.to_vec(),
                next_fragment_index: 0,
                fragment_id,
                total_fragments,
            };

            self.try_send_pending_fragment(pending)
        }
    }

    unsafe fn try_send_pending_fragment(&mut self, mut pending: PendingFragment) -> bool {
        unsafe {
            let sizes = self.transport.get_buffer_sizes();

            if pending.total_fragments == 1 {
                let header = MessageHeader {
                    size: pending.data.len() as u16,
                    fragment_id: 0,
                    fragment_count: 0,
                    flags: MSG_FLAG_COMPLETE,
                    _reserved: [0; 9],
                };

                let total_size = core::mem::size_of::<MessageHeader>() + pending.data.len();

                if !self.has_space_tx(total_size) {
                    let pending_queue = core::ptr::addr_of_mut!(PENDING_FRAGMENTS).as_mut().unwrap();
                    pending_queue.push_back(pending);
                    return true;
                }

                self.write_bytes_tx(
                    &header as *const MessageHeader as *const u8,
                    core::mem::size_of::<MessageHeader>(),
                );
                self.write_bytes_tx(pending.data.as_ptr(), pending.data.len());
                return true;
            }

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

                if !self.has_space_tx(total_size) {
                    if fragments_sent > 0 {
                        let remaining_offset = fragments_sent * chunk_size;
                        pending.data = remaining_data[remaining_offset..].to_vec();
                        pending.next_fragment_index += fragments_sent;
                    }
                    let pending_queue = core::ptr::addr_of_mut!(PENDING_FRAGMENTS).as_mut().unwrap();
                    pending_queue.push_back(pending);
                    return true;
                }

                self.write_bytes_tx(
                    &header as *const MessageHeader as *const u8,
                    core::mem::size_of::<MessageHeader>(),
                );
                self.write_bytes_tx(chunk.as_ptr(), chunk.len());
                fragments_sent += 1;
            }

            true
        }
    }

    pub unsafe fn process_pending_fragments(&mut self) {
        unsafe {
            let pending_queue = core::ptr::addr_of_mut!(PENDING_FRAGMENTS).as_mut().unwrap();

            while let Some(pending) = pending_queue.pop_front() {
                if !self.try_send_pending_fragment(pending) {
                    break;
                }
            }
        }
    }

    pub unsafe fn try_read_message(&mut self) -> Option<(*mut u8, usize)> {
        unsafe {
            if let Some(header) = self.peek_header_rx() {
                if header.flags & MSG_FLAG_COMPLETE != 0 {
                    self.advance_tail_rx(core::mem::size_of::<MessageHeader>());

                    let message_size = header.size as usize;
                    if self.available_bytes_rx() >= message_size {
                        let message_ptr = crate::xnu::kalloc(message_size);
                        if !message_ptr.is_null() {
                            if self.read_bytes_rx(message_ptr, message_size) {
                                return Some((message_ptr, message_size));
                            }
                            crate::xnu::free(message_ptr, message_size);
                        }
                    }
                } else if header.flags & MSG_FLAG_FRAGMENT != 0 {
                    return self.handle_fragment_rx();
                }
            }
            None
        }
    }

    unsafe fn handle_fragment_rx(&mut self) -> Option<(*mut u8, usize)> {
        unsafe {
            if let Some(header) = self.peek_header_rx() {
                let available = self.available_bytes_rx();
                let header_size = core::mem::size_of::<MessageHeader>();
                let total_message_size = header_size + header.size as usize;

                if available >= total_message_size {
                    self.advance_tail_rx(header_size);

                    let payload_size = header.size as usize;
                    let payload_ptr = crate::xnu::kalloc(payload_size);
                    if payload_ptr.is_null() {
                        return None;
                    }

                    if !self.read_bytes_rx(payload_ptr, payload_size) {
                        crate::xnu::free(payload_ptr, payload_size);
                        return None;
                    }

                    let fragment_cache = core::ptr::addr_of_mut!(FRAGMENT_CACHE).as_mut().unwrap();
                    let entry = fragment_cache
                        .entry(header.fragment_id)
                        .or_insert_with(Vec::new);

                    let payload_slice = core::slice::from_raw_parts(payload_ptr, payload_size);
                    entry.extend_from_slice(payload_slice);
                    crate::xnu::free(payload_ptr, payload_size);

                    let expected_total_size = (header.fragment_count as usize) * payload_size;
                    if entry.len() >= expected_total_size {
                        let complete_data = fragment_cache.remove(&header.fragment_id).unwrap();
                        let final_ptr = crate::xnu::kalloc(complete_data.len());
                        if !final_ptr.is_null() {
                            core::ptr::copy_nonoverlapping(complete_data.as_ptr(), final_ptr, complete_data.len());
                            return Some((final_ptr, complete_data.len()));
                        }
                    }
                }
            }
            None
        }
    }

    unsafe fn has_space_tx(&self, size: usize) -> bool {
        unsafe {
            let sizes = self.transport.get_buffer_sizes();
            let (head, tail) = self.tx_pointers();
            let head_val = head.load(Ordering::Acquire);
            let tail_val = tail.load(Ordering::Acquire);
            let available = if head_val >= tail_val {
                sizes.buffer_size - (head_val - tail_val) as usize - 1
            } else {
                (tail_val - head_val) as usize - 1
            };
            available >= size
        }
    }

    unsafe fn write_bytes_tx(&mut self, data: *const u8, size: usize) {
        unsafe {
            let sizes = self.transport.get_buffer_sizes();
            let (head, _tail) = self.tx_pointers();
            let head_val = head.load(Ordering::Acquire);
            let buffer = self.tx_buffer();
            let head_pos = head_val as usize % sizes.buffer_size;

            if head_pos + size <= sizes.buffer_size {
                core::ptr::copy_nonoverlapping(data, buffer.add(head_pos), size);
            } else {
                let first_chunk = sizes.buffer_size - head_pos;
                let second_chunk = size - first_chunk;

                core::ptr::copy_nonoverlapping(data, buffer.add(head_pos), first_chunk);
                core::ptr::copy_nonoverlapping(data.add(first_chunk), buffer, second_chunk);
            }

            head.store(
                (head_val + size as u32) % sizes.buffer_size as u32,
                Ordering::Release,
            );
        }
    }

    unsafe fn peek_header_rx(&self) -> Option<MessageHeader> {
        unsafe {
            let available = self.available_bytes_rx();
            if available < core::mem::size_of::<MessageHeader>() {
                return None;
            }

            let sizes = self.transport.get_buffer_sizes();
            let (_head, tail) = self.rx_pointers();
            let tail_val = tail.load(Ordering::Acquire);
            let buffer = self.rx_buffer();
            let tail_pos = tail_val as usize % sizes.buffer_size;
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

    unsafe fn advance_tail_rx(&mut self, size: usize) {
        unsafe {
            let sizes = self.transport.get_buffer_sizes();
            let (_head, tail) = self.rx_pointers();
            let tail_val = tail.load(Ordering::Acquire);
            tail.store(
                (tail_val + size as u32) % sizes.buffer_size as u32,
                Ordering::Release,
            );
        }
    }

    unsafe fn read_bytes_rx(&mut self, dest: *mut u8, size: usize) -> bool {
        unsafe {
            if self.available_bytes_rx() < size {
                return false;
            }

            let sizes = self.transport.get_buffer_sizes();
            let (_head, tail) = self.rx_pointers();
            let tail_val = tail.load(Ordering::Acquire);
            let buffer = self.rx_buffer();
            let tail_pos = tail_val as usize % sizes.buffer_size;

            if tail_pos + size <= sizes.buffer_size {
                core::ptr::copy_nonoverlapping(buffer.add(tail_pos), dest, size);
            } else {
                let first_chunk = sizes.buffer_size - tail_pos;
                let second_chunk = size - first_chunk;

                core::ptr::copy_nonoverlapping(buffer.add(tail_pos), dest, first_chunk);
                core::ptr::copy_nonoverlapping(buffer, dest.add(first_chunk), second_chunk);
            }

            tail.store(
                (tail_val + size as u32) % sizes.buffer_size as u32,
                Ordering::Release,
            );
            true
        }
    }

    unsafe fn available_bytes_rx(&self) -> usize {
        unsafe {
            let (head, tail) = self.rx_pointers();
            let head_val = head.load(Ordering::Acquire);
            let tail_val = tail.load(Ordering::Acquire);
            let sizes = self.transport.get_buffer_sizes();

            if head_val >= tail_val {
                (head_val - tail_val) as usize
            } else {
                sizes.buffer_size - (tail_val - head_val) as usize
            }
        }
    }
}
