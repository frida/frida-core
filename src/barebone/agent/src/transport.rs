use alloc::vec::Vec;
use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::bindings::gpointer;
use crate::gum;
use crate::xnu;

#[derive(Debug, Clone)]
struct PendingMessage {
    remaining_data: Vec<u8>,
    offset: usize,
}

static mut PENDING_QUEUE: VecDeque<PendingMessage> = VecDeque::new();
static mut FRAGMENT_BUFFER: Vec<u8> = Vec::new();

pub unsafe fn allocate_shared_transport(page_size: usize) -> (*mut SharedTransport, usize) {
    let transport_ptr = xnu::kalloc(page_size) as *mut SharedTransport;

    unsafe {
        core::ptr::write(
            transport_ptr,
            SharedTransport {
                magic: 0x44495246,
                page_size: page_size as u32,
                channel_a_head: AtomicU32::new(0),
                channel_a_tail: AtomicU32::new(0),
                channel_b_head: AtomicU32::new(0),
                channel_b_tail: AtomicU32::new(0),
                data: [],
            },
        );
    }

    let physical_addr = gum::gum_barebone_virtual_to_physical(transport_ptr as gpointer) as usize;
    (transport_ptr, physical_addr)
}

#[repr(C)]
pub struct SharedTransport {
    pub magic: u32,
    pub page_size: u32,
    pub channel_a_head: AtomicU32,
    pub channel_a_tail: AtomicU32,
    pub channel_b_head: AtomicU32,
    pub channel_b_tail: AtomicU32,
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
    buffer_size: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MessageHeader {
    pub size: u16,
    pub flags: u8,
}

const MSG_FLAG_COMPLETE: u8 = 0x01;

impl SharedTransport {
    pub unsafe fn as_view(&mut self, role: TransportRole) -> TransportView {
        let header_size = core::mem::size_of::<SharedTransport>();
        let available_data = self.page_size as usize - header_size;
        let buffer_size = available_data / 2;

        TransportView {
            transport: self,
            role,
            buffer_size,
        }
    }

    unsafe fn channel_a_buffer(&self) -> *mut u8 {
        self.data.as_ptr() as *mut u8
    }

    unsafe fn channel_b_buffer(&self) -> *mut u8 {
        let header_size = core::mem::size_of::<SharedTransport>();
        let available_data = self.page_size as usize - header_size;
        let buffer_size = available_data / 2;
        let base = self.data.as_ptr() as *mut u8;
        unsafe { base.add(buffer_size) }
    }
}

impl<'a> TransportView<'a> {
    pub unsafe fn write_message(&mut self, data: &[u8]) {
        unsafe { self.flush_pending() };

        let pending = PendingMessage {
            remaining_data: data.to_vec(),
            offset: 0,
        };

        let queue_ptr = core::ptr::addr_of_mut!(PENDING_QUEUE);
        unsafe {
            (*queue_ptr).push_back(pending);
        }

        unsafe { self.flush_pending() };
    }

    pub unsafe fn try_read_message(&mut self) -> Option<Vec<u8>> {
        let header_size = core::mem::size_of::<MessageHeader>();

        if unsafe { self.available_rx_data() } < header_size {
            return None;
        }

        let header_data = unsafe { self.peek_bytes(header_size)? };
        let header = unsafe { core::ptr::read(header_data.as_ptr() as *const MessageHeader) };
        if header.size == 0 || header.size as usize > self.buffer_size {
            panic!("Protocol violation: invalid header size {}, buffer_size {}", header.size, self.buffer_size);
        }

        let total_size = header_size + header.size as usize;
        if unsafe { self.available_rx_data() } < total_size {
            return None;
        }

        let message_data = unsafe { self.read_bytes(total_size)? };
        let payload = &message_data[header_size..];

        let fragment_ptr = core::ptr::addr_of_mut!(FRAGMENT_BUFFER);

        if header.flags & MSG_FLAG_COMPLETE != 0 {
            unsafe {
                if !(*fragment_ptr).is_empty() {
                    (*fragment_ptr).extend_from_slice(payload);
                    let complete_message = (*fragment_ptr).clone();
                    (*fragment_ptr).clear();
                    return Some(complete_message);
                } else {
                    return Some(payload.to_vec());
                }
            }
        } else {
            unsafe {
                (*fragment_ptr).extend_from_slice(payload);
            }
            None
        }
    }

    pub unsafe fn flush_pending(&mut self) {
        let header_size = core::mem::size_of::<MessageHeader>();
        let max_payload = self.buffer_size.saturating_sub(header_size + 1);

        let queue_ptr = core::ptr::addr_of_mut!(PENDING_QUEUE);

        if unsafe {
            (*queue_ptr).is_empty()
        } {
            return;
        }

        let pending = unsafe {
            (*queue_ptr).front().cloned().unwrap()
        };

        let remaining = pending.remaining_data.len() - pending.offset;
        let chunk_size = remaining.min(max_payload);
        let total_needed = header_size + chunk_size;

        if unsafe { self.available_tx_space() } < total_needed {
            return;
        }

        let chunk = &pending.remaining_data[pending.offset..pending.offset + chunk_size];
        let is_last = pending.offset + chunk_size >= pending.remaining_data.len();

        let flags = if is_last { MSG_FLAG_COMPLETE } else { 0 };

        let header = MessageHeader {
            size: chunk_size as u16,
            flags,
        };

        let header_bytes = unsafe {
            core::slice::from_raw_parts(
                &header as *const _ as *const u8,
                header_size
            )
        };

        let mut combined_data = Vec::with_capacity(header_size + chunk.len());
        combined_data.extend_from_slice(header_bytes);
        combined_data.extend_from_slice(chunk);

        unsafe { self.write_bytes(&combined_data) };

        if !is_last {
            unsafe {
                if let Some(front_msg) = (*queue_ptr).front_mut() {
                    front_msg.offset += chunk_size;
                }
            }
        } else {
            unsafe {
                (*queue_ptr).pop_front();
            }
        }
    }

    pub unsafe fn available_tx_space(&self) -> usize {
        let (head, tail) = unsafe { self.tx_pointers() };
        let head_val = head.load(Ordering::Acquire);
        let tail_val = tail.load(Ordering::Acquire);

        if head_val >= tail_val {
            self.buffer_size - (head_val - tail_val) as usize - 1
        } else {
            (tail_val - head_val) as usize - 1
        }
    }

    unsafe fn write_bytes(&mut self, data: &[u8]) {
        if unsafe { self.available_tx_space() } < data.len() {
            panic!("Insufficient space: need {} bytes, have {} bytes", data.len(), unsafe { self.available_tx_space() });
        }

        let (head, _tail) = unsafe { self.tx_pointers() };
        let head_val = head.load(Ordering::Acquire);
        let buffer = unsafe { self.tx_buffer() };
        let pos = head_val as usize % self.buffer_size;

        if pos + data.len() <= self.buffer_size {
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr(), buffer.add(pos), data.len());
            }
        } else {
            let first = self.buffer_size - pos;
            let second = data.len() - first;
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr(), buffer.add(pos), first);
                core::ptr::copy_nonoverlapping(data.as_ptr().add(first), buffer, second);
            }
        }

        head.store(head_val + data.len() as u32, Ordering::Release);
    }

    unsafe fn available_rx_data(&self) -> usize {
        let (head, tail) = unsafe { self.rx_pointers() };
        let head_val = head.load(Ordering::Acquire);
        let tail_val = tail.load(Ordering::Acquire);

        if head_val >= tail_val {
            (head_val - tail_val) as usize
        } else {
            self.buffer_size - (tail_val - head_val) as usize
        }
    }

    unsafe fn read_bytes(&mut self, size: usize) -> Option<Vec<u8>> {
        unsafe { self.read_bytes_common(size, true) }
    }

    unsafe fn peek_bytes(&self, size: usize) -> Option<Vec<u8>> {
        unsafe { self.read_bytes_common(size, false) }
    }

    unsafe fn read_bytes_common(&self, size: usize, advance_tail: bool) -> Option<Vec<u8>> {
        if unsafe { self.available_rx_data() } < size {
            return None;
        }

        let (_head, tail) = unsafe { self.rx_pointers() };
        let tail_val = tail.load(Ordering::Acquire);
        let buffer = unsafe { self.rx_buffer() };
        let pos = tail_val as usize % self.buffer_size;

        let mut data = alloc::vec![0u8; size];

        if pos + size <= self.buffer_size {
            unsafe {
                core::ptr::copy_nonoverlapping(buffer.add(pos), data.as_mut_ptr(), size);
            }
        } else {
            let first = self.buffer_size - pos;
            let second = size - first;
            unsafe {
                core::ptr::copy_nonoverlapping(buffer.add(pos), data.as_mut_ptr(), first);
                core::ptr::copy_nonoverlapping(buffer, data.as_mut_ptr().add(first), second);
            }
        }

        if advance_tail {
            tail.store(tail_val + size as u32, Ordering::Release);
        }

        Some(data)
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

    unsafe fn tx_buffer(&self) -> *mut u8 {
        match self.role {
            TransportRole::Primary => unsafe { self.transport.channel_a_buffer() },
            TransportRole::Secondary => unsafe { self.transport.channel_b_buffer() },
        }
    }

    unsafe fn rx_buffer(&self) -> *mut u8 {
        match self.role {
            TransportRole::Primary => unsafe { self.transport.channel_b_buffer() },
            TransportRole::Secondary => unsafe { self.transport.channel_a_buffer() },
        }
    }
}
