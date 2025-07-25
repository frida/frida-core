use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

#[repr(C)]
pub struct SharedTransport {
    pub magic: u32,
    pub buffer_size: u32,
    pub channel_a: Channel,
    pub channel_b: Channel,
    pub data: [u8; 0],
}

#[repr(C)]
pub struct Channel {
    pub head: AtomicU32,
    pub tail: AtomicU32,
}

impl Channel {
    fn new() -> Self {
        Self {
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
        }
    }

    fn pointers(&self) -> (&AtomicU32, &AtomicU32) {
        (&self.head, &self.tail)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MessageHeader {
    pub size: u16,
    pub flags: u8,
}

const MSG_FLAG_COMPLETE: u8 = 0x01;

pub struct TransportView<'a> {
    transport: &'a mut SharedTransport,
    role: TransportRole,
    buffer_size: usize,
    write_pending_queue: VecDeque<PendingMessage>,
    read_fragment_buffer: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub enum TransportRole {
    Primary,
    Secondary,
}

#[derive(Debug, Clone)]
struct PendingMessage {
    remaining_data: Vec<u8>,
    offset: usize,
}

impl SharedTransport {
    pub fn new(buffer_size: usize) -> Self {
        Self {
            magic: 0x44495246,
            buffer_size: buffer_size as u32,
            channel_a: Channel::new(),
            channel_b: Channel::new(),
            data: [],
        }
    }

    pub fn as_view(&mut self, role: TransportRole) -> TransportView {
        let header_size = core::mem::size_of::<SharedTransport>();
        let available_data = self.buffer_size as usize - header_size;
        let buffer_size = available_data / 2;

        TransportView {
            transport: self,
            role,
            buffer_size,
            write_pending_queue: VecDeque::new(),
            read_fragment_buffer: Vec::new(),
        }
    }

    fn channel_a_buffer(&self) -> *mut u8 {
        self.data.as_ptr() as *mut u8
    }

    fn channel_b_buffer(&self) -> *mut u8 {
        let header_size = core::mem::size_of::<SharedTransport>();
        let available_data = self.buffer_size as usize - header_size;
        let buffer_size = available_data / 2;
        let base = self.data.as_ptr() as *mut u8;
        unsafe { base.add(buffer_size) }
    }

    fn write_channel(&self, role: TransportRole) -> &Channel {
        match role {
            TransportRole::Primary => &self.channel_a,
            TransportRole::Secondary => &self.channel_b,
        }
    }

    fn read_channel(&self, role: TransportRole) -> &Channel {
        match role {
            TransportRole::Primary => &self.channel_b,
            TransportRole::Secondary => &self.channel_a,
        }
    }

    fn write_buffer(&self, role: TransportRole) -> *mut u8 {
        match role {
            TransportRole::Primary => self.channel_a_buffer(),
            TransportRole::Secondary => self.channel_b_buffer(),
        }
    }

    fn read_buffer(&self, role: TransportRole) -> *mut u8 {
        match role {
            TransportRole::Primary => self.channel_b_buffer(),
            TransportRole::Secondary => self.channel_a_buffer(),
        }
    }
}

impl<'a> TransportView<'a> {
    pub fn write_message(&mut self, data: &[u8]) {
        self.flush_pending();

        let pending = PendingMessage {
            remaining_data: data.to_vec(),
            offset: 0,
        };
        self.write_pending_queue.push_back(pending);

        self.flush_pending();
    }

    pub fn try_read_message(&mut self) -> Option<Vec<u8>> {
        let header_size = core::mem::size_of::<MessageHeader>();
        let header_data = self.peek_bytes(header_size)?;
        let header = unsafe { core::ptr::read(header_data.as_ptr() as *const MessageHeader) };
        if header.size == 0 || header.size as usize > self.buffer_size {
            panic!(
                "Protocol violation: invalid header size {}, buffer_size {}",
                header.size, self.buffer_size
            );
        }

        let total_size = header_size + header.size as usize;
        let message_data = self.read_bytes(total_size)?;
        let payload = &message_data[header_size..];

        if header.flags & MSG_FLAG_COMPLETE != 0 {
            if !self.read_fragment_buffer.is_empty() {
                self.read_fragment_buffer.extend_from_slice(payload);
                let complete_message = self.read_fragment_buffer.clone();
                self.read_fragment_buffer.clear();
                return Some(complete_message);
            } else {
                return Some(payload.to_vec());
            }
        } else {
            self.read_fragment_buffer.extend_from_slice(payload);
            None
        }
    }

    pub fn flush_pending(&mut self) {
        if self.write_pending_queue.is_empty() {
            return;
        }

        let header_size = core::mem::size_of::<MessageHeader>();
        let max_payload = self.buffer_size.saturating_sub(header_size + 1);
        let pending = self.write_pending_queue.front().cloned().unwrap();

        let remaining = pending.remaining_data.len() - pending.offset;
        let chunk_size = remaining.min(max_payload);
        let total_needed = header_size + chunk_size;
        if self.available_write_space() < total_needed {
            return;
        }

        let chunk = &pending.remaining_data[pending.offset..pending.offset + chunk_size];
        let is_last = pending.offset + chunk_size >= pending.remaining_data.len();

        let flags = if is_last { MSG_FLAG_COMPLETE } else { 0 };

        let header = MessageHeader {
            size: chunk_size as u16,
            flags,
        };

        let header_bytes =
            unsafe { core::slice::from_raw_parts(&header as *const _ as *const u8, header_size) };

        let mut combined_data = Vec::with_capacity(header_size + chunk.len());
        combined_data.extend_from_slice(header_bytes);
        combined_data.extend_from_slice(chunk);

        self.write_bytes(&combined_data);

        if is_last {
            self.write_pending_queue.pop_front();
        } else {
            if let Some(front_msg) = self.write_pending_queue.front_mut() {
                front_msg.offset += chunk_size;
            }
        }
    }

    pub fn available_write_space(&self) -> usize {
        let (head, tail) = self.transport.write_channel(self.role).pointers();
        let head_val = head.load(Ordering::Acquire);
        let tail_val = tail.load(Ordering::Acquire);

        if head_val >= tail_val {
            self.buffer_size - (head_val - tail_val) as usize - 1
        } else {
            (tail_val - head_val) as usize - 1
        }
    }

    fn write_bytes(&mut self, data: &[u8]) {
        if self.available_write_space() < data.len() {
            panic!(
                "Insufficient space: need {} bytes, have {} bytes",
                data.len(),
                self.available_write_space()
            );
        }

        let (head, _tail) = self.transport.write_channel(self.role).pointers();
        let head_val = head.load(Ordering::Acquire);
        let buffer = self.transport.write_buffer(self.role);
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

    fn available_read_data(&self) -> usize {
        let (head, tail) = self.transport.read_channel(self.role).pointers();
        let head_val = head.load(Ordering::Acquire);
        let tail_val = tail.load(Ordering::Acquire);

        if head_val >= tail_val {
            (head_val - tail_val) as usize
        } else {
            self.buffer_size - (tail_val - head_val) as usize
        }
    }

    fn read_bytes(&mut self, size: usize) -> Option<Vec<u8>> {
        self.read_bytes_common(size, true)
    }

    fn peek_bytes(&self, size: usize) -> Option<Vec<u8>> {
        self.read_bytes_common(size, false)
    }

    fn read_bytes_common(&self, size: usize, advance_tail: bool) -> Option<Vec<u8>> {
        if self.available_read_data() < size {
            return None;
        }

        let (_head, tail) = self.transport.read_channel(self.role).pointers();
        let tail_val = tail.load(Ordering::Acquire);
        let buffer = self.transport.read_buffer(self.role);
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
}
