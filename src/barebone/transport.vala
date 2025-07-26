[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	public struct SharedTransport {
		public const uint32 MAGIC = 0x44495246;

		public uint32 magic;
		public uint32 buffer_size;
		public Channel channel_a;
		public Channel channel_b;

		public static SharedTransport * from_memory (void * ptr, size_t size) throws Error {
			if (size < sizeof (SharedTransport)) {
				throw new Error.PROTOCOL ("Memory size %zu is too small for SharedTransport (need %zu)", size,
					sizeof (SharedTransport));
			}

			var transport = (SharedTransport *) ptr;
			if (transport->magic != MAGIC)
				throw new Error.PROTOCOL ("Invalid magic: expected 0x%08x, got 0x%08x", MAGIC, transport->magic);

			if (transport->buffer_size > size)
				throw new Error.PROTOCOL ("Buffer size %u exceeds memory size %zu", transport->buffer_size, size);

			return transport;
		}

		public TransportView as_view (TransportRole role) {
			size_t header_size = sizeof (SharedTransport);
			size_t available_data = this.buffer_size - header_size;
			size_t buffer_size_per_channel = available_data / 2;

			return new TransportView (&this, role, buffer_size_per_channel);
		}

		public uint8 * data_ptr () {
			return (uint8 *) &this + sizeof (SharedTransport);
		}

		public uint8 * channel_a_buffer () {
			return data_ptr ();
		}

		public uint8 * channel_b_buffer () {
			size_t header_size = sizeof (SharedTransport);
			size_t available_data = this.buffer_size - header_size;
			size_t buffer_size_per_channel = available_data / 2;
			return data_ptr () + buffer_size_per_channel;
		}

		public Channel * write_channel (TransportRole role) {
			return (role == TransportRole.PRIMARY) ? &this.channel_a : &this.channel_b;
		}

		public Channel * read_channel (TransportRole role) {
			return (role == TransportRole.PRIMARY) ? &this.channel_b : &this.channel_a;
		}

		public uint8 * write_buffer (TransportRole role) {
			return (role == TransportRole.PRIMARY) ? channel_a_buffer () : channel_b_buffer ();
		}

		public uint8 * read_buffer (TransportRole role) {
			return (role == TransportRole.PRIMARY) ? channel_b_buffer () : channel_a_buffer ();
		}

		public void flush () {
#if !WINDOWS
			Posix.msync ((void *) &this, buffer_size, Posix.MS_SYNC);
#endif
		}
	}

	public struct Channel {
		public uint32 head;
		public uint32 tail;
	}

	public struct MessageHeader {
		public uint16 size;
		public uint8 flags;
	}

	public const uint8 MSG_FLAG_COMPLETE = 0x01;

	public enum TransportRole {
		PRIMARY,
		SECONDARY
	}

	public class TransportView : Object {
		private SharedTransport * transport;
		private TransportRole role;
		private size_t buffer_size;
		private Gee.Queue<PendingMessage> write_pending_queue;
		private ByteArray read_fragment_buffer;

		internal TransportView (SharedTransport * transport, TransportRole role, size_t buffer_size) {
			this.transport = transport;
			this.role = role;
			this.buffer_size = buffer_size;
			this.write_pending_queue = new Gee.LinkedList<PendingMessage> ();
			this.read_fragment_buffer = new ByteArray ();
		}

		public void write_message (Bytes data) throws Error {
			flush_pending ();

			var pending = new PendingMessage (data);
			write_pending_queue.offer (pending);

			flush_pending ();
		}

		public Bytes? try_read_message () throws Error {
			size_t header_size = sizeof (MessageHeader);
			Bytes? header_data = peek_bytes (header_size);
			if (header_data == null)
				return null;

			var header = (MessageHeader *) header_data.get_data ();
			if (header->size == 0 || header->size > buffer_size) {
				throw new Error.PROTOCOL ("Protocol violation: invalid header size %u, buffer_size %zu", header->size,
					buffer_size);
			}

			size_t total_size = header_size + header->size;
			Bytes? message_data = read_bytes (total_size);
			if (message_data == null)
				return null;

			unowned uint8[] message_array = message_data.get_data ();
			unowned uint8[] payload = message_array[header_size:total_size];

			if ((header->flags & MSG_FLAG_COMPLETE) != 0) {
				if (read_fragment_buffer.len > 0) {
					read_fragment_buffer.append (payload);
					Bytes complete_message = new Bytes (read_fragment_buffer.data);
					read_fragment_buffer = new ByteArray ();
					return complete_message;
				} else {
					return new Bytes (payload);
				}
			} else {
				read_fragment_buffer.append (payload);
				return null;
			}
		}

		public void flush_pending () throws Error {
			if (write_pending_queue.is_empty)
				return;

			size_t header_size = sizeof (MessageHeader);
			size_t max_payload = buffer_size - header_size - 1;
			var pending = write_pending_queue.peek ();

			unowned uint8[] pending_data = pending.remaining_data.get_data ();
			size_t remaining = pending_data.length - pending.offset;
			size_t chunk_size = size_t.min (remaining, max_payload);
			size_t total_needed = header_size + chunk_size;

			if (available_write_space () < total_needed)
				return;

			unowned uint8[] chunk = pending_data[pending.offset:pending.offset + chunk_size];
			bool is_last = pending.offset + chunk_size >= pending_data.length;

			uint8 flags = is_last ? MSG_FLAG_COMPLETE : 0;

			var header = MessageHeader () {
				size = (uint16) chunk_size,
				flags = flags
			};

			var combined_data = new ByteArray.sized ((uint) total_needed);
			combined_data.append ((uint8[]) &header);
			combined_data.append (chunk);

			write_bytes (new Bytes.take (combined_data.steal ()));

			if (is_last)
				write_pending_queue.poll ();
			else
				pending.offset += chunk_size;
		}

		public size_t available_write_space () {
			Channel * channel = transport->write_channel (role);
			uint32 head_val = AtomicUint.@get (ref channel->head);
			uint32 tail_val = AtomicUint.@get (ref channel->tail);

			if (head_val >= tail_val)
				return buffer_size - (head_val - tail_val) - 1;
			else
				return (tail_val - head_val) - 1;
		}

		private void write_bytes (Bytes data) throws Error {
			unowned uint8[] data_array = data.get_data ();
			if (available_write_space () < data_array.length) {
				throw new Error.PROTOCOL ("Insufficient space: need %zu bytes, have %zu bytes",
					   data_array.length, available_write_space ());
			}

			Channel * channel = transport->write_channel (role);
			uint32 head_val = AtomicUint.@get (ref channel->head);
			uint8 * buffer = transport->write_buffer (role);
			size_t pos = head_val % buffer_size;

			if (pos + data_array.length <= buffer_size) {
				Memory.copy (buffer + pos, data_array, data_array.length);
			} else {
				size_t first = buffer_size - pos;
				size_t second = data_array.length - first;
				Memory.copy (buffer + pos, data_array, first);
				Memory.copy (buffer, (uint8 *) data_array + first, second);
			}

			AtomicUint.@set (ref channel->head, head_val + (uint32) data_array.length);
			transport->flush ();
		}

		private size_t available_read_data () {
			Channel * channel = transport->read_channel (role);
			uint32 head_val = AtomicUint.@get (ref channel->head);
			uint32 tail_val = AtomicUint.@get (ref channel->tail);

			if (head_val >= tail_val)
				return head_val - tail_val;
			else
				return buffer_size - (tail_val - head_val);
		}

		private Bytes? read_bytes (size_t size) {
			return read_bytes_common (size, true);
		}

		private Bytes? peek_bytes (size_t size) {
			return read_bytes_common (size, false);
		}

		private Bytes? read_bytes_common (size_t size, bool advance_tail) {
			if (available_read_data () < size)
				return null;

			Channel * channel = transport->read_channel (role);
			uint32 tail_val = AtomicUint.@get (ref channel->tail);
			uint8 * buffer = transport->read_buffer (role);
			size_t pos = tail_val % buffer_size;

			var data = new uint8[size];

			if (pos + size <= buffer_size) {
				Memory.copy (data, buffer + pos, size);
			} else {
				size_t first = buffer_size - pos;
				size_t second = size - first;
				Memory.copy (data, buffer + pos, first);
				Memory.copy ((uint8 *) data + first, buffer, second);
			}

			if (advance_tail) {
				AtomicUint.@set (ref channel->tail, tail_val + (uint32) size);
				transport->flush ();
			}

			return new Bytes.take ((owned) data);
		}
	}

	private class PendingMessage {
		public Bytes remaining_data;
		public size_t offset;

		public PendingMessage (Bytes data) {
			this.remaining_data = data;
			this.offset = 0;
		}
	}
}
