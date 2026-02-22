[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Kcdata {
	public delegate void ItemVisitor (ItemHeader header, BufferReader payload) throws Error;

	public struct ItemHeader {
		public ItemType type;
		public uint32 size;
		public uint64 flags;
	}

	public enum ItemType : uint32 {
		BUFFER_BEGIN_STACKSHOT	= 0x59a25807u,
		BUFFER_END		= 0xf19158edu,

		CONTAINER_BEGIN		= 0x00000013u,
		CONTAINER_END		= 0x00000014u,

		UINT32_DESC		= 0x00000002u,
		UINT64_DESC		= 0x00000003u,

		ARRAY_PAD0		= 0x20,
		ARRAY_PAD1		= 0x21,
		ARRAY_PAD2		= 0x22,
		ARRAY_PAD3		= 0x23,
		ARRAY_PAD4		= 0x24,
		ARRAY_PAD5		= 0x25,
		ARRAY_PAD6		= 0x26,
		ARRAY_PAD7		= 0x27,
		ARRAY_PAD8		= 0x28,
		ARRAY_PAD9		= 0x29,
		ARRAY_PADa		= 0x2a,
		ARRAY_PADb		= 0x2b,
		ARRAY_PADc		= 0x2c,
		ARRAY_PADd		= 0x2d,
		ARRAY_PADe		= 0x2e,
		ARRAY_PADf		= 0x2f,
	}

	private const size_t HEADER_SIZE = 16;
	private const size_t ALIGNMENT_SIZE = 16;

	public sealed class Reader : Object {
		public size_t offset {
			get {
				return r.offset;
			}
		}

		public size_t available {
			get {
				return r.available;
			}
		}

		public bool eof {
			get {
				return r.available == 0;
			}
		}

		private Buffer buf;
		private BufferReader r;

		private Buffer payload_buf;
		private BufferReader payload_r;

		public Reader (Bytes bytes) {
			buf = new Buffer (bytes, LITTLE_ENDIAN);
			r = new BufferReader (buf);

			payload_buf = new Buffer.from_data ((uint8[]) null, buf.byte_order, buf.pointer_size);
			payload_r = new BufferReader (payload_buf);
		}

		public ItemHeader peek_header () throws Error {
			if (r.available < HEADER_SIZE)
				throw new Error.PROTOCOL ("KCDATA truncated at %zu (need header, avail=%zu)", r.offset, r.available);

			size_t item_start = r.offset;

			var h = ItemHeader ();
			h.type = (ItemType) buf.read_uint32 (item_start);
			h.size = buf.read_uint32 (item_start + 4);
			h.flags = buf.read_uint64 (item_start + 8);

			if (h.size > (r.available - HEADER_SIZE)) {
				throw new Error.PROTOCOL ("KCDATA truncated at %zu (type=0x%x size=%u avail=%zu)", item_start,
					(uint32) h.type, h.size, r.available - HEADER_SIZE);
			}

			return h;
		}

		public ItemHeader read_header () throws Error {
			if (r.available < HEADER_SIZE)
				throw new Error.PROTOCOL ("KCDATA truncated at %zu (need header, avail=%zu)", r.offset, r.available);

			size_t item_start = r.offset;

			var h = ItemHeader ();
			h.type = (ItemType) r.read_uint32 ();
			h.size = r.read_uint32 ();
			h.flags = r.read_uint64 ();

			if (h.size > r.available) {
				throw new Error.PROTOCOL ("KCDATA truncated at %zu (type=0x%x size=%u avail=%zu)", item_start,
					(uint32) h.type, h.size, r.available);
			}

			return h;
		}

		public unowned BufferReader read_payload (ItemHeader h) throws Error {
			unowned uint8[] payload = r.read_data (h.size);

			payload_buf.reset_data (payload);
			payload_r.reset (payload_buf);

			r.align (ALIGNMENT_SIZE);

			return payload_r;
		}

		public void skip_payload (ItemHeader h) throws Error {
			read_payload (h);
		}

		public bool read_item (out ItemHeader h, out unowned BufferReader payload) throws Error {
			if (r.available == 0) {
				h = ItemHeader ();
				payload = null;
				return false;
			}

			h = read_header ();
			payload = read_payload (h);
			return true;
		}
	}

	public void parse (Bytes bytes, ItemVisitor visitor) throws Error {
		var r = new Reader (bytes);

		ItemHeader h;
		unowned BufferReader payload;

		while (r.read_item (out h, out payload))
			visitor (h, payload);
	}
}
