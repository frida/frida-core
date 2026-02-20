[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Kcdata {
	public delegate void ItemVisitor (ItemHeader header, uint8[] payload) throws Error;

	public struct ItemHeader {
		public ItemType type;
		public uint32 size;
		public uint64 flags;
	}

	public enum ItemType {
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

	public void parse (Bytes bytes, ItemVisitor visitor) throws Error {
		var buf = new Frida.Buffer (bytes, LITTLE_ENDIAN);
		var r = new Frida.BufferReader (buf);

		while (true) {
			var available = r.available;

			if (available == 0)
				return;

			if (available < HEADER_SIZE)
				throw new Error.PROTOCOL ("KCDATA truncated at %zu (need header, avail=%zu)", r.offset, available);

			size_t item_start = r.offset;

			var h = ItemHeader ();
			h.type = (ItemType) r.read_uint32 ();
			h.size = r.read_uint32 ();
			h.flags = r.read_uint64 ();

			if (h.size > r.available) {
				throw new Error.PROTOCOL ("KCDATA truncated at %zu (type=0x%x size=%u avail=%zu)",
					item_start, (uint32) h.type, h.size, r.available);
			}

			unowned uint8[] payload = r.read_data (h.size);
			visitor (h, payload);

			size_t rem = r.offset & (ALIGNMENT_SIZE - 1);
			if (rem != 0) {
				size_t pad = ALIGNMENT_SIZE - rem;
				if (pad > r.available) {
					throw new Error.PROTOCOL ("KCDATA truncated at %zu (need pad=%zu avail=%zu)",
						r.offset, pad, r.available);
				}
				r.skip (pad);
			}
		}
	}
}
