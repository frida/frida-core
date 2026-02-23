[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
	public class CsSignature : Object {
		public uint32 version;
		public uint32 pid;
		public uint32 stuff;
		public uint32 flags;

		public Gee.List<CsSigOwner> owners = new Gee.ArrayList<CsSigOwner> ();
	}

	public class CsSigOwner : Object {
		public uint8[] uuid = new uint8[16];

		public uint32 a;
		public uint32 flags;

		public uint64 x;
		public uint64 y;

		public uint64 arch;

		public string path;
		public Gee.List<CsSigSegment> segments = new Gee.ArrayList<CsSigSegment> ();

		public string? version;
	}

	public class CsSigSegment {
		public string name;
		public uint64 vmaddr;
		public uint64 vmsize;
	}

	public sealed class CsSignatureParser : Object {
		private Buffer buf;
		private BufferReader r;

		public CsSignatureParser (Bytes blob) {
			buf = new Buffer (blob, LITTLE_ENDIAN, 8);
			r = new BufferReader (buf);
		}

		public CsSignature parse () throws Error {
			uint32 magic = r.read_uint32 ();
			uint32 sig_version = r.read_uint32 ();
			uint32 pid = r.read_uint32 ();
			uint32 stuff = r.read_uint32 ();
			uint32 flags = r.read_uint32 ();
			uint32 owner_count = r.read_uint32 ();

			if (magic != 0xff01ff02u)
				throw new Error.PROTOCOL ("Bad signature magic 0x%08x", magic);

			var sig = new CsSignature ();
			sig.version = sig_version;
			sig.pid = pid;
			sig.stuff = stuff;
			sig.flags = flags;

			for (uint32 i = 0; i != owner_count; i++)
				sig.owners.add (parse_owner ());

			decode_optional_data (sig);

			return sig;
		}

		private CsSigOwner parse_owner () throws Error {
			var o = new CsSigOwner ();

			unowned uint8[] uuid_slice = r.read_data (16);
			for (int i = 0; i != 16; i++)
				o.uuid[i] = uuid_slice[i];

			o.a = r.read_uint32 ();
			o.flags = r.read_uint32 () & 0x7fffffff;

			o.x = r.read_uint64 ();

			o.y = r.read_uint64 ();
			if ((o.y & 0x8000000000000000ULL) != 0)
				o.y = 0x7fffffffffffffffULL;

			uint32 arch_lo = r.read_uint32 ();
			uint32 arch_hi = r.read_uint32 ();
			o.arch = ((uint64) arch_hi << 32) | (uint64) arch_lo;

			uint32 nsegs = r.read_uint32 ();
			uint32 str_len = r.read_uint32 ();

			o.path = r.read_fixed_string (str_len);

			for (uint32 i = 0; i != nsegs; i++) {
				var s = new CsSigSegment ();
				s.name = r.read_fixed_string (16);
				s.vmaddr = r.read_uint64 ();
				s.vmsize = r.read_uint64 ();
				o.segments.add (s);
			}

			return o;
		}

		private void decode_optional_data (CsSignature sig) throws Error {
			if (r.available < 8)
				return;

			size_t start = r.offset;

			uint64 hdr = r.read_uint64 ();
			uint32 magic = (uint32) (hdr & 0xffffffffu);
			uint32 sel = (uint32) (hdr >> 32);

			if (magic != 0x00c0ffeeu) {
				r.seek (start);
				return;
			}

			if (sel == 2) {
				if (r.available < 0x18)
					throw new Error.PROTOCOL ("Optional v2 truncated");
				r.skip (0x18);
				return;
			}

			if (sel == 3) {
				skip_optional_v3 ();
				return;
			}

			if (sel != 4)
				return;

			size_t v3_start = r.offset;

			uint32 count = skip_optional_v3 ();

			size_t table_end = v3_start + 0x38 + (size_t) count * 0x60;
			if (table_end + 4 > buf.size)
				throw new Error.PROTOCOL ("Optional v4 truncated");

			r.seek (table_end);

			uint32 strings_size = r.read_uint32 ();
			size_t strings_start = r.offset;
			size_t strings_end = strings_start + (size_t) strings_size;

			if (strings_end > buf.size)
				throw new Error.PROTOCOL ("Optional v4 strings overrun");

			r.seek (strings_start);

			for (int i = 0; i < sig.owners.size; i++) {
				if (r.offset >= strings_end)
					throw new Error.PROTOCOL ("Optional v4 strings truncated");

				sig.owners[i].version = r.read_string ();
			}

			r.seek (v3_start + 0x3c + (size_t) count * 0x60 + (size_t) strings_size);
		}

		private uint32 skip_optional_v3 () throws Error {
			if (r.available < 0x38)
				throw new Error.PROTOCOL ("Optional v3 truncated");

			size_t base_offset = r.offset;

			r.skip (0x30);
			r.read_uint8 ();
			r.skip (3);

			uint32 count = r.read_uint32 ();

			size_t total = 0x38 + (size_t) count * 0x60;

			if (base_offset + total > buf.size)
				throw new Error.PROTOCOL ("Optional v3 overrun");

			r.seek (base_offset + total);

			return count;
		}
	}
}
