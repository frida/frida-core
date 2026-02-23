[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
	public class CsSignature : Object {
		public uint32 version;
		public uint32 pid;
		public uint32 stuff;
		public uint32 flags;

		public Gee.List<CsSigOwner> owners = new Gee.ArrayList<CsSigOwner> ();

		private CsSegIndexEntry[]? seg_index = null;

		private struct CsSegIndexEntry {
			public uint64 start;
			public uint64 end;
			public unowned CsSigOwner owner;
		}

		public void resolve_addresses (uint64[] addrs, AddressResolved on_symbol, ModulesReady on_modules) {
			ensure_index ();

			var used_owner_to_mod = new Gee.HashMap<CsSigOwner, uint32> ();
			var module_list = new Gee.ArrayList<string> ();

			foreach (var addr in addrs) {
				CsSigOwner? owner;
				uint32 rel;

				if (!try_resolve (addr, out owner, out rel)) {
					on_symbol (addr, uint32.MAX, 0);
					continue;
				}

				uint32 mod_idx;
				if (!used_owner_to_mod.has_key (owner)) {
					mod_idx = (uint32) module_list.size;
					used_owner_to_mod[owner] = mod_idx;
					module_list.add (owner.path);
				} else {
					mod_idx = used_owner_to_mod[owner];
				}

				on_symbol (addr, mod_idx, rel);
			}

			on_modules (module_list);
		}

		public delegate void AddressResolved (uint64 addr, uint32 module_index, uint32 rel);
		public delegate void ModulesReady (Gee.List<string> modules);

		private void ensure_index () {
			if (seg_index != null)
				return;

			var tmp = new Array<CsSegIndexEntry> (false, false);

			foreach (var owner in owners) {
				foreach (var seg in owner.segments) {
					if (seg.name == "__PAGEZERO")
						continue;
					tmp.append_val (CsSegIndexEntry () {
						start = seg.vmaddr,
						end = seg.vmaddr + seg.vmsize,
						owner = owner,
					});
				}
			}

			tmp.sort ((a, b) => {
				if (a.start < b.start)
					return -1;
				if (a.start > b.start)
					return 1;
				return 0;
			});

			seg_index = tmp.steal ();
		}

		private bool try_resolve (uint64 addr, out CsSigOwner? owner, out uint32 rel) {
			owner = null;
			rel = 0;

			int n = seg_index.length;
			if (n == 0)
				return false;

			int lo = 0;
			int hi = n - 1;
			int best = -1;

			while (lo <= hi) {
				int mid = lo + ((hi - lo) / 2);
				if (seg_index[mid].start <= addr) {
					best = mid;
					lo = mid + 1;
				} else {
					hi = mid - 1;
				}
			}

			if (best == -1)
				return false;

			for (int i = best; i >= 0; i--) {
				var e = seg_index[i];
				if (e.start > addr)
					continue;

				if (addr < e.end) {
					owner = e.owner;
					rel = (uint32) (addr - owner.image_base);
					return true;
				}
			}

			return false;
		}
	}

	public class CsSigOwner : Object {
		public uint8[] uuid = new uint8[16];

		public uint32 a;
		public uint32 flags;

		public uint64 x;
		public uint64 y;

		public uint64 arch;

		public string path;
		public uint64 image_base;
		public uint64 image_end;
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

			o.segments.sort ((a, b) => {
				if (a.vmaddr < b.vmaddr)
					return -1;
				if (a.vmaddr > b.vmaddr)
					return 1;
				return 0;
			});

			uint64 image_base = uint64.MAX;
			uint64 image_end = 0;

			foreach (var seg in o.segments) {
				if (seg.name != "__PAGEZERO" && seg.vmaddr < image_base)
					image_base = seg.vmaddr;

				uint64 seg_end = seg.vmaddr + seg.vmsize;
				if (seg_end > image_end)
					image_end = seg_end;
			}

			o.image_base = image_base;
			o.image_end = image_end;

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
