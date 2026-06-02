[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	/**
	 * Translates static kernelcache addresses to their runtime locations.
	 *
	 * The on-device kernel collection slides each segment independently (the SPTM loader scatters
	 * __TEXT, __TEXT_EXEC, __DATA_CONST, ... to unrelated runtime addresses), so a single KASLR
	 * slide cannot map a static address to its runtime location. The in-memory com.apple.kernel
	 * Mach-O header carries the rebased per-segment vmaddrs; we pair them with the static segment
	 * table (same header, same order) to translate any static address.
	 */
	public sealed class KernelRelocation : Object {
		public uint64 reference_base {
			get;
			private set;
		}

		private Gee.List<Entry> entries = new Gee.ArrayList<Entry> ();

		private const size_t KERNEL_PAGE_SIZE = 0x4000;
		private const size_t HEADER_PROBE_SPAN = 0x20000;
		private const uint64 COLLECTION_WINDOW = 0x8000000;
		private const uint32 MH_MAGIC_64 = 0xfeedfacfU;
		private const uint32 MH_EXECUTE = 0x2;
		private const uint32 MH_FILESET = 0xc;
		private const uint32 CPU_TYPE_ARM64 = 0x0100000cU;
		private const uint32 LC_SEGMENT_64 = 0x19;
		private const uint32 LC_FILESET_ENTRY = 0x80000035U;

		public static async KernelRelocation compute (Machine machine, Bytes kernelcache_blob, Cancellable? cancellable)
				throws Error, IOError {
			var gdb = machine.gdb;
			Buffer image = gdb.make_buffer (kernelcache_blob);
			size_t kernel_header_offset = (size_t) find_kernel_fileoff (image);
			Gee.List<SegmentInfo> static_segments = parse_segments (image, kernel_header_offset);

			uint64 runtime_header = yield find_kernel_header (machine, cancellable);
			uint32 header_span = 32 + image.read_uint32 (kernel_header_offset + 20);
			Buffer runtime_image = yield gdb.read_buffer (runtime_header, header_span, cancellable);
			Gee.List<SegmentInfo> runtime_segments = parse_segments (runtime_image, 0);

			var reloc = new KernelRelocation ();
			reloc.reference_base = runtime_header;
			for (int i = 0; i != static_segments.size; i++) {
				reloc.entries.add (new Entry () {
					static_base = static_segments[i].vmaddr,
					size = static_segments[i].vmsize,
					runtime_base = runtime_segments[i].vmaddr
				});
			}
			return reloc;
		}

		public uint64 translate (uint64 static_address) throws Error {
			foreach (var e in entries) {
				if (static_address >= e.static_base && static_address < e.static_base + e.size)
					return e.runtime_base + (static_address - e.static_base);
			}
			throw new Error.INVALID_ARGUMENT ("Address 0x%" + uint64.FORMAT_MODIFIER + "x is outside the kernelcache",
				static_address);
		}

		public uint32 runtime_offset (uint64 static_address) throws Error {
			return (uint32) (translate (static_address) - reference_base);
		}

		/**
		 * Reads of unmapped memory wedge the VZ stub indefinitely, so the runtime header cannot be
		 * located by blind-scanning down from a kernel pointer: scattered segments leave unmapped
		 * gaps in between. We instead walk the kernel's own page tables for the readable ranges and
		 * probe only the first pages of each — every byte touched is guaranteed mapped.
		 */
		private static async uint64 find_kernel_header (Machine machine, Cancellable? cancellable)
				throws Error, IOError {
			var gdb = machine.gdb;

			uint64 vbar = yield gdb.exception.thread.read_register ("vbar_el1", cancellable);

			var range_bases = new Gee.ArrayList<uint64?> ();
			var range_sizes = new Gee.ArrayList<uint64?> ();
			yield machine.enumerate_ranges (Gum.PageProtection.READ, details => {
				if (details.base_va < vbar - COLLECTION_WINDOW || details.base_va > vbar + COLLECTION_WINDOW)
					return true;
				range_bases.add (details.base_va);
				range_sizes.add (details.size);
				return true;
			}, cancellable);

			for (int i = 0; i != range_bases.size; i++) {
				uint64 range_base = range_bases[i];
				if (range_sizes[i] < 16)
					continue;
				Buffer head = yield gdb.read_buffer (range_base, 16, cancellable);
				if (head.read_uint32 (0) != MH_MAGIC_64 || head.read_uint32 (4) != CPU_TYPE_ARM64)
					continue;

				uint32 filetype = head.read_uint32 (12);
				if (filetype == MH_EXECUTE)
					return range_base;
				if (filetype != MH_FILESET)
					continue;

				size_t span = (size_t) uint64.min (range_sizes[i], HEADER_PROBE_SPAN);
				Buffer region = yield gdb.read_buffer (range_base, span, cancellable);
				for (size_t off = KERNEL_PAGE_SIZE; off + 16 <= span; off += KERNEL_PAGE_SIZE) {
					if (region.read_uint32 (off) == MH_MAGIC_64 && region.read_uint32 (off + 4) == CPU_TYPE_ARM64
							&& region.read_uint32 (off + 12) == MH_EXECUTE)
						return range_base + off;
				}
			}
			throw new Error.NOT_SUPPORTED ("Unable to locate the runtime com.apple.kernel header");
		}

		private static uint64 find_kernel_fileoff (Buffer image) throws Error {
			uint32 ncmds = image.read_uint32 (16);
			size_t off = 32;
			for (uint32 i = 0; i != ncmds; i++) {
				uint32 cmd = image.read_uint32 (off);
				uint32 cmdsize = image.read_uint32 (off + 4);
				if (cmd == LC_FILESET_ENTRY && read_lc_string (image, off + 0x20) == "com.apple.kernel")
					return image.read_uint64 (off + 16);
				off += cmdsize;
			}
			throw new Error.NOT_SUPPORTED ("Kernelcache is missing the com.apple.kernel fileset entry");
		}

		private static Gee.List<SegmentInfo> parse_segments (Buffer image, size_t header_offset) throws Error {
			var result = new Gee.ArrayList<SegmentInfo> ();
			uint32 ncmds = image.read_uint32 (header_offset + 16);
			size_t off = header_offset + 32;
			for (uint32 i = 0; i != ncmds; i++) {
				uint32 cmd = image.read_uint32 (off);
				uint32 cmdsize = image.read_uint32 (off + 4);
				if (cmd == LC_SEGMENT_64) {
					result.add (new SegmentInfo () {
						vmaddr = image.read_uint64 (off + 24),
						vmsize = image.read_uint64 (off + 32)
					});
				}
				off += cmdsize;
			}
			return result;
		}

		private static string read_lc_string (Buffer image, size_t offset) throws Error {
			var builder = new StringBuilder ();
			for (size_t i = 0; ; i++) {
				uint8 c = image.read_uint8 (offset + i);
				if (c == 0)
					break;
				builder.append_c ((char) c);
			}
			return builder.str;
		}

		private class SegmentInfo {
			public uint64 vmaddr;
			public uint64 vmsize;
		}

		private class Entry {
			public uint64 static_base;
			public uint64 size;
			public uint64 runtime_base;
		}
	}
}
