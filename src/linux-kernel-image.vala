namespace Frida {
	/**
	 * What a Linux kernel names, taken from wherever the caller happens to have it. Ask it
	 * what the kernel names to tell what a guest supports before anything is launched, and
	 * hand it to a barebone session so nothing is read twice.
	 */
	public abstract class LinuxKernelSymbols : Object {
		/**
		 * Whether the kernel names @name.
		 *
		 * @param name the symbol to look for
		 */
		public bool has_symbol (string name) {
			uint64 address;
			return try_find_symbol (name, out address);
		}

		/**
		 * Looks up the address @name was linked for.
		 *
		 * @param name the symbol to look for
		 * @param address the address it was linked for
		 */
		public abstract bool try_find_symbol (string name, out uint64 address);

		internal Gee.List<LinuxKernelSymbol> to_list () {
			var image = this as LinuxKernelImage;
			if (image != null)
				return image.table.to_list ();

			return ((LinuxSystemMap) this).symbols;
		}
	}

	/**
	 * A kernel image: a raw one, a gzip-compressed one, or a bzImage whose payload is packed
	 * with LZ4. Its symbols come from the kallsyms tables embedded in it.
	 */
	public sealed class LinuxKernelImage : LinuxKernelSymbols {
		internal KallsymsTable table;

		private LinuxKernelImage (KallsymsTable table) {
			this.table = table;
		}

		/**
		 * Finds the kallsyms tables in @blob, without decoding the names yet.
		 *
		 * @param blob the kernel image
		 */
		public static LinuxKernelImage from_blob (Bytes blob) throws Error {
			return new LinuxKernelImage (KallsymsTable.load (blob.get_data ()));
		}

		/**
		 * Reads the kernel image at @path.
		 *
		 * @param path the image's location
		 */
		public static LinuxKernelImage open (string path) throws Error {
			return from_blob (FS.read_all_bytes_sync (File.new_for_path (path)));
		}

		public override bool try_find_symbol (string name, out uint64 address) {
			return table.try_find (name, out address);
		}
	}

	/**
	 * The System.map a kernel build leaves beside its image: a line per symbol, each an
	 * address, a one-letter type, and a name.
	 */
	public sealed class LinuxSystemMap : LinuxKernelSymbols {
		internal Gee.List<LinuxKernelSymbol> symbols;

		private LinuxSystemMap (Gee.List<LinuxKernelSymbol> symbols) {
			this.symbols = symbols;
		}

		/**
		 * Reads a System.map.
		 *
		 * @param blob the map's text
		 */
		public static LinuxSystemMap from_blob (Bytes blob) throws Error {
			var symbols = new Gee.ArrayList<LinuxKernelSymbol> ();

			var text = (string) blob.get_data ();
			foreach (unowned string line in text.split ("
")) {
				string[] fields = line.split (" ", 3);
				if (fields.length != 3)
					continue;

				uint64 address;
				if (!uint64.try_parse (fields[0], out address, null, 16))
					continue;

				symbols.add (new LinuxKernelSymbol () {
					name = fields[2].strip (),
					address = address,
					symbol_type = 0xf,
					section = 0x10,
				});
			}

			if (symbols.is_empty)
				throw new Error.INVALID_ARGUMENT ("Map names no symbols");

			return new LinuxSystemMap (symbols);
		}

		/**
		 * Reads the System.map at @path.
		 *
		 * @param path the map's location
		 */
		public static LinuxSystemMap open (string path) throws Error {
			return from_blob (FS.read_all_bytes_sync (File.new_for_path (path)));
		}

		public override bool try_find_symbol (string name, out uint64 address) {
			foreach (var symbol in symbols) {
				if (symbol.name == name) {
					address = symbol.address;
					return true;
				}
			}

			address = 0;
			return false;
		}
	}

	internal class LinuxKernelSymbol {
		public string name;
		public uint64 address;
		public uint8 symbol_type;
		public uint8 section;
	}

	/**
	 * Reconstructs a kernel's symbols from the kallsyms tables embedded in its on-disk image,
	 * so a System.map is not needed. The image is a raw kernel, a gzip-compressed one, or an
	 * x86 bzImage whose payload is packed with LZ4, which Android builds its x86 kernels with.
	 * The tables are located by their structure and the names are decoded with the token table,
	 * pairing each name with the address it was linked for.
	 */
	internal class KallsymsTable {
		private uint8[] raw;
		private string[] tokens;
		private uint num_syms;
		private uint table_pos;
		private uint names_pos;
		private uint64 relative_base;
		private bool absolute;
		private bool percpu;

		public static KallsymsTable load (uint8[] image) throws Error {
			var table = new KallsymsTable ();
			table.raw = unpack (image);
			uint tokens_pos;
			table.tokens = find_tokens (table.raw, out tokens_pos);

			if (find_percpu_layout (table.raw, table.tokens, out table.table_pos, out table.num_syms,
					out table.relative_base, out table.names_pos)) {
				table.absolute = false;
				table.percpu = true;
				return table;
			}

			uint claimed_pos = 0;
			uint claimed_syms = 0;
			uint64 claimed_base = 0;
			bool claimed_absolute = false;
			bool addresses_found = true;
			try {
				claimed_absolute = find_addresses (table.raw, tokens_pos, out claimed_pos,
					out claimed_syms, out claimed_base);
			} catch (Error e) {
				addresses_found = false;
			}

			uint exact_pos, counted_pos, counted_syms;
			uint32 longest;
			scan_names (table.raw, table.tokens, tokens_pos, claimed_syms, out exact_pos, out longest,
				out counted_pos, out counted_syms);

			if (addresses_found && exact_pos != 0 && longest <= claimed_syms * 2) {
				table.absolute = claimed_absolute;
				table.table_pos = claimed_pos;
				table.num_syms = claimed_syms;
				table.relative_base = claimed_base;
				table.names_pos = exact_pos;
				return table;
			}

			bool got_offsets = counted_syms != 0 && find_offsets (table.raw, counted_syms,
				out table.table_pos, out table.relative_base);
			if (got_offsets) {
				table.absolute = false;
				table.num_syms = counted_syms;
				table.names_pos = counted_pos;
				table.percpu = offsets_hold_absolute_percpu (table.raw, table.table_pos,
					table.num_syms);
				return table;
			}

			throw new Error.NOT_SUPPORTED ("Unable to locate the kallsyms tables in kernel image");
		}

		public bool try_find (string name, out uint64 address) {
			uint p = names_pos;
			for (uint i = 0; i != num_syms; i++) {
				uint len = raw[p];
				uint start = p + 1;
				if ((len & 0x80) != 0) {
					len = (len & 0x7f) | (raw[start] << 7);
					start++;
				}

				if (names_symbol (start, len, name)) {
					address = address_at (i);
					return true;
				}

				p = start + len;
			}

			address = 0;
			return false;
		}

		public Gee.List<LinuxKernelSymbol> to_list () {
			var symbols = new Gee.ArrayList<LinuxKernelSymbol> ();
			uint p = names_pos;
			for (uint i = 0; i != num_syms; i++) {
				string name;
				p = decode_symbol (raw, p, tokens, out name);
				if (name.length < 2)
					continue;
				symbols.add (new LinuxKernelSymbol () {
					name = name.substring (1),
					address = address_at (i),
					symbol_type = 0xf,
					section = 0x10,
				});
			}
			return symbols;
		}

		/**
		 * Compares a name against its tokens where it sits, so nothing is built to throw away.
		 * The first character each symbol carries is its type, which the caller does not name.
		 */
		private bool names_symbol (uint start, uint len, string name) {
			char* needle = (char*) name;
			bool typed = false;

			for (uint i = 0; i != len; i++) {
				char* c = (char*) tokens[raw[start + i]];
				if (!typed) {
					if (*c == '\0')
						return false;
					c++;
					typed = true;
				}

				for (; *c != '\0'; c++) {
					if (*needle != *c)
						return false;
					needle++;
				}
			}

			return typed && *needle == '\0';
		}

		private uint64 address_at (uint i) {
			if (absolute)
				return read_u64 (raw, table_pos + i * 8);

			int32 offset = read_i32 (raw, table_pos + i * 4);
			if (!percpu)
				return relative_base + (int64) offset;

			return (offset >= 0)
				? (uint64) offset
				: relative_base - 1 + (uint64) (-(int64) offset);
		}

		private const uint MIN_SYMS = 1024;
		private const uint MAX_SYMS = 4000000;

		private static uint8[] unpack (uint8[] image) throws Error {
			if (image.length >= 4 && image[0] == 0x1f && image[1] == 0x8b)
				return gunzip (image);

			uint8[]? payload = find_lz4_payload (image);
			if (payload != null)
				return payload;

			payload = find_gzip_payload (image);
			if (payload != null)
				return payload;

			return image;
		}

		private static uint8[]? find_gzip_payload (uint8[] image) {
			uint n = image.length;
			for (uint i = 0; i + 3 <= n; i++) {
				if (image[i] != 0x1f || image[i + 1] != 0x8b || image[i + 2] != 0x08)
					continue;

				uint8[] rest = image[i:n];
				try {
					uint8[] payload = gunzip (rest);
					if (payload.length >= MIN_PAYLOAD_SIZE)
						return payload;
				} catch (Error e) {
				}
			}
			return null;
		}

		private static uint8[] gunzip (uint8[] image) throws Error {
			try {
				var decompressor = new ZlibDecompressor (ZlibCompressorFormat.GZIP);
				var source = new MemoryInputStream.from_data (image, null);
				var stream = new ConverterInputStream (source, decompressor);
				var output = new MemoryOutputStream.resizable ();
				output.splice (stream, OutputStreamSpliceFlags.CLOSE_TARGET);
				size_t size = output.get_data_size ();
				uint8[] buffer = output.steal_data ();
				buffer.length = (int) size;
				return buffer;
			} catch (GLib.Error e) {
				throw new Error.NOT_SUPPORTED ("Unable to decompress kernel image: %s", e.message);
			}
		}

		private static uint8[]? find_lz4_payload (uint8[] image) {
			uint n = image.length;
			for (uint i = 0; i + 8 <= n; i++) {
				if (image[i] != 0x02 || image[i + 1] != 0x21 || image[i + 2] != 0x4c || image[i + 3] != 0x18)
					continue;
				uint8[]? payload = inflate_lz4_legacy (image, i + 4);
				if (payload != null)
					return payload;
			}
			return null;
		}

		private const uint INFLATE_INITIAL_SIZE = 16 * 1024 * 1024;
		private const uint MIN_PAYLOAD_SIZE = 1024 * 1024;
		private const uint MAX_PAYLOAD_SIZE = 256 * 1024 * 1024;
		private const uint MAX_BLOCK_SIZE = 16 * 1024 * 1024;

		private static uint8[]? inflate_lz4_legacy (uint8[] image, uint start) {
			uint n = image.length;
			uint guess = uint.min ((uint) image.length * 4, MAX_PAYLOAD_SIZE);
			var output = new uint8[uint.max (guess, INFLATE_INITIAL_SIZE)];
			uint filled = 0;

			uint pos = start;
			while (pos + 4 <= n) {
				uint size = image[pos] | (image[pos + 1] << 8) | (image[pos + 2] << 16) |
					((uint) image[pos + 3] << 24);
				pos += 4;
				if (size == 0 || size > MAX_BLOCK_SIZE || pos + size > n)
					break;
				if (!inflate_lz4_block (image, pos, size, ref output, ref filled))
					break;
				pos += size;
				if (filled >= MAX_PAYLOAD_SIZE)
					break;
			}

			if (filled < MIN_PAYLOAD_SIZE)
				return null;
			output.resize ((int) filled);
			return output;
		}

		private static bool inflate_lz4_block (uint8[] image, uint start, uint size, ref uint8[] output,
				ref uint filled) {
			uint end = start + size;
			uint p = start;

			while (p < end) {
				uint token = image[p++];

				uint literals = token >> 4;
				if (literals == 15 && !read_length_extension (image, ref p, end, ref literals))
					return false;
				if (p + literals > end)
					return false;
				if (literals != 0) {
					if (filled + literals > output.length)
						reserve (ref output, filled + literals);
					Memory.copy (&output[filled], &image[p], literals);
					filled += literals;
					p += literals;
				}

				if (p == end)
					break;
				if (p + 2 > end)
					return false;
				uint offset = image[p] | (image[p + 1] << 8);
				p += 2;
				if (offset == 0 || offset > filled)
					return false;

				uint length = token & 15;
				if (length == 15 && !read_length_extension (image, ref p, end, ref length))
					return false;
				length += 4;

				if (filled + length > output.length)
					reserve (ref output, filled + length);
				uint from = filled - offset;
				if (offset >= length) {
					Memory.copy (&output[filled], &output[from], length);
				} else {
					for (uint i = 0; i != length; i++)
						output[filled + i] = output[from + i];
				}
				filled += length;
			}

			return true;
		}

		private static bool read_length_extension (uint8[] image, ref uint p, uint end, ref uint length) {
			while (p < end) {
				uint b = image[p++];
				length += b;
				if (b != 255)
					return true;
			}
			return false;
		}

		private static void reserve (ref uint8[] output, uint needed) {
			uint size = output.length;
			if (needed <= size)
				return;
			while (size < needed)
				size *= 2;
			output.resize ((int) size);
		}

		/**
		 * kallsyms_token_index is 256 little-endian uint16 cumulative offsets, and the token
		 * table is the 256 NUL-terminated tokens right before it. The index is distinctive:
		 * it starts at 0 and rises by each token's length. A matching base is where every
		 * token's terminator lands, and the tokens then read as mostly-printable BPE fragments.
		 */
		private static string[] find_tokens (uint8[] raw, out uint tokens_pos) throws Error {
			tokens_pos = 0;
			uint n = raw.length;
			var index = new uint16[256];
			for (uint i = 0; i + 512 <= n; i += 2) {
				if (raw[i] != 0 || raw[i + 1] != 0)
					continue;

				uint first = raw[i + 2] | (raw[i + 3] << 8);
				if (first < 1 || first > 255)
					continue;

				uint prev = 0;
				bool monotonic = true;
				for (uint k = 1; k != 256; k++) {
					uint v = raw[i + 2 * k] | (raw[i + 2 * k + 1] << 8);
					uint delta = v - prev;
					if (delta < 1 || delta > 255) {
						monotonic = false;
						break;
					}
					index[k] = (uint16) v;
					prev = v;
				}
				if (!monotonic)
					continue;

				string[]? tokens = reconstruct_tokens (raw, i, index, out tokens_pos);
				if (tokens != null)
					return tokens;
			}
			throw new Error.NOT_SUPPORTED ("Unable to locate kallsyms token table in kernel image");
		}

		private static string[]? reconstruct_tokens (uint8[] raw, uint index_pos, uint16[] index,
				out uint tokens_pos) {
			tokens_pos = 0;
			uint idx_last = index[255];
			if (index_pos < idx_last + 2)
				return null;
			uint search_lo = (index_pos > idx_last + 4096) ? index_pos - idx_last - 4096 : 0;
			for (uint table_base = index_pos - idx_last - 2; table_base >= search_lo; table_base--) {
				bool aligned = true;
				for (uint k = 1; k != 256; k++) {
					if (raw[table_base + index[k] - 1] != 0) {
						aligned = false;
						break;
					}
				}
				if (aligned) {
					uint printable = 0;
					uint total = 0;
					uint non_empty = 0;
					for (uint k = 0; k != 256; k++) {
						uint start = table_base + index[k];
						uint end = start;
						while (end < index_pos && raw[end] != 0)
							end++;
						if (end > start)
							non_empty++;
						for (uint b = start; b != end; b++) {
							total++;
							if (raw[b] >= 0x20 && raw[b] < 0x7f)
								printable++;
						}
					}
					// A real token table is 256 non-trivial byte-pair fragments; a run of
					// mostly-empty tokens is a lookalike index, not the table.
					if (non_empty >= 200 && printable >= (total * 90) / 100) {
						var tokens = new string[256];
						for (uint k = 0; k != 256; k++) {
							uint start = table_base + index[k];
							uint end = start;
							while (end < index_pos && raw[end] != 0)
								end++;
							tokens[k] = slice_to_string (raw, start, end);
						}
						tokens_pos = table_base;
						return tokens;
					}
				}
				if (table_base == 0)
					break;
			}
			return null;
		}

		/**
		 * The address of each symbol is stored one of two ways. A modern kernel keeps a signed
		 * 32-bit offset per symbol (kallsyms_offsets) and a base to add them to
		 * (kallsyms_relative_base); an older one keeps the absolute 64-bit address per symbol
		 * (kallsyms_addresses). Both are sorted by address, so each is the longest ascending run
		 * of its word size. The relative form is tried first and confirmed by the kernel pointer
		 * that follows it; failing that, the absolute form is located. Returns whether the table
		 * is absolute.
		 */
		private static bool find_addresses (uint8[] raw, uint limit, out uint table_pos,
				out uint num_syms, out uint64 relative_base) throws Error {
			relative_base = 0;

			uint offsets_words;
			uint offsets_pos = longest_ascending_run (raw, limit, 4, 0, 0x8000000, out offsets_words);
			if (offsets_words >= 1024) {
				uint after_offsets = offsets_pos + offsets_words * 4;
				uint64 candidate = read_u64 (raw, (after_offsets + 7) & ~((uint) 7));
				if (looks_like_kernel_base (candidate)) {
					table_pos = offsets_pos;
					num_syms = offsets_words;
					relative_base = candidate;
					return false;
				}
			}

			uint address_words;
			uint address_pos = longest_ascending_run (raw, limit, 8, KERNEL_VA_MIN, uint64.MAX,
				out address_words);
			if (address_words >= 1024) {
				table_pos = address_pos;
				num_syms = address_words;
				return true;
			}

			throw new Error.NOT_SUPPORTED ("Unable to locate kallsyms address table in kernel image");
		}

		/**
		 * The byte offset of the longest run of non-decreasing little-endian words (4 or 8 bytes)
		 * whose values lie in [low, high), and its length in words.
		 */
		private static uint longest_ascending_run (uint8[] raw, uint limit, uint word_size, uint64 low,
				uint64 high, out uint length) {
			uint words = ((limit != 0) ? limit : raw.length) / word_size;
			uint best_pos = 0;
			uint best_len = 0;
			uint i = 0;
			while (i < words) {
				uint64 v = read_word (raw, i * word_size, word_size);
				if (v < low || v >= high) {
					i++;
					continue;
				}
				uint j = i + 1;
				uint64 prev = v;
				uint rises = 0;
				while (j < words) {
					uint64 w = read_word (raw, j * word_size, word_size);
					if (w < low || w >= high || w < prev)
						break;
					if (w > prev)
						rises++;
					prev = w;
					j++;
				}
				uint len = j - i;
				if (len > best_len && rises * 2 >= len) {
					best_len = len;
					best_pos = i;
				}
				i = j;
			}
			length = best_len;
			return best_pos * word_size;
		}

		private static uint64 read_word (uint8[] raw, uint pos, uint word_size) {
			return (word_size == 8) ? read_u64 (raw, pos) : (uint64) (uint32) read_i32 (raw, pos);
		}

		private static bool looks_like_kernel_base (uint64 candidate) {
			return (candidate >> 40) == 0xffffff && (candidate & 0xfff) == 0;
		}

		private const uint64 KERNEL_VA_MIN = 0xffffff8000000000;

		/**
		 * kallsyms_names is the run of symbols the offsets index into, each one a length byte
		 * (extended when the high bit is set) and that many token indices, decoding to a type
		 * letter and the name. Its start is found by seeding on a stretch of plausible names,
		 * proving positions reach that seed by walking symbol by symbol, and taking the earliest
		 * such start whose own leading names are short, printable and distinct -- i.e. _text.
		 */
		private const uint SYMBOL_SPAN_MAX = 512;
		private const uint COUNT_SLACK = 16;
		private const uint OFFSET_SAMPLES = 64;

		private static void scan_names (uint8[] raw, string[] tokens, uint tokens_pos, uint claimed_syms,
				out uint exact_pos, out uint32 longest, out uint counted_pos, out uint counted_syms) {
			exact_pos = 0;
			longest = 0;
			counted_pos = 0;
			counted_syms = 0;

			var printable = printable_tokens (tokens);
			var openers = symbol_openers (tokens, printable);
			uint n = (tokens_pos != 0) ? tokens_pos : raw.length;
			var run = new uint32[SYMBOL_SPAN_MAX];
			uint printable_from_next = 0;
			uint printable_from_second = 0;

			for (uint p = n; p-- > 0;) {
				uint printable_from_here = printable[raw[p]] ? printable_from_next + 1 : 0;

				uint32 length = 0;
				if (printable_from_next != 0) {
					uint span = symbol_span (raw, p, n, openers, printable_from_next,
						printable_from_second);
					if (span != 0) {
						uint next = p + span;
						length = 1 + ((next < n) ? run[next & (SYMBOL_SPAN_MAX - 1)] : 0);
					}
				}
				run[p & (SYMBOL_SPAN_MAX - 1)] = length;

				printable_from_second = printable_from_next;
				printable_from_next = printable_from_here;

				if (length > longest)
					longest = length;
				if (length < MIN_SYMS)
					continue;

				uint stored = count_ahead_of (raw, p, length);
				bool wants_exact = length == claimed_syms;
				bool wants_counted = stored > counted_syms;
				if (!wants_exact && !wants_counted)
					continue;
				if (!names_read_cleanly (raw, p, tokens))
					continue;

				if (wants_exact)
					exact_pos = p;
				if (wants_counted) {
					counted_pos = p;
					counted_syms = stored;
				}
			}
		}

		private static uint symbol_span (uint8[] raw, uint pos, uint n, bool[] openers,
				uint printable_from_next, uint printable_from_second) {
			uint len = raw[pos];
			uint start = pos + 1;
			uint printable_ahead = printable_from_next;
			if ((len & 0x80) != 0) {
				if (start >= n)
					return 0;
				len = (len & 0x7f) | (raw[start] << 7);
				start++;
				printable_ahead = printable_from_second;
			}

			if (len == 0 || len > 300 || start + len > n)
				return 0;
			if (printable_ahead < len || !openers[raw[start]])
				return 0;

			return (start - pos) + len;
		}

		private static bool[] symbol_openers (string[] tokens, bool[] printable) {
			var openers = new bool[256];
			for (uint i = 0; i != 256; i++) {
				unowned string token = tokens[i];
				openers[i] = printable[i] && token.length != 0 && is_symbol_type (token[0]);
			}
			return openers;
		}

		private static uint count_ahead_of (uint8[] raw, uint pos, uint32 length) {
			for (uint back = 4; back <= 8; back += 4) {
				if (pos < back)
					break;

				uint stored = (uint) (uint32) read_i32 (raw, pos - back);
				if (stored >= MIN_SYMS && stored <= length && stored + COUNT_SLACK >= length)
					return stored;
			}

			return 0;
		}

		private static bool find_offsets (uint8[] raw, uint num_syms, out uint table_pos,
				out uint64 relative_base) {
			table_pos = 0;
			relative_base = 0;

			uint span = num_syms * 4;
			uint pad = ((span % 8) == 0) ? 0 : 8 - (span % 8);
			uint n = raw.length;

			for (uint pos = span + pad; pos + 8 <= n; pos += 8) {
				uint64 candidate = read_u64 (raw, pos);
				if ((candidate >> 32) != 0xffffffff || (candidate & 0xfff) != 0)
					continue;

				uint start = pos - span - pad;
				if (read_i32 (raw, start) != 0)
					continue;
				if (!offsets_climb (raw, start, num_syms, candidate))
					continue;

				table_pos = start;
				relative_base = candidate;
				return true;
			}

			return false;
		}

		private static bool offsets_climb (uint8[] raw, uint table_pos, uint num_syms, uint64 origin) {
			bool percpu = offsets_hold_absolute_percpu (raw, table_pos, num_syms);

			uint stride = (num_syms / OFFSET_SAMPLES) + 1;
			uint64 previous = 0;
			for (uint i = 0; i < num_syms; i += stride) {
				int32 offset = read_i32 (raw, table_pos + i * 4);
				uint64 address = percpu
					? ((offset >= 0) ? (uint64) offset : origin - 1 + (uint64) (-(int64) offset))
					: origin + (uint64) (uint32) offset;
				if (address < previous)
					return false;
				previous = address;
			}

			return previous > origin;
		}

		private static bool offsets_hold_absolute_percpu (uint8[] raw, uint table_pos, uint num_syms) {
			uint stride = (num_syms / OFFSET_SAMPLES) + 1;
			for (uint i = 0; i < num_syms; i += stride) {
				if (read_i32 (raw, table_pos + i * 4) < 0)
					return true;
			}

			return read_i32 (raw, table_pos + (num_syms - 1) * 4) < 0;
		}

		private static bool names_read_cleanly (uint8[] raw, uint pos, string[] tokens) {
			var seen = new Gee.HashSet<string> ();
			uint p = pos;
			for (uint i = 0; i != NAMES_SAMPLE_SIZE; i++) {
				string name;
				uint next = try_decode_symbol (raw, p, tokens, out name);
				if (next == 0 || name.length < 3 || name.length > 80)
					return false;
				seen.add (name);
				p = next;
			}
			return seen.size >= (NAMES_SAMPLE_SIZE * 9) / 10;
		}

		private const uint NAMES_SAMPLE_SIZE = 200;

		private static bool[] printable_tokens (string[] tokens) {
			var printable = new bool[256];
			for (uint i = 0; i != 256; i++) {
				unowned string token = tokens[i];
				bool ok = true;
				for (char* c = (char*) token; *c != '\0'; c++) {
					uint8 byte = (uint8) (*c);
					if (byte < 0x21 || byte > 0x7e) {
						ok = false;
						break;
					}
				}
				printable[i] = ok;
			}
			return printable;
		}

		private static bool symbol_decodes (uint8[] raw, uint pos, bool[] printable, bool[] opens_a_symbol) {
			uint n = raw.length;
			if (pos >= n)
				return false;
			uint len = raw[pos];
			uint p = pos + 1;
			if ((len & 0x80) != 0) {
				if (p >= n)
					return false;
				len = (len & 0x7f) | (raw[p] << 7);
				p++;
			}
			if (len == 0 || len > 300 || p + len > n)
				return false;
			if (!opens_a_symbol[raw[p]])
				return false;
			for (uint i = 1; i != len; i++) {
				if (!printable[raw[p + i]])
					return false;
			}
			return true;
		}

		private static bool decodes_full_table (uint8[] raw, uint start, string[] tokens, uint num_syms) {
			uint p = start;
			for (uint i = 0; i != num_syms; i++) {
				string name;
				uint next = try_decode_symbol (raw, p, tokens, out name);
				if (next == 0)
					return false;
				p = next;
			}
			string tail;
			return try_decode_symbol (raw, p, tokens, out tail) == 0;
		}

		private static uint symbol_size (uint8[] raw, uint pos) {
			uint len = raw[pos];
			uint adv = 1;
			if ((len & 0x80) != 0) {
				len = (len & 0x7f) | (raw[pos + 1] << 7);
				adv = 2;
			}
			return adv + len;
		}

		private static bool find_percpu_layout (uint8[] raw, string[] tokens, out uint table_pos,
				out uint num_syms, out uint64 relative_base, out uint names_pos) {
			table_pos = 0;
			num_syms = 0;
			relative_base = 0;
			names_pos = 0;

			uint n = raw.length;
			for (uint pos = 0; pos + 16 <= n; pos += 8) {
				uint64 candidate = read_u64 (raw, pos);
				if (!looks_like_kernel_base (candidate))
					continue;

				uint count = (uint) (uint32) read_i32 (raw, pos + 8);
				if (count < MIN_SYMS || count > MAX_SYMS)
					continue;

				uint span = count * 4;
				uint pad = ((span % 8) == 0) ? 0 : 8 - (span % 8);
				if (pos < span + pad)
					continue;

				uint start = (pos + 12 + 7) & ~((uint) 7);
				if (start >= n)
					continue;
				if (!decodes_full_table (raw, start, tokens, count))
					continue;

				table_pos = pos - span - pad;
				num_syms = count;
				relative_base = candidate;
				names_pos = start;
				return true;
			}

			return false;
		}

		private static uint decode_symbol (uint8[] raw, uint pos, string[] tokens, out string name) {
			uint len = raw[pos];
			uint p = pos + 1;
			if ((len & 0x80) != 0) {
				len = (len & 0x7f) | (raw[p] << 7);
				p++;
			}
			var builder = new StringBuilder ();
			for (uint i = 0; i != len; i++)
				builder.append (tokens[raw[p + i]]);
			name = builder.str;
			return p + len;
		}

		/**
		 * Decodes a symbol only if it is a plausible name: a type letter followed by printable,
		 * non-space characters. Returns 0 when it is not, so a scan can reject a position without
		 * trusting whatever bytes it landed on.
		 */
		private static uint try_decode_symbol (uint8[] raw, uint pos, string[] tokens, out string name) {
			name = "";
			if (pos >= raw.length)
				return 0;
			uint len = raw[pos];
			uint p = pos + 1;
			if ((len & 0x80) != 0) {
				if (p >= raw.length)
					return 0;
				len = (len & 0x7f) | (raw[p] << 7);
				p++;
			}
			if (len == 0 || len > 300 || p + len > raw.length)
				return 0;
			var builder = new StringBuilder ();
			for (uint i = 0; i != len; i++) {
				unowned string token = tokens[raw[p + i]];
				char* cursor = (char*) token;
				for (char* c = cursor; *c != '\0'; c++) {
					uint8 byte = (uint8) (*c);
					if (byte < 0x21 || byte > 0x7e)
						return 0;
				}
				builder.append (token);
			}
			string decoded = builder.str;
			if (decoded.length < 1 || !is_symbol_type (decoded[0]))
				return 0;
			name = decoded;
			return p + len;
		}

		private static bool is_symbol_type (char c) {
			return c.isalpha () || c == '?' || c == '-';
		}

		private static string slice_to_string (uint8[] raw, uint start, uint end) {
			var builder = new StringBuilder ();
			for (uint i = start; i != end; i++)
				builder.append_c ((char) raw[i]);
			return builder.str;
		}

		private static int32 read_i32 (uint8[] raw, uint pos) {
			uint8 * bytes = raw;
			return *((int32 *) (bytes + pos));
		}

		private static uint64 read_u64 (uint8[] raw, uint pos) {
			uint8 * bytes = raw;
			return *((uint64 *) (bytes + pos));
		}
	}
}
