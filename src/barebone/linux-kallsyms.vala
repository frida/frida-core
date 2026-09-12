[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	/**
	 * Reconstructs a kernel's symbols from the kallsyms tables embedded in its on-disk image,
	 * so a System.map is not needed. The image is a raw arm64 Image (optionally gzip-compressed);
	 * the tables are located by their structure and the names are decoded with the token table,
	 * pairing each name with relative_base + offsets[i] -- the address it was linked for.
	 */
	internal class KallsymsImage {
		public static Gee.List<SymbolInfo> parse (uint8[] image) throws Error {
			uint8[] raw = maybe_gunzip (image);

			var tokens = find_tokens (raw);

			uint num_syms;
			uint offsets_pos;
			uint64 relative_base;
			find_offsets (raw, out offsets_pos, out num_syms, out relative_base);

			uint names_pos = find_names (raw, tokens);

			var symbols = new Gee.ArrayList<SymbolInfo> ();
			uint p = names_pos;
			for (uint i = 0; i != num_syms; i++) {
				string name;
				p = decode_symbol (raw, p, tokens, out name);
				if (name.length < 2)
					continue;
				int32 offset = read_i32 (raw, offsets_pos + i * 4);
				uint64 address = relative_base + (int64) offset;
				symbols.add (new SymbolInfo () {
					name = name.substring (1),
					offset = address,
					symbol_type = 0xf,
					section = 0x10,
				});
			}
			return symbols;
		}

		private static uint8[] maybe_gunzip (uint8[] image) throws Error {
			if (image.length < 4 || image[0] != 0x1f || image[1] != 0x8b)
				return image;
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

		/**
		 * kallsyms_token_index is 256 little-endian uint16 cumulative offsets, and the token
		 * table is the 256 NUL-terminated tokens right before it. The index is distinctive:
		 * it starts at 0 and rises by each token's length. A matching base is where every
		 * token's terminator lands, and the tokens then read as mostly-printable BPE fragments.
		 */
		private static string[] find_tokens (uint8[] raw) throws Error {
			uint n = raw.length;
			for (uint i = 0; i + 512 <= n; i++) {
				if (raw[i] != 0 || raw[i + 1] != 0)
					continue;
				var index = new uint16[256];
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

				string[]? tokens = reconstruct_tokens (raw, i, index);
				if (tokens != null)
					return tokens;
			}
			throw new Error.NOT_SUPPORTED ("Unable to locate kallsyms token table in kernel image");
		}

		private static string[]? reconstruct_tokens (uint8[] raw, uint index_pos, uint16[] index) {
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
					var tokens = new string[256];
					uint printable = 0;
					uint total = 0;
					for (uint k = 0; k != 256; k++) {
						uint start = table_base + index[k];
						uint end = start;
						while (end < index_pos && raw[end] != 0)
							end++;
						tokens[k] = slice_to_string (raw, start, end);
						for (uint b = start; b != end; b++) {
							total++;
							if (raw[b] >= 0x20 && raw[b] < 0x7f)
								printable++;
						}
					}
					if (total != 0 && printable >= (total * 90) / 100)
						return tokens;
				}
				if (table_base == 0)
					break;
			}
			return null;
		}

		/**
		 * kallsyms_offsets is one signed 32-bit entry per symbol, sorted by address, so it is
		 * the longest run of non-decreasing int32 in kernel-offset range. kallsyms_relative_base
		 * -- the address offset 0 is measured from -- is the aligned kernel pointer right after it.
		 */
		private static void find_offsets (uint8[] raw, out uint offsets_pos, out uint num_syms,
				out uint64 relative_base) throws Error {
			uint words = raw.length / 4;
			uint best_pos = 0;
			uint best_len = 0;
			uint i = 0;
			while (i < words) {
				int32 v = read_i32 (raw, i * 4);
				if (v < 0 || v >= 0x8000000) {
					i++;
					continue;
				}
				uint j = i + 1;
				int32 prev = v;
				while (j < words) {
					int32 w = read_i32 (raw, j * 4);
					if (w < 0 || w >= 0x8000000 || w < prev)
						break;
					prev = w;
					j++;
				}
				if (j - i > best_len) {
					best_len = j - i;
					best_pos = i;
				}
				i = j;
			}
			if (best_len < 1024)
				throw new Error.NOT_SUPPORTED ("Unable to locate kallsyms offsets in kernel image");

			offsets_pos = best_pos * 4;
			num_syms = best_len;

			uint64 candidate = read_u64 (raw, offsets_pos + num_syms * 4);
			if ((candidate & 0xffffff0000000000) == 0)
				throw new Error.NOT_SUPPORTED ("Unable to locate kallsyms relative base in kernel image");
			relative_base = candidate;
		}

		/**
		 * kallsyms_names is the run of symbols the offsets index into, each one a length byte
		 * (extended when the high bit is set) and that many token indices, decoding to a type
		 * letter and the name. Its start is found by seeding on a stretch of plausible names,
		 * proving positions reach that seed by walking symbol by symbol, and taking the earliest
		 * such start whose own leading names are short, printable and distinct -- i.e. _text.
		 */
		private static uint find_names (uint8[] raw, string[] tokens) throws Error {
			uint seed = find_names_seed (raw, tokens);

			uint lo = (seed > 3000000) ? seed - 3000000 : 0;
			var reaches = new bool[seed - lo + 1];
			reaches[seed - lo] = true;
			uint pos = seed;
			while (pos > lo) {
				pos--;
				uint next = pos + symbol_size (raw, pos);
				if (next == seed || (next < seed && reaches[next - lo]))
					reaches[pos - lo] = true;
			}

			for (uint start = lo; start <= seed; start++) {
				if (reaches[start - lo] && leads_with_clean_names (raw, start, tokens))
					return start;
			}
			throw new Error.NOT_SUPPORTED ("Unable to locate kallsyms names in kernel image");
		}

		/**
		 * A short stretch of names is not enough to seed on: other token-like data (exported
		 * symbol name tables) can decode as a handful of plausible names too. A run this long
		 * only holds together inside the real names table, so it cannot land anywhere else.
		 */
		private static uint find_names_seed (uint8[] raw, string[] tokens) throws Error {
			uint n = raw.length;
			for (uint c = 0; c + 64 < n; c++) {
				string first;
				if (try_decode_symbol (raw, c, tokens, out first) == 0)
					continue;
				if (distinct_clean_names (raw, c, tokens, 200))
					return c;
			}
			throw new Error.NOT_SUPPORTED ("Unable to seed kallsyms names in kernel image");
		}

		private static bool distinct_clean_names (uint8[] raw, uint pos, string[] tokens, uint count) {
			var seen = new Gee.HashSet<string> ();
			uint p = pos;
			for (uint i = 0; i != count; i++) {
				string name;
				uint next = try_decode_symbol (raw, p, tokens, out name);
				if (next == 0 || name.length < 3 || name.length > 80)
					return false;
				seen.add (name);
				p = next;
			}
			return seen.size >= (count * 9) / 10;
		}

		private static bool leads_with_clean_names (uint8[] raw, uint pos, string[] tokens) {
			var seen = new Gee.HashSet<string> ();
			uint p = pos;
			for (uint i = 0; i != 20; i++) {
				string name;
				uint next = try_decode_symbol (raw, p, tokens, out name);
				if (next == 0 || name.length < 2 || name.length > 60)
					return false;
				seen.add (name);
				p = next;
			}
			return seen.size >= 18;
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
			return (int32) ((uint32) raw[pos] | ((uint32) raw[pos + 1] << 8)
				| ((uint32) raw[pos + 2] << 16) | ((uint32) raw[pos + 3] << 24));
		}

		private static uint64 read_u64 (uint8[] raw, uint pos) {
			uint64 v = 0;
			for (uint i = 0; i != 8; i++)
				v |= ((uint64) raw[pos + i]) << (int) (8 * i);
			return v;
		}
	}
}
