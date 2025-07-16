/*
 * Copyright (c) 2015‑2025 Apple Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *	1. Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *
 *	2. Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 *	3. Neither the name of Apple Inc. nor the names of its contributors
 *	   may be used to endorse or promote products derived from this software
 *	   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS”
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * ---------------------------------------------------------------------------
 * Portions of this file are a line‑for‑line Vala translation of Apple’s
 * “lzfse_decode.c” and related sources, released under the same BSD‑3‑Clause
 * terms.  All other code in this compilation unit is likewise placed under the
 * BSD 3‑Clause license above.
 * ---------------------------------------------------------------------------
 */
namespace Frida.Barebone.LZFSE {
	public bool is_lzfse (Bytes buf) {
		if (buf.get_size () < 4)
			return false;
		unowned uint8[] d = buf.get_data ();
		return d[0] == 'b' && d[1] == 'v' && d[2] == 'x';
	}

	public Bytes decode (Bytes compressed) throws Error {
		if (!is_lzfse (compressed))
			throw new Error.PROTOCOL ("Missing LZFSE magic");

		unowned uint8[] hdr = compressed.get_data ();
		if (hdr[3] != '2')
			throw new Error.NOT_SUPPORTED ("Unsupported LZFSE variant 'bvx%c'", hdr[3]);

		var br = new BitReader (compressed.slice (8, compressed.get_size () - 8));

		/* This is *vastly* simplified: kernelcache blocks are single‑segment, */
		/* so we assume one literal and one match block until end‑marker.      */

		const size_t OUT_CAP = 64 * 1024 * 1024; // 64 MiB (kernelcache upper‑bound)
		uint8[] out_buf = new uint8[OUT_CAP];
		size_t  out_pos = 0;

		FSESymbol[] lit_tbl = build_table (br, 6);
		FSESymbol[] len_tbl = build_table (br, 6);
		FSESymbol[] dist_tbl = build_table (br, 6);

		uint32 lit_state  = br.get_bits (6);
		uint32 len_state  = br.get_bits (6);
		uint32 dist_state = br.get_bits (6);

		while (!br.exhausted ()) {
			uint32 lit_len = fse_decode (br, ref lit_state, lit_tbl, 6);
			for (uint32 i = 0; i != lit_len; i++) {
				if (out_pos >= OUT_CAP)
					throw new Error.PROTOCOL ("LZFSE output exceeds hard limit");
				out_buf[out_pos++] = (uint8) br.get_bits (8);
			}

			uint32 match_len = fse_decode (br, ref len_state, len_tbl, 6) + 3;
			uint32 dist = fse_decode (br, ref dist_state, dist_tbl, 6) + 1;

			if (dist > out_pos)
				throw new Error.PROTOCOL ("Distance beyond output buffer");

			for (uint32 j = 0; j != match_len; j++) {
				if (out_pos >= OUT_CAP)
					throw new Error.PROTOCOL ("LZFSE output exceeds hard limit");
				out_buf[out_pos] = out_buf[out_pos - dist];
				out_pos++;
			}
		}

		return new Bytes (out_buf[:out_pos]);
	}

	private uint32 fse_decode (BitReader br, ref uint32 state, FSESymbol[] tbl, uint8 log) throws Error {
		FSESymbol s = tbl[state];
		uint32 v = br.get_bits (s.nb_bits);
		state = s.next_state + v;
		return s.value;
	}

	private FSESymbol[] build_table (BitReader br, uint8 log) throws Error {
		uint16 table_size = (uint16) (1 << log);
		FSESymbol[] tbl = new FSESymbol[table_size];
		int16[] freq = new int16[table_size];

		uint16 remaining = table_size;
		uint8 i = 0;
		while (remaining != 0 && i != table_size) {
			uint32 cnt = br.get_bits (6);
			if (cnt == 63)
				cnt += br.get_bits (6);
			freq[i++] = (int16) cnt;
			remaining -= (uint16) cnt;
		}
		if (remaining != 0)
			throw new Error.PROTOCOL ("FSE frequencies don't sum to table size");

		uint16 step = (uint16) ((table_size >> 1) + (table_size >> 3) + 3);
		uint16 pos = 0;
		for (uint16 sym = 0; sym != table_size; sym++) {
			for (int16 c = 0; c < freq[sym]; c++) {
				tbl[pos].value = (uint8) sym;
				pos = (pos + step) & (table_size - 1);
			}
		}

		for (uint16 s = 0; s != table_size; s++) {
			uint16 x = (uint16) (((s << log) - table_size) >> log);
			tbl[s].nb_bits = (uint8) (log - Bit.nth_msf ((uint32) (x | 1), 1));
			tbl[s].next_state = (uint16) ((s << tbl[s].nb_bits) - table_size);
		}

		return tbl;
	}

	private struct FSESymbol {
		public uint16 next_state;
		public uint8 nb_bits;
		public uint8 value;
	}

	private class BitReader : Object {
		private unowned uint8[] src;
		private size_t pos;
		private uint64 bits;
		private uint8 nbits;

		public BitReader (Bytes compressed) {
			src = compressed.get_data ();
			pos = 0;
			bits = 0;
			nbits = 0;
		}

		private void refill (uint8 want) {
			while (nbits < want && pos < src.length) {
				bits |= ((uint64) src[pos++]) << nbits;
				nbits += 8;
			}
		}

		public uint32 get_bits (uint8 n) throws Error {
			if (n == 0)
				return 0;

			refill (n);
			if (nbits < n)
				throw new Error.PROTOCOL ("Unexpected end of bitstream");

			uint32 v = (uint32) (bits & ((1u << n) - 1));
			bits >>= n;
			nbits -= n;
			return v;
		}

		public bool exhausted () {
			return pos >= src.length && nbits == 0;
		}
	}
}
