[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	public static async Gee.List<SymbolInfo> collect_win9x_symbols (Machine machine, Cancellable? cancellable)
			throws Error, IOError {
		var symbols = new Gee.ArrayList<SymbolInfo> ();

		foreach (DeviceDescriptorBlock ddb in yield find_descriptor_blocks (machine, cancellable)) {
			unowned string[]? names = known_service_names (ddb.name);
			if (names == null)
				continue;

			var addresses = yield read_service_table (machine, ddb, cancellable);
			for (int ordinal = 0; ordinal != addresses.size; ordinal++) {
				uint64 address = addresses[ordinal];
				if (!is_implemented (address))
					continue;

				symbols.add (new SymbolInfo () {
					name = (ordinal < names.length)
						? names[ordinal]
						: "%s_service_%d".printf (ddb.name, ordinal),
					offset = (uint32) address,
					symbol_type = 0xf,
					section = 0x10,
				});
			}
		}

		return symbols;
	}

	private static async Gee.List<DeviceDescriptorBlock> find_descriptor_blocks (Machine machine, Cancellable? cancellable)
			throws Error, IOError {
		var arena = new Gee.ArrayList<RangeDetails> ();
		yield machine.enumerate_ranges (Gum.PageProtection.READ, r => {
			if (r.base_va >= SYSTEM_ARENA_BASE && r.base_va < SYSTEM_ARENA_LIMIT)
				arena.add (r.clone ());
			return true;
		}, cancellable);

		var blocks = new Gee.ArrayList<DeviceDescriptorBlock> ();
		foreach (RangeDetails r in arena) {
			foreach (DeviceDescriptorBlock candidate in yield harvest_candidates (machine, r, cancellable)) {
				if (yield candidate.is_credible (machine, cancellable))
					blocks.add (candidate);
			}
		}

		return blocks;
	}

	private static async Gee.List<DeviceDescriptorBlock> harvest_candidates (Machine machine, RangeDetails range,
			Cancellable? cancellable) throws Error, IOError {
		var candidates = new Gee.ArrayList<DeviceDescriptorBlock> ();

		GDB.Client gdb = machine.gdb;
		for (uint64 offset = 0; offset < range.size; offset += SCAN_CHUNK_SIZE) {
			uint64 chunk_start = range.base_va + offset;
			uint64 remaining = range.size - offset;
			size_t readable_size = (size_t) uint64.min (SCAN_CHUNK_SIZE + STRADDLE_ALLOWANCE, remaining);
			size_t claimed_size = (size_t) uint64.min (SCAN_CHUNK_SIZE, remaining);

			Bytes chunk;
			try {
				chunk = yield gdb.read_byte_array (chunk_start, readable_size, cancellable);
			} catch (Error e) {
				continue;
			}

			Buffer buf = gdb.make_buffer (chunk);
			for (size_t pos = 0; pos < claimed_size && pos + DDB_SIZE <= readable_size; pos += 4) {
				DeviceDescriptorBlock? ddb = DeviceDescriptorBlock.parse (buf, pos, chunk_start + pos);
				if (ddb != null)
					candidates.add (ddb);
			}
		}

		return candidates;
	}

	private static async Gee.List<uint64?> read_service_table (Machine machine, DeviceDescriptorBlock ddb,
			Cancellable? cancellable) throws Error, IOError {
		Bytes raw = yield machine.gdb.read_byte_array (ddb.service_table, ddb.service_count * 4, cancellable);
		Buffer buf = machine.gdb.make_buffer (raw);

		var addresses = new Gee.ArrayList<uint64?> ();
		for (uint i = 0; i != ddb.service_count; i++)
			addresses.add (buf.read_uint32 (i * 4));
		return addresses;
	}

	private class DeviceDescriptorBlock {
		public string name;
		public uint64 address;
		public uint64 service_table;
		public uint32 service_count;

		public static DeviceDescriptorBlock? parse (Buffer buf, size_t offset, uint64 address) {
			string? name = parse_name (buf, offset + NAME_OFFSET);
			if (name == null)
				return null;

			uint32 count = buf.read_uint32 (offset + SERVICE_TABLE_SIZE_OFFSET);
			if (count == 0 || count > MAX_SERVICES)
				return null;

			uint32 table = buf.read_uint32 (offset + SERVICE_TABLE_PTR_OFFSET);
			if (!is_arena_address (table))
				return null;

			uint32 control_proc = buf.read_uint32 (offset + CONTROL_PROC_OFFSET);
			if (control_proc != 0 && !is_arena_address (control_proc))
				return null;

			return new DeviceDescriptorBlock () {
				name = name,
				address = address,
				service_table = table,
				service_count = count,
			};
		}

		public async bool is_credible (Machine machine, Cancellable? cancellable) throws Error, IOError {
			Bytes first_entry;
			try {
				first_entry = yield machine.gdb.read_byte_array (service_table, 4, cancellable);
			} catch (Error e) {
				return false;
			}
			return is_arena_address (machine.gdb.make_buffer (first_entry).read_uint32 (0));
		}

		private static string? parse_name (Buffer buf, size_t offset) {
			var name = new StringBuilder ();
			bool padding_reached = false;
			for (size_t i = 0; i != NAME_SIZE; i++) {
				char c = (char) buf.read_uint8 (offset + i);
				if (c == ' ') {
					padding_reached = true;
					continue;
				}
				if (padding_reached)
					return null;
				if (!c.isupper () && !c.isdigit () && c != '_' && c != '$')
					return null;
				name.append_c (c);
			}
			if (name.len == 0)
				return null;
			return name.str;
		}

		private const size_t CONTROL_PROC_OFFSET = 0x18;
		private const size_t NAME_OFFSET = 0x0c;
		private const size_t NAME_SIZE = 8;
		private const size_t SERVICE_TABLE_PTR_OFFSET = 0x30;
		private const size_t SERVICE_TABLE_SIZE_OFFSET = 0x34;
	}

	private static unowned string[]? known_service_names (string vxd) {
		if (vxd == "VMM")
			return VMM_SERVICE_NAMES;
		if (vxd == "VPICD")
			return VPICD_SERVICE_NAMES;
		if (vxd == "VWIN32")
			return VWIN32_SERVICE_NAMES;
		if (vxd == "IFSMGR")
			return IFSMGR_SERVICE_NAMES;
		return null;
	}

	private static bool is_arena_address (uint64 address) {
		return address >= SYSTEM_ARENA_BASE && address < SYSTEM_ARENA_LIMIT;
	}

	private static bool is_implemented (uint64 service_address) {
		return service_address != 0;
	}

	private const size_t DDB_SIZE = 0x38;
	private const size_t STRADDLE_ALLOWANCE = DDB_SIZE;

	private const uint64 SYSTEM_ARENA_BASE = 0xc0000000;
	private const uint64 SYSTEM_ARENA_LIMIT = 0xc4000000;

	private const uint32 MAX_SERVICES = 0x400;

	private const size_t SCAN_CHUNK_SIZE = 256 * 1024;
}
