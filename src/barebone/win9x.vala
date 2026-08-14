[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	public static async Win9xLayout collect_win9x_layout (Machine machine, Cancellable? cancellable)
			throws Error, IOError {
		var modules = new Gee.ArrayList<ModuleInfo> ();
		var symbols = new Gee.ArrayList<SymbolInfo> ();

		var blocks = yield find_descriptor_blocks (machine, cancellable);
		if (blocks.is_empty) {
			throw new Error.NOT_SUPPORTED (
				"Unable to find any VxD; the guest is probably still booting, as none of its " +
				"memory is paged in yet");
		}

		var images = yield read_loader_images (machine, blocks, cancellable);

		uint64 obfuscator = yield find_process_id_obfuscator (machine, cancellable);
		if (obfuscator != 0) {
			symbols.add (new SymbolInfo () {
				name = PROCESS_ID_OBFUSCATOR,
				offset = (uint32) obfuscator,
				symbol_type = 0xf,
				section = 0x10,
			});
		}

		foreach (DeviceDescriptorBlock ddb in blocks) {
			unowned string[]? names = known_service_names (ddb.name);

			uint64 lowest = uint64.MAX;
			uint64 highest = 0;

			var addresses = yield read_service_table (machine, ddb, cancellable);
			for (int ordinal = 0; ordinal != addresses.size; ordinal++) {
				uint64 address = addresses[ordinal];
				if (!is_implemented (address))
					continue;

				symbols.add (new SymbolInfo () {
					name = (names != null && ordinal < names.length)
						? names[ordinal]
						: "%s_service_%d".printf (ddb.name, ordinal),
					offset = (uint32) address,
					symbol_type = 0xf,
					section = 0x10,
				});

				lowest = uint64.min (lowest, address);
				highest = uint64.max (highest, address);
			}

			uint64 image_base = 0;
			uint32 image_size = 0;
			LoaderImage? image = find_loader_image (images, ddb.address);
			if (image != null) {
				image_base = image.base_address;
				image_size = image.size;
			} else if (highest != 0) {
				image_base = lowest;
				image_size = (uint32) (highest - lowest);
			} else {
				image_base = ddb.address;
				image_size = (uint32) DDB_SIZE;
			}

			modules.add (new ModuleInfo () {
				name = "%s.VXD".printf (ddb.name),
				version = "",
				offset = (uint32) image_base,
				size = image_size,
			});
		}

		return new Win9xLayout (modules, symbols);
	}

	public sealed class Win9xLayout : Object {
		public Gee.List<ModuleInfo> modules {
			get;
			construct;
		}

		public Gee.List<SymbolInfo> symbols {
			get;
			construct;
		}

		public Win9xLayout (Gee.List<ModuleInfo> modules, Gee.List<SymbolInfo> symbols) {
			Object (modules: modules, symbols: symbols);
		}
	}

	// Every VxD is on VMM's chain, including the ones that export no services and would
	// therefore be indistinguishable from noise when sweeping. Sweep only far enough to
	// find VMM itself, then follow it.
	// A Win9x process id is its database pointer XOR a per-boot value, so ask KERNEL32 where it
	// keeps that value: GetCurrentProcessId() pushes the pointer and tail-calls a helper whose
	// first instruction loads the obfuscator.
	private static async uint64 find_process_id_obfuscator (Machine machine, Cancellable? cancellable)
			throws Error, IOError {
		GDB.Client gdb = machine.gdb;

		uint64 kernel32 = yield find_kernel32 (machine, cancellable);
		if (kernel32 == 0)
			return 0;

		uint64 getter = yield find_export (machine, kernel32, "GetCurrentProcessId", cancellable);
		if (getter == 0)
			return 0;

		Buffer code = gdb.make_buffer (yield gdb.read_byte_array (getter, 12, cancellable));
		if (code.read_uint8 (0) != LOAD_EAX_ABSOLUTE || code.read_uint8 (7) != CALL_RELATIVE)
			return 0;
		uint64 helper = getter + 12 + code.read_uint32 (8);

		Buffer body = gdb.make_buffer (yield gdb.read_byte_array (helper, 5, cancellable));
		if (body.read_uint8 (0) != LOAD_EAX_ABSOLUTE)
			return 0;

		return body.read_uint32 (1);
	}

	private static async uint64 find_kernel32 (Machine machine, Cancellable? cancellable) throws Error, IOError {
		for (uint64 candidate = KERNEL32_SEARCH_BASE; candidate < KERNEL32_SEARCH_LIMIT;
				candidate += IMAGE_ALIGNMENT) {
			if ((yield find_export (machine, candidate, "GetCurrentProcessId", cancellable)) != 0)
				return candidate;
		}

		return 0;
	}

	private static async uint64 find_export (Machine machine, uint64 image, string wanted, Cancellable? cancellable)
			throws Error, IOError {
		GDB.Client gdb = machine.gdb;

		Bytes header;
		try {
			header = yield gdb.read_byte_array (image, 0x200, cancellable);
		} catch (Error e) {
			return 0;
		}
		Buffer h = gdb.make_buffer (header);
		if (h.read_uint16 (0) != DOS_SIGNATURE)
			return 0;
		uint32 headers = h.read_uint32 (DOS_HEADERS_OFFSET);
		if (headers > 0x180 || h.read_uint32 (headers) != PE_SIGNATURE)
			return 0;

		uint32 directory = h.read_uint32 (headers + EXPORT_DIRECTORY_OFFSET);
		if (directory == 0)
			return 0;

		Buffer d = gdb.make_buffer (yield gdb.read_byte_array (image + directory, 0x28, cancellable));
		uint32 count = d.read_uint32 (0x18);
		uint32 functions = d.read_uint32 (0x1c);
		uint32 names = d.read_uint32 (0x20);
		uint32 ordinals = d.read_uint32 (0x24);
		if (count == 0 || count > MAX_EXPORTS)
			return 0;

		Buffer name_rvas = gdb.make_buffer (yield gdb.read_byte_array (image + names, count * 4, cancellable));
		Buffer ordinal_values = gdb.make_buffer (yield gdb.read_byte_array (image + ordinals, count * 2,
			cancellable));
		for (uint32 i = 0; i != count; i++) {
			Bytes raw = yield gdb.read_byte_array (image + name_rvas.read_uint32 (i * 4), wanted.length + 1,
				cancellable);
			unowned uint8[] actual = raw.get_data ();
			if (actual[wanted.length] != 0 || Memory.cmp (actual, wanted.data, wanted.length) != 0)
				continue;

			uint32 ordinal = ordinal_values.read_uint16 (i * 2);
			Buffer entry = gdb.make_buffer (yield gdb.read_byte_array (image + functions + ordinal * 4, 4,
				cancellable));
			return image + entry.read_uint32 (0);
		}

		return 0;
	}

	// VXDLDR knows the object each dynamically loaded VxD was scattered into; the one holding
	// the descriptor block is the VxD proper. Statically linked VxDs live inside VMM32.VXD and
	// have no image of their own to ask about.
	private static async Gee.List<LoaderImage> read_loader_images (Machine machine,
			Gee.List<DeviceDescriptorBlock> blocks, Cancellable? cancellable) throws Error, IOError {
		var images = new Gee.ArrayList<LoaderImage> ();

		DeviceDescriptorBlock? loader = null;
		foreach (DeviceDescriptorBlock ddb in blocks) {
			if (ddb.name == "VXDLDR")
				loader = ddb;
		}
		if (loader == null || loader.service_count <= GET_DEVICE_LIST_ORDINAL)
			return images;

		GDB.Client gdb = machine.gdb;
		uint64 getter = gdb.make_buffer (yield gdb.read_byte_array (
			loader.service_table + GET_DEVICE_LIST_ORDINAL * 4, 4, cancellable)).read_uint32 (0);

		Buffer code = gdb.make_buffer (yield gdb.read_byte_array (getter, 5, cancellable));
		if (code.read_uint8 (0) != LOAD_EAX_ABSOLUTE)
			return images;

		uint64 head = gdb.make_buffer (yield gdb.read_byte_array (code.read_uint32 (1), 4, cancellable))
			.read_uint32 (0);

		uint64 record = head;
		var visited = new Gee.HashSet<uint64?> ((n) => (uint) (*(uint64 *) n), (a, b) => *(uint64 *) a == *(uint64 *) b);
		while (is_arena_address (record) && !visited.contains (record)) {
			visited.add (record);

			Buffer r = gdb.make_buffer (yield gdb.read_byte_array (record, LOADER_RECORD_SIZE, cancellable));
			uint64 ddb_address = r.read_uint32 (LOADER_DDB_OFFSET);
			uint objects = r.read_uint8 (LOADER_OBJECT_COUNT_OFFSET);
			uint64 table = r.read_uint32 (LOADER_OBJECT_TABLE_OFFSET);

			if (objects != 0 && is_arena_address (table)) {
				Buffer entries = gdb.make_buffer (yield gdb.read_byte_array (table,
					objects * LOADER_OBJECT_SIZE, cancellable));
				for (uint i = 0; i != objects; i++) {
					uint64 object_base = entries.read_uint32 (i * LOADER_OBJECT_SIZE);
					uint32 object_size = entries.read_uint32 (i * LOADER_OBJECT_SIZE + 4);
					if (ddb_address >= object_base && ddb_address < object_base + object_size) {
						images.add (new LoaderImage () {
							ddb = ddb_address,
							base_address = object_base,
							size = object_size,
						});
						break;
					}
				}
			}

			record = r.read_uint32 (NEXT_OFFSET);
		}

		return images;
	}

	private static LoaderImage? find_loader_image (Gee.List<LoaderImage> images, uint64 ddb) {
		foreach (LoaderImage image in images) {
			if (image.ddb == ddb)
				return image;
		}
		return null;
	}

	private class LoaderImage {
		public uint64 ddb;
		public uint64 base_address;
		public uint32 size;
	}

	private static async Gee.List<DeviceDescriptorBlock> find_descriptor_blocks (Machine machine,
			Cancellable? cancellable) throws Error, IOError {
		var blocks = new Gee.ArrayList<DeviceDescriptorBlock> ();

		uint64 address = yield find_kernel_descriptor_block (machine, cancellable);
		var visited = new Gee.HashSet<uint64?> ((n) => (uint) (*(uint64 *) n), (a, b) => *(uint64 *) a == *(uint64 *) b);
		while (is_arena_address (address) && !visited.contains (address)) {
			visited.add (address);

			Bytes raw;
			try {
				raw = yield machine.gdb.read_byte_array (address, DDB_SIZE, cancellable);
			} catch (Error e) {
				break;
			}

			Buffer buf = machine.gdb.make_buffer (raw);
			DeviceDescriptorBlock? ddb = DeviceDescriptorBlock.parse_linked (buf, address);
			if (ddb == null)
				break;
			blocks.add (ddb);

			address = buf.read_uint32 (NEXT_OFFSET);
		}

		return blocks;
	}

	private static async uint64 find_kernel_descriptor_block (Machine machine, Cancellable? cancellable)
			throws Error, IOError {
		var arena = new Gee.ArrayList<RangeDetails> ();
		yield machine.enumerate_ranges (Gum.PageProtection.READ, r => {
			if (r.base_va >= SYSTEM_ARENA_BASE && r.base_va < SYSTEM_ARENA_LIMIT)
				arena.add (r.clone ());
			return true;
		}, cancellable);

		foreach (RangeDetails r in arena) {
			foreach (DeviceDescriptorBlock candidate in yield harvest_candidates (machine, r, cancellable)) {
				if (candidate.name == "VMM" && yield candidate.is_credible (machine, cancellable))
					return candidate.address;
			}
		}

		return 0;
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

		public static DeviceDescriptorBlock? parse_linked (Buffer buf, uint64 address) {
			string? name = parse_name (buf, NAME_OFFSET);
			if (name == null)
				return null;

			uint32 count = buf.read_uint32 (SERVICE_TABLE_SIZE_OFFSET);
			uint32 table = buf.read_uint32 (SERVICE_TABLE_PTR_OFFSET);
			if (count > MAX_SERVICES || !is_arena_address (table))
				count = 0;

			return new DeviceDescriptorBlock () {
				name = name,
				address = address,
				service_table = table,
				service_count = count,
			};
		}

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
				if (!c.isalpha () && !c.isdigit () && c != '_' && c != '$')
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

	private const size_t NEXT_OFFSET = 0x00;
	public const string PROCESS_ID_OBFUSCATOR = "KERNEL32_ProcessIdObfuscator";

	private const uint64 KERNEL32_SEARCH_BASE = 0xbff00000;
	private const uint64 KERNEL32_SEARCH_LIMIT = 0xc0000000;
	private const uint64 IMAGE_ALIGNMENT = 0x10000;
	private const uint16 DOS_SIGNATURE = 0x5a4d;
	private const size_t DOS_HEADERS_OFFSET = 0x3c;
	private const uint32 PE_SIGNATURE = 0x00004550;
	private const size_t EXPORT_DIRECTORY_OFFSET = 0x78;
	private const uint32 MAX_EXPORTS = 0x2000;
	private const uint8 CALL_RELATIVE = 0xe8;

	private const uint GET_DEVICE_LIST_ORDINAL = 5;
	private const uint8 LOAD_EAX_ABSOLUTE = 0xa1;
	private const size_t LOADER_RECORD_SIZE = 0x24;
	private const size_t LOADER_DDB_OFFSET = 0x05;
	private const size_t LOADER_OBJECT_COUNT_OFFSET = 0x13;
	private const size_t LOADER_OBJECT_TABLE_OFFSET = 0x17;
	private const size_t LOADER_OBJECT_SIZE = 0x10;
	private const size_t DDB_SIZE = 0x38;
	private const size_t STRADDLE_ALLOWANCE = DDB_SIZE;

	private const uint64 SYSTEM_ARENA_BASE = 0xc0000000;
	private const uint64 SYSTEM_ARENA_LIMIT = 0xc4000000;

	private const uint32 MAX_SERVICES = 0x400;

	private const size_t SCAN_CHUNK_SIZE = 256 * 1024;
}
