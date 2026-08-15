[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	public static async WinNtLayout collect_winnt_layout (Machine machine, Cancellable? cancellable)
			throws Error, IOError {
		var modules = new Gee.ArrayList<ModuleInfo> ();
		var symbols = new Gee.ArrayList<SymbolInfo> ();

		uint64 version_block = yield find_version_block (machine, cancellable);
		uint64 module_list = yield read_loaded_module_list (machine, version_block, cancellable);

		foreach (LoadedModule module in yield read_loaded_modules (machine, module_list, cancellable)) {
			modules.add (new ModuleInfo () {
				name = module.name,
				version = "",
				offset = (uint32) module.base_address,
				size = module.size,
			});

			yield add_export_symbols (machine, module, symbols, cancellable);
		}

		yield add_process_list_symbol (machine, version_block, symbols, cancellable);

		return new WinNtLayout (modules, symbols);
	}

	public sealed class WinNtLayout : Object {
		public Gee.List<ModuleInfo> modules {
			get;
			construct;
		}

		public Gee.List<SymbolInfo> symbols {
			get;
			construct;
		}

		public WinNtLayout (Gee.List<ModuleInfo> modules, Gee.List<SymbolInfo> symbols) {
			Object (modules: modules, symbols: symbols);
		}
	}

	// The processor control region sits at a fixed address on 32-bit NT and points at the block
	// the kernel debugger bootstraps itself from. That block names the kernel and its module
	// list, which is everything needed to find the rest without symbols.
	private static async uint64 find_version_block (Machine machine, Cancellable? cancellable)
			throws Error, IOError {
		GDB.Client gdb = machine.gdb;

		Buffer pcr;
		try {
			pcr = gdb.make_buffer (yield gdb.read_byte_array (PCR_BASE, PCR_PROLOGUE_SIZE, cancellable));
		} catch (Error e) {
			throw new Error.NOT_SUPPORTED (
				"Unable to read the processor control region; the guest is probably still booting");
		}
		if (pcr.read_uint32 (SELF_PCR_OFFSET) != PCR_BASE)
			throw new Error.NOT_SUPPORTED ("Unable to find the processor control region");

		uint64 version_block = pcr.read_uint32 (VERSION_BLOCK_OFFSET);
		if (!is_kernel_address (version_block))
			throw new Error.NOT_SUPPORTED ("Unable to find the kernel debugger version block");

		Buffer v = gdb.make_buffer (yield gdb.read_byte_array (version_block, VERSION_BLOCK_SIZE, cancellable));
		if (v.read_uint16 (MACHINE_TYPE_OFFSET) != IMAGE_FILE_MACHINE_I386)
			throw new Error.NOT_SUPPORTED ("Only 32-bit x86 kernels are supported for now");

		return version_block;
	}

	// Both kernels use the 64-bit form of this structure, and a 32-bit kernel extends the sign of
	// the pointers in it.
	private static async uint64 read_loaded_module_list (Machine machine, uint64 version_block,
			Cancellable? cancellable) throws Error, IOError {
		GDB.Client gdb = machine.gdb;

		uint64 list = gdb.make_buffer (yield gdb.read_byte_array (version_block + LOADED_MODULE_LIST_OFFSET, 4,
			cancellable)).read_uint32 (0);
		if (!is_kernel_address (list))
			throw new Error.NOT_SUPPORTED ("Unable to find the loaded module list");

		return list;
	}

	private static async Gee.List<LoadedModule> read_loaded_modules (Machine machine, uint64 head,
			Cancellable? cancellable) throws Error, IOError {
		var modules = new Gee.ArrayList<LoadedModule> ();

		GDB.Client gdb = machine.gdb;
		uint64 entry = gdb.make_buffer (yield gdb.read_byte_array (head, 4, cancellable)).read_uint32 (0);
		var visited = new Gee.HashSet<uint64?> ((n) => (uint) (*(uint64 *) n), (a, b) => *(uint64 *) a == *(uint64 *) b);
		while (entry != head && is_kernel_address (entry) && !visited.contains (entry)) {
			visited.add (entry);

			Buffer e = gdb.make_buffer (yield gdb.read_byte_array (entry, TABLE_ENTRY_SIZE, cancellable));

			uint64 base_address = e.read_uint32 (DLL_BASE_OFFSET);
			if (is_kernel_address (base_address)) {
				modules.add (new LoadedModule () {
					base_address = base_address,
					size = e.read_uint32 (IMAGE_SIZE_OFFSET),
					name = yield read_unicode_string (machine, e, BASE_NAME_OFFSET, cancellable),
				});
			}

			entry = e.read_uint32 (FORWARD_LINK_OFFSET);
		}

		return modules;
	}

	private class LoadedModule {
		public uint64 base_address;
		public uint32 size;
		public string name;
	}

	private static async void add_export_symbols (Machine machine, LoadedModule module,
			Gee.List<SymbolInfo> symbols, Cancellable? cancellable) throws Error, IOError {
		foreach (Export e in yield enumerate_exports (machine, module.base_address, cancellable)) {
			symbols.add (new SymbolInfo () {
				name = e.name,
				offset = (uint32) (module.base_address + e.rva),
				symbol_type = 0xf,
				section = 0x10,
			});
		}
	}

	// The kernel gives the addresses that a debugger needs here, and no module exports them.
	private static async void add_process_list_symbol (Machine machine, uint64 version_block,
			Gee.List<SymbolInfo> symbols, Cancellable? cancellable) throws Error, IOError {
		GDB.Client gdb = machine.gdb;

		uint64 data_list = gdb.make_buffer (yield gdb.read_byte_array (
			version_block + DEBUGGER_DATA_LIST_OFFSET, 4, cancellable)).read_uint32 (0);
		if (!is_kernel_address (data_list))
			return;

		uint64 block = gdb.make_buffer (yield gdb.read_byte_array (data_list, 4, cancellable)).read_uint32 (0);
		if (!is_kernel_address (block))
			return;

		uint64 head = gdb.make_buffer (yield gdb.read_byte_array (block + PROCESS_LIST_HEAD_OFFSET, 4,
			cancellable)).read_uint32 (0);
		if (!is_kernel_address (head))
			return;

		symbols.add (new SymbolInfo () {
			name = PROCESS_LIST_HEAD,
			offset = (uint32) head,
			symbol_type = 0xf,
			section = 0x10,
		});
	}

	private static async string read_unicode_string (Machine machine, Buffer owner, size_t offset,
			Cancellable? cancellable) throws Error, IOError {
		uint16 length = owner.read_uint16 (offset);
		uint64 buffer = owner.read_uint32 (offset + UNICODE_STRING_BUFFER_OFFSET);
		if (length == 0 || length > MAX_NAME_SIZE || !is_kernel_address (buffer))
			return "";

		Bytes raw = yield machine.gdb.read_byte_array (buffer, length, cancellable);
		try {
			return convert ((string) raw.get_data (), length, "UTF-8", "UTF-16LE");
		} catch (ConvertError e) {
			return "";
		}
	}

	private static bool is_kernel_address (uint64 address) {
		return address >= KERNEL_SPACE_BASE && address <= uint32.MAX;
	}

	private const uint64 PCR_BASE = 0xffdff000;
	private const size_t PCR_PROLOGUE_SIZE = 0x38;
	private const size_t SELF_PCR_OFFSET = 0x1c;
	private const size_t VERSION_BLOCK_OFFSET = 0x34;

	private const size_t VERSION_BLOCK_SIZE = 0x28;
	private const size_t MACHINE_TYPE_OFFSET = 0x08;
	private const size_t LOADED_MODULE_LIST_OFFSET = 0x18;
	private const size_t DEBUGGER_DATA_LIST_OFFSET = 0x20;
	private const uint16 IMAGE_FILE_MACHINE_I386 = 0x014c;

	public const string PROCESS_LIST_HEAD = "PsActiveProcessHead";
	private const size_t PROCESS_LIST_HEAD_OFFSET = 0x50;

	private const size_t TABLE_ENTRY_SIZE = 0x34;
	private const size_t FORWARD_LINK_OFFSET = 0x00;
	private const size_t DLL_BASE_OFFSET = 0x18;
	private const size_t IMAGE_SIZE_OFFSET = 0x20;
	private const size_t BASE_NAME_OFFSET = 0x2c;
	private const size_t UNICODE_STRING_BUFFER_OFFSET = 0x04;
	private const uint16 MAX_NAME_SIZE = 0x200;

	private const uint64 KERNEL_SPACE_BASE = 0x80000000;
}
