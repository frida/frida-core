[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	public static async WinNtLayout collect_winnt_layout (Machine machine, Cancellable? cancellable)
			throws Error, IOError {
		var modules = new Gee.ArrayList<ModuleInfo> ();
		var symbols = new Gee.ArrayList<SymbolInfo> ();

		Shape shape = Shape.of (machine.gdb.pointer_size);

		uint64 version_block = yield find_version_block (machine, shape, cancellable);
		uint64 module_list = yield read_loaded_module_list (machine, version_block, shape, cancellable);

		foreach (LoadedModule module in yield read_loaded_modules (machine, module_list, shape, cancellable)) {
			modules.add (new ModuleInfo () {
				name = module.name,
				version = "",
				offset = module.base_address,
				size = module.size,
			});

			yield add_export_symbols (machine, module, symbols, cancellable);
		}

		yield add_process_list_symbol (machine, version_block, shape, symbols, cancellable);

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

	// The processor control region points to the block that a kernel debugger uses. That block
	// gives the kernel and its module list, which is sufficient to find the other data.
	private static async uint64 find_version_block (Machine machine, Shape shape, Cancellable? cancellable)
			throws Error, IOError {
		GDB.Client gdb = machine.gdb;

		uint64 pcr_base = yield find_processor_control_region (machine, shape, cancellable);

		Buffer pcr = gdb.make_buffer (yield gdb.read_byte_array (pcr_base,
			shape.version_block + shape.pointer_size, cancellable));
		uint64 version_block = read_pointer (pcr, shape.version_block, shape);
		if (!is_kernel_address (version_block, shape))
			throw new Error.NOT_SUPPORTED ("Unable to find the kernel debugger version block");

		Buffer v = gdb.make_buffer (yield gdb.read_byte_array (version_block, VERSION_BLOCK_SIZE, cancellable));
		if (v.read_uint16 (MACHINE_TYPE_OFFSET) != shape.machine_type)
			throw new Error.NOT_SUPPORTED ("Kernel is not the architecture the stub reports");

		return version_block;
	}

	// A 32-bit kernel keeps this block at a constant address. A 64-bit kernel selects the address
	// and points GS to it in kernel mode. In user mode GS points to the block of the current
	// thread, because the processor exchanges the two values.
	private static async uint64 find_processor_control_region (Machine machine, Shape shape,
			Cancellable? cancellable) throws Error, IOError {
		GDB.Client gdb = machine.gdb;

		if (shape.pointer_size == 4) {
			if (yield points_at_itself (machine, PCR_BASE, shape, cancellable))
				return PCR_BASE;
			throw new Error.NOT_SUPPORTED ("Unable to find the processor control region");
		}

		for (uint attempt = 0; attempt != MAX_CATCH_ATTEMPTS; attempt++) {
			GDB.Thread thread = gdb.exception.thread;
			foreach (string name in new string[] { "gs_base", "k_gs_base" }) {
				uint64 candidate;
				try {
					candidate = yield thread.read_register (name, cancellable);
				} catch (Error e) {
					continue;
				}
				if (yield points_at_itself (machine, candidate, shape, cancellable))
					return candidate;
			}

			yield catch_processor_again (gdb, cancellable);
		}

		throw new Error.NOT_SUPPORTED ("Unable to find the processor control region");
	}

	// You can read only the value that GS holds now. Thus continue the guest and try again.
	private static async void catch_processor_again (GDB.Client gdb, Cancellable? cancellable)
			throws Error, IOError {
		yield gdb.continue (cancellable);

		var source = new TimeoutSource (CATCH_INTERVAL_MS);
		source.set_callback (catch_processor_again.callback);
		source.attach (MainContext.get_thread_default ());
		yield;

		yield gdb.stop (cancellable);
	}

	private const uint MAX_CATCH_ATTEMPTS = 20;
	private const uint CATCH_INTERVAL_MS = 20;

	// A processor control region starts with its own address. Use this to identify a candidate.
	private static async bool points_at_itself (Machine machine, uint64 candidate, Shape shape,
			Cancellable? cancellable) throws Error, IOError {
		if (!is_kernel_address (candidate, shape))
			return false;

		GDB.Client gdb = machine.gdb;
		Buffer head;
		try {
			head = gdb.make_buffer (yield gdb.read_byte_array (candidate + shape.self,
				shape.pointer_size, cancellable));
		} catch (Error e) {
			return false;
		}

		return read_pointer (head, 0, shape) == candidate;
	}

	// Both kernels use the 64-bit form of this structure, and a 32-bit kernel extends the sign of
	// the pointers in it.
	private static async uint64 read_loaded_module_list (Machine machine, uint64 version_block, Shape shape,
			Cancellable? cancellable) throws Error, IOError {
		GDB.Client gdb = machine.gdb;

		uint64 list = read_pointer (gdb.make_buffer (yield gdb.read_byte_array (
			version_block + LOADED_MODULE_LIST_OFFSET, shape.pointer_size, cancellable)), 0, shape);
		if (!is_kernel_address (list, shape))
			throw new Error.NOT_SUPPORTED ("Unable to find the loaded module list");

		return list;
	}

	private static async Gee.List<LoadedModule> read_loaded_modules (Machine machine, uint64 head, Shape shape,
			Cancellable? cancellable) throws Error, IOError {
		var modules = new Gee.ArrayList<LoadedModule> ();

		GDB.Client gdb = machine.gdb;
		uint64 entry = read_pointer (gdb.make_buffer (yield gdb.read_byte_array (head, shape.pointer_size,
			cancellable)), 0, shape);
		var visited = new Gee.HashSet<uint64?> ((n) => (uint) (*(uint64 *) n), (a, b) => *(uint64 *) a == *(uint64 *) b);
		while (entry != head && is_kernel_address (entry, shape) && !visited.contains (entry)) {
			visited.add (entry);

			Buffer e = gdb.make_buffer (yield gdb.read_byte_array (entry, shape.table_entry_size, cancellable));

			uint64 base_address = read_pointer (e, shape.dll_base, shape);
			if (is_kernel_address (base_address, shape)) {
				modules.add (new LoadedModule () {
					base_address = base_address,
					size = e.read_uint32 (shape.image_size),
					name = yield read_unicode_string (machine, e, shape.base_name, shape, cancellable),
				});
			}

			entry = read_pointer (e, FORWARD_LINK_OFFSET, shape);
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
				offset = module.base_address + e.rva,
				symbol_type = 0xf,
				section = 0x10,
			});
		}
	}

	// The kernel gives the addresses that a debugger needs here, and no module exports them.
	private static async void add_process_list_symbol (Machine machine, uint64 version_block, Shape shape,
			Gee.List<SymbolInfo> symbols, Cancellable? cancellable) throws Error, IOError {
		GDB.Client gdb = machine.gdb;

		uint64 data_list = read_pointer (gdb.make_buffer (yield gdb.read_byte_array (
			version_block + DEBUGGER_DATA_LIST_OFFSET, shape.pointer_size, cancellable)), 0, shape);
		if (!is_kernel_address (data_list, shape))
			return;

		uint64 block = read_pointer (gdb.make_buffer (yield gdb.read_byte_array (data_list, shape.pointer_size,
			cancellable)), 0, shape);
		if (!is_kernel_address (block, shape))
			return;

		uint64 head = read_pointer (gdb.make_buffer (yield gdb.read_byte_array (
			block + PROCESS_LIST_HEAD_OFFSET, shape.pointer_size, cancellable)), 0, shape);
		if (!is_kernel_address (head, shape))
			return;

		symbols.add (new SymbolInfo () {
			name = PROCESS_LIST_HEAD,
			offset = head,
			symbol_type = 0xf,
			section = 0x10,
		});
	}

	private static async string read_unicode_string (Machine machine, Buffer owner, size_t offset, Shape shape,
			Cancellable? cancellable) throws Error, IOError {
		uint16 length = owner.read_uint16 (offset);
		uint64 buffer = read_pointer (owner, offset + shape.name_buffer, shape);
		if (length == 0 || length > MAX_NAME_SIZE || !is_kernel_address (buffer, shape))
			return "";

		Bytes raw = yield machine.gdb.read_byte_array (buffer, length, cancellable);
		try {
			return convert ((string) raw.get_data (), length, "UTF-8", "UTF-16LE");
		} catch (ConvertError e) {
			return "";
		}
	}

	private static uint64 read_pointer (Buffer buf, size_t offset, Shape shape) {
		return (shape.pointer_size == 8) ? buf.read_uint64 (offset) : buf.read_uint32 (offset);
	}

	private static bool is_kernel_address (uint64 address, Shape shape) {
		if (shape.pointer_size == 8)
			return address >= KERNEL_SPACE_BASE_64;
		return address >= KERNEL_SPACE_BASE && address <= uint32.MAX;
	}

	private class Shape {
		public uint pointer_size;
		public uint16 machine_type;
		public size_t self;
		public size_t version_block;
		public size_t table_entry_size;
		public size_t dll_base;
		public size_t image_size;
		public size_t base_name;
		public size_t name_buffer;

		public static Shape of (uint pointer_size) {
			if (pointer_size == 8) {
				return new Shape () {
					pointer_size = 8,
					machine_type = IMAGE_FILE_MACHINE_AMD64,
					self = 0x18,
					version_block = 0x108,
					table_entry_size = 0x68,
					dll_base = 0x30,
					image_size = 0x40,
					base_name = 0x58,
					name_buffer = 0x08,
				};
			}

			return new Shape () {
				pointer_size = 4,
				machine_type = IMAGE_FILE_MACHINE_I386,
				self = 0x1c,
				version_block = 0x34,
				table_entry_size = 0x34,
				dll_base = 0x18,
				image_size = 0x20,
				base_name = 0x2c,
				name_buffer = 0x04,
			};
		}
	}

	private const uint64 PCR_BASE = 0xffdff000;

	private const size_t VERSION_BLOCK_SIZE = 0x28;
	private const size_t MACHINE_TYPE_OFFSET = 0x08;
	private const size_t LOADED_MODULE_LIST_OFFSET = 0x18;
	private const size_t DEBUGGER_DATA_LIST_OFFSET = 0x20;
	private const uint16 IMAGE_FILE_MACHINE_I386 = 0x014c;
	private const uint16 IMAGE_FILE_MACHINE_AMD64 = 0x8664;

	public const string PROCESS_LIST_HEAD = "PsActiveProcessHead";
	private const size_t PROCESS_LIST_HEAD_OFFSET = 0x50;

	private const size_t FORWARD_LINK_OFFSET = 0x00;
	private const uint16 MAX_NAME_SIZE = 0x200;

	private const uint64 KERNEL_SPACE_BASE = 0x80000000;
	private const uint64 KERNEL_SPACE_BASE_64 = 0xffff800000000000;
}
