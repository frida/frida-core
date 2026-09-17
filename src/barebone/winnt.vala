[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	public static async WinNtLayout collect_winnt_layout (Machine machine, Cancellable? cancellable)
			throws Error, IOError {
		var modules = new Gee.ArrayList<ModuleInfo> ();
		var symbols = new Gee.ArrayList<SymbolInfo> ();

		Shape shape = Shape.of (machine.debugger);

		Anchors anchors = yield find_anchors (machine, shape, cancellable);

		LoadedModule? kernel = yield read_first_loaded_module (machine, anchors.module_list, shape, cancellable);
		if (kernel != null) {
			modules.add (new ModuleInfo () {
				name = kernel.name,
				version = "",
				offset = kernel.base_address,
				size = kernel.size,
			});

			yield add_export_symbols (machine, kernel, anchors.exports, symbols, cancellable);
		}

		if (anchors.process_list_head != 0) {
			symbols.add (new SymbolInfo () {
				name = PROCESS_LIST_HEAD,
				offset = anchors.process_list_head,
				symbol_type = 0xf,
				section = 0x10,
			});
		}

		return new WinNtLayout (modules, symbols, anchors.module_list);
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

		public uint64 module_list {
			get;
			construct;
		}

		public WinNtLayout (Gee.List<ModuleInfo> modules, Gee.List<SymbolInfo> symbols, uint64 module_list) {
			Object (modules: modules, symbols: symbols, module_list: module_list);
		}
	}

	private static async Anchors find_anchors (Machine machine, Shape shape, Cancellable? cancellable)
			throws Error, IOError {
		if (processor_control_region_is_reachable (machine.debugger, shape)) {
			uint64 version_block = yield find_version_block (machine, shape, cancellable);
			if (version_block != 0) {
				return new Anchors () {
					module_list = yield read_loaded_module_list (machine, version_block, shape,
						cancellable),
					process_list_head = yield read_process_list_head (machine, version_block, shape,
						cancellable),
				};
			}
		}

		return yield read_anchors_from_kernel (machine, shape, cancellable);
	}

	private class KernelImage {
		public uint64 address;
		public Gee.List<Export> exports;

		public KernelImage (uint64 address, Gee.List<Export> exports) {
			this.address = address;
			this.exports = exports;
		}
	}

	private class Anchors {
		public uint64 module_list;
		public uint64 process_list_head;
		public Gee.List<Export>? exports;
	}

	private static bool processor_control_region_is_reachable (Debugger debugger, Shape shape) {
		if (shape.pointer_size == 4)
			return true;
		return debugger.has_register ("gs_base") || debugger.has_register ("k_gs_base");
	}

	private static async Anchors read_anchors_from_kernel (Machine machine, Shape shape,
			Cancellable? cancellable) throws Error, IOError {
		KernelImage found = yield find_kernel_image (machine, shape, cancellable);
		uint64 kernel = found.address;

		uint64 module_list = 0;
		foreach (Export e in found.exports) {
			if (e.name == LOADED_MODULE_LIST) {
				module_list = kernel + e.rva;
				break;
			}
		}
		if (!is_kernel_address (module_list, shape))
			throw new Error.NOT_SUPPORTED ("Unable to find the loaded module list");

		return new Anchors () {
			module_list = module_list,
			process_list_head = 0,
			exports = found.exports,
		};
	}

	private static async KernelImage find_kernel_image (Machine machine, Shape shape,
			Cancellable? cancellable) throws Error, IOError {
		Debugger debugger = machine.debugger;

		for (uint attempt = 0; attempt != MAX_CATCH_ATTEMPTS; attempt++) {
			if (yield stopped_in_kernel_mode (debugger, cancellable)) {
				DebuggerThread thread = debugger.exception.thread;
				var visited = make_visited ();

				string? entry = system_call_entry_register (debugger);
				if (entry != null) {
					uint64 handler = yield thread.read_register (entry, cancellable);
					if (is_kernel_address (handler, shape)) {
						KernelImage? image = yield find_image_below (machine, handler, visited,
							cancellable);
						if (image != null)
							return image;
					}
				}

				uint64 pc = yield thread.read_register (program_counter_register (debugger), cancellable);
				if (is_kernel_address (pc, shape)) {
					KernelImage? image = yield find_image_below (machine, pc, visited, cancellable);
					if (image != null)
						return image;
				}

				uint64 seed = yield thread.read_register (image_pointer_register (debugger), cancellable);
				if (is_kernel_address (seed, shape)) {
					KernelImage? image = yield find_image_below_pointers (machine, seed, shape,
						visited, cancellable);
					if (image != null)
						return image;
				}
			}

			yield catch_processor_again (debugger, cancellable);
		}

		throw new Error.NOT_SUPPORTED ("Unable to find the kernel image");
	}

	private static string? system_call_entry_register (Debugger debugger) {
		if (debugger.arch != TargetArch.X64 || !debugger.has_register (SYSTEM_CALL_ENTRY_REGISTER))
			return null;

		return SYSTEM_CALL_ENTRY_REGISTER;
	}

	private static string program_counter_register (Debugger debugger) {
		switch (debugger.arch) {
			case IA32:	return "eip";
			case X64:	return "rip";
			default:	return "pc";
		}
	}

	private static async KernelImage? find_image_below (Machine machine, uint64 address,
			Gee.Set<uint64?> visited, Cancellable? cancellable) throws Error, IOError {
		KernelImage? image = yield sweep_for_image_below (machine, address, LARGE_PAGE_SIZE,
			make_visited (), cancellable);
		if (image != null)
			return image;

		return yield sweep_for_image_below (machine, address, KERNEL_IMAGE_ALIGNMENT, visited,
			cancellable);
	}

	private static Gee.Set<uint64?> make_visited () {
		return new Gee.HashSet<uint64?> ((n) => (uint) (*(uint64 *) n),
			(a, b) => *(uint64 *) a == *(uint64 *) b);
	}

	private static async KernelImage? sweep_for_image_below (Machine machine, uint64 address,
			uint64 stride, Gee.Set<uint64?> visited, Cancellable? cancellable) throws Error, IOError {
		uint64 image = address - (address % stride);
		for (uint step = 0; step != MAX_IMAGE_STEPS && visited.size != MAX_IMAGE_PROBES; step++,
				image -= stride) {
			if (!visited.add (image))
				break;

			Gee.List<Export> candidate;
			try {
				candidate = yield enumerate_exports (machine, image, cancellable);
			} catch (Error e) {
				continue;
			}

			uint64 module_list = 0;
			foreach (Export e in candidate) {
				if (e.name == LOADED_MODULE_LIST) {
					module_list = image + e.rva;
					break;
				}
			}

			if (module_list != 0)
				return new KernelImage (image, candidate);
		}

		return null;
	}

	private static string image_pointer_register (Debugger debugger) {
		return (debugger.arch == TargetArch.ARM64) ? KERNEL_PCR_REGISTER : KERNEL_STACK_REGISTER;
	}

	private static async KernelImage? find_image_below_pointers (Machine machine, uint64 seed,
			Shape shape, Gee.Set<uint64?> visited, Cancellable? cancellable) throws Error, IOError {

		Debugger debugger = machine.debugger;
		uint64 seed_page = seed - (seed % PCR_SCAN_SIZE);
		Buffer page = debugger.make_buffer (yield debugger.read_byte_array (seed_page, PCR_SCAN_SIZE, cancellable));

		for (size_t offset = 0; offset != PCR_SCAN_SIZE; offset += shape.pointer_size) {
			uint64 candidate = read_pointer (page, offset, shape);
			if (!is_kernel_address (candidate, shape))
				continue;

			KernelImage? image = yield find_image_below (machine, candidate, visited, cancellable);
			if (image != null)
				return image;
		}

		return null;
	}

	// The processor control region points to the block that a kernel debugger uses. That block
	// gives the kernel and its module list, which is sufficient to find the other data.
	private static async uint64 find_version_block (Machine machine, Shape shape, Cancellable? cancellable)
			throws Error, IOError {
		Debugger debugger = machine.debugger;

		uint64 pcr_base = yield find_processor_control_region (machine, shape, cancellable);
		if (pcr_base == 0)
			return 0;

		Buffer pcr = debugger.make_buffer (yield debugger.read_byte_array (pcr_base,
			shape.version_block + shape.pointer_size, cancellable));
		uint64 version_block = read_pointer (pcr, shape.version_block, shape);
		if (!is_kernel_address (version_block, shape))
			return 0;

		Buffer v = debugger.make_buffer (yield debugger.read_byte_array (version_block, VERSION_BLOCK_SIZE, cancellable));
		if (v.read_uint16 (MACHINE_TYPE_OFFSET) != shape.machine_type)
			return 0;

		return version_block;
	}

	// A 32-bit kernel keeps this block at a constant address. A 64-bit kernel selects the address
	// and points GS to it in kernel mode. In user mode GS points to the block of the current
	// thread, because the processor exchanges the two values.
	private static async uint64 find_processor_control_region (Machine machine, Shape shape,
			Cancellable? cancellable) throws Error, IOError {
		Debugger debugger = machine.debugger;

		if (shape.pointer_size == 4) {
			return (yield points_at_itself (machine, PCR_BASE, shape, cancellable)) ? PCR_BASE : 0;
		}

		for (uint attempt = 0; attempt != MAX_CATCH_ATTEMPTS; attempt++) {
			DebuggerThread thread = debugger.exception.thread;
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

			yield catch_processor_again (debugger, cancellable);
		}

		return 0;
	}

	// You can read only the value that GS holds now. Thus continue the guest and try again.
	private static async void catch_processor_again (Debugger debugger, Cancellable? cancellable)
			throws Error, IOError {
		yield debugger.resume (cancellable);

		var source = new TimeoutSource (CATCH_INTERVAL_MS);
		source.set_callback (catch_processor_again.callback);
		source.attach (MainContext.get_thread_default ());
		yield;

		yield debugger.stop (cancellable);
	}

	private const uint MAX_CATCH_ATTEMPTS = 20;
	private const uint CATCH_INTERVAL_MS = 20;

	// A processor control region starts with its own address. Use this to identify a candidate.
	private static async bool points_at_itself (Machine machine, uint64 candidate, Shape shape,
			Cancellable? cancellable) throws Error, IOError {
		if (!is_kernel_address (candidate, shape))
			return false;

		Debugger debugger = machine.debugger;
		Buffer head;
		try {
			head = debugger.make_buffer (yield debugger.read_byte_array (candidate + shape.self,
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
		Debugger debugger = machine.debugger;

		uint64 list = read_pointer (debugger.make_buffer (yield debugger.read_byte_array (
			version_block + LOADED_MODULE_LIST_OFFSET, shape.pointer_size, cancellable)), 0, shape);
		if (!is_kernel_address (list, shape))
			throw new Error.NOT_SUPPORTED ("Unable to find the loaded module list");

		return list;
	}

	// The kernel gives the addresses that a debugger needs here, and no module exports them.
	private static async uint64 read_process_list_head (Machine machine, uint64 version_block, Shape shape,
			Cancellable? cancellable) throws Error, IOError {
		Debugger debugger = machine.debugger;

		uint64 data_list = read_pointer (debugger.make_buffer (yield debugger.read_byte_array (
			version_block + DEBUGGER_DATA_LIST_OFFSET, shape.pointer_size, cancellable)), 0, shape);
		if (!is_kernel_address (data_list, shape))
			return 0;

		uint64 block = read_pointer (debugger.make_buffer (yield debugger.read_byte_array (data_list, shape.pointer_size,
			cancellable)), 0, shape);
		if (!is_kernel_address (block, shape))
			return 0;

		uint64 head = read_pointer (debugger.make_buffer (yield debugger.read_byte_array (
			block + PROCESS_LIST_HEAD_OFFSET, shape.pointer_size, cancellable)), 0, shape);
		if (!is_kernel_address (head, shape))
			return 0;

		return head;
	}

	private static async LoadedModule? read_first_loaded_module (Machine machine, uint64 head, Shape shape,
			Cancellable? cancellable) throws Error, IOError {
		Debugger debugger = machine.debugger;

		uint64 entry = read_pointer (debugger.make_buffer (yield debugger.read_byte_array (head, shape.pointer_size,
			cancellable)), 0, shape);
		if (entry == head || !is_kernel_address (entry, shape))
			return null;

		Buffer e = debugger.make_buffer (yield debugger.read_byte_array (entry, shape.table_entry_size, cancellable));

		uint64 base_address = read_pointer (e, shape.dll_base, shape);
		if (!is_kernel_address (base_address, shape))
			return null;

		return new LoadedModule () {
			base_address = base_address,
			size = e.read_uint32 (shape.image_size),
			name = yield read_unicode_string (machine, e, shape.base_name, shape, cancellable),
		};
	}

	private class LoadedModule {
		public uint64 base_address;
		public uint32 size;
		public string name;
	}

	private static async void add_export_symbols (Machine machine, LoadedModule module,
			Gee.List<Export>? known, Gee.List<SymbolInfo> symbols, Cancellable? cancellable)
			throws Error, IOError {
		Gee.List<Export> exports;
		if (known != null) {
			exports = known;
		} else {
			try {
				exports = yield enumerate_exports (machine, module.base_address, cancellable);
			} catch (Error e) {
				return;
			}
		}

		foreach (Export e in exports) {
			symbols.add (new SymbolInfo () {
				name = e.name,
				offset = module.base_address + e.rva,
				symbol_type = 0xf,
				section = 0x10,
			});
		}
	}

	private static async string read_unicode_string (Machine machine, Buffer owner, size_t offset, Shape shape,
			Cancellable? cancellable) throws Error, IOError {
		uint16 length = owner.read_uint16 (offset);
		uint64 buffer = read_pointer (owner, offset + shape.name_buffer, shape);
		if (length == 0 || length > MAX_NAME_SIZE || !is_kernel_address (buffer, shape))
			return "";

		Bytes raw = yield machine.debugger.read_byte_array (buffer, length, cancellable);
		try {
			return convert ((string) raw.get_data (), length, "UTF-8", "UTF-16LE");
		} catch (ConvertError e) {
			return "";
		}
	}

	internal static async bool stopped_in_kernel_mode (Debugger debugger, Cancellable? cancellable)
			throws Error, IOError {
		DebuggerThread thread = debugger.exception.thread;

		if (debugger.arch == TargetArch.ARM64) {
			uint64 state = yield thread.read_register ("cpsr", cancellable);
			return ((state >> EXCEPTION_LEVEL_SHIFT) & EXCEPTION_LEVEL_MASK) == KERNEL_EXCEPTION_LEVEL;
		}

		uint64 cs = yield thread.read_register ("cs", cancellable);
		return (cs & RING_MASK) == 0;
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

		public static Shape of (Debugger debugger) {
			Shape shape = for_pointer_size (debugger.pointer_size);
			if (debugger.arch == TargetArch.ARM64)
				shape.machine_type = IMAGE_FILE_MACHINE_ARM64;
			return shape;
		}

		private static Shape for_pointer_size (uint pointer_size) {
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
	private const uint16 IMAGE_FILE_MACHINE_ARM64 = 0xaa64;

	private const string KERNEL_PCR_REGISTER = "x18";
	private const string KERNEL_STACK_REGISTER = "rsp";
	private const string SYSTEM_CALL_ENTRY_REGISTER = "lstar";
	private const size_t PCR_SCAN_SIZE = 0x1000;
	private const uint64 KERNEL_IMAGE_ALIGNMENT = 0x10000;
	private const uint64 LARGE_PAGE_SIZE = 0x200000;
	private const uint MAX_IMAGE_STEPS = 512;
	private const uint MAX_IMAGE_PROBES = 4096;

	private const string LOADED_MODULE_LIST = "PsLoadedModuleList";

	private const uint64 RING_MASK = 3;
	private const uint EXCEPTION_LEVEL_SHIFT = 2;
	private const uint64 EXCEPTION_LEVEL_MASK = 3;
	private const uint64 KERNEL_EXCEPTION_LEVEL = 1;

	public const string MODULE_LIST_NOTE = "kernel.modules";
	public const string PROCESS_LIST_HEAD = "PsActiveProcessHead";
	private const size_t PROCESS_LIST_HEAD_OFFSET = 0x50;

	private const size_t FORWARD_LINK_OFFSET = 0x00;
	private const uint16 MAX_NAME_SIZE = 0x200;

	private const uint64 KERNEL_SPACE_BASE = 0x80000000;
	private const uint64 KERNEL_SPACE_BASE_64 = 0xffff800000000000;
}
