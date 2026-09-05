[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	/**
	 * Linux names its symbols in a System.map alongside the kernel, at the addresses it was
	 * linked for. The running kernel is somewhere else, so the two are told apart here: the
	 * image in memory says where it landed, and every symbol moves by the same distance.
	 */
	public static async LinuxLayout collect_linux_layout (Machine machine, string system_map_path,
			Cancellable? cancellable) throws Error, IOError {
		var symbols = parse_system_map (yield read_system_map (system_map_path, cancellable));
		if (symbols.is_empty)
			throw new Error.INVALID_ARGUMENT ("System.map names no symbols");

		uint64 linked_base = base_of (symbols);
		uint64 running_base = yield find_running_kernel (machine, linked_base, symbols, cancellable);

		var modules = new Gee.ArrayList<ModuleInfo> ();
		modules.add (new ModuleInfo () {
			name = "kernel",
			version = "",
			offset = 0,
			size = span_of (symbols, linked_base),
		});

		foreach (var symbol in symbols)
			symbol.offset -= linked_base;

		return new LinuxLayout (running_base, modules, symbols);
	}

	private static async string read_system_map (string path, Cancellable? cancellable) throws Error, IOError {
		var bytes = yield FS.read_all_bytes (File.new_for_path (path), cancellable);
		return (string) Bytes.unref_to_data ((owned) bytes);
	}

	/**
	 * Each line is an address, a one-letter type, and a name. Only the text and data symbols
	 * are worth carrying: the rest name sections and boundaries the agent never asks for.
	 */
	private static Gee.List<SymbolInfo> parse_system_map (string text) {
		var symbols = new Gee.ArrayList<SymbolInfo> ();

		foreach (unowned string line in text.split ("\n")) {
			string[] fields = line.split (" ", 3);
			if (fields.length != 3)
				continue;

			uint64 address;
			if (!uint64.try_parse (fields[0], out address, null, 16))
				continue;

			symbols.add (new SymbolInfo () {
				name = fields[2].strip (),
				offset = address,
				symbol_type = 0xf,
				section = 0x10,
			});
		}

		return symbols;
	}

	private static uint64 base_of (Gee.List<SymbolInfo> symbols) {
		uint64 lowest = uint64.MAX;
		foreach (var symbol in symbols) {
			if (symbol.name == "_text")
				return symbol.offset;
			lowest = uint64.min (lowest, symbol.offset);
		}
		return lowest;
	}

	private static uint64 span_of (Gee.List<SymbolInfo> symbols, uint64 base_address) {
		uint64 highest = base_address;
		foreach (var symbol in symbols)
			highest = uint64.max (highest, symbol.offset);
		return highest - base_address;
	}

	/**
	 * Where the guest is executing says which way to look for the kernel it was linked apart
	 * from. arm64 walks back through memory, a segment at a time, until the magic every image
	 * carries turns up. x86 slides the whole image by a random aligned amount instead of
	 * heading it, so the pc caught in the kernel bounds where its text can be and the banner
	 * every build carries confirms the landing.
	 *
	 * A 32-bit ARM kernel carries no header and nothing relocates it, so it runs at the
	 * address its symbols were linked for.
	 */
	private static async uint64 find_running_kernel (Machine machine, uint64 linked_base,
			Gee.List<SymbolInfo> symbols, Cancellable? cancellable) throws Error, IOError {
		// A guest idling in a shell is executing userspace, whose addresses say nothing about
		// where the kernel is and cannot be walked with the kernel's tables.
		yield machine.enter_exception_level (1, ENTER_KERNEL_TIMEOUT_MS, cancellable);

		if (machine is ArmMachine)
			return linked_base;

		GDB.Client gdb = machine.gdb;
		var thread = gdb.exception.thread;
		var registers = yield thread.read_registers (cancellable);

		if (machine is IA32Machine || machine is X64Machine)
			return yield find_relocated_kernel (gdb, registers, linked_base, symbols, cancellable);

		uint64 pc = registers["pc"].get_uint64 ();
		uint64 candidate = pc - (pc % KERNEL_ALIGNMENT);

		for (uint step = 0; step != MAX_STEPS_BACK; step++) {
			// Most of what is walked past is not mapped at all, and saying so is how the
			// guest declines to be read.
			try {
				var header = yield gdb.read_byte_array (candidate + IMAGE_MAGIC_OFFSET,
					IMAGE_MAGIC.length, cancellable);
				if (Memory.cmp (header.get_data (), IMAGE_MAGIC.data, IMAGE_MAGIC.length) == 0)
					return candidate;
			} catch (Error e) {
			}

			candidate -= KERNEL_ALIGNMENT;
		}

		throw new Error.NOT_SUPPORTED ("Unable to find the running kernel; is the guest in kernel mode?");
	}

	private static async uint64 find_relocated_kernel (GDB.Client gdb, Gee.Map<string, Variant> registers,
			uint64 linked_base, Gee.List<SymbolInfo> symbols, Cancellable? cancellable) throws Error, IOError {
		uint64 pc = registers.has_key ("rip")
			? registers["rip"].get_uint64 ()
			: registers["eip"].get_uint64 ();

		uint64 banner = address_of (symbols, KERNEL_BANNER_SYMBOL);
		if (banner == 0)
			throw new Error.NOT_SUPPORTED ("System.map names no %s to anchor relocation", KERNEL_BANNER_SYMBOL);
		uint64 banner_offset = banner - linked_base;

		uint64 span = span_of (symbols, linked_base);
		uint64 lowest = (pc - span) & ~(KERNEL_ALIGNMENT - 1);
		uint64 highest = (pc + KERNEL_ALIGNMENT) & ~(KERNEL_ALIGNMENT - 1);

		for (uint64 landing = lowest; landing <= highest; landing += KERNEL_ALIGNMENT) {
			try {
				var head = yield gdb.read_byte_array (landing + banner_offset, KERNEL_BANNER.length, cancellable);
				if (Memory.cmp (head.get_data (), KERNEL_BANNER.data, KERNEL_BANNER.length) == 0)
					return landing;
			} catch (Error e) {
			}
		}

		throw new Error.NOT_SUPPORTED ("Unable to find the relocated kernel; is the guest in kernel mode?");
	}

	private static uint64 address_of (Gee.List<SymbolInfo> symbols, string name) {
		foreach (var symbol in symbols) {
			if (symbol.name == name)
				return symbol.offset;
		}
		return 0;
	}

	private const string IMAGE_MAGIC = "ARM\x64";
	private const uint64 IMAGE_MAGIC_OFFSET = 0x38;
	private const string KERNEL_BANNER_SYMBOL = "linux_banner";
	private const string KERNEL_BANNER = "Linux version ";
	private const uint64 KERNEL_ALIGNMENT = 2 * 1024 * 1024;
	private const uint MAX_STEPS_BACK = 512;
	private const uint ENTER_KERNEL_TIMEOUT_MS = 1000;

	public sealed class LinuxLayout : Object {
		public uint64 base_address {
			get;
			construct;
		}

		public Gee.List<ModuleInfo> modules {
			get;
			construct;
		}

		public Gee.List<SymbolInfo> symbols {
			get;
			construct;
		}

		public LinuxLayout (uint64 base_address, Gee.List<ModuleInfo> modules, Gee.List<SymbolInfo> symbols) {
			Object (base_address: base_address, modules: modules, symbols: symbols);
		}
	}
}
