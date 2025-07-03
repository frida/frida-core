[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	public sealed class Layout : Object {
		public Gee.List<ModuleInfo> modules {
			get;
			construct;
		}

		public Gee.List<SymbolInfo> symbols {
			get;
			construct;
		}

		private const uint64 CHAINED_PTR_TARGET_MASK = (1 << 30) - 1;

		private Layout (Gee.List<ModuleInfo> modules, Gee.List<SymbolInfo> symbols) {
			Object (modules: modules, symbols: symbols);
		}

		public Layout.empty () {
			Object (modules: new Gee.ArrayList<ModuleInfo> (), symbols: new Gee.ArrayList<SymbolInfo> ());
		}

		public static async Layout load_from_symbol_source (File symbol_source, uint64 kernel_base, ByteOrder byte_order,
				uint pointer_size, Cancellable? cancellable) throws Error, IOError {
			var payload = yield Img4.parse_file (symbol_source, cancellable);

			Bytes kerncache = payload.data;

			Gum.DarwinModule mod;
			try {
				mod = new Gum.DarwinModule.from_blob (kerncache, ARM64, Gum.PtrauthSupport.SUPPORTED);
			} catch (Gum.Error e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}

			var blob = new Blob (kerncache, byte_order, pointer_size);

			var modules = compute_module_list (mod, blob, kernel_base);
			var symbols = compute_symbol_list (mod);

			return new Layout (modules, symbols);
		}

		private static Gee.List<ModuleInfo> compute_module_list (Gum.DarwinModule mod, Blob blob, uint64 kernel_base) throws Error {
			Buffer? kmod_info = null;
			Buffer? kmod_start = null;
			Error? pending_error = null;
			mod.enumerate_sections (s => {
				if (s.segment_name == "__PRELINK_INFO") {
					try {
						if (s.section_name == "__kmod_info")
							kmod_info = blob.slice (s.file_offset, (size_t) s.size, "__kmod_info");
						else if (s.section_name == "__kmod_start")
							kmod_start = blob.slice (s.file_offset, (size_t) s.size, "__kmod_start");
					} catch (Error e) {
						pending_error = e;
						return false;
					}
				}
				return true;
			});
			if (pending_error != null)
				throw pending_error;
			if (kmod_info == null)
				throw new Error.NOT_SUPPORTED ("Unable to find __kmod_info");
			if (kmod_start == null)
				throw new Error.NOT_SUPPORTED ("Unable to find __kmod_start");

			var kexts = new Gee.ArrayList<ModuleInfo> ();
			var info_pointers = new BufferReader (kmod_info);
			while (info_pointers.available != 0) {
				var kmodinfo_start = chained_pointer_to_vm_offset (info_pointers.read_pointer (), kernel_base);
				var kmodinfo = new BufferReader (blob.slice (kmodinfo_start, 196, "__kmod_info entry"));

				kmodinfo.skip (blob.pointer_size + 4 + 4);

				string name = kmodinfo.read_fixed_string (64);
				string version = kmodinfo.read_fixed_string (64);

				kmodinfo.skip (4 + (2 * blob.pointer_size) + 8 + 8);

				size_t start = chained_pointer_to_vm_offset (kmodinfo.read_pointer (), kernel_base);
				size_t stop = chained_pointer_to_vm_offset (kmodinfo.read_pointer (), kernel_base);

				kexts.add (new ModuleInfo () {
					name = name,
					version = version,
					start_func_offset = (uint32) start,
					stop_func_offset = (uint32) stop,
				});
			}

			var start_offsets = new Gee.ArrayList<uint> ();
			var start_pointers = new BufferReader (kmod_start);
			while (start_pointers.available != 0)
				start_offsets.add ((uint) chained_pointer_to_vm_offset (start_pointers.read_pointer (), kernel_base));
			if (start_offsets.size != kexts.size + 1)
				throw new Error.PROTOCOL ("Unexpected __kmod_start length");

			var n = kexts.size;
			for (var i = 0; i != n; i++) {
				var kext = kexts[i];
				kext.offset = start_offsets[i];
				kext.size = start_offsets[i + 1] - kext.offset;
			}

			var result = new Gee.ArrayList<ModuleInfo> ();

			result.add (new ModuleInfo () {
				name = "mach_kernel",
				version = mod.source_version,
				offset = 0,
				size = kexts[0].offset,
			});
			result.add_all (kexts);

			return result;
		}

		private static size_t chained_pointer_to_vm_offset (uint64 val, uint64 kernel_base) {
			var target = (size_t) (val & CHAINED_PTR_TARGET_MASK);

			bool is_auth = (val >> 63) != 0;
			if (is_auth)
				return target;

			return target - (size_t) (kernel_base & CHAINED_PTR_TARGET_MASK);
		}

		private static Gee.List<SymbolInfo> compute_symbol_list (Gum.DarwinModule mod) {
			var symbols = new Gee.ArrayList<SymbolInfo> ();
			mod.enumerate_symbols (s => {
				symbols.add (new SymbolInfo () {
					name = (s.name[0] == '_') ? s.name[1:] : s.name,
					offset = (uint32) s.address,
					symbol_type = s.type,
					section = s.section,
					description = s.description
				});
				return true;
			});
			return symbols;
		}
	}

	public class ModuleInfo {
		public string name;
		public string version;
		public uint32 offset;
		public uint32 size;
		public uint32 start_func_offset;
		public uint32 stop_func_offset;
	}

	public class SymbolInfo {
		public string name;
		public uint32 offset;
		public uint8 symbol_type;
		public uint8 section;
		public uint16 description;
	}

	private class Blob {
		private Bytes bytes;
		private size_t size;
		public ByteOrder byte_order;
		public uint pointer_size;

		public Blob (Bytes b, ByteOrder o, uint ptr_size) {
			bytes = b;
			size = b.get_size ();
			byte_order = o;
			pointer_size = ptr_size;
		}

		public Buffer slice (size_t offset, size_t n, string label) throws Error {
			if (offset >= size)
				throw new Error.PROTOCOL ("Offset out of bounds while parsing %s", label);

			size_t end = offset + n;
			if (end > size)
				throw new Error.PROTOCOL ("Size out of bounds while parsing %s", label);

			return new Buffer (bytes[offset:end], byte_order, pointer_size);
		}
	}
}
