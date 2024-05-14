[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	public interface Machine : Object {
		public abstract GDB.Client gdb {
			get;
			set;
		}

		public abstract string llvm_target {
			get;
		}

		public abstract string llvm_code_model {
			get;
		}

		public abstract async size_t query_page_size (Cancellable? cancellable) throws Error, IOError;

		public abstract async void enumerate_ranges (Gum.PageProtection prot, FoundRangeFunc func, Cancellable? cancellable)
			throws Error, IOError;

		public abstract async Allocation allocate_pages (uint64 physical_address, uint num_pages, Cancellable? cancellable)
			throws Error, IOError;

		public abstract async Gee.List<uint64?> scan_ranges (Gee.List<Gum.MemoryRange?> ranges, MatchPattern pattern,
			uint max_matches, Cancellable? cancellable) throws Error, IOError;

		public Bytes relocate (Gum.ElfModule module, uint64 base_va) throws Error {
			uint64 file_start = uint64.MAX;
			uint64 file_end = 0;
			module.enumerate_segments (s => {
				if (s.file_size != 0) {
					file_start = uint64.min (s.file_offset, file_start);
					file_end = uint64.max (s.file_offset + s.file_size, file_end);
				}
				return true;
			});

			var relocated_buf = gdb.make_buffer (new Bytes (module.get_file_data ()[file_start:file_end]));
			Error? pending_error = null;
			module.enumerate_relocations (r => {
				unowned string parent_section = (r.parent != null) ? r.parent.name : "";
				if (parent_section == ".rela.text" || parent_section.has_prefix (".rela.debug_"))
					return true;

				try {
					apply_relocation (r, base_va, relocated_buf);
				} catch (Error e) {
					pending_error = e;
					return false;
				}

				return true;
			});
			if (pending_error != null)
				throw pending_error;

			Bytes relocated_bytes = relocated_buf.bytes;
			Bytes relocated_image = gdb.make_buffer_builder ()
				.append_bytes (relocated_bytes)
				.skip ((size_t) (module.mapped_size - relocated_bytes.get_size ()))
				.build ();
			return relocated_image;
		}

		public abstract void apply_relocation (Gum.ElfRelocationDetails r, uint64 base_va, Buffer relocated) throws Error;

		public abstract async uint64 invoke (uint64 impl, uint64[] args, uint64 landing_zone, Cancellable? cancellable)
			throws Error, IOError;

		public abstract async CallFrame load_call_frame (GDB.Thread thread, uint arity, Cancellable? cancellable)
			throws Error, IOError;

		public abstract uint64 address_from_funcptr (uint64 ptr);
		public abstract size_t breakpoint_size_from_funcptr (uint64 ptr);

		public abstract async InlineHook create_inline_hook (uint64 target, uint64 handler, Allocator allocator,
			Cancellable? cancellable) throws Error, IOError;
	}

	public delegate bool FoundRangeFunc (RangeDetails details);

	public class RangeDetails {
		public uint64 base_va;
		public uint64 base_pa;
		public uint64 size;
		public Gum.PageProtection protection;
		public MappingType type;

		public uint64 end {
			get { return base_va + size; }
		}

		public RangeDetails (uint64 base_va, uint64 base_pa, uint64 size, Gum.PageProtection protection, MappingType type) {
			this.base_va = base_va;
			this.base_pa = base_pa;
			this.size = size;
			this.protection = protection;
			this.type = type;
		}

		public RangeDetails clone () {
			return new RangeDetails (base_va, base_pa, size, protection, type);
		}

		public bool contains_virtual_address (uint64 va) {
			return va >= base_va && va < base_va + size;
		}

		public bool contains_physical_address (uint64 pa) {
			return pa >= base_pa && pa < base_pa + size;
		}

		public uint64 virtual_to_physical (uint64 va) {
			assert (contains_virtual_address (va));
			return base_pa + (va - base_va);
		}

		public uint64 physical_to_virtual (uint64 pa) {
			assert (contains_physical_address (pa));
			return base_va + (pa - base_pa);
		}
	}

	public enum MappingType {
		UNKNOWN,
		MEMORY,
		DEVICE;

		public string to_nick () {
			return Marshal.enum_to_nick<MappingType> (this);
		}
	}

	public interface CallFrame : Object {
		public abstract uint64 return_address {
			get;
		}

		public abstract Gee.Map<string, Variant> registers {
			get;
		}

		public abstract uint64 get_nth_argument (uint n);
		public abstract void replace_nth_argument (uint n, uint64 val);
		public abstract uint64 get_return_value ();
		public abstract void replace_return_value (uint64 retval);

		public abstract void force_return ();

		public abstract async void commit (Cancellable? cancellable) throws Error, IOError;
	}

	public interface InlineHook : Object {
		public abstract async void destroy (Cancellable? cancellable) throws Error, IOError;
		public abstract async void enable (Cancellable? cancellable) throws Error, IOError;
		public abstract async void disable (Cancellable? cancellable) throws Error, IOError;
	}

	internal static uint64 round_address_up (uint64 address, size_t n) {
		return (address + n - 1) & ~((uint64) n - 1);
	}

	internal static size_t round_size_up (size_t size, size_t n) {
		return (size + n - 1) & ~(n - 1);
	}

	internal static uint64 page_start (uint64 address, size_t page_size) {
		return address & ~((uint64) page_size - 1);
	}
}
