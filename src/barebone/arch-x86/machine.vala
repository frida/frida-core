[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	public sealed class IA32Machine : Object, Machine {
		public override GDB.Client gdb {
			get;
			set;
		}

		public override string llvm_target {
			get { return "x86-unknown-none"; }
		}

		public override string llvm_code_model {
			get { return "small"; }
		}

		public PhysicalMemory? physical_memory;

		// Fixed for the kernel we are attached to.
		private MMUParameters? cached_mmu_parameters;

		private const size_t PAGE_SIZE = 4096;

		private const uint PDPT_LEVEL = 0;
		private const uint PAGE_DIRECTORY_LEVEL = 1;
		private const uint PAGE_TABLE_LEVEL = 2;
		private const uint LEAF_LEVEL = PAGE_TABLE_LEVEL;

		private const uint64 PRESENT_BIT = 1ULL << 0;
		private const uint64 WRITABLE_BIT = 1ULL << 1;
		private const uint64 LARGE_PAGE_BIT = 1ULL << 7;
		private const uint64 NX_BIT = 1ULL << 63;

		private const uint64 LEGACY_ADDRESS_MASK = 0xfffff000ULL;
		private const uint64 PAE_ADDRESS_MASK = 0x000ffffffffff000ULL;

		private const uint64 LEGACY_LARGE_PAGE_ADDRESS_MASK = 0xffc00000ULL;
		private const uint64 PAE_LARGE_PAGE_OFFSET_MASK = (1ULL << 21) - 1;

		private const uint64 PSE36_ADDRESS_MASK = 0x001fe000ULL;
		private const uint PSE36_ADDRESS_SHIFT = 19;

		public IA32Machine (GDB.Client gdb) {
			Object (gdb: gdb);
		}

		public async size_t query_page_size (Cancellable? cancellable) throws Error, IOError {
			return PAGE_SIZE;
		}

		public async uint query_exception_level (Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async void enumerate_ranges (Gum.PageProtection prot, FoundRangeFunc func, Cancellable? cancellable)
				throws Error, IOError {
			foreach (RangeDetails r in coalesce_ranges (yield collect_ranges (cancellable))) {
				if ((r.protection & prot) != prot)
					continue;
				if (!func (r))
					return;
			}
		}

		private async Gee.List<RangeDetails> collect_ranges (Cancellable? cancellable) throws Error, IOError {
			var result = new Gee.ArrayList<RangeDetails> ();

			MMUParameters p = yield load_mmu_parameters (cancellable);
			if (!p.paging_enabled) {
				result.add (new RangeDetails (0, 0, 1ULL << 32, READ | WRITE | EXECUTE, MappingType.UNKNOWN));
				return result;
			}

			yield begin_table_access (cancellable);
			GLib.Error? failure = null;
			try {
				yield collect_ranges_in_table (p.root_table, p.first_level, 0, READ | WRITE | EXECUTE, p, result,
					cancellable);
			} catch (GLib.Error e) {
				failure = e;
			}
			yield end_table_access (cancellable);
			throw_if_failed (failure);

			return result;
		}

		private async void collect_ranges_in_table (uint64 table_pa, uint level, uint64 upper_bits,
				Gum.PageProtection inherited, MMUParameters p, Gee.List<RangeDetails> ranges,
				Cancellable? cancellable) throws Error, IOError {
			uint num_entries = num_entries_at_level (level, p);
			Buffer entries = yield read_physical_buffer (table_pa, num_entries * p.entry_size, cancellable);
			uint shift = address_shift_at_level (level, p);

			for (uint i = 0; i != num_entries; i++) {
				uint64 entry = read_entry (entries, i * p.entry_size, p);
				if ((entry & PRESENT_BIT) == 0)
					continue;

				uint64 va = upper_bits | ((uint64) i << shift);
				Gum.PageProtection prot = inherited & protection_from_entry (entry, level, p);

				if (is_leaf_entry (entry, level, p)) {
					ranges.add (new RangeDetails (va, leaf_address (entry, level, p), 1ULL << shift, prot,
						MappingType.UNKNOWN));
					continue;
				}

				yield collect_ranges_in_table (table_address (entry, p), level + 1, va, prot, p, ranges,
					cancellable);
			}
		}

		public async Allocation allocate_pages (Gee.List<uint64?> physical_addresses, Cancellable? cancellable)
				throws Error, IOError {
			throw_not_supported ();
		}

		public async void protect_pages (uint64 virtual_address, size_t size, Gum.PageProtection prot,
				Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async Gee.List<uint64?> scan_ranges (Gee.List<Gum.MemoryRange?> ranges, MatchPattern pattern, uint max_matches,
				Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public void apply_relocation (Gum.ElfRelocationDetails r, uint64 base_va, Buffer relocated) throws Error {
			throw_not_supported ();
		}

		public async uint64 invoke (uint64 impl, uint64[] args, Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async CallFrame load_call_frame (GDB.Thread thread, uint arity, Cancellable? cancellable) throws Error, IOError {
			var regs = yield thread.read_registers (cancellable);

			uint64 original_esp = regs["esp"].get_uint64 ();
			var stack = yield gdb.read_buffer (original_esp, (1 + arity) * 4, cancellable);

			return new IA32CallFrame (thread, regs, stack, original_esp);
		}

		private class IA32CallFrame : Object, CallFrame {
			public uint64 return_address {
				get { return stack.read_uint32 (0); }
			}

			public Gee.Map<string, Variant> registers {
				get { return regs; }
			}

			private GDB.Thread thread;

			private Gee.Map<string, Variant> regs;

			private Buffer stack;
			private uint64 original_esp;
			private State stack_state = PRISTINE;

			private enum State {
				PRISTINE,
				MODIFIED
			}

			public IA32CallFrame (GDB.Thread thread, Gee.Map<string, Variant> regs, Buffer stack, uint64 original_esp) {
				this.thread = thread;

				this.regs = regs;

				this.stack = stack;
				this.original_esp = original_esp;
			}

			public uint64 get_nth_argument (uint n) {
				size_t offset;
				if (try_get_stack_offset_of_nth_argument (n, out offset))
					return stack.read_uint32 (offset);
				return uint64.MAX;
			}

			public void replace_nth_argument (uint n, uint64 val) {
				size_t offset;
				if (try_get_stack_offset_of_nth_argument (n, out offset)) {
					stack.write_uint32 (offset, (uint32) val);
					invalidate_stack ();
				}
			}

			private bool try_get_stack_offset_of_nth_argument (uint n, out size_t offset) {
				size_t start = (1 + n) * 4;
				size_t end = start + 4;
				if (end > stack.bytes.get_size ()) {
					offset = 0;
					return false;
				}

				offset = start;
				return true;
			}

			public uint64 get_return_value () {
				return regs["eax"].get_uint64 ();
			}

			public void replace_return_value (uint64 retval) {
				regs["eax"] = retval;
				invalidate_regs ();
			}

			public void force_return () {
				regs["eip"] = return_address;
				invalidate_regs ();
			}

			private void invalidate_regs () {
				regs.set_data ("dirty", true);
			}

			private void invalidate_stack () {
				stack_state = MODIFIED;
			}

			public async void commit (Cancellable? cancellable) throws Error, IOError {
				if (regs.get_data<bool> ("dirty"))
					yield thread.write_registers (regs, cancellable);

				if (stack_state == MODIFIED)
					yield thread.client.write_byte_array (original_esp, stack.bytes, cancellable);
			}
		}

		public uint64 address_from_funcptr (uint64 ptr) {
			return ptr;
		}

		public size_t breakpoint_size_from_funcptr (uint64 ptr) {
			return 1;
		}

		public async InlineHook create_inline_hook (uint64 target, uint64 handler, Allocator allocator, Cancellable? cancellable)
				throws Error, IOError {
			throw_not_supported ();
		}

		public async uint64 translate_address (uint64 va, Cancellable? cancellable) throws Error, IOError {
			MMUParameters p = yield load_mmu_parameters (cancellable);
			if (!p.paging_enabled)
				return va;

			yield begin_table_access (cancellable);
			uint64 pa = 0;
			GLib.Error? failure = null;
			try {
				LeafEntry leaf = yield find_leaf_entry (va, p, cancellable);
				uint64 page_mask = (1ULL << address_shift_at_level (leaf.level, p)) - 1;

				pa = leaf_address (leaf.value, leaf.level, p) | (va & page_mask);
			} catch (GLib.Error e) {
				failure = e;
			}
			yield end_table_access (cancellable);
			throw_if_failed (failure);

			return pa;
		}

		private async LeafEntry find_leaf_entry (uint64 va, MMUParameters p, Cancellable? cancellable)
				throws Error, IOError {
			uint64 table_pa = p.root_table;
			for (uint level = p.first_level; ; level++) {
				uint64 slot_pa = slot_address (va, table_pa, level, p);
				uint64 entry = yield read_entry_at (slot_pa, p, cancellable);

				if ((entry & PRESENT_BIT) == 0)
					throw new Error.NOT_SUPPORTED ("Address 0x%08x is not mapped", (uint32) va);

				if (is_leaf_entry (entry, level, p))
					return { entry, level };

				table_pa = table_address (entry, p);
			}
		}

		private struct LeafEntry {
			public uint64 value;
			public uint level;
		}

		private async void begin_table_access (Cancellable? cancellable) throws Error, IOError {
			if (physical_memory == null)
				yield set_addressing_mode (gdb, PHYSICAL, cancellable);
		}

		private async void end_table_access (Cancellable? cancellable) throws Error, IOError {
			if (physical_memory == null)
				yield set_addressing_mode (gdb, VIRTUAL, cancellable);
		}

		private static uint num_entries_at_level (uint level, MMUParameters p) {
			if (!p.pae)
				return 1024;
			return (level == PDPT_LEVEL) ? 4 : 512;
		}

		private static uint address_shift_at_level (uint level, MMUParameters p) {
			switch (level) {
				case PDPT_LEVEL:
					return 30;
				case PAGE_DIRECTORY_LEVEL:
					return p.pae ? 21 : 22;
				default:
					return 12;
			}
		}

		private static uint64 slot_address (uint64 va, uint64 table_pa, uint level, MMUParameters p) {
			uint index = (uint) ((va >> address_shift_at_level (level, p)) & (num_entries_at_level (level, p) - 1));
			return table_pa + ((uint64) index * p.entry_size);
		}

		private static bool is_leaf_entry (uint64 entry, uint level, MMUParameters p) {
			if (level == LEAF_LEVEL)
				return true;
			return level == PAGE_DIRECTORY_LEVEL && p.large_pages_enabled && (entry & LARGE_PAGE_BIT) != 0;
		}

		private static uint64 table_address (uint64 entry, MMUParameters p) {
			return entry & (p.pae ? PAE_ADDRESS_MASK : LEGACY_ADDRESS_MASK);
		}

		private static uint64 leaf_address (uint64 entry, uint level, MMUParameters p) {
			if (level == LEAF_LEVEL)
				return table_address (entry, p);

			if (p.pae)
				return entry & PAE_ADDRESS_MASK & ~PAE_LARGE_PAGE_OFFSET_MASK;

			uint64 low_bits = entry & LEGACY_LARGE_PAGE_ADDRESS_MASK;
			uint64 pse36_high_bits = (entry & PSE36_ADDRESS_MASK) << PSE36_ADDRESS_SHIFT;
			return low_bits | pse36_high_bits;
		}

		// What a single entry contributes is a ceiling, not the effective right: the bits are ANDed
		// across levels.
		private static Gum.PageProtection protection_from_entry (uint64 entry, uint level, MMUParameters p) {
			if (!has_protection_bits (level, p))
				return READ | WRITE | EXECUTE;

			Gum.PageProtection prot = READ;
			if ((entry & WRITABLE_BIT) != 0)
				prot |= WRITE;
			if (!p.nx_enabled || (entry & NX_BIT) == 0)
				prot |= EXECUTE;
			return prot;
		}

		private static bool has_protection_bits (uint level, MMUParameters p) {
			return !(p.pae && level == PDPT_LEVEL);
		}

		private async uint64 read_entry_at (uint64 slot_pa, MMUParameters p, Cancellable? cancellable)
				throws Error, IOError {
			Buffer buf = yield read_physical_buffer (slot_pa, p.entry_size, cancellable);
			return read_entry (buf, 0, p);
		}

		private static uint64 read_entry (Buffer entries, size_t offset, MMUParameters p) {
			return p.pae ? entries.read_uint64 (offset) : entries.read_uint32 (offset);
		}

		private async Buffer read_physical_buffer (uint64 pa, size_t size, Cancellable? cancellable)
				throws Error, IOError {
			if (physical_memory != null && physical_memory.contains (pa))
				return gdb.make_buffer (new Bytes (physical_memory.read (pa, size)));
			return yield gdb.read_buffer (pa, size, cancellable);
		}

		private async MMUParameters load_mmu_parameters (Cancellable? cancellable) throws Error, IOError {
			if (cached_mmu_parameters == null)
				cached_mmu_parameters = yield MMUParameters.load (gdb, cancellable);
			return cached_mmu_parameters;
		}

		private class MMUParameters {
			public bool paging_enabled;
			public bool pae;
			public bool large_pages_enabled;
			public bool nx_enabled;
			public uint64 root_table;
			public uint first_level;
			public size_t entry_size;

			private const uint64 PAE_ROOT_TABLE_MASK = ~0x1fULL;

			private const uint64 CR0_PG = 1ULL << 31;
			private const uint64 CR4_PSE = 1ULL << 4;
			private const uint64 CR4_PAE = 1ULL << 5;
			private const uint64 EFER_NXE = 1ULL << 11;

			public static async MMUParameters load (GDB.Client gdb, Cancellable? cancellable) throws Error, IOError {
				ControlRegisters regs = yield ControlRegisters.read (gdb, cancellable);

				var parameters = new MMUParameters ();

				parameters.paging_enabled = (regs.cr0 & CR0_PG) != 0;
				parameters.pae = (regs.cr4 & CR4_PAE) != 0;
				parameters.large_pages_enabled = parameters.pae || (regs.cr4 & CR4_PSE) != 0;
				parameters.nx_enabled = parameters.pae && (regs.efer & EFER_NXE) != 0;
				parameters.entry_size = parameters.pae ? 8 : 4;
				parameters.first_level = parameters.pae ? 0 : 1;

				parameters.root_table = parameters.pae
					? (regs.cr3 & PAE_ROOT_TABLE_MASK)
					: (regs.cr3 & LEGACY_ADDRESS_MASK);

				return parameters;
			}
		}

		private class ControlRegisters {
			public uint64 cr0;
			public uint64 cr3;
			public uint64 cr4;
			public uint64 efer;

			public static async ControlRegisters read (GDB.Client gdb, Cancellable? cancellable) throws Error, IOError {
				var regs = new ControlRegisters ();

				if (yield regs.try_read_from_registers (gdb, cancellable))
					return regs;

				yield regs.read_from_monitor (gdb, cancellable);

				return regs;
			}

			private async bool try_read_from_registers (GDB.Client gdb, Cancellable? cancellable) throws Error, IOError {
				GDB.Exception? exception = gdb.exception;
				if (exception == null)
					throw new Error.INVALID_OPERATION ("Unable to query in current state");
				GDB.Thread thread = exception.thread;

				try {
					cr0 = yield thread.read_register ("cr0", cancellable);
					cr3 = yield thread.read_register ("cr3", cancellable);
					cr4 = yield thread.read_register ("cr4", cancellable);
				} catch (Error e) {
					return false;
				}

				try {
					efer = yield thread.read_register ("efer", cancellable);
				} catch (Error e) {
				}

				return true;
			}

			private async void read_from_monitor (GDB.Client gdb, Cancellable? cancellable) throws Error, IOError {
				string dump = yield gdb.run_remote_command ("info registers", cancellable);

				bool found_cr3 = false;
				foreach (string token in dump.split_set (" \t\r\n")) {
					string[] parts = token.split ("=");
					if (parts.length != 2)
						continue;
					uint64 val = uint64.parse (parts[1], 16);

					switch (parts[0]) {
						case "CR0":
							cr0 = val;
							break;
						case "CR3":
							cr3 = val;
							found_cr3 = true;
							break;
						case "CR4":
							cr4 = val;
							break;
						case "EFER":
							efer = val;
							break;
						default:
							break;
					}
				}

				if (!found_cr3)
					throw new Error.NOT_SUPPORTED ("Unable to determine the target's control registers");
			}
		}
	}
}
