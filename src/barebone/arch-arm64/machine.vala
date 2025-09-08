[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	public sealed class Arm64Machine : Object, Machine {
		public override GDB.Client gdb {
			get;
			set;
		}

		public override string llvm_target {
			get { return "aarch64-unknown-none"; }
		}

		public override string llvm_code_model {
			get { return "tiny"; }
		}

		private enum AddressingMode {
			VIRTUAL,
			PHYSICAL
		}

		private const uint NUM_ARGS_IN_REGS = 8;

		private const uint64 INT2_MASK = 0x3ULL;
		private const uint64 INT6_MASK = 0x3fULL;
		private const uint64 INT48_MASK = 0xffffffffffffULL;

		private const uint64 TABLE_PXN_BIT = 1ULL << 59;

		private const uint64 UXN_BIT = 1ULL << 54;
		private const uint64 PXN_BIT = 1ULL << 53;
		private const uint64 AP1_BIT = 1ULL << 7;
		private const uint64 AP0_BIT = 1ULL << 6;

		public Arm64Machine (GDB.Client gdb) {
			Object (gdb: gdb);
		}

		public async size_t query_page_size (Cancellable? cancellable) throws Error, IOError {
			MMUParameters p = yield MMUParameters.load (gdb, cancellable);

			return p.granule;
		}

		public async uint query_exception_level (Cancellable? cancellable) throws Error, IOError {
			GDB.Exception? exception = gdb.exception;
			if (exception == null)
				throw new Error.INVALID_OPERATION ("Unable to query in current state");
			GDB.Thread thread = exception.thread;

			var cpsr = yield thread.read_register ("cpsr", cancellable);

			return (uint) ((cpsr >> 2) & 3);
		}

		public async void enumerate_ranges (Gum.PageProtection prot, FoundRangeFunc func, Cancellable? cancellable)
				throws Error, IOError {
			Gee.List<RangeDetails> ranges = ("corellium" in gdb.features)
				? yield collect_ranges_using_corellium (cancellable)
				: yield collect_ranges_using_mmu (cancellable);
			foreach (RangeDetails r in coalesce_ranges (ranges)) {
				if ((r.protection & prot) != prot)
					continue;
				if (!func (r))
					return;
			}
		}

		private async Gee.List<RangeDetails> collect_ranges_using_mmu (Cancellable? cancellable) throws Error, IOError {
			var result = new Gee.ArrayList<RangeDetails> ();

			MMUParameters p = yield MMUParameters.load (gdb, cancellable);

			yield set_addressing_mode (gdb, PHYSICAL, cancellable);
			try {
				yield collect_ranges_in_table (p.tt1, p.first_level, p.upper_bits, p, result, cancellable);
			} finally {
				set_addressing_mode.begin (gdb, VIRTUAL, null);
			}

			return result;
		}

		private async void collect_ranges_in_table (uint64 table_address, uint level, uint64 upper_bits, MMUParameters p,
				Gee.List<RangeDetails> ranges, Cancellable? cancellable) throws Error, IOError {
			uint max_entries = compute_max_entries (level, p);
			Buffer entries = yield gdb.read_buffer (table_address, max_entries * Descriptor.SIZE, cancellable);
			uint shift = address_shift_at_level (level, p.granule);
			for (uint i = 0; i != max_entries; i++) {
				uint64 raw_descriptor = entries.read_uint64 (i * Descriptor.SIZE);

				Descriptor desc = Descriptor.parse (raw_descriptor, level, p.granule);
				if (desc.kind == INVALID)
					continue;

				uint64 address = upper_bits | ((uint64) i << shift);

				if (desc.kind == BLOCK) {
					size_t size = 1 << num_block_bits_at_level (level, p.granule);
					Gum.PageProtection prot = protection_from_flags (desc.flags, p);

					ranges.add (new RangeDetails (address, desc.target_address, size, prot, MappingType.UNKNOWN));

					continue;
				}

				yield collect_ranges_in_table (desc.target_address, level + 1, address, p, ranges, cancellable);
			}
		}

		private async Gee.List<RangeDetails> collect_ranges_using_corellium (Cancellable? cancellable) throws Error, IOError {
			var result = new Gee.ArrayList<RangeDetails> ();

			string pt = yield gdb.run_remote_command ("pt", cancellable);
			foreach (string line in pt.split ("\n")) {
				string[] tokens = line.split (" -> ");
				if (tokens.length != 2)
					continue;
				unowned string range = tokens[0];
				unowned string details = tokens[1];

				string[] range_tokens = range.split ("-");
				if (range_tokens.length != 2)
					throw new Error.PROTOCOL ("Unexpected Corellium response; please file a bug");

				uint64 base_va = uint64.parse (range_tokens[0], 16);
				uint64 end_va = uint64.parse (range_tokens[1], 16) + 1;
				uint64 base_pa = uint64.parse (details.split (" ")[0], 16);
				uint64 size = end_va - base_va;
				Gum.PageProtection prot = protection_from_corellium_pt_details (details);
				MappingType type = mapping_type_from_corellium_pt_details (details);

				result.add (new RangeDetails (base_va, base_pa, size, prot, type));
			}

			return result;
		}

		private Gee.List<RangeDetails> coalesce_ranges (Gee.List<RangeDetails> ranges) {
			var result = new Gee.ArrayList<RangeDetails> ();

			RangeDetails? pending = null;
			foreach (RangeDetails r in ranges) {
				if (pending == null) {
					pending = r.clone ();
					continue;
				}

				if (r.base_va == pending.base_va + pending.size &&
						r.base_pa == pending.base_pa + pending.size &&
						r.protection == pending.protection &&
						r.type == pending.type) {
					pending.size += r.size;
					continue;
				}

				result.add (pending);
				pending = r.clone ();
			}
			if (pending != null)
				result.add (pending);

			return result;
		}

		public async Allocation allocate_pages (Gee.List<uint64?> physical_addresses, Cancellable? cancellable)
				throws Error, IOError {
			MMUParameters p = yield MMUParameters.load (gdb, cancellable);

			yield set_addressing_mode (gdb, PHYSICAL, cancellable);
			try {
				Allocation? allocation = yield maybe_insert_descriptor_in_table (physical_addresses, p.tt1, p.first_level,
					p.upper_bits, p, cancellable);
				if (allocation == null)
					throw new Error.NOT_SUPPORTED ("Unable to insert page table mapping; please file a bug");

				return allocation;
			} finally {
				set_addressing_mode.begin (gdb, VIRTUAL, null);
			}
		}

		private async Allocation? maybe_insert_descriptor_in_table (Gee.List<uint64?> physical_addresses,
				uint64 table_address, uint level, uint64 upper_bits, MMUParameters p, Cancellable? cancellable)
				throws Error, IOError {
			uint max_entries = compute_max_entries (level, p);
			uint shift = address_shift_at_level (level, p.granule);

			uint64 first_available_va = 0;
			uint64 first_available_slot = 0;
			uint num_available_slots = 0;
			uint chunk_max_size = (level < 3) ? 4 : 64;
			uint chunk_offset = 0;
			uint num_pages = physical_addresses.size;
			while (chunk_offset != max_entries && num_available_slots != num_pages) {
				uint64 chunk_base_address = table_address + (chunk_offset * Descriptor.SIZE);
				uint chunk_size = uint.min (chunk_max_size, max_entries - chunk_offset);

				Buffer descriptors = yield gdb.read_buffer (chunk_base_address, chunk_size * Descriptor.SIZE, cancellable);
				for (uint i = 0; i != chunk_size && num_available_slots != num_pages; i++) {
					uint buffer_offset = i * Descriptor.SIZE;
					uint64 raw_descriptor = descriptors.read_uint64 (buffer_offset);

					uint table_index = chunk_offset + i;
					uint64 address = upper_bits | ((uint64) table_index << shift);

					Descriptor desc = Descriptor.parse (raw_descriptor, level, p.granule);

					if (level < 3) {
						if (desc.kind != TABLE)
							continue;
						if ((desc.flags & DescriptorFlags.PXNTABLE) != 0)
							continue;
						Allocation? allocation = yield maybe_insert_descriptor_in_table (physical_addresses,
							desc.target_address, level + 1, address, p, cancellable);
						if (allocation != null)
							return allocation;
						continue;
					}

					if (desc.kind != INVALID) {
						first_available_va = 0;
						first_available_slot = 0;
						num_available_slots = 0;
						continue;
					}

					if (first_available_va == 0) {
						first_available_va = address;
						first_available_slot = chunk_base_address + buffer_offset;
					}
					num_available_slots++;
				}

				chunk_offset += chunk_size;
			}
			if (num_available_slots != num_pages)
				return null;

			Gum.PageProtection page_prot = Gum.PageProtection.READ | Gum.PageProtection.WRITE;
			if (!p.sprr_enabled)
				page_prot |= Gum.PageProtection.EXECUTE;

			var builder = gdb.make_buffer_builder ();
			for (uint i = 0; i != num_available_slots; i++) {
				uint64 base_descriptor = physical_addresses[(int) i] | 0x403ULL;
				uint64 new_descriptor = apply_protection_bits (base_descriptor, page_prot, p);
				builder.append_uint64 (new_descriptor);
			}
			Bytes new_descriptors = builder.build ();
			Bytes old_descriptors = yield gdb.read_byte_array (first_available_slot, new_descriptors.get_size (), cancellable);
			yield gdb.write_byte_array (first_available_slot, new_descriptors, cancellable);

			size_t size = num_pages * p.granule;
			return new DescriptorAllocation (first_available_va, size, first_available_slot, old_descriptors, gdb);
		}

		public async void protect_pages (uint64 virtual_address, size_t size, Gum.PageProtection prot, Cancellable? cancellable)
				throws Error, IOError {
			MMUParameters p = yield MMUParameters.load (gdb, cancellable);

			yield set_addressing_mode (gdb, PHYSICAL, cancellable);
			try {
				uint64 page_mask = p.granule - 1;
				uint64 aligned_va = virtual_address & ~page_mask;
				uint64 aligned_end = (virtual_address + size + page_mask) & ~page_mask;
				uint num_pages = (uint) ((aligned_end - aligned_va) / p.granule);

				yield perform_protect_pages (aligned_va, num_pages, prot, p, cancellable);
			} finally {
				set_addressing_mode.begin (gdb, VIRTUAL, null);
			}
		}

		private async void perform_protect_pages (uint64 start_va, uint num_pages, Gum.PageProtection prot, MMUParameters p,
				Cancellable? cancellable) throws Error, IOError {
			var table_cache = new TableWalkCache ();
			uint pages_processed = 0;

			var processed_tables = new Gee.HashSet<uint64?> (Numeric.uint64_hash, Numeric.uint64_equal);
			bool need_exec = (prot & Gum.PageProtection.EXECUTE) != 0;

			while (pages_processed != num_pages) {
				uint64 current_va = start_va + (uint64) pages_processed * p.granule;

				uint64 table_pa = yield find_level3_table (current_va, p, table_cache, cancellable);

				if (need_exec && !processed_tables.contains (table_pa)) {
					yield clear_pxn_table_bits_for_va (current_va, p, table_cache, cancellable);
					processed_tables.add (table_pa);
				}

				uint level3_shift = address_shift_at_level (3, p.granule);
				uint64 level3_mask = (1ULL << level3_shift) - 1;
				uint64 table_base_va = current_va & ~level3_mask;
				uint64 table_end_va = table_base_va + (1ULL << level3_shift);
				uint64 remaining_va = start_va + num_pages * p.granule;
				uint64 batch_end_va = uint64.min (remaining_va, table_end_va);
				uint batch_size = (uint) ((batch_end_va - current_va) / p.granule);

				yield protect_pages_in_table (current_va, batch_size, prot, table_pa, p, cancellable);

				pages_processed += batch_size;
			}
		}

		private async void protect_pages_in_table (uint64 current_va, uint batch_size, Gum.PageProtection prot,
				uint64 table_pa, MMUParameters p, Cancellable? cancellable) throws Error, IOError {
			uint index_bits = num_address_bits_at_level (3, p);
			uint index_shift = inpage_bits_for_granule (p.granule);
			uint index_mask = (1U << index_bits) - 1;

			uint64 first_index = (current_va >> index_shift) & index_mask;
			uint64 first_slot_pa = table_pa + (first_index * Descriptor.SIZE);

			Buffer descriptors = yield gdb.read_buffer (first_slot_pa, batch_size * Descriptor.SIZE, cancellable);

			bool any_changed = false;
			for (uint i = 0; i != batch_size; i++) {
				uint64 raw_desc = descriptors.read_uint64 (i * Descriptor.SIZE);
				uint64 new_desc = apply_protection_bits (raw_desc, prot, p);

				if (new_desc != raw_desc) {
					descriptors.write_uint64 (i * Descriptor.SIZE, new_desc);
					any_changed = true;
				}
			}

			if (any_changed)
				yield gdb.write_byte_array (first_slot_pa, descriptors.bytes, cancellable);
		}

		private async uint64 find_level3_table (uint64 va, MMUParameters p, TableWalkCache cache, Cancellable? cancellable)
				throws Error, IOError {
			TableWalkResult? cached = cache.lookup (va, p);
			if (cached != null)
				return yield walk_to_level3 (va, cached.table_pa, cached.level, p, cache, cancellable);

			return yield walk_to_level3 (va, p.tt1, p.first_level, p, cache, cancellable);
		}

		private async uint64 walk_to_level3 (uint64 va, uint64 start_table_pa, uint start_level, MMUParameters p,
				TableWalkCache cache, Cancellable? cancellable) throws Error, IOError {
			uint64 table_pa = start_table_pa;
			uint level = start_level;

			while (level != 3) {
				cache.store (va, level, table_pa, p);

				uint shift = address_shift_at_level (level, p.granule);
				uint entries = compute_max_entries (level, p);
				uint index = (uint) ((va >> shift) & (entries - 1));
				uint64 slot_pa = table_pa + ((uint64) index * Descriptor.SIZE);

				Buffer d_buf = yield gdb.read_buffer (slot_pa, Descriptor.SIZE, cancellable);
				uint64 raw = d_buf.read_uint64 (0);
				Descriptor desc = Descriptor.parse (raw, level, p.granule);

				if (desc.kind != TABLE)
					throw new Error.NOT_SUPPORTED ("Walk failed at level %u", level);

				table_pa = desc.target_address;
				level++;
			}

			return table_pa;
		}

		private async void clear_pxn_table_bits_for_va (uint64 va, MMUParameters p, TableWalkCache cache, Cancellable? cancellable)
				throws Error, IOError {
			uint64 table_pa = p.tt1;
			for (uint level = p.first_level; level != 3; level++) {
				uint entries = compute_max_entries (level, p);
				uint shift = address_shift_at_level (level, p.granule);
				uint index = (uint) ((va >> shift) & (entries - 1));
				uint64 slot_pa = table_pa + (index * Descriptor.SIZE);

				Buffer d_buf = yield gdb.read_buffer (slot_pa, Descriptor.SIZE, cancellable);
				uint64 raw_desc = d_buf.read_uint64 (0);
				Descriptor desc = Descriptor.parse (raw_desc, level, p.granule);
				if (desc.kind != TABLE)
					break;

				if ((raw_desc & TABLE_PXN_BIT) != 0) {
					uint64 new_desc = raw_desc & ~TABLE_PXN_BIT;
					d_buf.write_uint64 (0, new_desc);
					yield gdb.write_byte_array (slot_pa, d_buf.bytes, cancellable);
				}

				table_pa = desc.target_address;
			}
		}

		private class TableWalkCache {
			private Gee.Map<uint64?, TableWalkResult> cache =
				new Gee.HashMap<uint64?, TableWalkResult> (Numeric.uint64_hash, Numeric.uint64_equal);

			public TableWalkResult? lookup (uint64 va, MMUParameters p) {
				for (int level = 2; level >= (int) p.first_level; level--) {
					uint64 cache_key = compute_cache_key (va, (uint) level, p);
					TableWalkResult? result = cache[cache_key];
					if (result != null)
						return result;
				}
				return null;
			}

			public void store (uint64 va, uint level, uint64 table_pa, MMUParameters p) {
				if (level >= 3)
					return;

				uint64 cache_key = compute_cache_key (va, level, p);
				cache[cache_key] = new TableWalkResult () {
					table_pa = table_pa,
					level = level
				};
			}

			private uint64 compute_cache_key (uint64 va, uint level, MMUParameters p) {
				uint shift = address_shift_at_level (level + 1, p.granule);
				return (va >> shift) << shift;
			}
		}

		private class TableWalkResult {
			public uint64 table_pa;
			public uint level;
		}

		public async Gee.List<uint64?> scan_ranges (Gee.List<Gum.MemoryRange?> ranges, MatchPattern pattern, uint max_matches,
				Cancellable? cancellable) throws Error, IOError {
			unowned uint8[] scanner_blob = Data.Barebone.get_memory_scanner_arm64_elf_blob ().data;

			var raw_scanner = new Bytes.static (scanner_blob);

			Gum.ElfModule scanner;
			try {
				scanner = new Gum.ElfModule.from_blob (raw_scanner);
			} catch (Gum.Error e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}

			size_t vm_size = (size_t) scanner.mapped_size;

			size_t landing_zone_offset = vm_size;
			size_t landing_zone_size = 4;
			vm_size += landing_zone_size;

			vm_size = round_size_up (vm_size, 16);
			size_t data_offset = vm_size;
			var builder = gdb.make_buffer_builder ();
			size_t data_size;
			append_memory_scanner_data (builder, ranges, pattern, max_matches, out data_size);
			vm_size += data_size;

			size_t page_size = yield query_page_size (cancellable);
			uint num_pages = (uint) (vm_size / page_size);
			if (vm_size % page_size != 0)
				num_pages++;

			bool was_running = gdb.state != STOPPED;
			if (was_running)
				yield gdb.stop (cancellable);

			GDB.Thread thread = gdb.exception.thread;
			Gee.Map<string, Variant> saved_regs = yield thread.read_registers (cancellable);

			uint64 old_sp = saved_regs["sp"].get_uint64 ();

			var writable_ranges = new Gee.ArrayList<RangeDetails> ();
			yield enumerate_ranges (READ | WRITE, d => {
				if (d.type != DEVICE)
					writable_ranges.add (d);
				return true;
			}, cancellable);

			RangeDetails? stack_range = writable_ranges.first_match (r => r.contains_virtual_address (old_sp));
			if (stack_range == null)
				throw new Error.NOT_SUPPORTED ("Unable to find stack memory range");

			uint64 module_pa;
			size_t logical_page_size = 4096;
			uint64 candidate_above_start = round_address_up (old_sp, logical_page_size);
			uint64 candidate_above_end = candidate_above_start + vm_size;
			if (stack_range.contains_virtual_address (candidate_above_end - 1)) {
				module_pa = stack_range.virtual_to_physical (candidate_above_start);
			} else {
				size_t padding_needed = (size_t) ((old_sp - vm_size) % logical_page_size);
				uint64 candidate_below_end = old_sp - padding_needed;
				uint64 candidate_below_start = candidate_below_end - vm_size;
				module_pa = stack_range.virtual_to_physical (candidate_below_start);
				old_sp = candidate_below_start;
			}

			uint64 module_page_pa = page_start (module_pa, page_size);

			var module_pas = new Gee.ArrayList<uint64?> ();
			for (uint i = 0; i != num_pages; i++)
				module_pas.add (module_page_pa + (i * page_size)); // FIXME: This assumes a contiguous range.

			Allocation module_allocation = yield allocate_pages (module_pas, cancellable);

			size_t page_offset = (size_t) (module_pa - module_page_pa);
			uint64 module_va = module_allocation.virtual_address + page_offset;
			uint64 data_va = module_va + data_offset;

			Bytes scanner_module = relocate (scanner, raw_scanner, module_va);
			Bytes original_memory = yield gdb.read_byte_array (module_va, vm_size, cancellable);
			yield gdb.write_byte_array (module_va, scanner_module, cancellable);

			Bytes data = builder.build (data_va);
			yield gdb.write_byte_array (data_va, data, cancellable);

			var regs = new Gee.HashMap<string, Variant> ();
			regs.set_all (saved_regs);

			regs["pc"] = module_va + scanner.entrypoint;

			uint64 landing_zone_va = module_va + landing_zone_offset;
			regs["x30"] = landing_zone_va;

			uint64 sp = old_sp;
			sp -= RED_ZONE_SIZE;
			regs["sp"] = sp;

			regs["x0"] = builder.address_of ("search-parameters");
			regs["x1"] = builder.address_of ("search-results");

			yield thread.write_registers (regs, cancellable);

			GDB.Breakpoint bp = yield gdb.add_breakpoint (SOFT, landing_zone_va, 4, cancellable);
			GDB.Exception ex = yield gdb.continue_until_exception (cancellable);
			if (ex.breakpoint != bp)
				throw new Error.NOT_SUPPORTED ("Breakpoint did not trigger; please file a bug");
			yield bp.remove (cancellable);

			var num_matches = (uint) yield thread.read_register ("x0", cancellable);
			var matches = new Gee.ArrayList<uint64?> ();
			var pointer_size = gdb.pointer_size;
			var raw_matches = yield gdb.read_buffer (builder.address_of ("matches"), num_matches * pointer_size, cancellable);
			for (uint i = 0; i != num_matches; i++) {
				uint64 address = raw_matches.read_pointer (i * pointer_size);
				matches.add (address);
			}

			yield gdb.write_byte_array (module_va, original_memory, cancellable);
			yield module_allocation.deallocate (cancellable);
			yield thread.write_registers (saved_regs, cancellable);

			if (was_running)
				yield gdb.continue (cancellable);

			return matches;
		}

		public void apply_relocation (Gum.ElfRelocationDetails r, uint64 base_va, Buffer relocated) throws Error {
			Gum.ElfArm64Relocation type = (Gum.ElfArm64Relocation) r.type;
			switch (type) {
				case ABS64:
					relocated.write_uint64 ((size_t) r.address, base_va + r.symbol.address + r.addend);
					break;
				case PREL32:
					var diff = (int64) (base_va + r.symbol.address + r.addend) - (int64) (base_va + r.address);
					relocated.write_int32 ((size_t) r.address, (int32) diff);
					break;
				default:
					throw new Error.NOT_SUPPORTED ("Unsupported relocation type: %s",
						Marshal.enum_to_nick<Gum.ElfArm64Relocation> (type));
			}
		}

		public async uint64 invoke (uint64 impl, uint64[] args, Cancellable? cancellable) throws Error, IOError {
			if (args.length > 8)
				throw new Error.NOT_SUPPORTED ("Unsupported number of arguments; please open a PR");

			bool was_running = gdb.state != STOPPED;
			if (was_running)
				yield gdb.stop (cancellable);

			GDB.Thread thread = gdb.exception.thread;
			Gee.Map<string, Variant> saved_regs = yield thread.read_registers (cancellable);

			var regs = new Gee.HashMap<string, Variant> ();
			regs.set_all (saved_regs);

			regs["pc"] = impl;

			uint64 landing_zone = saved_regs["pc"].get_uint64 ();
			regs["x30"] = landing_zone;

			uint64 sp = saved_regs["sp"].get_uint64 ();
			sp -= RED_ZONE_SIZE;
			regs["sp"] = sp;

			for (uint i = 0; i != args.length; i++)
				regs["x%u".printf (i)] = args[i];

			yield thread.write_registers (regs, cancellable);

			GDB.Breakpoint bp = yield gdb.add_breakpoint (SOFT, landing_zone, 4, cancellable);
			GDB.Exception ex = null;
			do {
				ex = yield gdb.continue_until_exception (cancellable);
			} while (ex.breakpoint != bp || ex.thread.id != thread.id);
			// TODO: Improve GDB.Client to guarantee a single GDB.Thread instance per ID.
			yield bp.remove (cancellable);

			uint64 retval = yield thread.read_register ("x0", cancellable);

			yield thread.write_registers (saved_regs, cancellable);

			if (was_running)
				yield gdb.continue (cancellable);

			return retval;
		}

		public async void execute (uint64 start, uint64 end, Cancellable? cancellable) throws Error, IOError {
			bool was_running = gdb.state != STOPPED;
			if (was_running)
				yield gdb.stop (cancellable);

			GDB.Thread thread = gdb.exception.thread;
			Gee.Map<string, Variant> saved_regs = yield thread.read_registers (cancellable);

			var regs = new Gee.HashMap<string, Variant> ();
			regs.set_all (saved_regs);

			regs["pc"] = start;

			yield thread.write_registers (regs, cancellable);

			GDB.Breakpoint bp = yield gdb.add_breakpoint (SOFT, end, 4, cancellable);
			GDB.Exception ex = null;
			do {
				ex = yield gdb.continue_until_exception (cancellable);
			} while (ex.breakpoint != bp || ex.thread.id != thread.id);
			// TODO: Improve GDB.Client to guarantee a single GDB.Thread instance per ID.
			yield bp.remove (cancellable);

			yield thread.write_registers (saved_regs, cancellable);

			if (was_running)
				yield gdb.continue (cancellable);
		}

		public async CallFrame load_call_frame (GDB.Thread thread, uint arity, Cancellable? cancellable) throws Error, IOError {
			var regs = yield thread.read_registers (cancellable);

			Buffer? stack = null;
			uint64 original_sp = regs["sp"].get_uint64 ();
			if (arity > NUM_ARGS_IN_REGS)
				stack = yield gdb.read_buffer (original_sp, (arity - NUM_ARGS_IN_REGS) * 8, cancellable);

			return new Arm64CallFrame (thread, regs, stack, original_sp);
		}

		private class Arm64CallFrame : Object, CallFrame {
			public uint64 return_address {
				get { return regs["x30"].get_uint64 (); }
			}

			public Gee.Map<string, Variant> registers {
				get { return regs; }
			}

			private GDB.Thread thread;

			private Gee.Map<string, Variant> regs;

			private Buffer? stack;
			private uint64 original_sp;
			private State stack_state = PRISTINE;

			private enum State {
				PRISTINE,
				MODIFIED
			}

			public Arm64CallFrame (GDB.Thread thread, Gee.Map<string, Variant> regs, Buffer? stack, uint64 original_sp) {
				this.thread = thread;

				this.regs = regs;

				this.stack = stack;
				this.original_sp = original_sp;
			}

			public uint64 get_nth_argument (uint n) {
				if (n < NUM_ARGS_IN_REGS)
					return regs["x%u".printf (n)].get_uint64 ();

				size_t offset;
				if (try_get_stack_offset_of_nth_argument (n, out offset))
					return stack.read_uint64 (offset);

				return uint64.MAX;
			}

			public void replace_nth_argument (uint n, uint64 val) {
				if (n < NUM_ARGS_IN_REGS) {
					regs["x%u".printf (n)] = val;
					invalidate_regs ();
					return;
				}

				size_t offset;
				if (try_get_stack_offset_of_nth_argument (n, out offset)) {
					stack.write_uint64 (offset, val);
					invalidate_stack ();
				}
			}

			private bool try_get_stack_offset_of_nth_argument (uint n, out size_t offset) {
				offset = 0;

				if (stack == null || n < NUM_ARGS_IN_REGS)
					return false;
				size_t start = (n - NUM_ARGS_IN_REGS) * 8;
				size_t end = start + 8;
				if (end > stack.bytes.get_size ())
					return false;

				offset = start;
				return true;
			}

			public uint64 get_return_value () {
				return regs["x0"].get_uint64 ();
			}

			public void replace_return_value (uint64 retval) {
				regs["x0"] = retval;
				invalidate_regs ();
			}

			public void force_return () {
				regs["pc"] = return_address;
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
					yield thread.client.write_byte_array (original_sp, stack.bytes, cancellable);
			}
		}

		public uint64 address_from_funcptr (uint64 ptr) {
			return ptr;
		}

		public size_t breakpoint_size_from_funcptr (uint64 ptr) {
			return 4;
		}

		public async InlineHook create_inline_hook (uint64 target, uint64 handler, Allocator allocator, Cancellable? cancellable)
				throws Error, IOError {
			size_t page_size = allocator.page_size;
			var allocation = yield allocator.allocate (page_size, page_size, cancellable);
			uint64 code_va = allocation.virtual_address;

			var scratch_buf = new uint8[512];

			var aw = new Gum.Arm64Writer (scratch_buf);
			aw.flush_on_destroy = false;
			aw.pc = code_va;

			void * on_invoke_label = aw.code;

			uint64 on_enter_trampoline = aw.pc;
			emit_prolog (aw, target);

			aw.put_call_address_with_arguments (handler, 1,
				Gum.ArgType.REGISTER, Gum.Arm64Reg.SP);

			emit_epilog (aw, on_invoke_label);

			size_t redirect_size = aw.can_branch_directly_between (target, on_enter_trampoline) ? 4 : 16;

			var old_target_code = yield gdb.read_byte_array (target, redirect_size, cancellable);

			aw.put_label (on_invoke_label);
			var rl = new Gum.Arm64Relocator (old_target_code.get_data (), aw);
			rl.input_pc = target;
			uint reloc_bytes = 0;
			do
				reloc_bytes = rl.read_one ();
			while (reloc_bytes < redirect_size);
			rl.write_all ();
			if (!rl.eoi)
				aw.put_branch_address (target + reloc_bytes);
			aw.flush ();
			var trampoline_code = new Bytes (scratch_buf[:aw.offset ()]);

			yield gdb.write_byte_array (code_va, trampoline_code, cancellable);

			aw.reset (scratch_buf);
			aw.pc = target;
			aw.put_branch_address (on_enter_trampoline);
			aw.flush ();
			var new_target_code = new Bytes (scratch_buf[:aw.offset ()]);

			return new Arm64InlineHook (target, old_target_code, new_target_code, allocation, gdb);
		}

		private static void emit_prolog (Gum.Arm64Writer aw, uint64 target) {
			aw.put_sub_reg_reg_imm (SP, SP, 16);

			for (int i = 30; i != -2; i -= 2)
				aw.put_push_reg_reg (Gum.Arm64Reg.Q0 + i, Gum.Arm64Reg.Q1 + i);

			aw.put_push_reg_reg (FP, LR);
			for (int i = 27; i != -1; i -= 2)
				aw.put_push_reg_reg (Gum.Arm64Reg.X0 + i, Gum.Arm64Reg.X1 + i);

			aw.put_mov_reg_nzcv (X1);
			aw.put_push_reg_reg (X1, X0);

			size_t cpu_context_size = 784;
			size_t nzcv_offset = 16;

			aw.put_ldr_reg_address (X0, target);
			aw.put_add_reg_reg_imm (X1, SP, cpu_context_size - nzcv_offset + 16);
			aw.put_push_reg_reg (X0, X1);

			aw.put_str_reg_reg_offset (LR, SP, cpu_context_size + 8);
			aw.put_str_reg_reg_offset (FP, SP, cpu_context_size + 0);
			aw.put_add_reg_reg_imm (FP, SP, cpu_context_size);
		}

		private static void emit_epilog (Gum.Arm64Writer aw, void * next_hop_label) {
			aw.put_add_reg_reg_imm (SP, SP, 16);

			aw.put_pop_reg_reg (X1, X0);
			aw.put_mov_nzcv_reg (X1);

			for (int i = 1; i != 29; i += 2)
				aw.put_pop_reg_reg (Gum.Arm64Reg.X0 + i, Gum.Arm64Reg.X1 + i);
			aw.put_pop_reg_reg (FP, LR);

			for (int i = 0; i != 32; i += 2)
				aw.put_pop_reg_reg (Gum.Arm64Reg.Q0 + i, Gum.Arm64Reg.Q1 + i);

			aw.put_add_reg_reg_imm (SP, SP, 16);
			aw.put_b_label (next_hop_label);
		}

		private class Arm64InlineHook : Object, InlineHook {
			private State state = DISABLED;
			private uint64 target;
			private Bytes old_target_code;
			private Bytes new_target_code;
			private Allocation allocation;
			private GDB.Client gdb;

			private enum State {
				DISABLED,
				ENABLED,
				DESTROYED
			}

			public Arm64InlineHook (uint64 target, Bytes old_target_code, Bytes new_target_code, Allocation allocation,
					GDB.Client gdb) {
				this.target = target;
				this.old_target_code = old_target_code;
				this.new_target_code = new_target_code;
				this.allocation = allocation;
				this.gdb = gdb;
			}

			public async void destroy (Cancellable? cancellable) throws Error, IOError {
				if (state == DESTROYED)
					return;

				// TODO: Refactor.
				bool was_running = gdb.state != STOPPED;
				if (was_running)
					yield gdb.stop (cancellable);

				yield disable (cancellable);
				yield allocation.deallocate (cancellable);
				state = DESTROYED;

				if (was_running)
					yield gdb.continue (cancellable);
			}

			public async void enable (Cancellable? cancellable) throws Error, IOError {
				if (state == ENABLED)
					return;
				if (state != DISABLED)
					throw new Error.INVALID_OPERATION ("Invalid operation");
				yield gdb.write_byte_array (target, new_target_code, cancellable);
				state = ENABLED;
			}

			public async void disable (Cancellable? cancellable) throws Error, IOError {
				if (state != ENABLED)
					return;
				yield gdb.write_byte_array (target, old_target_code, cancellable);
				state = DISABLED;
			}
		}

		private static async void set_addressing_mode (GDB.Client gdb, AddressingMode mode, Cancellable? cancellable)
				throws Error, IOError {
			Gee.Set<string> features = gdb.features;
			if ("qemu-phy-mem-mode" in features)
				yield gdb.execute_simple ("Qqemu.PhyMemMode:" + ((mode == PHYSICAL) ? "1" : "0"), cancellable);
			else
				throw new Error.NOT_SUPPORTED ("Unsupported GDB remote stub; please file a bug");
		}

		private class MMUParameters {
			public Granule granule;
			public uint first_level;
			public uint64 upper_bits;
			public uint64 tt1;
			public uint t1sz;

			public bool sprr_enabled;
			public uint64 sprr_perm;

			public static async MMUParameters load (GDB.Client gdb, Cancellable? cancellable) throws Error, IOError {
				GDB.Exception? exception = gdb.exception;
				if (exception == null)
					throw new Error.INVALID_OPERATION ("Unable to query in current state");
				GDB.Thread thread = exception.thread;

				MMURegisters regs = yield MMURegisters.read (thread, cancellable);

				var parameters = new MMUParameters ();

				uint tg1 = (uint) ((regs.tcr >> 30) & INT2_MASK);
				parameters.granule = granule_from_tg1 (tg1);

				uint t1sz = (uint) ((regs.tcr >> 16) & INT6_MASK);
				uint num_resolution_bits = 64 - t1sz - inpage_bits_for_granule (parameters.granule);
				uint max_bits_per_level = (uint) Math.log2f (parameters.granule / Descriptor.SIZE);
				uint num_levels = num_resolution_bits / max_bits_per_level;
				if (num_resolution_bits % max_bits_per_level != 0)
					num_levels++;

				parameters.first_level = 4 - num_levels;

				for (uint i = 0; i != t1sz; i++)
					parameters.upper_bits |= 1ULL << (63 - i);

				parameters.tt1 = regs.ttbr1 & INT48_MASK;
				parameters.t1sz = t1sz;

				parameters.sprr_enabled = (regs.sprr_config & 1) != 0;
				parameters.sprr_perm = regs.sprr_perm;

				return parameters;
			}
		}

		private class MMURegisters {
			public uint64 tcr;
			public uint64 ttbr1;
			public uint64 sprr_config;
			public uint64 sprr_perm;

			public static async MMURegisters read (GDB.Thread thread, Cancellable? cancellable) throws Error, IOError {
				var regs = new MMURegisters ();

				GDB.Client client = thread.client;
				if ("corellium" in client.features) {
					string system_regs = yield client.run_remote_command ("sr", cancellable);
					foreach (string line in system_regs.split ("\n")) {
						string[] tokens = line.split ("=");
						if (tokens.length != 2)
							continue;
						string name = tokens[0].strip ().down ();
						uint64 val = uint64.parse (tokens[1].strip ());
						if (name == "tcr_el1")
							regs.tcr = val;
						else if (name == "ttbr1_el1")
							regs.ttbr1 = val;
						else if (name == "sprr_config_el1")
							regs.sprr_config = val;
						else if (name == "sprr_el1br1_el1")
							regs.sprr_perm = val;
					}
				} else {
					regs.tcr = yield thread.read_register ("tcr_el1", cancellable);
					regs.ttbr1 = yield thread.read_register ("ttbr1_el1", cancellable);
					try {
						regs.sprr_config = yield thread.read_register ("sprr_config_el1", cancellable);
						regs.sprr_perm = yield thread.read_register ("sprr_el1br1_el1", cancellable);
					} catch (Error e) {
					}
				}

				return regs;
			}
		}

		private struct Descriptor {
			public DescriptorKind kind;
			public uint64 target_address;
			public DescriptorFlags flags;

			public const uint SIZE = 8;

			public static Descriptor parse (uint64 bits, uint level, Granule granule) {
				var d = Descriptor ();

				if (level <= 2) {
					bool is_valid = (bits & 1) != 0;
					if (!is_valid) {
						d.kind = INVALID;
						return d;
					}

					d.kind = ((bits & 2) != 0) ? DescriptorKind.TABLE : DescriptorKind.BLOCK;

					if (d.kind == TABLE) {
						uint m = inpage_bits_for_granule (granule);
						d.target_address = ((bits >> m) << m) & INT48_MASK;
					} else {
						uint n = num_block_bits_at_level (level, granule);
						d.target_address = ((bits >> n) << n) & INT48_MASK;
					}
				} else {
					bool is_mapped = (bits & INT2_MASK) == 3;
					if (!is_mapped) {
						d.kind = INVALID;
						return d;
					}

					d.kind = BLOCK;

					uint m = inpage_bits_for_granule (granule);
					d.target_address = ((bits >> m) << m) & INT48_MASK;
				}

				if (d.kind == TABLE) {
					if (((bits >> 63) & 1) != 0)
						d.flags |= NSTABLE;
					if (((bits >> 62) & 1) != 0)
						d.flags |= APTABLE_READ_ONLY;
					if (((bits >> 61) & 1) != 0)
						d.flags |= APTABLE_DENY_APPLICATION;
					if (((bits >> 60) & 1) != 0)
						d.flags |= UXNTABLE;
					if (((bits >> 59) & 1) != 0)
						d.flags |= PXNTABLE;
				} else {
					if (((bits >> 54) & 1) != 0)
						d.flags |= UXN;
					if (((bits >> 53) & 1) != 0)
						d.flags |= PXN;
					if (((bits >> 52) & 1) != 0)
						d.flags |= CONTIGUOUS;
					if (((bits >> 11) & 1) != 0)
						d.flags |= NG;
					if (((bits >> 10) & 1) != 0)
						d.flags |= AF;
					if (((bits >> 7) & 1) != 0)
						d.flags |= AP_READ_ONLY;
					if (((bits >> 6) & 1) != 0)
						d.flags |= AP_ALLOW_APPLICATION;
					if (((bits >> 5) & 1) != 0)
						d.flags |= NS;
				}

				return d;
			}
		}

		private enum DescriptorKind {
			INVALID,
			TABLE,
			BLOCK
		}

		[Flags]
		private enum DescriptorFlags {
			NSTABLE,
			APTABLE_READ_ONLY,
			APTABLE_DENY_APPLICATION,
			UXNTABLE,
			PXNTABLE,
			NS,
			UXN,
			PXN,
			CONTIGUOUS,
			NG,
			AF,
			AP_READ_ONLY,
			AP_ALLOW_APPLICATION,
			SH,
		}

		private class DescriptorAllocation : Object, Allocation {
			public uint64 virtual_address {
				get {
					return base_va;
				}
			}

			public size_t size {
				get {
					return _size;
				}
			}

			private uint64 base_va;
			private size_t _size;
			private uint64 first_slot;
			private Bytes? old_descriptors;
			private GDB.Client gdb;

			public DescriptorAllocation (uint64 base_va, size_t size, uint64 first_slot, Bytes old_descriptors,
					GDB.Client gdb) {
				this.base_va = base_va;
				this._size = size;
				this.first_slot = first_slot;
				this.old_descriptors = old_descriptors;
				this.gdb = gdb;
			}

			public async void deallocate (Cancellable? cancellable) throws Error, IOError {
				if (old_descriptors == null)
					throw new Error.INVALID_OPERATION ("Already deallocated");
				Bytes d = old_descriptors;
				old_descriptors = null;
				yield set_addressing_mode (gdb, PHYSICAL, cancellable);
				try {
					yield gdb.write_byte_array (first_slot, d, cancellable);
				} finally {
					set_addressing_mode.begin (gdb, VIRTUAL, null);
				}
			}
		}

		private enum Granule {
			4K = 4096,
			16K = 16384,
			64K = 65536
		}

		private static Granule granule_from_tg1 (uint tg1) throws Error {
			switch (tg1) {
				case 1:
					return 16K;
				case 2:
					return 4K;
				case 3:
					return 64K;
				default:
					throw new Error.PROTOCOL ("Invalid TG1 value");
			}
		}

		private static uint inpage_bits_for_granule (Granule granule) {
			switch (granule) {
				case 4K: return 12;
				case 16K: return 14;
				case 64K: return 16;
			}

			assert_not_reached ();
		}

		private static uint compute_max_entries (uint level, MMUParameters p) {
			return 1 << num_address_bits_at_level (level, p);
		}

		private static uint num_address_bits_at_level (uint level, MMUParameters p) {
			if (level == p.first_level) {
				uint available_address_bits = 64 - p.t1sz - inpage_bits_for_granule (p.granule);
				uint consumed_by_lower_levels = 0;
				for (uint l = level + 1; l <= 3; l++)
					consumed_by_lower_levels += unclipped_address_bits_at_level (l, p.granule);
				return available_address_bits - consumed_by_lower_levels;
			} else {
				return unclipped_address_bits_at_level (level, p.granule);
			}
		}

		private static uint unclipped_address_bits_at_level (uint level, Granule granule) {
			switch (granule) {
				case 4K:
					return 9;
				case 16K:
					return (level == 0) ? 1 : 11;
				case 64K:
					if (level == 0)
						return 0;
					if (level == 1)
						return 6;
					return 13;
				default:
					assert_not_reached ();
			}
		}

		private static uint address_shift_at_level (uint level, Granule granule) {
			uint shift = inpage_bits_for_granule (granule);
			for (int l = 2; l != (int) level - 1; l--)
				shift += unclipped_address_bits_at_level (l, granule);
			return shift;
		}

		private static uint num_block_bits_at_level (uint level, Granule granule) {
			if (level <= 2) {
				switch (granule) {
					case 4K: return (level == 1) ? 30 : 21;
					case 16K: return 25;
					case 64K: return 29;
					default: assert_not_reached ();
				}
			} else {
				return inpage_bits_for_granule (granule);
			}
		}

		private static Gum.PageProtection protection_from_flags (DescriptorFlags flags, MMUParameters p) {
			if (p.sprr_enabled) {
				uint idx = 0;
				if ((flags & DescriptorFlags.AP_READ_ONLY) != 0)
					idx |= 1 << 3;
				if ((flags & DescriptorFlags.AP_ALLOW_APPLICATION) != 0)
					idx |= 1 << 2;
				if ((flags & DescriptorFlags.UXN) != 0)
					idx |= 1 << 1;
				if ((flags & DescriptorFlags.PXN) != 0)
					idx |= 1 << 0;

				uint perm = (uint) ((p.sprr_perm >> (idx * 4)) & 0xf);

				Gum.PageProtection prot;
				switch (perm & 3) {
					case 0:
						prot = 0;
						break;
					case 1:
						prot = READ | EXECUTE;
						if ((perm >> 2) == 2)
							prot = EXECUTE;
						break;
					case 2:
						prot = READ;
						break;
					case 3:
						prot = READ | WRITE;
						if ((perm >> 2) == 1)
							prot = 0;
						break;
					default:
						assert_not_reached ();
				}

				return prot;
			}

			Gum.PageProtection prot = READ;
			if ((flags & DescriptorFlags.PXN) == 0)
				prot |= EXECUTE;
			if ((flags & DescriptorFlags.AP_READ_ONLY) == 0)
				prot |= WRITE;
			return prot;
		}

		private static uint64 apply_protection_bits (uint64 descriptor, Gum.PageProtection prot, MMUParameters p) throws Error {
			uint64 result = descriptor;

			if (p.sprr_enabled) {
				uint target_sprr_index = find_sprr_index_for_permissions (prot, p);
				result = apply_sprr_index_to_descriptor (result, target_sprr_index);
			} else {
				result = apply_non_sprr_protection_bits (result, prot);
			}

			return result;
		}

		private static uint64 apply_non_sprr_protection_bits (uint64 descriptor, Gum.PageProtection prot) {
			uint64 result = descriptor;

			bool want_exec = (prot & Gum.PageProtection.EXECUTE) != 0;
			bool want_write = (prot & Gum.PageProtection.WRITE) != 0;

			if (want_exec)
				result &= ~(UXN_BIT | PXN_BIT);
			else
				result |= (UXN_BIT | PXN_BIT);

			if (want_write) {
				result &= ~(AP1_BIT | AP0_BIT);
			} else {
				result |= AP1_BIT;
				result &= ~AP0_BIT;
			}

			return result;
		}

		private static uint find_sprr_index_for_permissions (Gum.PageProtection prot, MMUParameters p) throws Error {
			bool want_read = (prot & Gum.PageProtection.READ) != 0;
			bool want_write = (prot & Gum.PageProtection.WRITE) != 0;
			bool want_exec = (prot & Gum.PageProtection.EXECUTE) != 0;

			for (uint i = 0; i != 16; i++) {
				uint perm = (uint) ((p.sprr_perm >> (i * 4)) & 0xf);

				bool slot_allows_read = false;
				bool slot_allows_write = false;
				bool slot_allows_exec = false;

				switch (perm & 3) {
					case 0:
						break;
					case 1:
						slot_allows_exec = true;
						if ((perm >> 2) != 2)
							slot_allows_read = true;
						break;
					case 2:
						slot_allows_read = true;
						break;
					case 3:
						slot_allows_read = true;
						slot_allows_write = ((perm >> 2) != 1);
						break;
				}

				if (slot_allows_read == want_read && slot_allows_write == want_write && slot_allows_exec == want_exec)
					return i;
			}

			throw new Error.INVALID_ARGUMENT ("No suitable SPRR slot found for protection 0x%x", prot);
		}

		private static uint64 apply_sprr_index_to_descriptor (uint64 descriptor, uint sprr_index) {
			uint64 result = descriptor;

			result &= ~(AP1_BIT | AP0_BIT | UXN_BIT | PXN_BIT);

			if ((sprr_index & 0x8) != 0)
				result |= AP1_BIT;
			if ((sprr_index & 0x4) != 0)
				result |= AP0_BIT;
			if ((sprr_index & 0x2) != 0)
				result |= UXN_BIT;
			if ((sprr_index & 0x1) != 0)
				result |= PXN_BIT;

			return result;
		}

		private static Gum.PageProtection protection_from_corellium_pt_details (string details) {
			Gum.PageProtection prot = READ;
			if (!("pXN" in details))
				prot |= EXECUTE;
			if (!("read-only" in details))
				prot |= WRITE;
			return prot;
		}

		private static MappingType mapping_type_from_corellium_pt_details (string details) {
			if ("memory" in details)
				return MEMORY;
			if ("device" in details)
				return DEVICE;
			return UNKNOWN;
		}

#if 0
		private static void print_registers (Gee.Map<string, Variant> regs) {
			var reg_names = new Gee.ArrayList<string> ();
			reg_names.add_all (regs.keys);
			reg_names.sort ((a, b) => {
				int score_a = score_register_name (a);
				int score_b = score_register_name (b);
				return score_a - score_b;
			});

			foreach (string name in reg_names) {
				Variant val = regs[name];

				string str;
				if (val.is_of_type (VariantType.UINT64))
					str = ("0x%016" + uint64.FORMAT_MODIFIER + "x").printf (val.get_uint64 ());
				else if (val.is_of_type (VariantType.UINT32))
					str = ("0x%08" + uint32.FORMAT_MODIFIER + "x").printf (val.get_uint32 ());
				else
					str = val.print (false);

				printerr ("%3s: %s\n", name, str);
			}
		}

		private static int score_register_name (string name) {
			if (name == "pc")
				return 10;
			if (name == "sp")
				return 11;
			if (name == "cpsr")
				return 1000;
			if (name == "fpsr")
				return 1001;
			if (name == "fpcr")
				return 1002;

			int result = (name[0] == 'x') ? 100 : 200;
			switch (name[0]) {
				case 'x':
				case 'v':
					result += int.parse (name[1:]);
					break;
			}
			return result;
		}
#endif

		private const size_t RED_ZONE_SIZE = 128;
	}
}
