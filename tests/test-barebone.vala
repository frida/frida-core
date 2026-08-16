namespace Frida.BareboneTest {
	public static void add_tests () {
		GLib.Test.add_func ("/Barebone/IA32/enumerate-ranges-walks-legacy-tables", () => {
			var h = new Harness ((h) => enumerate_ranges_walks_legacy_tables.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/IA32/enumerate-ranges-walks-pae-tables", () => {
			var h = new Harness ((h) => enumerate_ranges_walks_pae_tables.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/IA32/enumerate-ranges-honors-protection-filter", () => {
			var h = new Harness ((h) => enumerate_ranges_honors_protection_filter.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/IA32/control-registers-read-from-target-description", () => {
			var h = new Harness ((h) => control_registers_read_from_target_description.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/IA32/translate-address-resolves-leaf-mappings", () => {
			var h = new Harness ((h) => translate_address_resolves_leaf_mappings.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/IA32/protect-pages-updates-legacy-entries", () => {
			var h = new Harness ((h) => protect_pages_updates_legacy_entries.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/IA32/protect-pages-widens-pae-parents", () => {
			var h = new Harness ((h) => protect_pages_widens_pae_parents.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/IA32/protect-pages-rejects-large-pages", () => {
			var h = new Harness ((h) => protect_pages_rejects_large_pages.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/IA32/relocations-apply-load-bias", () => {
			var h = new Harness ((h) => relocations_apply_load_bias.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/IA32/allocate-pages-spans-leaf-tables", () => {
			var h = new Harness ((h) => allocate_pages_spans_leaf_tables.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/IA32/protect-pages-spans-leaf-tables", () => {
			var h = new Harness ((h) => protect_pages_spans_leaf_tables.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/Win9x/services-resolve-from-descriptor-block", () => {
			var h = new Harness ((h) => services_resolve_from_descriptor_block.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/IA32/scans-ranges", () => {
			var h = new Harness ((h) => ia32_scans_ranges.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/Win9x/agent-runs-in-live-guest", () => {
			var h = new Harness ((h) => agent_runs_in_live_guest.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/Win9x/enumerates-processes-in-live-guest", () => {
			var h = new Harness ((h) => enumerates_processes_in_live_guest.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/Win9x/injects-into-process-in-live-guest", () => {
			var h = new Harness ((h) => injects_into_process_in_live_guest.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/Win9x/shares-one-agent-between-sessions-in-live-guest", () => {
			var h = new Harness ((h) => shares_one_agent_between_sessions_in_live_guest.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/Win9x/enumerates-threads-in-live-guest", () => {
			var h = new Harness ((h) => enumerates_threads_in_live_guest.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/Win9x/enumerates-ranges-in-live-guest", () => {
			var h = new Harness ((h) => win9x_enumerates_ranges_in_live_guest.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/Win9x/enumerates-modules-in-live-guest", () => {
			var h = new Harness ((h) => enumerates_modules_in_live_guest.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/Win9x/agent-recovers-from-exception-in-live-guest", () => {
			var h = new Harness ((h) => agent_recovers_from_exception_in_live_guest.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/WinNt/modules-resolve-from-loaded-module-list", () => {
			var h = new Harness ((h) => modules_resolve_from_loaded_module_list.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/WinNt/maps-out-a-64-bit-kernel-in-live-guest", () => {
			var h = new Harness ((h) => winnt_maps_out_a_64_bit_kernel_in_live_guest.begin (h as Harness));
			h.run ();
		});

		// One suite for each word size. Each suite uses its own set of variables and its own guest.
		GLib.Test.add_func ("/Barebone/WinNt/agent-runs-in-live-guest", () => {
			var h = new Harness ((h) => winnt_agent_runs_in_live_guest.begin (h as Harness, "WINNT"));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/WinNt/enumerates-modules-in-live-guest", () => {
			var h = new Harness ((h) => winnt_enumerates_modules_in_live_guest.begin (h as Harness, "WINNT"));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/WinNt/compiles-c-calling-kernel-in-live-guest", () => {
			var h = new Harness ((h) => winnt_compiles_c_calling_kernel_in_live_guest.begin (h as Harness, "WINNT"));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/WinNt/agent-recovers-from-exception-in-live-guest", () => {
			var h = new Harness ((h) => winnt_agent_recovers_from_exception_in_live_guest.begin (h as Harness, "WINNT"));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/WinNt/hooks-kernel-function-in-live-guest", () => {
			var h = new Harness ((h) => winnt_hooks_kernel_function_in_live_guest.begin (h as Harness, "WINNT"));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/WinNt/enumerates-processes-in-live-guest", () => {
			var h = new Harness ((h) => winnt_enumerates_processes_in_live_guest.begin (h as Harness, "WINNT"));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/WinNt/reads-and-writes-memory-in-live-guest", () => {
			var h = new Harness ((h) => winnt_reads_and_writes_memory_in_live_guest.begin (h as Harness, "WINNT"));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/WinNt/enumerates-threads-in-live-guest", () => {
			var h = new Harness ((h) => winnt_enumerates_threads_in_live_guest.begin (h as Harness, "WINNT"));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/WinNt/enumerates-ranges-in-live-guest", () => {
			var h = new Harness ((h) => winnt_enumerates_ranges_in_live_guest.begin (h as Harness, "WINNT"));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/WinNt/resolves-symbols-in-live-guest", () => {
			var h = new Harness ((h) => winnt_resolves_symbols_in_live_guest.begin (h as Harness, "WINNT"));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/WinNt64/agent-runs-in-live-guest", () => {
			var h = new Harness ((h) => winnt_agent_runs_in_live_guest.begin (h as Harness, "WINNT64"));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/WinNt64/enumerates-modules-in-live-guest", () => {
			var h = new Harness ((h) => winnt_enumerates_modules_in_live_guest.begin (h as Harness, "WINNT64"));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/WinNt64/compiles-c-calling-kernel-in-live-guest", () => {
			var h = new Harness ((h) => winnt_compiles_c_calling_kernel_in_live_guest.begin (h as Harness, "WINNT64"));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/WinNt64/agent-recovers-from-exception-in-live-guest", () => {
			var h = new Harness ((h) => winnt_agent_recovers_from_exception_in_live_guest.begin (h as Harness, "WINNT64"));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/WinNt64/hooks-kernel-function-in-live-guest", () => {
			var h = new Harness ((h) => winnt_hooks_kernel_function_in_live_guest.begin (h as Harness, "WINNT64"));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/WinNt64/enumerates-processes-in-live-guest", () => {
			var h = new Harness ((h) => winnt_enumerates_processes_in_live_guest.begin (h as Harness, "WINNT64"));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/WinNt64/reads-and-writes-memory-in-live-guest", () => {
			var h = new Harness ((h) => winnt_reads_and_writes_memory_in_live_guest.begin (h as Harness, "WINNT64"));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/WinNt64/enumerates-threads-in-live-guest", () => {
			var h = new Harness ((h) => winnt_enumerates_threads_in_live_guest.begin (h as Harness, "WINNT64"));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/WinNt64/enumerates-ranges-in-live-guest", () => {
			var h = new Harness ((h) => winnt_enumerates_ranges_in_live_guest.begin (h as Harness, "WINNT64"));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/WinNt64/resolves-symbols-in-live-guest", () => {
			var h = new Harness ((h) => winnt_resolves_symbols_in_live_guest.begin (h as Harness, "WINNT64"));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/Config/parses-kernel-kind", () => {
			assert_true (parse_config ("{}").kernel == Barebone.KernelKind.AUTO);
			assert_true (parse_config ("{ \"kernel\": \"bare\" }").kernel == Barebone.KernelKind.BARE);
			assert_true (parse_config ("{ \"kernel\": \"xnu\" }").kernel == Barebone.KernelKind.XNU);
			assert_true (parse_config ("{ \"kernel\": \"win9x\" }").kernel == Barebone.KernelKind.WIN9X);
			assert_true (parse_config ("{ \"kernel\": \"winnt\" }").kernel == Barebone.KernelKind.WINNT);
		});

		GLib.Test.add_func ("/Barebone/Config/parses-allocator-arguments", () => {
			var allocator = (Barebone.TargetFunctionsAllocatorConfig) parse_config (
				"{ \"allocator\": { \"mode\": \"target-functions\", \"alloc_function\": \"804e1000\", \"free_function\": \"804e2000\", \"alloc_arguments\": [ \"0\", \"size\", \"64697246\" ], \"free_arguments\": [ \"address\", \"64697246\" ] } }").allocator;

			var alloc = allocator.effective_alloc_arguments ();
			assert_true (alloc.size == 3);
			assert_argument (alloc[0], Barebone.CallArgumentRole.LITERAL, 0);
			assert_argument (alloc[1], Barebone.CallArgumentRole.SIZE, 0);
			assert_argument (alloc[2], Barebone.CallArgumentRole.LITERAL, 0x64697246);

			var free = allocator.effective_free_arguments ();
			assert_true (free.size == 2);
			assert_argument (free[0], Barebone.CallArgumentRole.ADDRESS, 0);
			assert_argument (free[1], Barebone.CallArgumentRole.LITERAL, 0x64697246);

			// Without a template, the flags still give the argument list.
			var shorthand = (Barebone.TargetFunctionsAllocatorConfig) parse_config (
				"{ \"allocator\": { \"mode\": \"target-functions\", \"alloc_function\": \"1000\", \"free_function\": \"2000\", \"alloc_flags\": 3 } }").allocator;

			var inferred = shorthand.effective_alloc_arguments ();
			assert_true (inferred.size == 2);
			assert_argument (inferred[0], Barebone.CallArgumentRole.SIZE, 0);
			assert_argument (inferred[1], Barebone.CallArgumentRole.LITERAL, 3);
		});

		GLib.Test.add_func ("/Barebone/X64/enumerate-ranges-walks-long-mode-tables", () => {
			var h = new Harness ((h) => enumerate_ranges_walks_long_mode_tables.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/X64/translate-address-resolves-leaf-mappings", () => {
			var h = new Harness ((h) => x64_translate_address_resolves_leaf_mappings.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/X64/protect-pages-updates-long-mode-entries", () => {
			var h = new Harness ((h) => protect_pages_updates_long_mode_entries.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/X64/protect-pages-copes-with-large-pages", () => {
			var h = new Harness ((h) => x64_protect_pages_copes_with_large_pages.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/X64/relocations-apply-load-bias", () => {
			var h = new Harness ((h) => x64_relocations_apply_load_bias.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/IA32/QEMU/walk-matches-guest", () => {
			var h = new SlowHarness ((h) => QEMU.walk_matches_x86_guest.begin (h as SlowHarness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/IA32/QEMU/allocate-pages-maps-into-guest", () => {
			var h = new SlowHarness ((h) => QEMU.allocate_pages_maps_into_x86_guest.begin (h as SlowHarness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/IA32/QEMU/invoke-calls-into-guest", () => {
			var h = new SlowHarness ((h) => QEMU.invoke_calls_into_x86_guest.begin (h as SlowHarness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/X64/QEMU/walk-matches-guest", () => {
			var h = new SlowHarness ((h) => QEMU.walk_matches_x86_64_guest.begin (h as SlowHarness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/X64/QEMU/allocate-pages-maps-into-guest", () => {
			var h = new SlowHarness ((h) => QEMU.allocate_pages_maps_into_x86_64_guest.begin (h as SlowHarness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/X64/QEMU/invoke-calls-into-guest", () => {
			var h = new SlowHarness ((h) => QEMU.invoke_calls_into_x86_64_guest.begin (h as SlowHarness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/IA32/QEMU/inline-hook-fires-in-guest", () => {
			var h = new SlowHarness ((h) => QEMU.inline_hook_fires_in_x86_guest.begin (h as SlowHarness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/IA32/QEMU/injected-elf-runs-in-guest", () => {
			var h = new SlowHarness ((h) => QEMU.injected_elf_runs_in_x86_guest.begin (h as SlowHarness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/IA32/QEMU/whole-agent-loads-into-guest", () => {
			var h = new SlowHarness ((h) => QEMU.whole_agent_loads_into_x86_guest.begin (h as SlowHarness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/X64/QEMU/inline-hook-fires-in-guest", () => {
			var h = new SlowHarness ((h) => QEMU.inline_hook_fires_in_x86_64_guest.begin (h as SlowHarness));
			h.run ();
		});
	}

	private static Barebone.Config parse_config (string json) {
		try {
			return (Barebone.Config) Json.gobject_from_data (typeof (Barebone.Config), json);
		} catch (GLib.Error e) {
			assert_not_reached ();
		}
	}

	private static async void enumerate_ranges_walks_legacy_tables (Harness h) {
		var target = new FakeTarget (IA32, legacy_page_tables (), LEGACY_MONITOR_DUMP);
		try {
			yield target.open ();
			var machine = new Barebone.IA32Machine (target.client);

			var ranges = yield collect_ranges (machine, Gum.PageProtection.READ);

			assert_true (ranges.size == 3);

			assert_range (ranges[0], 0x00000000, 0x00100000, 0x2000, READ | WRITE | EXECUTE);
			assert_range (ranges[1], 0x00002000, 0x00102000, 0x1000, READ | EXECUTE);

			assert_range (ranges[2], 0x00400000, 0x00800000, 0x400000, READ | EXECUTE);
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n", e.message);
			assert_not_reached ();
		} finally {
			target.stop ();
		}

		h.done ();
	}

	private static async void enumerate_ranges_walks_pae_tables (Harness h) {
		var target = new FakeTarget (IA32, pae_page_tables (), PAE_MONITOR_DUMP);
		try {
			yield target.open ();
			var machine = new Barebone.IA32Machine (target.client);

			var ranges = yield collect_ranges (machine, Gum.PageProtection.READ);

			assert_true (ranges.size == 3);

			assert_range (ranges[0], 0x00000000, 0x00100000, 0x1000, READ | WRITE);
			assert_range (ranges[1], 0x00001000, 0x00101000, 0x1000, READ | WRITE | EXECUTE);

			assert_range (ranges[2], 0x00200000, 0x140000000, 0x200000, READ);
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n", e.message);
			assert_not_reached ();
		} finally {
			target.stop ();
		}

		h.done ();
	}

	private static async void enumerate_ranges_honors_protection_filter (Harness h) {
		var target = new FakeTarget (IA32, legacy_page_tables (), LEGACY_MONITOR_DUMP);
		try {
			yield target.open ();
			var machine = new Barebone.IA32Machine (target.client);

			var ranges = yield collect_ranges (machine, Gum.PageProtection.WRITE);

			assert_true (ranges.size == 1);
			assert_range (ranges[0], 0x00000000, 0x00100000, 0x2000, READ | WRITE | EXECUTE);
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n", e.message);
			assert_not_reached ();
		} finally {
			target.stop ();
		}

		h.done ();
	}

	private static async void control_registers_read_from_target_description (Harness h) {
		// No monitor command here: the machine must prefer the exposed registers.
		var target = new FakeTarget (IA32, legacy_page_tables (), null, EXPOSE_CONTROL_REGISTERS);
		try {
			yield target.open ();
			var machine = new Barebone.IA32Machine (target.client);

			var ranges = yield collect_ranges (machine, Gum.PageProtection.READ);

			assert_true (ranges.size == 3);
			assert_range (ranges[0], 0x00000000, 0x00100000, 0x2000, READ | WRITE | EXECUTE);
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n", e.message);
			assert_not_reached ();
		} finally {
			target.stop ();
		}

		h.done ();
	}

	private static async void translate_address_resolves_leaf_mappings (Harness h) {
		var target = new FakeTarget (IA32, legacy_page_tables (), LEGACY_MONITOR_DUMP);
		try {
			yield target.open ();
			var machine = new Barebone.IA32Machine (target.client);

			assert_true ((yield machine.translate_address (0x00002010, null)) == 0x00102010);
			assert_true ((yield machine.translate_address (0x00400123, null)) == 0x00800123);

			try {
				yield machine.translate_address (0x00003000, null);
				assert_not_reached ();
			} catch (Error e) {
				assert_true (e is Error.NOT_SUPPORTED);
			}
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n", e.message);
			assert_not_reached ();
		} finally {
			target.stop ();
		}

		h.done ();
	}

	private static async void protect_pages_updates_legacy_entries (Harness h) {
		var target = new FakeTarget (IA32, legacy_page_tables (), LEGACY_MONITOR_DUMP);
		try {
			yield target.open ();
			var machine = new Barebone.IA32Machine (target.client);

			yield machine.protect_pages (0x00002000, 4096, READ | WRITE, null);

			assert_true (target.read_uint32 (PT_PA + (2 * 4)) == 0x00102003);

			assert_true (target.read_uint32 (PT_PA + (0 * 4)) == 0x00100003);
			assert_true (target.read_uint32 (PD_PA + (0 * 4)) == (PT_PA | 0x3));
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n", e.message);
			assert_not_reached ();
		} finally {
			target.stop ();
		}

		h.done ();
	}

	private static async void protect_pages_widens_pae_parents (Harness h) {
		var target = new FakeTarget (IA32, pae_page_tables (), PAE_MONITOR_DUMP);
		try {
			yield target.open ();
			var machine = new Barebone.IA32Machine (target.client);

			yield machine.protect_pages (0x00000000, 4096, READ | EXECUTE, null);

			assert_true (target.read_uint64 (PAE_PT_PA + (0 * 8)) == 0x00100001);

			// The levels above already grant what was asked for, so they must be left alone.
			assert_true (target.read_uint64 (PAE_PD_PA + (0 * 8)) == (PAE_PT_PA | 0x3));
			assert_true (target.read_uint64 (PAE_PDPT_PA + (0 * 8)) == (PAE_PD_PA | 0x1));
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n", e.message);
			assert_not_reached ();
		} finally {
			target.stop ();
		}

		h.done ();
	}

	private static async void protect_pages_rejects_large_pages (Harness h) {
		var target = new FakeTarget (IA32, legacy_page_tables (), LEGACY_MONITOR_DUMP);
		try {
			yield target.open ();
			var machine = new Barebone.IA32Machine (target.client);

			try {
				yield machine.protect_pages (0x00400000, 4096, READ | WRITE, null);
				assert_not_reached ();
			} catch (Error e) {
				assert_true (e is Error.NOT_SUPPORTED);
			}

			assert_true (target.read_uint32 (PD_PA + (1 * 4)) == 0x00800081);
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n", e.message);
			assert_not_reached ();
		} finally {
			target.stop ();
		}

		h.done ();
	}

	private static async void relocations_apply_load_bias (Harness h) {
		var target = new FakeTarget (IA32, legacy_page_tables (), LEGACY_MONITOR_DUMP);
		try {
			yield target.open ();
			var machine = new Barebone.IA32Machine (target.client);

			uint64 base_va = 0xc0010000;

			var image = target.client.make_buffer (new Bytes (new uint8[12]));
			image.write_uint32 (0, 0x00000040);
			image.write_uint32 (4, 0x00000080);
			image.write_uint32 (8, 0x11223344);

			machine.apply_relocation (make_relocation (Gum.ElfIA32Relocation.@32, 0), base_va, image);
			machine.apply_relocation (make_relocation (Gum.ElfIA32Relocation.RELATIVE, 4), base_va, image);

			machine.apply_relocation (make_relocation (Gum.ElfIA32Relocation.PC32, 8), base_va, image);

			assert_true (image.read_uint32 (0) == 0xc0010040);
			assert_true (image.read_uint32 (4) == 0xc0010080);
			assert_true (image.read_uint32 (8) == 0x11223344);

			try {
				machine.apply_relocation (make_relocation (Gum.ElfIA32Relocation.TLS_DESC, 0), base_va, image);
				assert_not_reached ();
			} catch (Error e) {
				assert_true (e is Error.NOT_SUPPORTED);
			}
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n", e.message);
			assert_not_reached ();
		} finally {
			target.stop ();
		}

		h.done ();
	}

	private static async void allocate_pages_spans_leaf_tables (Harness h) {
		var target = new FakeTarget (IA32, adjacent_leaf_tables (), LEGACY_MONITOR_DUMP);
		try {
			yield target.open ();
			var machine = new Barebone.IA32Machine (target.client);

			var physical_addresses = new Gee.ArrayList<uint64?> ();
			for (uint i = 0; i != 3; i++)
				physical_addresses.add (0x00200000 + (i * 4096));

			var allocation = yield machine.allocate_pages (physical_addresses, null);

			// The last two of the first table, then the first of the second.
			uint64 first_free = (uint64) (SPAN_ENTRIES_PER_TABLE - SPAN_FREE_IN_FIRST) * 4096;
			assert_true (allocation.virtual_address == first_free);
			assert_true (allocation.size == 3 * 4096);

			uint slot = SPAN_ENTRIES_PER_TABLE - SPAN_FREE_IN_FIRST;
			assert_true (target.read_uint32 (SPAN_PT0_PA + (slot * 4)) == 0x00200003);
			assert_true (target.read_uint32 (SPAN_PT0_PA + ((slot + 1) * 4)) == 0x00201003);
			assert_true (target.read_uint32 (SPAN_PT1_PA + (0 * 4)) == 0x00202003);

			yield allocation.deallocate (null);

			assert_true (target.read_uint32 (SPAN_PT0_PA + (slot * 4)) == 0);
			assert_true (target.read_uint32 (SPAN_PT1_PA + (0 * 4)) == 0);
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n", e.message);
			assert_not_reached ();
		} finally {
			target.stop ();
		}

		h.done ();
	}

	private static async void protect_pages_spans_leaf_tables (Harness h) {
		var target = new FakeTarget (IA32, adjacent_leaf_tables (), LEGACY_MONITOR_DUMP);
		try {
			yield target.open ();
			var machine = new Barebone.IA32Machine (target.client);

			// The last mapped page of the first table, and the first page of the second.
			uint last_slot = SPAN_ENTRIES_PER_TABLE - SPAN_FREE_IN_FIRST - 1;
			uint64 start_va = (uint64) last_slot * 4096;
			yield machine.protect_pages (start_va, 4096, READ, null);

			uint32 entry = target.read_uint32 (SPAN_PT0_PA + (last_slot * 4));
			assert_true ((entry & 0x2) == 0);
			assert_true ((entry & 0x1) != 0);

			assert_true ((target.read_uint32 (SPAN_PT0_PA + ((last_slot - 1) * 4)) & 0x2) != 0);
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n", e.message);
			assert_not_reached ();
		} finally {
			target.stop ();
		}

		h.done ();
	}

	private static async void enumerate_ranges_walks_long_mode_tables (Harness h) {
		var target = new FakeTarget (X64, long_mode_page_tables (), X64_MONITOR_DUMP);
		try {
			yield target.open ();
			var machine = new Barebone.X64Machine (target.client);

			var ranges = yield collect_ranges (machine, Gum.PageProtection.READ);

			assert_true (ranges.size == 4);

			assert_range (ranges[0], 0x00000000, 0x00100000, 0x1000, READ | WRITE);
			assert_range (ranges[1], 0x00001000, 0x00101000, 0x1000, READ | WRITE | EXECUTE);
			assert_range (ranges[2], 0x00200000, 0x140000000, 0x200000, READ);

			// A 1 GiB mapping in the kernel half, which only comes out right if the walker
			// sign-extends what it composes from the indices.
			assert_range (ranges[3], 0xffffc00000000000, 0x40000000, 0x40000000,
				READ | WRITE | EXECUTE);
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n", e.message);
			assert_not_reached ();
		} finally {
			target.stop ();
		}

		h.done ();
	}

	private static async void x64_translate_address_resolves_leaf_mappings (Harness h) {
		var target = new FakeTarget (X64, long_mode_page_tables (), X64_MONITOR_DUMP);
		try {
			yield target.open ();
			var machine = new Barebone.X64Machine (target.client);

			assert_true ((yield machine.translate_address (0x00001010, null)) == 0x00101010);
			assert_true ((yield machine.translate_address (0x00200123, null)) == 0x140000123);
			assert_true ((yield machine.translate_address (0xffffc00000000123, null)) == 0x40000123);

			try {
				yield machine.translate_address (0x00003000, null);
				assert_not_reached ();
			} catch (Error e) {
				assert_true (e is Error.NOT_SUPPORTED);
			}
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n", e.message);
			assert_not_reached ();
		} finally {
			target.stop ();
		}

		h.done ();
	}

	private static async void protect_pages_updates_long_mode_entries (Harness h) {
		var target = new FakeTarget (X64, long_mode_page_tables (), X64_MONITOR_DUMP);
		try {
			yield target.open ();
			var machine = new Barebone.X64Machine (target.client);

			yield machine.protect_pages (0x00000000, 4096, READ | EXECUTE, null);

			assert_true (target.read_uint64 (X64_PT_PA + (0 * 8)) == 0x00100001);

			// The levels above already grant what was asked for, so they must be left alone.
			assert_true (target.read_uint64 (X64_PD_PA + (0 * 8)) == (X64_PT_PA | 0x3));
			assert_true (target.read_uint64 (X64_PML4_PA + (0 * 8)) == (X64_PDPT_PA | 0x3));

			yield machine.protect_pages (0x00001000, 4096, READ, null);
			assert_true (target.read_uint64 (X64_PT_PA + (1 * 8)) == (0x00101001 | (1ULL << 63)));
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n", e.message);
			assert_not_reached ();
		} finally {
			target.stop ();
		}

		h.done ();
	}

	private static async void x64_protect_pages_copes_with_large_pages (Harness h) {
		var target = new FakeTarget (X64, long_mode_page_tables (), X64_MONITOR_DUMP);
		try {
			yield target.open ();
			var machine = new Barebone.X64Machine (target.client);

			// This gigabyte page is already writable, thus there is nothing to do. Do not make it more
			// restrictive, because the kernel put other data in the same mapping.
			yield machine.protect_pages (0xffffc00000000000, 4096, READ | WRITE, null);
			assert_true (target.read_uint64 (X64_KERNEL_PDPT_PA + (0 * 8)) == 0x400000e3);

			// This range is read-only, and you cannot make one part of it writable.
			try {
				yield machine.protect_pages (0x200000, 4096, READ | WRITE, null);
				assert_not_reached ();
			} catch (Error e) {
				assert_true (e is Error.NOT_SUPPORTED);
			}

			assert_true (target.read_uint64 (X64_PD_PA + (1 * 8)) == 0x8000000140000081);
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n", e.message);
			assert_not_reached ();
		} finally {
			target.stop ();
		}

		h.done ();
	}

	private static async void x64_relocations_apply_load_bias (Harness h) {
		var target = new FakeTarget (X64, long_mode_page_tables (), X64_MONITOR_DUMP);
		try {
			yield target.open ();
			var machine = new Barebone.X64Machine (target.client);

			uint64 base_va = 0xffffffff81000000;

			var image = target.client.make_buffer (new Bytes (new uint8[20]));
			image.write_uint64 (0, 0x40);
			image.write_uint64 (8, 0x80);
			image.write_uint32 (16, 0x11223344);

			machine.apply_relocation (make_relocation (Gum.ElfX64Relocation.@64, 0), base_va, image);
			machine.apply_relocation (make_relocation (Gum.ElfX64Relocation.RELATIVE, 8), base_va, image);
			machine.apply_relocation (make_relocation (Gum.ElfX64Relocation.PC32, 16), base_va, image);

			assert_true (image.read_uint64 (0) == 0xffffffff81000040);
			assert_true (image.read_uint64 (8) == 0xffffffff81000080);
			assert_true (image.read_uint32 (16) == 0x11223344);

			try {
				machine.apply_relocation (make_relocation (Gum.ElfX64Relocation.TLSGD, 0), base_va, image);
				assert_not_reached ();
			} catch (Error e) {
				assert_true (e is Error.NOT_SUPPORTED);
			}
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n", e.message);
			assert_not_reached ();
		} finally {
			target.stop ();
		}

		h.done ();
	}

	/**
	 * The fake-stub tests above pin down the bit-level behaviour; this one checks the walker
	 * against a real MMU, using a stock Linux guest whose page tables QEMU can describe to us
	 * independently. The guest is non-PAE with PSE, so it covers the legacy two-level walk and
	 * 4 MiB pages; PAE and NX remain the fake stub's job.
	 */
	namespace QEMU {
		private static async void walk_matches_x86_guest (SlowHarness h) {
			yield walk_matches_guest (h, X86);
		}

		private static async void walk_matches_x86_64_guest (SlowHarness h) {
			yield walk_matches_guest (h, X86_64);
		}

		private static async void walk_matches_guest (SlowHarness h, GuestArch arch) {
			QemuGuest? guest = null;
			try {
				string? unavailable_reason = yield QemuGuest.check_availability (arch);
				if (unavailable_reason != null) {
					stdout.printf ("<skipping: %s> ", unavailable_reason);
					h.done ();
					return;
				}

				guest = yield QemuGuest.boot (arch);
				assert_true (guest != null);

				Barebone.Machine machine = (arch == X86)
					? (Barebone.Machine) new Barebone.IA32Machine (guest.client)
					: (Barebone.Machine) new Barebone.X64Machine (guest.client);

				var ours = yield collect_ranges (machine, Gum.PageProtection.READ);
				assert_true (ours.size != 0);

				Gee.List<Interval> mapped_by_guest = yield guest.query_mapped_intervals ();
				assert_intervals_equal (merge_by_virtual_address (ours), mapped_by_guest);

				Gee.List<GuestPage> pages = yield guest.query_pages ();
				assert_true (pages.size != 0);

				bool saw_large_page = false;
				foreach (GuestPage page in pages) {
					Barebone.RangeDetails? r = find_range_containing (ours, page.va);
					assert_true (r != null);

					assert_true (r.virtual_to_physical (page.va) == page.pa);

					// QEMU reports the leaf entry's own bits, while the walker ANDs in every level
					// above it, so the walker's rights can only ever be the narrower of the two.
					if ((r.protection & Gum.PageProtection.WRITE) != 0)
						assert_true (page.writable);
					if ((r.protection & Gum.PageProtection.EXECUTE) != 0)
						assert_true (!page.no_execute);

					if (page.large) {
						assert_true (r.size >= 0x200000);
						saw_large_page = true;
					}
				}

				assert_true (saw_large_page);

				yield check_protect_pages_takes_effect (machine, guest, pages);
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n", e.message);
				assert_not_reached ();
			} finally {
				if (guest != null)
					guest.stop ();
			}

			h.done ();
		}

		private static async void allocate_pages_maps_into_x86_guest (SlowHarness h) {
			yield allocate_pages_maps_into_guest (h, X86);
		}

		private static async void allocate_pages_maps_into_x86_64_guest (SlowHarness h) {
			yield allocate_pages_maps_into_guest (h, X86_64);
		}

		private static async void allocate_pages_maps_into_guest (SlowHarness h, GuestArch arch) {
			QemuGuest? guest = null;
			try {
				string? unavailable_reason = yield QemuGuest.check_availability (arch);
				if (unavailable_reason != null) {
					stdout.printf ("<skipping: %s> ", unavailable_reason);
					h.done ();
					return;
				}

				guest = yield QemuGuest.boot (arch);

				Barebone.Machine machine = make_machine (arch, guest);

				Gee.List<GuestPage> pages = yield guest.query_pages ();
				assert_true (pages.size != 0);

				uint64 first_pa = pages[0].pa;
				var physical_addresses = new Gee.ArrayList<uint64?> ();
				physical_addresses.add (first_pa);
				physical_addresses.add (first_pa + 4096);

				Barebone.Allocation allocation = yield machine.allocate_pages (physical_addresses, null);
				uint64 va = allocation.virtual_address;
				assert_true (va != 0);
				assert_true (allocation.size == 2 * 4096);

				GuestPage first = yield guest.query_page (va);
				assert_true (first.pa == first_pa);
				assert_true (first.writable);
				assert_true (!first.no_execute);

				GuestPage second = yield guest.query_page (va + 4096);
				assert_true (second.pa == first_pa + 4096);

				yield allocation.deallocate (null);
				foreach (GuestPage page in yield guest.query_pages ())
					assert_true (page.va != va);
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n", e.message);
				assert_not_reached ();
			} finally {
				if (guest != null)
					guest.stop ();
			}

			h.done ();
		}

		private static async void invoke_calls_into_x86_guest (SlowHarness h) {
			yield invoke_calls_into_guest (h, X86);
		}

		private static async void invoke_calls_into_x86_64_guest (SlowHarness h) {
			yield invoke_calls_into_guest (h, X86_64);
		}

		private static async void invoke_calls_into_guest (SlowHarness h, GuestArch arch) {
			QemuGuest? guest = null;
			try {
				string? unavailable_reason = yield QemuGuest.check_availability (arch);
				if (unavailable_reason != null) {
					stdout.printf ("<skipping: %s> ", unavailable_reason);
					h.done ();
					return;
				}

				guest = yield QemuGuest.boot (arch);

				Barebone.Machine machine = make_machine (arch, guest);

				uint64 scratch_pa = ((uint64) QemuGuest.MEMORY_SIZE_IN_MB << 20) - (1024 * 1024);

				var physical_addresses = new Gee.ArrayList<uint64?> ();
				physical_addresses.add (scratch_pa);

				Barebone.Allocation allocation = yield machine.allocate_pages (physical_addresses, null);
				uint64 va = allocation.virtual_address;

				uint8[] sum_of_two_args;
				if (arch == X86) {
					sum_of_two_args = {
						0x8b, 0x44, 0x24, 0x04,	// mov eax, [esp+4]
						0x03, 0x44, 0x24, 0x08,	// add eax, [esp+8]
						0xc3			// ret
					};
				} else {
					sum_of_two_args = {
						0x48, 0x89, 0xf8,	// mov rax, rdi
						0x48, 0x01, 0xf0,	// add rax, rsi
						0xc3			// ret
					};
				}

				Buffer displaced = yield guest.client.read_buffer (va, sum_of_two_args.length, null);
				yield guest.client.write_byte_array (va, new Bytes (sum_of_two_args), null);

				uint64[] args = { 40, 2 };
				assert_true ((yield machine.invoke (va, args, null)) == 42);

				yield guest.client.write_byte_array (va, displaced.bytes, null);
				yield allocation.deallocate (null);
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n", e.message);
				assert_not_reached ();
			} finally {
				if (guest != null)
					guest.stop ();
			}

			h.done ();
		}

		private static async void inline_hook_fires_in_x86_guest (SlowHarness h) {
			yield inline_hook_fires_in_guest (h, X86);
		}

		private static async void inline_hook_fires_in_x86_64_guest (SlowHarness h) {
			yield inline_hook_fires_in_guest (h, X86_64);
		}

		private static async void inline_hook_fires_in_guest (SlowHarness h, GuestArch arch) {
			QemuGuest? guest = null;
			try {
				string? unavailable_reason = yield QemuGuest.check_availability (arch);
				if (unavailable_reason != null) {
					stdout.printf ("<skipping: %s> ", unavailable_reason);
					h.done ();
					return;
				}

				guest = yield QemuGuest.boot (arch);

				Barebone.Machine machine = make_machine (arch, guest);
				Barebone.Allocator allocator = make_scratch_allocator (machine);

				Barebone.Allocation target = yield allocator.allocate (4096, 4096, null);
				Barebone.Allocation handler = yield allocator.allocate (4096, 4096, null);
				Barebone.Allocation marker = yield allocator.allocate (4096, 4096, null);

				uint8[] answer_forty_two = {
					0xb8, 0x2a, 0x00, 0x00, 0x00,	// mov eax, 42
					0xc3				// ret
				};
				yield guest.client.write_byte_array (target.virtual_address, new Bytes (answer_forty_two), null);

				var hb = guest.client.make_buffer_builder ();
				if (arch == X86) {
					hb
						.append_uint8 (0xc7).append_uint8 (0x05)	// mov dword [marker], ...
						.append_uint32 ((uint32) marker.virtual_address)
						.append_uint32 (MARKER_VALUE)
						.append_uint8 (0xc3);				// ret
				} else {
					hb
						.append_uint8 (0x48).append_uint8 (0xb8)	// mov rax, marker
						.append_uint64 (marker.virtual_address)
						.append_uint8 (0xc7).append_uint8 (0x00)	// mov dword [rax], ...
						.append_uint32 (MARKER_VALUE)
						.append_uint8 (0xc3);				// ret
				}
				yield guest.client.write_byte_array (handler.virtual_address, hb.build (), null);

				Barebone.InlineHook hook = yield machine.create_inline_hook (target.virtual_address,
					handler.virtual_address, allocator, null);

				yield clear_marker (guest, marker.virtual_address);
				assert_true ((yield machine.invoke (target.virtual_address, {}, null)) == 42);
				assert_true ((yield read_marker (guest, marker.virtual_address)) == 0);

				yield hook.enable (null);
				assert_true ((yield machine.invoke (target.virtual_address, {}, null)) == 42);
				assert_true ((yield read_marker (guest, marker.virtual_address)) == MARKER_VALUE);

				yield hook.disable (null);
				yield clear_marker (guest, marker.virtual_address);
				assert_true ((yield machine.invoke (target.virtual_address, {}, null)) == 42);
				assert_true ((yield read_marker (guest, marker.virtual_address)) == 0);

				yield hook.destroy (null);
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n", e.message);
				assert_not_reached ();
			} finally {
				if (guest != null)
					guest.stop ();
			}

			h.done ();
		}

		private const uint32 MARKER_VALUE = 0xdeadbeefU;

		private static Barebone.Allocator make_scratch_allocator (Barebone.Machine machine,
				uint mb_below_top = 1) {
			var config = new Barebone.PhysicalAllocatorConfig ();
			config.physical_base = new Barebone.NonNullMemoryAddress ("scratch",
				((uint64) (QemuGuest.MEMORY_SIZE_IN_MB - mb_below_top)) << 20);
			return new Barebone.PhysicalAllocator (machine, 4096, config);
		}

		private static async void clear_marker (QemuGuest guest, uint64 va) throws Error, IOError {
			yield guest.client.write_byte_array (va, new Bytes (new uint8[4]), null);
		}

		private static async uint32 read_marker (QemuGuest guest, uint64 va) throws Error, IOError {
			return (yield guest.client.read_buffer (va, 4, null)).read_uint32 (0);
		}

		private static async void injected_elf_runs_in_x86_guest (SlowHarness h) {
			QemuGuest? guest = null;
			try {
				string? unavailable_reason = yield QemuGuest.check_availability (X86);
				if (unavailable_reason != null) {
					stdout.printf ("<skipping: %s> ", unavailable_reason);
					h.done ();
					return;
				}

				guest = yield QemuGuest.boot (X86);

				Barebone.Machine machine = make_machine (X86, guest);
				Barebone.Allocator allocator = make_scratch_allocator (machine);

				var elf = new Gum.ElfModule.from_file (marker_path ());
				size_t page_size = yield machine.query_page_size (null);
				Barebone.Allocation image = yield Barebone.inject_elf (elf, new Bytes (elf.get_file_data ()),
					page_size, machine, allocator, null);
				uint64 base_va = image.virtual_address;

				uint64 start = 0;
				elf.enumerate_symbols (e => {
					if (e.name == "_start")
						start = base_va + e.address;
					return true;
				});
				assert_true (start != 0);

				Barebone.Allocation reported = yield allocator.allocate (8, 4, null);
				yield guest.client.write_byte_array (reported.virtual_address, new Bytes (new uint8[8]), null);

				uint64[] args = { reported.virtual_address, 8 };
				yield machine.invoke (start, args, null);

				Buffer answer = yield guest.client.read_buffer (reported.virtual_address, 8, null);

				uint64 answer_address = answer.read_uint32 (0);
				assert_true (answer_address >= base_va);
				assert_true (answer_address < base_va + image.size);

				assert_true (answer.read_uint32 (4) == MARKER_ANSWER);
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n", e.message);
				assert_not_reached ();
			} finally {
				if (guest != null)
					guest.stop ();
			}

			h.done ();
		}

		private const uint32 MARKER_ANSWER = 0x1234abcdU;

		private static string marker_path () {
			return Path.build_filename (TESTS_SRCDIR, "..", "src", "barebone", "helpers", "marker-x86.elf");
		}

		private static async void whole_agent_loads_into_x86_guest (SlowHarness h) {
			string? agent_path = Environment.get_variable ("FRIDA_BAREBONE_AGENT_X86");
			if (agent_path == null) {
				stdout.printf ("<skipping: set FRIDA_BAREBONE_AGENT_X86 to an agent blob> ");
				h.done ();
				return;
			}

			QemuGuest? guest = null;
			try {
				string? unavailable_reason = yield QemuGuest.check_availability (X86);
				if (unavailable_reason != null) {
					stdout.printf ("<skipping: %s> ", unavailable_reason);
					h.done ();
					return;
				}

				guest = yield QemuGuest.boot (X86);

				Barebone.Machine machine = make_machine (X86, guest);
				Barebone.Allocator allocator = make_scratch_allocator (machine, 32);

				var elf = new Gum.ElfModule.from_file (agent_path);
				size_t page_size = yield machine.query_page_size (null);

				var timer = new Timer ();
				Barebone.Allocation image = yield Barebone.inject_elf (elf, new Bytes (elf.get_file_data ()),
					page_size, machine, allocator, null);
				stdout.printf ("<%u KiB in %.1fs> ", (uint) (image.size / 1024), timer.elapsed ());

				uint64 base_va = image.virtual_address;
				assert_true (base_va != 0);
				assert_true (image.size >= elf.mapped_size);

				uint64 start = 0;
				elf.enumerate_symbols (e => {
					if (e.name == "_start")
						start = base_va + e.address;
					return true;
				});
				assert_true (start != 0);

				Buffer entry = yield guest.client.read_buffer (start, 16, null);
				bool entry_populated = false;
				for (uint i = 0; i != 16; i++)
					entry_populated |= entry.read_uint8 (i) != 0;
				assert_true (entry_populated);

				// The far end has to be mapped too, not just the first pages.
				yield guest.client.read_buffer (base_va + image.size - 16, 16, null);
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n", e.message);
				assert_not_reached ();
			} finally {
				if (guest != null)
					guest.stop ();
			}

			h.done ();
		}

		private static Barebone.Machine make_machine (GuestArch arch, QemuGuest guest) {
			if (arch == X86)
				return new Barebone.IA32Machine (guest.client);
			return new Barebone.X64Machine (guest.client);
		}

		private static async void check_protect_pages_takes_effect (Barebone.Machine machine, QemuGuest guest,
				Gee.List<GuestPage> pages) throws Error, IOError {
			GuestPage? victim = null;
			foreach (GuestPage page in pages) {
				if (!page.writable && !page.large) {
					victim = page;
					break;
				}
			}
			assert_true (victim != null);

			yield machine.protect_pages (victim.va, 4096, READ | WRITE, null);
			assert_true ((yield guest.query_page (victim.va)).writable);

			yield machine.protect_pages (victim.va, 4096, READ, null);
			assert_true (!(yield guest.query_page (victim.va)).writable);
		}
	}

	private static async Gee.List<Barebone.RangeDetails> collect_ranges (Barebone.Machine machine,
			Gum.PageProtection prot) throws Error, IOError {
		var result = new Gee.ArrayList<Barebone.RangeDetails> ();
		yield machine.enumerate_ranges (prot, r => {
			result.add (r.clone ());
			return true;
		}, null);
		return result;
	}

	private static void assert_range (Barebone.RangeDetails r, uint64 base_va, uint64 base_pa, uint64 size,
			Gum.PageProtection prot) {
		assert_true (r.base_va == base_va);
		assert_true (r.base_pa == base_pa);
		assert_true (r.size == size);
		assert_true (r.protection == prot);
	}

	private static Gum.ElfRelocationDetails make_relocation (uint32 type, uint64 address) {
		var r = Gum.ElfRelocationDetails ();
		r.address = address;
		r.type = type;
		return r;
	}

	private const uint64 PD_PA = 0x1000;
	private const uint64 PT_PA = 0x2000;

	private const string LEGACY_MONITOR_DUMP =
		"EAX=00000000 EBX=00000000 ECX=00000000 EDX=00000000\n" +
		"CR0=8005003b CR2=00000000 CR3=00001000 CR4=00000010\n";

	// Paging on, PSE on, PAE off: 32-bit entries, one of them a 4 MiB page.
	private static async void ia32_scans_ranges (Harness h) {
		var target = new FakeTarget (IA32, arena_page_tables (), LEGACY_MONITOR_DUMP);
		try {
			target.map_virtual (ARENA_VA, arena_with_needles ());
			yield target.open ();
			var machine = new Barebone.IA32Machine (target.client);

			var ranges = new Gee.ArrayList<Gum.MemoryRange?> ();
			ranges.add (Gum.MemoryRange () { base_address = ARENA_VA, size = ARENA_SIZE });

			var exact = yield machine.scan_ranges (ranges, new Barebone.MatchPattern.from_string ("1deadbeef1"),
				10, null);
			assert_true (exact.size == 1);
			assert_true (exact[0] == ARENA_VA + FIRST_NEEDLE_OFFSET);

			// The wildcard must match the byte that is different in the two patterns, and the mask must
			// cover only its high nibble.
			var wildcard = yield machine.scan_ranges (ranges,
				new Barebone.MatchPattern.from_string ("1dea??eef1"), 10, null);
			assert_true (wildcard.size == 2);
			assert_true (wildcard[0] == ARENA_VA + FIRST_NEEDLE_OFFSET);
			assert_true (wildcard[1] == ARENA_VA + SECOND_NEEDLE_OFFSET);

			var masked = yield machine.scan_ranges (ranges,
				new Barebone.MatchPattern.from_string ("1dead0eef1:fffff0ffff"), 10, null);
			assert_true (masked.size == 2);

			var capped = yield machine.scan_ranges (ranges,
				new Barebone.MatchPattern.from_string ("1dea??eef1"), 1, null);
			assert_true (capped.size == 1);

			var missing = yield machine.scan_ranges (ranges,
				new Barebone.MatchPattern.from_string ("0badc0ffee"), 10, null);
			assert_true (missing.is_empty);
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n\n", e.message);
			assert_not_reached ();
		} finally {
			target.stop ();
		}

		h.done ();
	}

	private static Bytes arena_with_needles () {
		var arena = new uint8[ARENA_SIZE];

		uint8[] first = { 0x1d, 0xea, 0xdb, 0xee, 0xf1 };
		uint8[] second = { 0x1d, 0xea, 0xd0, 0xee, 0xf1 };
		for (uint i = 0; i != first.length; i++) {
			arena[FIRST_NEEDLE_OFFSET + i] = first[i];
			arena[SECOND_NEEDLE_OFFSET + i] = second[i];
		}

		return new Bytes.take ((owned) arena);
	}

	private static async void services_resolve_from_descriptor_block (Harness h) {
		var target = new FakeTarget (IA32, arena_page_tables (), LEGACY_MONITOR_DUMP);
		try {
			target.map_virtual (ARENA_VA, arena_with_vmm_block ());
			yield target.open ();
			var machine = new Barebone.IA32Machine (target.client);

			var layout = yield Barebone.collect_win9x_layout (machine, null);

			var symbols = layout.symbols;
			assert_true (symbols.size == IMPLEMENTED_SERVICES);
			assert_symbol (symbols[0], "Get_VMM_Version", (uint32) 0xc0001000);
			assert_symbol (symbols[1], "Get_Cur_VM_Handle", (uint32) 0xc0001010);
			assert_symbol (symbols[2], "Get_Sys_VM_Handle", (uint32) 0xc0001030);
			assert_symbol (symbols[6], "Begin_Reentrant_Execution", (uint32) 0xc0001070);

			assert_true (layout.modules.size == 1);
			var vmm = layout.modules[0];
			assert_true (vmm.name == "VMM.VXD");
			assert_true (vmm.offset == 0xc0001000);
			assert_true (vmm.size == 0xc0001070 - 0xc0001000);
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n\n", e.message);
			assert_not_reached ();
		} finally {
			target.stop ();
		}

		h.done ();
	}

	private static async void enumerates_processes_in_live_guest (Harness h) {
		var config = win9x_config_from_environment (h);
		if (config == null)
			return;

		var manager = new DeviceManager ();
		try {
			var device = yield manager.add_barebone_device (config, null);
			var options = new ProcessQueryOptions ();
			options.scope = FULL;
			var processes = yield device.enumerate_processes (options, null);

			Process? shell = null;
			for (int i = 0; i != processes.size (); i++) {
				if (processes.get (i).name.down () == "explorer.exe")
					shell = processes.get (i);
			}
			assert_nonnull (shell);

			// An unobfuscated id would still be the process database pointer, which lives in
			// the shared arena.
			assert_true (shell.pid < 0x80000000 || shell.pid >= 0x83000000);

			for (int i = 0; i != processes.size (); i++)
				assert_true (processes.get (i).name != "");

			assert_true (shell.parameters["path"].get_string ().has_suffix ("EXPLORER.EXE"));

			var argv = shell.parameters["argv"];
			assert_nonnull (argv);
			assert_true (argv.n_children () == 1);
			assert_true (argv.get_child_value (0).get_string ().down ().has_suffix ("explorer.exe"));

			var icons = shell.parameters["icons"];
			assert_nonnull (icons);
			assert_true (icons.n_children () != 0);

			var icon = icons.get_child_value (0);
			assert_true (icon.lookup_value ("format", VariantType.STRING).get_string () == "rgba");
			uint16 width = icon.lookup_value ("width", VariantType.UINT16).get_uint16 ();
			uint16 height = icon.lookup_value ("height", VariantType.UINT16).get_uint16 ();
			assert_true (width != 0 && height != 0);
			assert_true (icon.lookup_value ("image", new VariantType ("ay")).get_size () == width * height * 4);

			// The image gives each size one time, at its best color depth.
			var seen = new Gee.HashSet<uint32> ();
			for (size_t i = 0; i != icons.n_children (); i++) {
				var one = icons.get_child_value (i);
				uint32 shape = ((uint32) one.lookup_value ("width", VariantType.UINT16).get_uint16 () << 16)
					| one.lookup_value ("height", VariantType.UINT16).get_uint16 ();
				assert_false (seen.contains (shape));
				seen.add (shape);
			}
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n\n", e.message);
			assert_not_reached ();
		} finally {
			try {
				yield manager.close (null);
			} catch (GLib.Error e) {
			}
		}

		h.done ();
	}

	private static async void injects_into_process_in_live_guest (Harness h) {
		var config = win9x_config_from_environment (h);
		if (config == null)
			return;

		var manager = new DeviceManager ();
		try {
			var device = yield manager.add_barebone_device (config, null);

			var processes = yield device.enumerate_processes (null, null);
			uint pid = 0;
			for (int i = 0; i != processes.size (); i++) {
				if (processes.get (i).name.down () == "explorer.exe")
					pid = processes.get (i).pid;
			}
			assert_true (pid != 0);

			// Success shows that the injected agent started and reported this process.
			var session = yield device.attach (pid, null, null);
			assert_nonnull (session);

			// The script runs in the target process, thus Process.id gives the id of the target.
			var script = yield session.create_script ("""
				recv('ping', () => { send(Process.id >>> 0); });
				send('ready');
			""", null, null);

			var messages = new Gee.ArrayList<string> ();
			script.message.connect ((json, data) => {
				messages.add (json);
			});
			yield script.load (null);
			while (messages.size < 1)
				yield h.process_events ();
			assert_true (messages[0].contains ("ready"));

			// The script answers only if the message arrives, thus this tests the reverse direction.
			script.post ("""{"type":"ping"}""");
			while (messages.size < 2)
				yield h.process_events ();
			assert_true (messages[1].contains (pid.to_string ()));

			try {
				yield device.attach (pid ^ 0x1234, null, null);
				assert_not_reached ();
			} catch (GLib.Error e) {
			}

		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n\n", e.message);
			assert_not_reached ();
		} finally {
			try {
				yield manager.close (null);
			} catch (GLib.Error e) {
			}
		}

		h.done ();
	}

	private static async void agent_runs_in_live_guest (Harness h) {
		yield run_script_in_live_guest (h, win9x_config_from_environment (h), "send(1 + 1);", "\"payload\":2");
	}

	// This test injects nothing. The agent is 32-bit, and the test examines only the host, which
	// must read a kernel of twice the width.
	private static async void winnt_maps_out_a_64_bit_kernel_in_live_guest (Harness h) {
		string? port = Environment.get_variable ("FRIDA_TEST_WINNT64_GDB_PORT");
		if (port == null) {
			h.done ();
			return;
		}

		try {
			var client = new SocketClient ();
			var connection = yield client.connect_to_host_async ("127.0.0.1", (uint16) uint.parse (port), null);
			var gdb = yield GDB.Client.open (connection, null);
			assert_true (gdb.pointer_size == 8);

			var machine = new Barebone.X64Machine (gdb);
			var layout = yield Barebone.collect_winnt_layout (machine, null);

			Barebone.ModuleInfo? kernel = null;
			foreach (var m in layout.modules) {
				if (m.name.down () == "ntoskrnl.exe")
					kernel = m;
			}
			assert_nonnull (kernel);

			// All of these addresses are above the limit of a 32-bit kernel.
			assert_true (kernel.offset > uint32.MAX);
			assert_true (layout.modules.size > 20);

			bool named = false;
			bool wide = true;
			foreach (var sym in layout.symbols) {
				if (sym.name == "ExAllocatePoolWithTag")
					named = true;
				if (sym.offset <= uint32.MAX)
					wide = false;
			}
			assert_true (named);
			assert_true (wide);

			yield gdb.close (null);
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n\n", e.message);
			assert_not_reached ();
		}

		h.done ();
	}

	private static async void winnt_agent_runs_in_live_guest (Harness h, string prefix) {
		yield run_script_in_live_guest (h, winnt_config_from_environment (h, prefix), "send(1 + 1);", "\"payload\":2");
	}

	private static async void winnt_enumerates_modules_in_live_guest (Harness h, string prefix) {
		yield run_script_in_live_guest (h, winnt_config_from_environment (h, prefix), """
			const mods = Process.enumerateModules();
			const kernel = mods.find(m => m.name === 'ntoskrnl.exe');
			const named = kernel.enumerateExports().some(e => e.name === 'ExAllocatePoolWithTag');
			const hal = mods.some(m => m.name === 'hal.dll');
			const drivers = mods.some(m => m.name === 'atapi.sys');
			send({ named, hal, drivers });
		""", "\"named\":true,\"hal\":true,\"drivers\":true");
	}

	private static async void winnt_enumerates_processes_in_live_guest (Harness h, string prefix) {
		var config = winnt_config_from_environment (h, prefix);
		if (config == null)
			return;

		var manager = new DeviceManager ();
		try {
			var device = yield manager.add_barebone_device (config, null);
			var options = new ProcessQueryOptions ();
			options.scope = FULL;
			var processes = yield device.enumerate_processes (options, null);

			Process? shell = null;
			Process? system = null;
			for (int i = 0; i != processes.size (); i++) {
				string name = processes.get (i).name.down ();
				if (name == "explorer.exe")
					shell = processes.get (i);
				else if (name == "system")
					system = processes.get (i);
			}
			assert_nonnull (shell);
			assert_nonnull (system);

			// Each of these is an id from the handle table, but the idle process is different.
			assert_true (system.pid == 4);
			assert_true (shell.pid > 4);

			for (int i = 0; i != processes.size (); i++)
				assert_true (processes.get (i).name != "");

			// A process gives its path and its command line. The processes of the kernel have neither.
			assert_true (shell.parameters["path"].get_string ().down ().has_suffix ("explorer.exe"));

			var argv = shell.parameters["argv"];
			assert_nonnull (argv);
			assert_true (argv.n_children () >= 1);

			var icons = shell.parameters["icons"];
			assert_nonnull (icons);
			assert_true (icons.n_children () != 0);

			var icon = icons.get_child_value (0);
			assert_true (icon.lookup_value ("format", VariantType.STRING).get_string () == "rgba");
			uint16 width = icon.lookup_value ("width", VariantType.UINT16).get_uint16 ();
			uint16 height = icon.lookup_value ("height", VariantType.UINT16).get_uint16 ();
			assert_true (width != 0 && height != 0);
			assert_true (icon.lookup_value ("image", new VariantType ("ay")).get_size () == width * height * 4);

			// This icon is drawn for 32 bits, thus its edges and its shadow are partly transparent. A
			// one-bit mask gives only full transparency or none.
			var pixels = icon.lookup_value ("image", new VariantType ("ay"));
			unowned uint8[] rgba = (uint8[]) pixels.get_data ();
			rgba.length = (int) pixels.get_size ();
			uint partly = 0;
			for (int i = 3; i < rgba.length; i += 4) {
				if (rgba[i] != 0 && rgba[i] != 255)
					partly++;
			}
			assert_true (partly != 0);

			// The image gives each size one time, at its best color depth.
			var seen = new Gee.HashSet<uint32> ();
			for (size_t i = 0; i != icons.n_children (); i++) {
				var one = icons.get_child_value (i);
				uint32 shape = ((uint32) one.lookup_value ("width", VariantType.UINT16).get_uint16 () << 16)
					| one.lookup_value ("height", VariantType.UINT16).get_uint16 ();
				assert_false (seen.contains (shape));
				seen.add (shape);
			}
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n\n", e.message);
			assert_not_reached ();
		} finally {
			try {
				yield manager.close (null);
			} catch (GLib.Error e) {
			}
		}

		h.done ();
	}

	private static async void winnt_resolves_symbols_in_live_guest (Harness h, string prefix) {
		yield run_script_in_live_guest (h, winnt_config_from_environment (h, prefix), """
			const alloc = Module.getGlobalExportByName('ExAllocatePoolWithTag');

			const exact = DebugSymbol.fromAddress(alloc);
			const inside = DebugSymbol.fromAddress(alloc.add(4));
			const byName = DebugSymbol.getFunctionByName('ExFreePoolWithTag');
			const matching = DebugSymbol.findFunctionsMatching('ExAllocatePool*');

			send({
				named: exact.name === 'ExAllocatePoolWithTag',
				module: exact.moduleName === 'ntoskrnl.exe',
				closest: inside.name === 'ExAllocatePoolWithTag',
				byName: !byName.isNull(),
				matching: matching.length > 0
			});
		""", "\"named\":true,\"module\":true,\"closest\":true,\"byName\":true,\"matching\":true");
	}

	private static async void winnt_enumerates_ranges_in_live_guest (Harness h, string prefix) {
		yield run_script_in_live_guest (h, winnt_config_from_environment (h, prefix), """
			const kernel = Process.enumerateModules().find(m => m.name === 'ntoskrnl.exe');
			const ranges = Process.enumerateRanges('r--');

			const covering = ranges.find(r => r.base.compare(kernel.base) <= 0 &&
				r.base.add(r.size).compare(kernel.base) > 0);
			const kernelSpace = ranges.every(r => r.base.compare(ptr('0x80000000')) >= 0);
			const sorted = ranges.every((r, i) =>
				i === 0 || ranges[i - 1].base.add(ranges[i - 1].size).compare(r.base) <= 0);

			send({
				found: ranges.length > 1,
				covering: covering !== undefined,
				kernelSpace: kernelSpace,
				sorted: sorted,
				executable: covering.protection.indexOf('x') !== -1
			});
		""", "\"found\":true,\"covering\":true,\"kernelSpace\":true,\"sorted\":true,\"executable\":true");
	}

	private static async void winnt_enumerates_threads_in_live_guest (Harness h, string prefix) {
		yield run_script_in_live_guest (h, winnt_config_from_environment (h, prefix), """
			const threads = Process.enumerateThreads();
			const mine = Process.getCurrentThreadId();

			// The kernel gives the registers of a thread only if the thread has a user-mode part. Thus
			// the threads that run only in the kernel give none.
			const pc = (Process.pointerSize === 4) ? 'eip' : 'rip';
			const sp = (Process.pointerSize === 4) ? 'esp' : 'rsp';
			const contextual = threads.filter(t => t.context !== undefined);

			send({
				several: threads.length > 10,
				listed: threads.some(t => t.id === mine),
				distinct: new Set(threads.map(t => t.id)).size === threads.length,
				reported: contextual.length > 0,
				quiet: contextual.length < threads.length,
				somewhere: contextual.every(t => !t.context[pc].isNull() && !t.context[sp].isNull()),
				apart: new Set(contextual.map(t => t.context[sp].toString())).size > 1
			});
		""", "\"several\":true,\"listed\":true,\"distinct\":true," +
			"\"reported\":true,\"quiet\":true,\"somewhere\":true,\"apart\":true");
	}

	private static async void winnt_reads_and_writes_memory_in_live_guest (Harness h, string prefix) {
		yield run_script_in_live_guest (h, winnt_config_from_environment (h, prefix), """
			const kernel = Process.enumerateModules().find(m => m.name === 'ntoskrnl.exe');
			const header = new Uint8Array(kernel.base.readByteArray(2));

			const scratch = Memory.alloc(8);
			scratch.writeByteArray([1, 2, 3, 4]);
			const written = new Uint8Array(scratch.readByteArray(4));

			let missing = 'no';
			try {
				if (ptr('0xfffff000').readByteArray(16) === null)
					missing = 'yes';
			} catch (e) {
				missing = 'yes';
			}

			send({
				mz: header[0] === 0x4d && header[1] === 0x5a,
				roundtrip: written[0] === 1 && written[3] === 4,
				missing: missing
			});
		""", "\"mz\":true,\"roundtrip\":true,\"missing\":\"yes\"");
	}

	// RtlUpperChar has no side effects and the kernel almost never calls it. Thus the hook sees
	// only the calls from this test.
	private static async void winnt_hooks_kernel_function_in_live_guest (Harness h, string prefix) {
		yield run_script_in_live_guest (h, winnt_config_from_environment (h, prefix), """
			const kernel = Process.enumerateModules().find(m => m.name === 'ntoskrnl.exe');
			const upper = kernel.enumerateExports().find(e => e.name === 'RtlUpperChar').address;

			let seen = null;
			Interceptor.attach(upper, {
				onEnter(args) {
					seen = args[0].toInt32();
				}
			});
			Interceptor.flush();

			const abi = (Process.pointerSize === 4) ? 'stdcall' : 'win64';
			const call = new NativeFunction(upper, 'uint8', ['uint8'], { abi });
			const result = call(0x61);
			send({ seen: seen, result: result });
		""", "\"seen\":97,\"result\":65");
	}

	// The compiler backend and the kernel must agree about the position of the arguments. This
	// answer is different for each word size.
	private static async void winnt_compiles_c_calling_kernel_in_live_guest (Harness h, string prefix) {
		yield run_script_in_live_guest (h, winnt_config_from_environment (h, prefix), """
			const kernel = Process.enumerateModules().find(m => m.name === 'ntoskrnl.exe');
			const upper = kernel.enumerateExports().find(e => e.name === 'RtlUpperChar').address;

			const convention = (Process.pointerSize === 4) ? '__attribute__((stdcall))' : '';
			const cm = new CModule(`
				extern unsigned char ${convention} RtlUpperChar (unsigned char c);

				unsigned char
				shout (unsigned char c)
				{
				  return RtlUpperChar (c);
				}
			`, { RtlUpperChar: upper });

			const shout = new NativeFunction(cm.shout, 'uint8', ['uint8']);
			send({ result: shout(0x62) });
		""", "\"result\":66");
	}

	private static async void winnt_agent_recovers_from_exception_in_live_guest (Harness h, string prefix) {
		yield run_script_in_live_guest (h, winnt_config_from_environment (h, prefix), """
			let caught = 'no';
			try {
				ptr('0xfffff000').readU32();
			} catch (e) {
				caught = 'yes';
			}
			send({ caught: caught });
		""", "\"caught\":\"yes\"");
	}

	// Two sessions on one process use the same copy. Thus one session can detach and the other
	// keeps a working agent and its own scripts.
	private static async void shares_one_agent_between_sessions_in_live_guest (Harness h) {
		var config = win9x_config_from_environment (h);
		if (config == null)
			return;

		var manager = new DeviceManager ();
		try {
			var device = yield manager.add_barebone_device (config, null);

			uint pid = yield find_explorer (device);

			var first = yield device.attach (pid, null, null);
			var second = yield device.attach (pid, null, null);

			var survivor = yield second.create_script ("recv('ping', () => { send('alive'); });", null, null);
			var messages = new Gee.ArrayList<string> ();
			survivor.message.connect ((json, data) => {
				messages.add (json);
			});
			yield survivor.load (null);

			var doomed = yield first.create_script ("send('doomed');", null, null);
			yield doomed.load (null);
			yield first.detach (null);

			// The copy stays for the session that is still attached.
			survivor.post ("""{"type":"ping"}""");
			while (messages.size < 1)
				yield h.process_events ();
			assert_true (messages[0].contains ("alive"));

			yield second.detach (null);

			// No session is attached now, thus the next attach places a new copy.
			var again = yield device.attach (pid, null, null);
			assert_nonnull (again);
			yield again.detach (null);
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n\n", e.message);
			assert_not_reached ();
		} finally {
			try {
				yield manager.close (null);
			} catch (GLib.Error e) {
			}
		}

		h.done ();
	}

	private static async uint find_explorer (Device device) throws GLib.Error {
		var processes = yield device.enumerate_processes (null, null);
		for (int i = 0; i != processes.size (); i++) {
			if (processes.get (i).name.down () == "explorer.exe")
				return processes.get (i).pid;
		}
		return 0;
	}

	private static async void enumerates_threads_in_live_guest (Harness h) {
		yield run_script_in_live_guest (h, win9x_config_from_environment (h), """
			const threads = Process.enumerateThreads();
			const mine = Process.getCurrentThreadId();
			const contextual = threads.filter(t => t.context !== undefined);
			const distinct = new Set(contextual.map(t => t.context.esp.toString())).size > 1;
			send({
				several: threads.length > 1,
				listed: threads.some(t => t.id === mine),
				contextual: contextual.length > 1,
				distinct
			});
		""", "\"several\":true,\"listed\":true,\"contextual\":true,\"distinct\":true");
	}

	private static async void win9x_enumerates_ranges_in_live_guest (Harness h) {
		yield run_script_in_live_guest (h, win9x_config_from_environment (h), """
			const vmm = Process.enumerateModules().find(m => m.name === 'VMM.VXD');
			const ranges = Process.enumerateRanges('r--');

			const covering = ranges.find(r => r.base.compare(vmm.base) <= 0 &&
				r.base.add(r.size).compare(vmm.base) > 0);
			const arena = ranges.every(r => r.base.compare(ptr('0xc0000000')) >= 0);

			send({ found: ranges.length > 1, covering: covering !== undefined, arena: arena });
		""", "\"found\":true,\"covering\":true,\"arena\":true");
	}

	private static async void enumerates_modules_in_live_guest (Harness h) {
		yield run_script_in_live_guest (h, win9x_config_from_environment (h), """
			const mods = Process.enumerateModules();
			const vmm = mods.find(m => m.name === 'VMM.VXD');
			const named = vmm.enumerateExports().some(e => e.name === 'Get_Sys_VM_Handle');
			const serviceless = mods.some(m => m.name === 'VFAT.VXD');
			const mixedCase = mods.some(m => m.name === 'VNetSup.VXD');
			send({ named, serviceless, mixedCase });
		""", "\"named\":true,\"serviceless\":true,\"mixedCase\":true");
	}

	private static async void agent_recovers_from_exception_in_live_guest (Harness h) {
		yield run_script_in_live_guest (h, win9x_config_from_environment (h), """
			let caught = 'no';
			try {
				ptr('0xfffff000').readU32();
			} catch (e) {
				caught = 'yes';
			}
			send({ caught: caught });
		""", "\"caught\":\"yes\"");
	}

	private static Barebone.Config? win9x_config_from_environment (Harness h) {
		string? agent_path = Environment.get_variable ("FRIDA_TEST_WIN9X_AGENT");
		string? qmp_path = Environment.get_variable ("FRIDA_TEST_WIN9X_QMP");
		string? stub_port = Environment.get_variable ("FRIDA_TEST_WIN9X_GDB_PORT");
		if (agent_path == null || qmp_path == null || stub_port == null) {
			h.done ();
			return null;
		}

		var config = new Barebone.Config ();
		config.connection.host = "127.0.0.1";
		config.connection.port = (uint16) uint.parse (stub_port);
		config.kernel = WIN9X;
		config.agent = new Barebone.AgentConfig () {
			path = agent_path,
			transport = new Barebone.HostlinkTransportConfig () {
				qmp = "unix:" + qmp_path,
				bus = Environment.get_variable ("FRIDA_TEST_WIN9X_BUS"),
			},
		};

		return config;
	}

	// The same guest is described the same way whatever its word size, so the two differ only in
	// which set of variables names it.
	private static Barebone.Config? winnt_config_from_environment (Harness h, string prefix) {
		string? agent_path = Environment.get_variable (@"FRIDA_TEST_$(prefix)_AGENT");
		string? qmp_path = Environment.get_variable (@"FRIDA_TEST_$(prefix)_QMP");
		string? stub_port = Environment.get_variable (@"FRIDA_TEST_$(prefix)_GDB_PORT");
		if (agent_path == null || qmp_path == null || stub_port == null) {
			h.done ();
			return null;
		}

		var config = new Barebone.Config ();
		config.connection.host = "127.0.0.1";
		config.connection.port = (uint16) uint.parse (stub_port);
		config.kernel = WINNT;
		config.agent = new Barebone.AgentConfig () {
			path = agent_path,
			transport = new Barebone.HostlinkTransportConfig () {
				qmp = "unix:" + qmp_path,
				bus = Environment.get_variable (@"FRIDA_TEST_$(prefix)_BUS"),
			},
		};

		return config;
	}

	private static async void run_script_in_live_guest (Harness h, Barebone.Config? config, string source,
			string expected) {
		if (config == null)
			return;

		var manager = new DeviceManager ();
		try {
			var device = yield manager.add_barebone_device (config, null);
			var session = yield device.attach (0, null, null);
			var script = yield session.create_script (source, null, null);

			string? received = null;
			script.message.connect ((json, data) => {
				received = json;
				run_script_in_live_guest.callback ();
			});
			yield script.load (null);
			if (received == null)
				yield;

			if (!received.contains (expected))
				printerr ("\nexpected %s in: %s\n", expected, received);
			assert_true (received.contains (expected));

			yield session.detach (null);
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n\n", e.message);
			assert_not_reached ();
		} finally {
			try {
				yield manager.close (null);
			} catch (GLib.Error e) {
			}
		}

		h.done ();
	}

	private static async void modules_resolve_from_loaded_module_list (Harness h) {
		var target = new FakeTarget (IA32, new Ram ().steal (), LEGACY_MONITOR_DUMP);
		try {
			target.map_virtual (PCR_VA, pcr_page ());
			target.map_virtual (NT_STRUCTS_VA, nt_kernel_structs ());
			target.map_virtual (NT_KERNEL_VA, nt_kernel_image ());
			target.map_virtual (NT_HAL_VA, nt_hal_image ());
			yield target.open ();
			var machine = new Barebone.IA32Machine (target.client);

			var layout = yield Barebone.collect_winnt_layout (machine, null);

			var modules = layout.modules;
			assert_true (modules.size == 2);
			assert_true (modules[0].name == "ntoskrnl.exe");
			assert_true (modules[0].offset == NT_KERNEL_VA);
			assert_true (modules[0].size == NT_IMAGE_SIZE);
			assert_true (modules[1].name == "hal.dll");
			assert_true (modules[1].offset == NT_HAL_VA);

			// The forwarded export is skipped, and the module without an export directory
			// contributes nothing.
			var symbols = layout.symbols;
			assert_true (symbols.size == 1);
			assert_symbol (symbols[0], "NtWaitForSingleObject", (uint32) (NT_KERNEL_VA + NT_WAIT_RVA));
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n\n", e.message);
			assert_not_reached ();
		} finally {
			target.stop ();
		}

		h.done ();
	}

	private static void assert_argument (Barebone.CallArgument argument, Barebone.CallArgumentRole role,
			uint64 value) {
		assert_true (argument.role == role);
		assert_true (argument.value == value);
	}

	private static void assert_symbol (Barebone.SymbolInfo symbol, string name, uint32 address) {
		assert_true (symbol.name == name);
		assert_true (symbol.offset == address);
	}

	private const size_t FIRST_NEEDLE_OFFSET = 0x40;
	private const size_t SECOND_NEEDLE_OFFSET = 0x1c0;
	private const uint64 ARENA_VA = 0xc0000000;
	private const uint64 ARENA_PA = 0x3000;
	private const size_t ARENA_SIZE = 0x1000;

	private const size_t SERVICE_TABLE_OFFSET = 0x100;
	private const size_t VMM_BLOCK_OFFSET = 0x200;
	private const size_t DECOY_BLOCK_OFFSET = 0x300;

	private const uint32 UNIMPLEMENTED_SERVICE = 0;
	private const uint32 SERVICE_TABLE_OUTSIDE_ARENA = 0x00001000;
	private const int IMPLEMENTED_SERVICES = 7;

	private static uint8[] arena_page_tables () {
		var ram = new Ram ();

		ram.write_uint32 (PD_PA + ((ARENA_VA >> 22) * 4), (uint32) PT_PA | 0x3);
		ram.write_uint32 (PT_PA + (0 * 4), (uint32) ARENA_PA | 0x3);

		return ram.steal ();
	}

	private static Bytes arena_with_vmm_block () {
		var arena = new uint8[ARENA_SIZE];

		uint32[] services = { (uint32) 0xc0001000, (uint32) 0xc0001010, UNIMPLEMENTED_SERVICE,
			(uint32) 0xc0001030, (uint32) 0xc0001040, (uint32) 0xc0001050, (uint32) 0xc0001060,
			(uint32) 0xc0001070 };
		for (uint i = 0; i != services.length; i++)
			put_uint32 (arena, SERVICE_TABLE_OFFSET + (i * 4), services[i]);

		put_descriptor_block (arena, VMM_BLOCK_OFFSET, "VMM     ", (uint32) (ARENA_VA + SERVICE_TABLE_OFFSET),
			services.length);
		put_descriptor_block (arena, DECOY_BLOCK_OFFSET, "VCACHE  ", SERVICE_TABLE_OUTSIDE_ARENA,
			services.length);

		return new Bytes.take ((owned) arena);
	}

	private static void put_descriptor_block (uint8[] arena, size_t offset, string name, uint32 service_table,
			uint service_count) {
		for (uint i = 0; i != name.length; i++)
			arena[offset + 0x0c + i] = (uint8) name[i];
		put_uint32 (arena, offset + 0x18, (uint32) ARENA_VA);
		put_uint32 (arena, offset + 0x30, service_table);
		put_uint32 (arena, offset + 0x34, service_count);
	}

	private static void put_uint32 (uint8[] buf, size_t offset, uint32 val) {
		for (uint i = 0; i != 4; i++)
			buf[offset + i] = (uint8) (val >> (i * 8));
	}

	private static void put_uint16 (uint8[] buf, size_t offset, uint16 val) {
		for (uint i = 0; i != 2; i++)
			buf[offset + i] = (uint8) (val >> (i * 8));
	}

	private static void put_utf16 (uint8[] buf, size_t offset, string text) {
		for (uint i = 0; i != text.length; i++)
			put_uint16 (buf, offset + (i * 2), (uint16) text[i]);
	}

	private static void put_ascii (uint8[] buf, size_t offset, string text) {
		for (uint i = 0; i != text.length; i++)
			buf[offset + i] = (uint8) text[i];
	}

	private const uint64 PCR_VA = 0xffdff000;
	private const uint64 NT_STRUCTS_VA = 0x80500000;
	private const uint64 NT_KERNEL_VA = 0x80400000;
	private const uint64 NT_HAL_VA = 0x80410000;
	private const size_t NT_PAGE_SIZE = 0x1000;

	private const size_t VERSION_BLOCK_OFFSET = 0x000;
	private const size_t MODULE_LIST_OFFSET = 0x100;
	private const size_t KERNEL_ENTRY_OFFSET = 0x200;
	private const size_t HAL_ENTRY_OFFSET = 0x280;
	private const size_t KERNEL_NAME_OFFSET = 0x300;
	private const size_t HAL_NAME_OFFSET = 0x340;

	private const uint32 NT_IMAGE_SIZE = 0x200000;
	private const uint32 NT_WAIT_RVA = 0x1000;
	private const size_t PE_HEADERS_OFFSET = 0xc0;
	private const uint32 EXPORT_DIRECTORY_RVA = 0x400;
	private const uint32 EXPORT_DIRECTORY_SIZE = 0x100;
	private const uint32 FORWARDED_EXPORT_RVA = 0x420;
	private const uint32 FUNCTION_TABLE_RVA = 0x430;
	private const uint32 NAME_TABLE_RVA = 0x440;
	private const uint32 ORDINAL_TABLE_RVA = 0x450;
	private const uint32 WAIT_NAME_RVA = 0x460;
	private const uint32 FORWARDED_NAME_RVA = 0x480;

	private static Bytes pcr_page () {
		var page = new uint8[NT_PAGE_SIZE];

		put_uint32 (page, 0x1c, (uint32) PCR_VA);
		put_uint32 (page, 0x34, (uint32) (NT_STRUCTS_VA + VERSION_BLOCK_OFFSET));

		return new Bytes.take ((owned) page);
	}

	private static Bytes nt_kernel_structs () {
		var structs = new uint8[NT_PAGE_SIZE];

		put_uint16 (structs, VERSION_BLOCK_OFFSET + 0x08, 0x014c);
		put_uint32 (structs, VERSION_BLOCK_OFFSET + 0x10, (uint32) NT_KERNEL_VA);
		put_uint32 (structs, VERSION_BLOCK_OFFSET + 0x18, (uint32) (NT_STRUCTS_VA + MODULE_LIST_OFFSET));

		put_uint32 (structs, MODULE_LIST_OFFSET, (uint32) (NT_STRUCTS_VA + KERNEL_ENTRY_OFFSET));

		put_table_entry (structs, KERNEL_ENTRY_OFFSET, NT_STRUCTS_VA + HAL_ENTRY_OFFSET, NT_KERNEL_VA,
			NT_IMAGE_SIZE, NT_STRUCTS_VA + KERNEL_NAME_OFFSET, "ntoskrnl.exe");
		put_table_entry (structs, HAL_ENTRY_OFFSET, NT_STRUCTS_VA + MODULE_LIST_OFFSET, NT_HAL_VA,
			0x20000, NT_STRUCTS_VA + HAL_NAME_OFFSET, "hal.dll");

		put_utf16 (structs, KERNEL_NAME_OFFSET, "ntoskrnl.exe");
		put_utf16 (structs, HAL_NAME_OFFSET, "hal.dll");

		return new Bytes.take ((owned) structs);
	}

	private static void put_table_entry (uint8[] structs, size_t offset, uint64 next, uint64 dll_base, uint32 size,
			uint64 name_buffer, string name) {
		put_uint32 (structs, offset + 0x00, (uint32) next);
		put_uint32 (structs, offset + 0x18, (uint32) dll_base);
		put_uint32 (structs, offset + 0x20, size);
		put_uint16 (structs, offset + 0x2c, (uint16) (name.length * 2));
		put_uint16 (structs, offset + 0x2e, (uint16) (name.length * 2));
		put_uint32 (structs, offset + 0x30, (uint32) name_buffer);
	}

	private static Bytes nt_kernel_image () {
		var image = new uint8[NT_PAGE_SIZE];

		put_pe_headers (image, EXPORT_DIRECTORY_RVA, EXPORT_DIRECTORY_SIZE);

		put_uint32 (image, EXPORT_DIRECTORY_RVA + 0x18, 2);
		put_uint32 (image, EXPORT_DIRECTORY_RVA + 0x1c, FUNCTION_TABLE_RVA);
		put_uint32 (image, EXPORT_DIRECTORY_RVA + 0x20, NAME_TABLE_RVA);
		put_uint32 (image, EXPORT_DIRECTORY_RVA + 0x24, ORDINAL_TABLE_RVA);

		put_uint32 (image, FUNCTION_TABLE_RVA, NT_WAIT_RVA);
		put_uint32 (image, FUNCTION_TABLE_RVA + 4, FORWARDED_EXPORT_RVA);
		put_uint32 (image, NAME_TABLE_RVA, WAIT_NAME_RVA);
		put_uint32 (image, NAME_TABLE_RVA + 4, FORWARDED_NAME_RVA);
		put_uint16 (image, ORDINAL_TABLE_RVA, 0);
		put_uint16 (image, ORDINAL_TABLE_RVA + 2, 1);
		put_ascii (image, WAIT_NAME_RVA, "NtWaitForSingleObject");
		put_ascii (image, FORWARDED_NAME_RVA, "Forwarded");

		return new Bytes.take ((owned) image);
	}

	private static Bytes nt_hal_image () {
		var image = new uint8[NT_PAGE_SIZE];

		put_pe_headers (image, 0, 0);

		return new Bytes.take ((owned) image);
	}

	private static void put_pe_headers (uint8[] image, uint32 export_directory_rva, uint32 export_directory_size) {
		put_uint16 (image, 0, 0x5a4d);
		put_uint32 (image, 0x3c, (uint32) PE_HEADERS_OFFSET);
		put_uint32 (image, PE_HEADERS_OFFSET, 0x00004550);
		put_uint16 (image, PE_HEADERS_OFFSET + 0x18, 0x010b);
		put_uint32 (image, PE_HEADERS_OFFSET + 0x78, export_directory_rva);
		put_uint32 (image, PE_HEADERS_OFFSET + 0x7c, export_directory_size);
	}

	private static uint8[] legacy_page_tables () {
		var ram = new Ram ();

		ram.write_uint32 (PD_PA + (0 * 4), (uint32) PT_PA | 0x3);
		ram.write_uint32 (PD_PA + (1 * 4), 0x00800081);

		ram.write_uint32 (PT_PA + (0 * 4), 0x00100003);
		ram.write_uint32 (PT_PA + (1 * 4), 0x00101003);
		ram.write_uint32 (PT_PA + (2 * 4), 0x00102001);

		return ram.steal ();
	}

	private const uint64 SPAN_PT0_PA = 0x4000;
	private const uint64 SPAN_PT1_PA = 0x5000;
	private const uint SPAN_ENTRIES_PER_TABLE = 1024;
	private const uint SPAN_FREE_IN_FIRST = 2;

	// Two adjacent leaf tables, the first all but full, so anything longer than what
	// it has left has to carry on into the second.
	private static uint8[] adjacent_leaf_tables () {
		var ram = new Ram ();

		ram.write_uint32 (PD_PA + (0 * 4), (uint32) SPAN_PT0_PA | 0x7);
		ram.write_uint32 (PD_PA + (1 * 4), (uint32) SPAN_PT1_PA | 0x7);

		uint occupied = SPAN_ENTRIES_PER_TABLE - SPAN_FREE_IN_FIRST;
		for (uint i = 0; i != occupied; i++)
			ram.write_uint32 (SPAN_PT0_PA + (i * 4), (uint32) (0x00100000 + (i * 0x1000)) | 0x3);

		return ram.steal ();
	}

	private const uint64 PAE_PDPT_PA = 0x1000;
	private const uint64 PAE_PD_PA = 0x2000;
	private const uint64 PAE_PT_PA = 0x3000;

	private const string PAE_MONITOR_DUMP =
		"CR0=80050033 CR2=00000000 CR3=00001000 CR4=00000020\n" +
		"EFER=0000000000000800\n";

	// Paging on with PAE and NX: 64-bit entries, one of them a 2 MiB page above the 4 GiB line.
	private static uint8[] pae_page_tables () {
		var ram = new Ram ();

		ram.write_uint64 (PAE_PDPT_PA + (0 * 8), PAE_PD_PA | 0x1);

		ram.write_uint64 (PAE_PD_PA + (0 * 8), PAE_PT_PA | 0x3);
		ram.write_uint64 (PAE_PD_PA + (1 * 8), 0x8000000140000081);

		ram.write_uint64 (PAE_PT_PA + (0 * 8), 0x8000000000100003);
		ram.write_uint64 (PAE_PT_PA + (1 * 8), 0x0000000000101003);

		return ram.steal ();
	}

	private const uint64 X64_PML4_PA = 0x1000;
	private const uint64 X64_PDPT_PA = 0x2000;
	private const uint64 X64_PD_PA = 0x3000;
	private const uint64 X64_PT_PA = 0x4000;
	private const uint64 X64_KERNEL_PDPT_PA = 0x5000;

	private const string X64_MONITOR_DUMP =
		"CR0=80050033 CR2=0000000000000000 CR3=0000000000001000 CR4=00000020\n" +
		"EFER=0000000000000d00\n";

	// Long mode with NX: a four-level walk, one 2 MiB page, and a 1 GiB page in the kernel half.
	private static uint8[] long_mode_page_tables () {
		var ram = new Ram ();

		ram.write_uint64 (X64_PML4_PA + (0 * 8), X64_PDPT_PA | 0x3);
		ram.write_uint64 (X64_PML4_PA + (384 * 8), X64_KERNEL_PDPT_PA | 0x3);

		ram.write_uint64 (X64_PDPT_PA + (0 * 8), X64_PD_PA | 0x3);

		ram.write_uint64 (X64_PD_PA + (0 * 8), X64_PT_PA | 0x3);
		ram.write_uint64 (X64_PD_PA + (1 * 8), 0x8000000140000081);

		ram.write_uint64 (X64_PT_PA + (0 * 8), 0x8000000000100003);
		ram.write_uint64 (X64_PT_PA + (1 * 8), 0x0000000000101003);

		ram.write_uint64 (X64_KERNEL_PDPT_PA + (0 * 8), 0x400000e3);

		return ram.steal ();
	}

	private class Ram {
		public const size_t SIZE = 0x6000;

		private uint8[] data = new uint8[SIZE];

		public void write_uint32 (uint64 offset, uint32 val) {
			for (uint i = 0; i != 4; i++)
				data[offset + i] = (uint8) (val >> (i * 8));
		}

		public void write_uint64 (uint64 offset, uint64 val) {
			for (uint i = 0; i != 8; i++)
				data[offset + i] = (uint8) (val >> (i * 8));
		}

		public uint8[] steal () {
			uint8[] result = data;
			data = new uint8[SIZE];
			return result;
		}
	}

	private enum TargetArch {
		IA32,
		X64
	}

	private enum ControlRegisterExposure {
		HIDE_CONTROL_REGISTERS,
		EXPOSE_CONTROL_REGISTERS
	}

	/**
	 * A minimal i386 GDB stub whose entire address space is a flat block of RAM, so that the
	 * machine's "physical" reads land on the page tables we planted.
	 */
	private class FakeTarget : Object {
		public GDB.Client? client {
			get;
			private set;
		}

		private TargetArch arch;
		private uint8[] ram;
		private Gee.List<Region> regions = new Gee.ArrayList<Region> ();
		private string? monitor_dump;
		private ControlRegisterExposure exposure;

		private class Region {
			public uint64 address;
			public Bytes data;
		}

		private SocketService service;
		private Cancellable cancellable = new Cancellable ();

		private const string IA32_CORE_REGISTERS =
			"<reg name=\"eax\" bitsize=\"32\" regnum=\"0\"/>" +
			"<reg name=\"ecx\" bitsize=\"32\" regnum=\"1\"/>" +
			"<reg name=\"edx\" bitsize=\"32\" regnum=\"2\"/>" +
			"<reg name=\"ebx\" bitsize=\"32\" regnum=\"3\"/>" +
			"<reg name=\"esp\" bitsize=\"32\" regnum=\"4\"/>" +
			"<reg name=\"ebp\" bitsize=\"32\" regnum=\"5\"/>" +
			"<reg name=\"esi\" bitsize=\"32\" regnum=\"6\"/>" +
			"<reg name=\"edi\" bitsize=\"32\" regnum=\"7\"/>" +
			"<reg name=\"eip\" bitsize=\"32\" regnum=\"8\"/>" +
			"<reg name=\"eflags\" bitsize=\"32\" regnum=\"9\"/>";

		private const string X64_CORE_REGISTERS =
			"<reg name=\"rax\" bitsize=\"64\" regnum=\"0\"/>" +
			"<reg name=\"rbx\" bitsize=\"64\" regnum=\"1\"/>" +
			"<reg name=\"rcx\" bitsize=\"64\" regnum=\"2\"/>" +
			"<reg name=\"rdx\" bitsize=\"64\" regnum=\"3\"/>" +
			"<reg name=\"rsi\" bitsize=\"64\" regnum=\"4\"/>" +
			"<reg name=\"rdi\" bitsize=\"64\" regnum=\"5\"/>" +
			"<reg name=\"rbp\" bitsize=\"64\" regnum=\"6\"/>" +
			"<reg name=\"rsp\" bitsize=\"64\" regnum=\"7\"/>" +
			"<reg name=\"rip\" bitsize=\"64\" regnum=\"8\"/>";

		private const string CONTROL_REGISTERS =
			"<reg name=\"cr0\" bitsize=\"32\" regnum=\"10\"/>" +
			"<reg name=\"cr3\" bitsize=\"32\" regnum=\"11\"/>" +
			"<reg name=\"cr4\" bitsize=\"32\" regnum=\"12\"/>";

		public FakeTarget (TargetArch arch, owned uint8[] ram, string? monitor_dump,
				ControlRegisterExposure exposure = HIDE_CONTROL_REGISTERS) {
			this.arch = arch;
			this.ram = (owned) ram;
			this.monitor_dump = monitor_dump;
			this.exposure = exposure;
		}

		public async void open () throws Error, IOError {
			service = new SocketService ();
			uint16 port;
			try {
				port = service.add_any_inet_port (null);
			} catch (GLib.Error e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}

			service.incoming.connect ((connection) => {
				serve.begin (connection);
				return true;
			});
			service.start ();

			IOStream stream;
			var socket_client = new SocketClient ();
			try {
				stream = yield socket_client.connect_to_host_async ("127.0.0.1", port, cancellable);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("%s", e.message);
			}

			client = yield GDB.Client.open (stream, cancellable);
		}

		public void stop () {
			cancellable.cancel ();
			if (service != null)
				service.stop ();
		}

		public void map_virtual (uint64 address, Bytes data) {
			regions.add (new Region () {
				address = address,
				data = data,
			});
		}

		public uint32 read_uint32 (uint64 address) {
			uint32 result = 0;
			for (uint i = 0; i != 4; i++)
				result |= ((uint32) ram[address + i]) << (i * 8);
			return result;
		}

		public uint64 read_uint64 (uint64 address) {
			uint64 result = 0;
			for (uint i = 0; i != 8; i++)
				result |= ((uint64) ram[address + i]) << (i * 8);
			return result;
		}

		private async void serve (IOStream connection) {
			var input = connection.get_input_stream ();
			var output = connection.get_output_stream ();
			try {
				string? request;
				while ((request = yield read_packet (input)) != null) {
					yield write_ack (output);
					foreach (string reply in compute_replies (request))
						yield write_packet (output, reply);
				}
			} catch (GLib.Error e) {
			}
		}

		private string[] compute_replies (string request) {
			if (request.has_prefix ("qSupported"))
				return { "PacketSize=1000;qXfer:features:read+" };
			if (request.has_prefix ("qXfer:features:read:target.xml:"))
				return { "l" + target_xml () };
			if (request == "qAttached")
				return { "1" };
			if (request == "?")
				return { "T05thread:1;" };
			if (request == "qC")
				return { "QC1" };
			// A no-op on a flat address space, but the machine insists the stub can do it.
			if (request == "qqemu.PhyMemMode")
				return { "0" };
			if (request.has_prefix ("Qqemu.PhyMemMode:"))
				return { "OK" };
			if (request[0] == 'H')
				return { "OK" };
			if (request[0] == 'p')
				return { read_register (request) };
			if (request[0] == 'm')
				return { read_memory (request) };
			if (request[0] == 'M')
				return { write_memory (request) };
			if (request.has_prefix ("qRcmd,"))
				return run_remote_command (request);
			return { "" };
		}

		private string target_xml () {
			var registers = new StringBuilder ((arch == X64) ? X64_CORE_REGISTERS : IA32_CORE_REGISTERS);
			if (exposure == EXPOSE_CONTROL_REGISTERS)
				registers.append (CONTROL_REGISTERS);

			return "<?xml version=\"1.0\"?>" +
				"<target version=\"1.0\">" +
				"<architecture>" + ((arch == X64) ? "i386:x86-64" : "i386") + "</architecture>" +
				"<feature name=\"org.gnu.gdb.i386.core\">" +
				registers.str +
				"</feature>" +
				"</target>";
		}

		private string read_register (string request) {
			uint regnum = uint.parse (request[1:].split (";")[0], 16);
			uint num_core_registers = (arch == X64) ? 9 : 10;
			size_t width = (arch == X64) ? 8 : 4;

			uint64 val = 0;
			if (regnum >= num_core_registers) {
				if (exposure != EXPOSE_CONTROL_REGISTERS)
					return "E01";

				switch (regnum - num_core_registers) {
					case 0:
						val = 0x8005003b;
						break;
					case 1:
						val = PD_PA;
						break;
					case 2:
						val = 0x00000010;
						break;
					default:
						return "E01";
				}
			}

			var result = new StringBuilder ();
			for (uint i = 0; i != width; i++)
				result.append_printf ("%02x", (uint8) (val >> (i * 8)));
			return result.str;
		}

		private string read_memory (string request) {
			string[] tokens = request[1:].split (",");
			uint64 address = uint64.parse (tokens[0], 16);
			size_t size = (size_t) uint64.parse (tokens[1], 16);

			uint8[]? data = read_span (address, size);
			if (data == null)
				return "E01";

			var result = new StringBuilder ();
			foreach (uint8 b in data)
				result.append_printf ("%02x", b);
			return result.str;
		}

		private uint8[]? read_span (uint64 address, size_t size) {
			foreach (Region r in regions) {
				unowned uint8[] mapped = r.data.get_data ();
				if (address >= r.address && address + size <= r.address + mapped.length) {
					size_t start = (size_t) (address - r.address);
					return mapped[start:start + size];
				}
			}

			if (address + size > ram.length)
				return null;
			return ram[(size_t) address:(size_t) address + size];
		}

		private string write_memory (string request) {
			string[] tokens = request[1:].split (":");
			string[] location = tokens[0].split (",");
			uint64 address = uint64.parse (location[0], 16);
			size_t size = (size_t) uint64.parse (location[1], 16);
			if (address + size > ram.length)
				return "E01";

			unowned string payload = tokens[1];
			for (size_t i = 0; i != size; i++)
				ram[address + i] = (uint8) uint.parse (payload[(long) (i * 2):(long) ((i * 2) + 2)], 16);
			return "OK";
		}

		private string[] run_remote_command (string request) {
			if (monitor_dump == null)
				return { "" };

			var output = new StringBuilder ("O");
			foreach (uint8 byte in monitor_dump.data)
				output.append_printf ("%02x", byte);
			return { output.str, "OK" };
		}

		private async string? read_packet (InputStream input) throws GLib.Error {
			while (true) {
				int c = yield read_byte (input);
				if (c < 0)
					return null;
				if (c != '$')
					continue;

				var payload = new StringBuilder ();
				while (true) {
					c = yield read_byte (input);
					if (c < 0)
						return null;
					if (c == '#')
						break;
					payload.append_c ((char) c);
				}
				yield read_byte (input);
				yield read_byte (input);
				return payload.str;
			}
		}

		private async int read_byte (InputStream input) throws GLib.Error {
			uint8 buf[1];
			size_t n;
			yield input.read_all_async (buf, Priority.DEFAULT, cancellable, out n);
			if (n == 0)
				return -1;
			return buf[0];
		}

		private async void write_ack (OutputStream output) throws GLib.Error {
			yield write_all (output, "+".data);
		}

		private async void write_packet (OutputStream output, string payload) throws GLib.Error {
			uint8 checksum = 0;
			for (int i = 0; i != payload.length; i++)
				checksum += (uint8) payload[i];
			var frame = "$%s#%02x".printf (payload, checksum);
			yield write_all (output, frame.data);
		}

		private async void write_all (OutputStream output, uint8[] data) throws GLib.Error {
			size_t written;
			yield output.write_all_async (data, Priority.DEFAULT, cancellable, out written);
		}
	}

	private static Barebone.RangeDetails? find_range_containing (Gee.List<Barebone.RangeDetails> ranges, uint64 va) {
		int lo = 0;
		int hi = ranges.size - 1;
		while (lo <= hi) {
			int mid = (lo + hi) / 2;
			Barebone.RangeDetails r = ranges[mid];
			if (va < r.base_va)
				hi = mid - 1;
			else if (va >= r.end)
				lo = mid + 1;
			else
				return r;
		}
		return null;
	}

	private static Gee.List<Interval> merge_by_virtual_address (Gee.List<Barebone.RangeDetails> ranges) {
		var result = new Gee.ArrayList<Interval> ();

		foreach (Barebone.RangeDetails r in ranges) {
			if (result.size != 0 && result[result.size - 1].end == r.base_va) {
				result[result.size - 1].end = r.end;
				continue;
			}
			result.add (new Interval (r.base_va, r.end));
		}

		return result;
	}

	private static void assert_intervals_equal (Gee.List<Interval> actual, Gee.List<Interval> expected) {
		assert_true (actual.size == expected.size);
		for (int i = 0; i != actual.size; i++) {
			assert_true (actual[i].start == expected[i].start);
			assert_true (actual[i].end == expected[i].end);
		}
	}

	// A class rather than a struct: the merging below updates entries in place, and a Gee list
	// hands back copies of struct elements.
	private class Interval {
		public uint64 start;
		public uint64 end;

		public Interval (uint64 start, uint64 end) {
			this.start = start;
			this.end = end;
		}
	}

	private enum GuestArch {
		X86,
		X86_64;

		public string to_nick () {
			return (this == X86) ? "x86" : "x86_64";
		}
	}

	private class GuestPage {
		public uint64 va;
		public uint64 pa;
		public bool writable;
		public bool no_execute;
		public bool large;
	}

	/**
	 * A QEMU guest with the GDB stub attached, plus the monitor commands that let us check our
	 * own answers against QEMU's view of the very same tables.
	 */
	private class QemuGuest : Object {
		public GDB.Client client {
			get;
			private set;
		}

		private Subprocess process;
		private Cancellable cancellable = new Cancellable ();

		private const uint CONNECT_TIMEOUT_MSEC = 10000;
		private const uint BOOT_TIMEOUT_SEC = 180;

		public static async string? check_availability (GuestArch arch) {
			try {
				var checker = new Subprocess (SubprocessFlags.STDOUT_SILENCE | SubprocessFlags.STDERR_PIPE,
					"python3", script_path (), "check-" + arch.to_nick ());

				string stderr_buf;
				yield checker.communicate_utf8_async (null, null, null, out stderr_buf);
				if (checker.get_exit_status () == 0)
					return null;

				return (stderr_buf != null) ? stderr_buf.strip () : "unable to prepare the guest";
			} catch (GLib.Error e) {
				return e.message;
			}
		}

		public const uint MEMORY_SIZE_IN_MB = 256;

		public static async QemuGuest? boot (GuestArch arch) throws Error, IOError {
			uint16 port = pick_unused_port ();

			Subprocess process;
			try {
				process = new Subprocess (SubprocessFlags.STDOUT_PIPE,
					"python3", script_path (), "boot-" + arch.to_nick (), "--gdb-port",
					port.to_string (), "--memory", MEMORY_SIZE_IN_MB.to_string ());
			} catch (GLib.Error e) {
				return null;
			}

			var guest = new QemuGuest ();
			guest.process = process;

			if (!yield guest.wait_until_booted ()) {
				guest.stop ();
				return null;
			}

			IOStream? stream = yield guest.connect_to_stub (port);
			if (stream == null) {
				guest.stop ();
				return null;
			}

			// Attaching is what pauses the guest, and it stays paused for the rest of the test.
			guest.client = yield GDB.Client.open (stream, guest.cancellable);

			return guest;
		}

		public void stop () {
			cancellable.cancel ();
			process.force_exit ();
		}

		private async IOStream? connect_to_stub (uint16 port) throws Error, IOError {
			var timer = new Timer ();
			var socket_client = new SocketClient ();

			do {
				try {
					return yield socket_client.connect_to_host_async ("127.0.0.1", port, cancellable);
				} catch (GLib.Error e) {
					if (e is IOError.CANCELLED)
						throw (IOError) e;
				}

				yield sleep (250);
			} while ((uint) (timer.elapsed () * 1000.0) < CONNECT_TIMEOUT_MSEC);

			return null;
		}

		private async bool wait_until_booted () throws IOError {
			var input = new DataInputStream (process.get_stdout_pipe ());

			var timeout_source = new TimeoutSource.seconds (BOOT_TIMEOUT_SEC);
			timeout_source.set_callback (() => {
				cancellable.cancel ();
				return false;
			});
			timeout_source.attach (MainContext.get_thread_default ());

			try {
				string? line = yield input.read_line_async (Priority.DEFAULT, cancellable);
				return line != null && line.strip () == "ready";
			} catch (GLib.Error e) {
				return false;
			} finally {
				timeout_source.destroy ();
			}
		}

		public async Gee.List<Interval> query_mapped_intervals () throws Error, IOError {
			var result = new Gee.ArrayList<Interval> ();

			// E.g.: 0000000000000000-0000800000000000 0000800000000000 -rw
			string dump = yield client.run_remote_command ("info mem", cancellable);
			foreach (string line in dump.split ("\n")) {
				string[] tokens = tokenize (line);
				if (tokens.length != 3)
					continue;

				string[] bounds = tokens[0].split ("-");
				if (bounds.length != 2)
					continue;

				var interval = new Interval (uint64.parse (bounds[0], 16), uint64.parse (bounds[1], 16));

				if (result.size != 0 && result[result.size - 1].end == interval.start) {
					result[result.size - 1].end = interval.end;
					continue;
				}
				result.add (interval);
			}

			return result;
		}

		public async Gee.List<GuestPage> query_pages () throws Error, IOError {
			var result = new Gee.ArrayList<GuestPage> ();

			// E.g.: 00000000d07ea000: 0000000001150000 -G--A----
			string dump = yield client.run_remote_command ("info tlb", cancellable);
			foreach (string line in dump.split ("\n")) {
				string[] tokens = tokenize (line);
				if (tokens.length != 3 || !tokens[0].has_suffix (":"))
					continue;
				unowned string flags = tokens[2];
				if (flags.length != NUM_PAGE_FLAGS)
					continue;

				result.add (new GuestPage () {
					va = uint64.parse (tokens[0][0:-1], 16),
					pa = uint64.parse (tokens[1], 16),
					writable = flags[WRITABLE_FLAG] == 'W',
					no_execute = flags[NO_EXECUTE_FLAG] == 'X',
					large = flags[LARGE_PAGE_FLAG] == 'P'
				});
			}

			return result;
		}

		public async GuestPage query_page (uint64 va) throws Error, IOError {
			foreach (GuestPage page in yield query_pages ()) {
				if (page.va == va)
					return page;
			}

			throw new Error.INVALID_ARGUMENT ("Guest no longer maps 0x%08x", (uint32) va);
		}

		private static string[] tokenize (string text) {
			var result = new Gee.ArrayList<string> ();
			foreach (string token in text.split_set (" \t\r\n")) {
				if (token.length != 0)
					result.add (token);
			}
			return result.to_array ();
		}

		private static string script_path () {
			return Path.build_filename (TESTS_SRCDIR, "vm.py");
		}

		private static uint16 pick_unused_port () throws Error {
			var service = new SocketService ();
			try {
				uint16 port = service.add_any_inet_port (null);
				service.stop ();
				return port;
			} catch (GLib.Error e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
		}

		private async void sleep (uint msec) {
			var source = new TimeoutSource (msec);
			source.set_callback (sleep.callback);
			source.attach (MainContext.get_thread_default ());
			yield;
		}

		private const int NUM_PAGE_FLAGS = 9;
		private const int NO_EXECUTE_FLAG = 0;
		private const int LARGE_PAGE_FLAG = 2;
		private const int WRITABLE_FLAG = 8;
	}

	[CCode (cname = "FRIDA_TESTS_SRCDIR")]
	private extern const string TESTS_SRCDIR;

	private class Harness : Frida.Test.AsyncHarness {
		public Harness (owned Frida.Test.AsyncHarness.TestSequenceFunc func) {
			base ((owned) func);
		}
	}

	// The first run downloads the kernel before it can boot the guest.
	private class SlowHarness : Frida.Test.AsyncHarness {
		public SlowHarness (owned Frida.Test.AsyncHarness.TestSequenceFunc func) {
			base ((owned) func);
		}

		protected override uint provide_timeout () {
			return 900;
		}
	}
}
