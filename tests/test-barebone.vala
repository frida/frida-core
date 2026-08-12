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

		GLib.Test.add_func ("/Barebone/X64/protect-pages-rejects-large-pages", () => {
			var h = new Harness ((h) => x64_protect_pages_rejects_large_pages.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Barebone/IA32/Qemu/walk-matches-guest", () => {
			var h = new SlowHarness ((h) => qemu_walk_matches_guest.begin (h as SlowHarness));
			h.run ();
		});

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

	private static async void x64_protect_pages_rejects_large_pages (Harness h) {
		var target = new FakeTarget (X64, long_mode_page_tables (), X64_MONITOR_DUMP);
		try {
			yield target.open ();
			var machine = new Barebone.X64Machine (target.client);

			try {
				yield machine.protect_pages (0xffffc00000000000, 4096, READ | WRITE, null);
				assert_not_reached ();
			} catch (Error e) {
				assert_true (e is Error.NOT_SUPPORTED);
			}

			assert_true (target.read_uint64 (X64_KERNEL_PDPT_PA + (0 * 8)) == 0x400000e3);
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
	private static async void qemu_walk_matches_guest (SlowHarness h) {
		QemuGuest? guest = null;
		try {
			string? unavailable_reason = yield QemuGuest.check_availability ();
			if (unavailable_reason != null) {
				stdout.printf ("<skipping: %s> ", unavailable_reason);
				h.done ();
				return;
			}

			guest = yield QemuGuest.boot ();
			assert_true (guest != null);

			var machine = new Barebone.IA32Machine (guest.client);

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
					assert_true (r.size >= 0x400000);
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

	private static Gum.ElfRelocationDetails make_relocation (Gum.ElfIA32Relocation type, uint64 address) {
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
	private static uint8[] legacy_page_tables () {
		var ram = new Ram ();

		ram.write_uint32 (PD_PA + (0 * 4), (uint32) PT_PA | 0x3);
		ram.write_uint32 (PD_PA + (1 * 4), 0x00800081);

		ram.write_uint32 (PT_PA + (0 * 4), 0x00100003);
		ram.write_uint32 (PT_PA + (1 * 4), 0x00101003);
		ram.write_uint32 (PT_PA + (2 * 4), 0x00102001);

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
		private string? monitor_dump;
		private ControlRegisterExposure exposure;

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
			if (address + size > ram.length)
				return "E01";

			var result = new StringBuilder ();
			for (size_t i = 0; i != size; i++)
				result.append_printf ("%02x", ram[address + i]);
			return result.str;
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

		public static async string? check_availability () {
			try {
				var checker = new Subprocess (SubprocessFlags.STDOUT_SILENCE | SubprocessFlags.STDERR_PIPE,
					"python3", script_path (), "check-x86");

				string stderr_buf;
				yield checker.communicate_utf8_async (null, null, null, out stderr_buf);
				if (checker.get_exit_status () == 0)
					return null;

				return (stderr_buf != null) ? stderr_buf.strip () : "unable to prepare the guest";
			} catch (GLib.Error e) {
				return e.message;
			}
		}

		public static async QemuGuest? boot () throws Error, IOError {
			uint16 port = pick_unused_port ();

			Subprocess process;
			try {
				process = new Subprocess (SubprocessFlags.STDOUT_PIPE,
					"python3", script_path (), "boot-x86", "--gdb-port", port.to_string ());
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

			// E.g.: 00000000c0000000-00000000c009b000 000000000009b000 -rw
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
