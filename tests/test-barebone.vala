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

	}

	private static async void enumerate_ranges_walks_legacy_tables (Harness h) {
		var target = new FakeTarget (legacy_page_tables (), LEGACY_MONITOR_DUMP);
		try {
			var machine = yield target.open_machine ();

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
		var target = new FakeTarget (pae_page_tables (), PAE_MONITOR_DUMP);
		try {
			var machine = yield target.open_machine ();

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
		var target = new FakeTarget (legacy_page_tables (), LEGACY_MONITOR_DUMP);
		try {
			var machine = yield target.open_machine ();

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
		var target = new FakeTarget (legacy_page_tables (), null, EXPOSE_CONTROL_REGISTERS);
		try {
			var machine = yield target.open_machine ();

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
		var target = new FakeTarget (legacy_page_tables (), LEGACY_MONITOR_DUMP);
		try {
			var machine = yield target.open_machine ();

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
		var target = new FakeTarget (legacy_page_tables (), LEGACY_MONITOR_DUMP);
		try {
			var machine = yield target.open_machine ();

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
		var target = new FakeTarget (pae_page_tables (), PAE_MONITOR_DUMP);
		try {
			var machine = yield target.open_machine ();

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
		var target = new FakeTarget (legacy_page_tables (), LEGACY_MONITOR_DUMP);
		try {
			var machine = yield target.open_machine ();

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
		var target = new FakeTarget (legacy_page_tables (), LEGACY_MONITOR_DUMP);
		try {
			var machine = yield target.open_machine ();

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

	private static async Gee.List<Barebone.RangeDetails> collect_ranges (Barebone.IA32Machine machine,
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

	private class Ram {
		public const size_t SIZE = 0x4000;

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

		private uint8[] ram;
		private string? monitor_dump;
		private ControlRegisterExposure exposure;

		private SocketService service;
		private Cancellable cancellable = new Cancellable ();

		private const string CORE_REGISTERS =
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

		private const string CONTROL_REGISTERS =
			"<reg name=\"cr0\" bitsize=\"32\" regnum=\"10\"/>" +
			"<reg name=\"cr3\" bitsize=\"32\" regnum=\"11\"/>" +
			"<reg name=\"cr4\" bitsize=\"32\" regnum=\"12\"/>";

		public FakeTarget (owned uint8[] ram, string? monitor_dump,
				ControlRegisterExposure exposure = HIDE_CONTROL_REGISTERS) {
			this.ram = (owned) ram;
			this.monitor_dump = monitor_dump;
			this.exposure = exposure;
		}

		public async Barebone.IA32Machine open_machine () throws Error, IOError {
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

			return new Barebone.IA32Machine (client);
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
			var registers = new StringBuilder (CORE_REGISTERS);
			if (exposure == EXPOSE_CONTROL_REGISTERS)
				registers.append (CONTROL_REGISTERS);

			return "<?xml version=\"1.0\"?>" +
				"<target version=\"1.0\">" +
				"<architecture>i386</architecture>" +
				"<feature name=\"org.gnu.gdb.i386.core\">" +
				registers.str +
				"</feature>" +
				"</target>";
		}

		private string read_register (string request) {
			uint regnum = uint.parse (request[1:].split (";")[0], 16);
			if (regnum >= 10 && exposure != EXPOSE_CONTROL_REGISTERS)
				return "E01";

			uint64 val;
			switch (regnum) {
				case 10:
					val = 0x8005003b;
					break;
				case 11:
					val = PD_PA;
					break;
				case 12:
					val = 0x00000010;
					break;
				default:
					if (regnum > 9)
						return "E01";
					val = 0;
					break;
			}

			var result = new StringBuilder ();
			for (uint i = 0; i != 4; i++)
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

	private class Harness : Frida.Test.AsyncHarness {
		public Harness (owned Frida.Test.AsyncHarness.TestSequenceFunc func) {
			base ((owned) func);
		}
	}
}
