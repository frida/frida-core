using WinIpc;

namespace Zed.CodeServiceTest {
	public static void add_tests () {
		GLib.Test.add_func ("/CodeService/Lookup/module-spec-by-uid", () => {
			var h = new Harness ((h) => Lookup.module_spec_by_uid (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/CodeService/Lookup/module-by-address", () => {
			var h = new Harness ((h) => Lookup.module_by_address (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/CodeService/Lookup/function-by-address", () => {
			var h = new Harness ((h) => Lookup.function_by_address (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/CodeService/Lookup/function-with-no-module", () => {
			var h = new Harness ((h) => Lookup.function_with_no_module (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/CodeService/Persist/function-spec", () => {
			var h = new Harness ((h) => Persist.function_spec (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/CodeService/Persist/module-spec", () => {
			var h = new Harness ((h) => Persist.module_spec (h as Harness));
			h.run ();
		});
	}

	public const string NTDLL_UID = "D0B2C365CAB344F1BED8A0DADD507D96";
	public const uint64 NTDLL_BASE = 0x7DE70000;
	public const uint64 NTDLL_SIZE = 1289712;

	public const string KERNEL32_UID = "606ECB76A424CC535407E7A24E2A34BC";
	public const uint64 KERNEL32_BASE = 0x7DD60000;
	public const uint64 KERNEL32_SIZE = 836608;

	public const string WS2_32_UID = "DAAE8A9B8C0ACC7F858454132553C30D";
	public const uint64 WS2_32_BASE = 0x41AC0000;
	public const uint64 WS2_32_SIZE = 206336;

	public const uint64 WSARECV_OFFSET = 0xc29f;

	namespace Lookup {

		private static async void module_spec_by_uid (Harness h) {
			assert (yield h.service.find_module_spec_by_uid (KERNEL32_UID) == null);

			yield h.add_module_specs ();

			var mspec = yield h.service.find_module_spec_by_uid (KERNEL32_UID);
			assert (mspec != null);
			assert (mspec.name == "kernel32.dll");
			assert (mspec.uid == KERNEL32_UID);
			assert (mspec.size == KERNEL32_SIZE);

			h.done ();
		}

		private static async void module_by_address (Harness h) {
			uint64 address = WS2_32_BASE + 42;

			assert (yield h.service.find_module_by_address (address) == null);
			yield h.add_module_specs ();
			assert (yield h.service.find_module_by_address (address) == null);
			yield h.add_modules ();

			var mod = yield h.service.find_module_by_address (address);
			assert (mod != null);
			assert (mod.address == WS2_32_BASE);
			assert (mod.spec.uid == WS2_32_UID);

			assert (yield h.service.find_module_by_address (WS2_32_BASE - 1) == null);
			assert (yield h.service.find_module_by_address (WS2_32_BASE) != null);
			assert (yield h.service.find_module_by_address (WS2_32_BASE + WS2_32_SIZE) == null);
			assert (yield h.service.find_module_by_address (WS2_32_BASE + WS2_32_SIZE - 1) != null);

			h.done ();
		}

		private static async void function_by_address (Harness h) {
			uint64 address = WS2_32_BASE + WSARECV_OFFSET;

			assert (yield h.service.find_function_by_address (address) == null);
			yield h.add_module_specs ();
			assert (yield h.service.find_function_by_address (address) == null);
			yield h.add_modules ();

			var func = yield h.service.find_function_by_address (address);
			assert (func != null);
			assert (func.address == address);
			assert (func.spec.name == "WSARecv");

			assert (yield h.service.find_function_by_address (address - 1) == null);
			assert (yield h.service.find_function_by_address (address + 1) == null);

			h.done ();
		}

		private static async void function_with_no_module (Harness h) {
			yield h.add_module_specs ();
			yield h.add_modules ();

			uint64 address = 0x60000;

			assert (yield h.service.find_function_by_address (address) == null);

			var spec = new FunctionSpec ("dynamic_0x60000", address);
			var func = new Function (spec, address);
			yield h.service.add_function (func);

			func = yield h.service.find_function_by_address (address);
			assert (func != null);
			assert (func.address == address);
			assert (func.spec.name == "dynamic_0x60000");

			h.done ();
		}

	}

	namespace Persist {

		private static async void function_spec (Harness h) {
			yield h.add_module_specs ();
			yield h.add_modules ();

			var spec_a = yield h.service.find_function_by_address (WS2_32_BASE + WSARECV_OFFSET).spec;
			Variant variant = spec_a.to_variant ();

			var spec_b = FunctionSpec.from_variant (variant);

			assert (spec_b.name == spec_a.name);
			assert (spec_b.offset == spec_a.offset);

			h.done ();
		}

		private static async void module_spec (Harness h) {
			yield h.add_module_specs ();

			var spec_a = yield h.service.find_module_spec_by_uid (WS2_32_UID);
			Variant variant = spec_a.to_variant ();

			assert (spec_a.function_count () == 1);

			var spec_b = ModuleSpec.from_variant (variant);

			assert (spec_b.name == spec_a.name);
			assert (spec_b.uid == spec_a.uid);
			assert (spec_b.size == spec_a.size);
			assert (spec_b.function_count () == 1);

			var iter_a = spec_a.functions.iterator ();
			var iter_b = spec_b.functions.iterator ();
			while (iter_a.next () && iter_b.next ()) {
				var fspec_a = iter_a.@get ();
				var fspec_b = iter_b.@get ();
				assert (fspec_b.name == fspec_a.name);
				assert (fspec_b.offset == fspec_a.offset);
			}

			h.done ();
		}

	}

	private class Harness : Zed.Test.AsyncHarness {
		public CodeService service {
			get;
			private set;
		}

		private ModuleSpec ntdll_mspec;
		private ModuleSpec kernel32_mspec;
		private ModuleSpec ws2_32_mspec;

		private Module ntdll_mod;
		private Module kernel32_mod;
		private Module ws2_32_mod;

		public Harness (Zed.Test.AsyncHarness.TestSequenceFunc func) {
			base (func);
		}

		construct {
			service = new CodeService ();

			ntdll_mspec = new ModuleSpec ("ntdll.dll", NTDLL_UID, NTDLL_SIZE);
			kernel32_mspec = new ModuleSpec ("kernel32.dll", KERNEL32_UID, KERNEL32_SIZE);
			ws2_32_mspec = new ModuleSpec ("ws2_32.dll", WS2_32_UID, WS2_32_SIZE);
			ws2_32_mspec.internal_add_function (new FunctionSpec ("WSARecv", WSARECV_OFFSET));

			ntdll_mod = new Module (ntdll_mspec, NTDLL_BASE);
			kernel32_mod = new Module (kernel32_mspec, KERNEL32_BASE);
			ws2_32_mod = new Module (ws2_32_mspec, WS2_32_BASE);
		}

		public async void add_module_specs () {
			yield service.add_module_spec (ntdll_mspec);
			yield service.add_module_spec (kernel32_mspec);
			yield service.add_module_spec (ws2_32_mspec);
		}

		public async void add_modules () {
			yield service.add_module (ntdll_mod);
			yield service.add_module (kernel32_mod);
			yield service.add_module (ws2_32_mod);
		}

		public override void done () {
			service = null;

			base.done ();
		}
	}
}
