[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	/**
	 * GDB-remote client for the debug server of Parallels Desktop, which a guest exposes once
	 * its configuration carries `vm.debug=1 vm.debug.protocol=0` among its system flags.
	 *
	 * It describes its registers the usual way, through `qXfer:features:read`, but names the
	 * architecture in that document by its feature name instead of the short name that the
	 * generic client knows. It also answers `qAttached` with an empty payload, and serves
	 * memory only once a client has asked why the guest stopped. That question is put to it
	 * after the target document arrives, because the answer carries register values, which
	 * only the document gives names to.
	 *
	 * Note that the stub of the monitor, which the `armv.args` flag turns on, is a different
	 * one that reads registers on the thread serving the connection. Ask that one for a
	 * register or for memory and the hypervisor refuses the thread, which ends the guest.
	 */
	public sealed class ParallelsStubClient : GDB.Client {
		private const uint HALT_TIMEOUT_MSEC = 1000;

		private ParallelsStubClient (IOStream stream) {
			Object (stream: stream);
		}

		/**
		 * Opens a client on a connection to the debug server, and brings the guest to a halt
		 * so that it serves memory.
		 */
		public static new async ParallelsStubClient open (IOStream stream, Cancellable? cancellable = null)
				throws Error, IOError {
			var client = new ParallelsStubClient (stream);

			try {
				yield client.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return client;
		}

		protected override async void detect_vendor_features (Cancellable? cancellable) throws Error, IOError {
			supported_features.add ("parallels");
			supported_features.add ("protected-code");
		}

		protected override async void enable_extensions (Cancellable? cancellable) throws Error, IOError {
			string info = yield query_property ("HostInfo", cancellable);
			var host = GDB.Client.PropertyDictionary.parse (info);

			arch = arch_from_cpu_type (GDB.Protocol.parse_uint (host.get_string ("cputype"), 10));
			pointer_size = GDB.Protocol.parse_uint (host.get_string ("ptrsize"), 10);
			byte_order = (host.get_string ("endian") == "little") ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN;

			yield halt (cancellable, HALT_TIMEOUT_MSEC);
		}

		private static GDB.TargetArch arch_from_cpu_type (uint cpu_type) {
			switch (cpu_type) {
				case 0x00000007:	return IA32;
				case 0x01000007:	return X64;
				case 0x0000000c:	return ARM;
				case 0x0100000c:	return ARM64;
				default:		return UNKNOWN;
			}
		}
	}
}
