using Efni;

[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	public sealed class ParallelsStubClient : GDB.Client {
		public PhysicalAddressResolver? physical_address_resolver {
			get;
			set;
		}

		private bool physical_addressing = false;

		private const uint HALT_TIMEOUT_MSEC = 1000;
		private const uint64 MONITOR_READ_ALIGNMENT = 16;
		private const uint64 MAX_MONITOR_READ_SIZE = 0x100;

		private ParallelsStubClient (IOStream stream) {
			Object (stream: stream);
		}

		public static new async ParallelsStubClient open (IOStream stream, Cancellable? cancellable = null)
				throws Efni.Error, IOError {
			var client = new ParallelsStubClient (stream);

			try {
				yield client.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				Efni.throw_api_error (e);
			}

			return client;
		}

		public async uint64 read_system_register (DebuggerThread stopped_thread, SystemRegister reg,
				Cancellable? cancellable) throws Efni.Error, IOError {
			uint processor = processor_index_of (stopped_thread);
			string line = yield run_monitor_command ("readmsr %x %x".printf (processor, reg), cancellable);
			string[] tokens = line.split (" ");
			return uint64.parse (tokens[2], 16);
		}

		public override async void set_physical_memory_mode (bool enabled, Cancellable? cancellable = null)
				throws Efni.Error, IOError {
			physical_addressing = enabled;
		}

		public override async Bytes read_byte_array (uint64 address, size_t size, Cancellable? cancellable = null)
				throws Efni.Error, IOError {
			if (physical_addressing)
				return yield read_physical (address, size, cancellable);

			return yield base.read_byte_array (address, size, cancellable);
		}

		public override async void write_byte_array (uint64 address, Bytes bytes, Cancellable? cancellable = null)
				throws Efni.Error, IOError {
			if (!physical_addressing) {
				yield base.write_byte_array (address, bytes, cancellable);
				return;
			}

			uint64 alias = yield physical_address_resolver.virtual_address_of (address, cancellable);
			yield base.write_byte_array (alias, bytes, cancellable);
		}

		protected override async void detect_vendor_features (Cancellable? cancellable) throws Efni.Error, IOError {
			supported_features.add ("parallels");
			supported_features.add ("protected-code");
		}

		protected override async void enable_extensions (Cancellable? cancellable) throws Efni.Error, IOError {
			string info = yield query_property ("HostInfo", cancellable);
			var host = GDB.Client.PropertyDictionary.parse (info);

			arch = arch_from_cpu_type (GDB.Protocol.parse_uint (host.get_string ("cputype"), 10));
			pointer_size = GDB.Protocol.parse_uint (host.get_string ("ptrsize"), 10);
			byte_order = (host.get_string ("endian") == "little") ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN;

			yield halt (cancellable, HALT_TIMEOUT_MSEC);
		}

		private async Bytes read_physical (uint64 address, size_t size, Cancellable? cancellable)
				throws Efni.Error, IOError {
			uint64 start = address & ~(MONITOR_READ_ALIGNMENT - 1);
			uint64 end = (address + size + MONITOR_READ_ALIGNMENT - 1) & ~(MONITOR_READ_ALIGNMENT - 1);

			var window = new ByteArray.sized ((uint) (end - start));
			for (uint64 cursor = start; cursor != end;) {
				uint64 chunk_size = uint64.min (end - cursor, MAX_MONITOR_READ_SIZE);
				window.append (yield dump_physical (cursor, (size_t) chunk_size, cancellable));
				cursor += chunk_size;
			}

			size_t offset = (size_t) (address - start);
			return new Bytes (window.data[offset:offset + size]);
		}

		private async uint8[] dump_physical (uint64 address, size_t size, Cancellable? cancellable)
				throws Efni.Error, IOError {
			string hex = yield run_monitor_command (("dm %" + uint64.FORMAT_MODIFIER + "x %zx").printf (address, size),
				cancellable);
			if (hex.length != size * 2) {
				throw new Efni.Error.INVALID_ARGUMENT ("Unable to read from physical address 0x%" + uint64.FORMAT_MODIFIER +
					"x", address);
			}

			var data = new uint8[size];
			for (size_t i = 0; i != size; i++)
				data[i] = (uint8) uint64.parse (hex.substring ((long) (i * 2), 2), 16);
			return data;
		}

		private async string run_monitor_command (string command, Cancellable? cancellable) throws Efni.Error, IOError {
			string output = yield run_remote_command (command, cancellable);
			return output.split ("\n")[0];
		}

		private static uint processor_index_of (DebuggerThread thread) {
			return (uint) uint64.parse (thread.id, 16) - 1;
		}

		private static TargetArch arch_from_cpu_type (uint cpu_type) {
			switch (cpu_type) {
				case 0x00000007:	return IA32;
				case 0x01000007:	return X64;
				case 0x0000000c:	return ARM;
				case 0x0100000c:	return ARM64;
				default:		return UNKNOWN;
			}
		}

		public enum SystemRegister {
			TTBR1_EL1 = 0xc101,
			TCR_EL1 = 0xc102,
		}
	}

	public interface PhysicalAddressResolver : Object {
		public abstract async uint64 virtual_address_of (uint64 physical_address, Cancellable? cancellable)
			throws Efni.Error, IOError;
	}
}
