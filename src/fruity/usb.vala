[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
	internal sealed class UsbDevice : Object, AsyncInitable {
		public LibUSB.Device raw_device {
			get;
			construct;
		}

		public LibUSB.DeviceHandle handle {
			get {
				return _handle;
			}
		}

		public string udid {
			get {
				return _udid;
			}
		}

		public uint16 default_language_id {
			get {
				return _default_language_id;
			}
		}

		private LibUSB.DeviceHandle _handle;
		private string _udid;
		private uint16 _default_language_id;

		public static async UsbDevice open (LibUSB.Device raw_device, Cancellable? cancellable = null) throws Error, IOError {
			var device = new UsbDevice (raw_device);

			try {
				yield device.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return device;
		}

		private UsbDevice (LibUSB.Device raw_device) {
			Object (raw_device: raw_device);
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			Usb.check (raw_device.open (out _handle), "Failed to open USB device");

			Bytes language_ids_response = yield read_string_descriptor_bytes (0, 0, cancellable);
			if (language_ids_response.get_size () < sizeof (uint16))
				throw new Error.PROTOCOL ("Invalid language IDs response");
			Buffer language_ids = new Buffer (language_ids_response, LITTLE_ENDIAN);
			_default_language_id = language_ids.read_uint16 (0);

			var dev_desc = LibUSB.DeviceDescriptor (raw_device);
			string serial_number = yield read_string_descriptor (dev_desc.iSerialNumber, _default_language_id, cancellable);
			_udid = udid_from_serial_number (serial_number);

			return true;
		}

		private static string udid_from_serial_number (string serial) {
			if (serial.length == 24)
				return serial.substring (0, 8) + "-" + serial.substring (8);
			return serial;
		}

		public async string read_string_descriptor (uint8 index, uint16 language_id, Cancellable? cancellable)
				throws Error, IOError {
			var response = yield read_string_descriptor_bytes (index, language_id, cancellable);
			try {
				var input = new DataInputStream (new MemoryInputStream.from_bytes (response));
				input.byte_order = LITTLE_ENDIAN;

				size_t size = response.get_size ();
				if (size % sizeof (unichar2) != 0)
					throw new Error.PROTOCOL ("Invalid string descriptor");
				size_t n = size / sizeof (unichar2);
				var chars = new unichar2[n];
				for (size_t i = 0; i != n; i++)
					chars[i] = input.read_uint16 ();

				unowned string16 str = (string16) chars;
				return str.to_utf8 ((long) n);
			} catch (GLib.Error e) {
				throw new Error.PROTOCOL ("%s", e.message);
			}
		}

		public async Bytes read_string_descriptor_bytes (uint8 index, uint16 language_id, Cancellable? cancellable)
				throws Error, IOError {
			var response = yield control_transfer (
				LibUSB.RequestType.STANDARD | LibUSB.EndpointDirection.IN,
				LibUSB.StandardRequest.GET_DESCRIPTOR,
				(LibUSB.DescriptorType.STRING << 8) | index,
				language_id,
				1024,
				1000,
				cancellable);
			try {
				var input = new DataInputStream (new MemoryInputStream.from_bytes (response));
				input.byte_order = LITTLE_ENDIAN;

				uint8 length = input.read_byte ();
				if (length < 2)
					throw new Error.PROTOCOL ("Invalid string descriptor length");

				uint8 type = input.read_byte ();
				if (type != LibUSB.DescriptorType.STRING)
					throw new Error.PROTOCOL ("Invalid string descriptor type");

				size_t remainder = response.get_size () - 2;
				length -= 2;
				if (length > remainder)
					throw new Error.PROTOCOL ("Invalid string descriptor length");

				return response[2:2 + length];
			} catch (GLib.Error e) {
				throw new Error.PROTOCOL ("%s", e.message);
			}
		}

		public async Bytes control_transfer (uint8 request_type, uint8 request, uint16 val, uint16 index, uint16 length,
				uint timeout, Cancellable? cancellable) throws Error, IOError {
			var transfer = new LibUSB.Transfer ();
			var ready_closure = new TransferReadyClosure (control_transfer.callback);

			var buffer = new uint8[sizeof (LibUSB.ControlSetup) + length];
			LibUSB.Transfer.fill_control_setup (buffer, request_type, request, val, index, length);
			transfer.fill_control_transfer (_handle, buffer, on_transfer_ready, ready_closure, timeout);

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (() => {
				transfer.cancel ();
				return Source.REMOVE;
			});
			cancel_source.attach (MainContext.get_thread_default ());

			try {
				Usb.check (transfer.submit (), "Failed to submit control transfer");
				yield;
			} finally {
				cancel_source.destroy ();
			}

			if (transfer.status != COMPLETED)
				throw new Error.TRANSPORT ("Control transfer failed");

			return new Bytes (((uint8[]) transfer.control_get_data ())[:transfer.actual_length]);
		}

		public async size_t bulk_transfer (uint8 endpoint, uint8[] buffer, uint timeout, Cancellable? cancellable)
				throws Error, IOError {
			var transfer = new LibUSB.Transfer ();
			var ready_closure = new TransferReadyClosure (bulk_transfer.callback);

			transfer.fill_bulk_transfer (_handle, endpoint, buffer, on_transfer_ready, ready_closure, timeout);

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (() => {
				transfer.cancel ();
				return Source.REMOVE;
			});
			cancel_source.attach (MainContext.get_thread_default ());

			try {
				Usb.check (transfer.submit (), "Failed to submit bulk transfer");
				yield;
			} finally {
				cancel_source.destroy ();
			}

			if (transfer.status != COMPLETED)
				throw new Error.TRANSPORT ("Bulk transfer failed");

			return transfer.actual_length;
		}

		private static void on_transfer_ready (LibUSB.Transfer transfer) {
			TransferReadyClosure * closure = transfer.user_data;
			closure->schedule ();
		}

		private class TransferReadyClosure {
			private SourceFunc? handler;
			private MainContext main_context;

			public TransferReadyClosure (owned SourceFunc handler) {
				this.handler = (owned) handler;
				main_context = MainContext.ref_thread_default ();
			}

			public void schedule () {
				var source = new IdleSource ();
				source.set_callback (() => {
					handler ();
					handler = null;
					return Source.REMOVE;
				});
				source.attach (main_context);
			}
		}
	}

	namespace Usb {
		internal static void check (LibUSB.Error error, string prefix) throws Error {
			if (error >= LibUSB.Error.SUCCESS)
				return;

			string message = @"$prefix: $(error.get_description ())";

			if (error == ACCESS)
				throw new Error.PERMISSION_DENIED ("%s", message);

			throw new Error.TRANSPORT ("%s", message);
		}
	}
}
