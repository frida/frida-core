[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
	internal sealed class UsbNcmDriver : Object, AsyncInitable {
		public LibUSB.Device device {
			get;
			construct;
		}

		private LibUSB.DeviceHandle handle;
		private uint8 data_iface;
		private int data_altsetting;
		private uint8 rx_address;
		private uint8 tx_address;
		private uint8 mac_address[6];

		private enum UsbDescriptorType {
			INTERFACE = 0x04,
		}

		private enum UsbCommSubclass {
			NCM		= 0x0d,
		}

		private enum UsbDataSubclass {
			UNDEFINED	= 0x00,
		}

		private enum UsbCdcDescriptorSubtype {
			ETHERNET = 0x0f,
		}

		public static async UsbNcmDriver open (LibUSB.Device device, Cancellable? cancellable = null) throws Error, IOError {
			var driver = new UsbNcmDriver (device);

			try {
				yield driver.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return driver;
		}

		private UsbNcmDriver (LibUSB.Device device) {
			Object (device: device);
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			check (device.open (out handle), "Failed to open USB device");

			Bytes language_ids_response = yield read_string_descriptor_bytes (0, 0, cancellable);
			if (language_ids_response.get_size () < sizeof (uint16))
				throw new Error.PROTOCOL ("Invalid language IDs response");
			Buffer language_ids = new Buffer (language_ids_response, LITTLE_ENDIAN);
			uint16 default_language_id = language_ids.read_uint16 (0);

			var dev_desc = LibUSB.DeviceDescriptor (device);
			string serial_number = yield read_string_descriptor_utf16 (dev_desc.iSerialNumber, default_language_id, cancellable);
			string udid = udid_from_serial_number (serial_number);

			int config_id = -1;
			check (handle.get_configuration (out config_id), "Failed to get USB device configuration");
			if (config_id != 5 && config_id != 6)
				throw new Error.NOT_SUPPORTED ("Expected USB device in config 5 or 6, device is in %d", config_id);

			LibUSB.ConfigDescriptor config;
			check (device.get_active_config_descriptor (out config), "Failed to get active USB config descriptor");

			bool found_cdc_header = false;
			bool found_data_interface = false;
			uint8 mac_address_index = 0;
			foreach (var iface in config.@interface) {
				foreach (var setting in iface.altsetting) {
					if (setting.bInterfaceClass == LibUSB.ClassCode.COMM &&
							setting.bInterfaceSubClass == UsbCommSubclass.NCM) {
						try {
							parse_cdc_header (setting.extra, out mac_address_index);
							found_cdc_header = true;
						} catch (Error e) {
							break;
						}
					} else if (setting.bInterfaceClass == LibUSB.ClassCode.DATA &&
							setting.bInterfaceSubClass == UsbDataSubclass.UNDEFINED &&
							setting.endpoint.length == 2) {
						found_data_interface = true;

						data_iface = setting.bInterfaceNumber;
						data_altsetting = setting.bAlternateSetting;

						foreach (var ep in setting.endpoint) {
							if ((ep.bEndpointAddress & LibUSB.EndpointDirection.MASK) == LibUSB.EndpointDirection.IN)
								rx_address = ep.bEndpointAddress;
							else
								tx_address = ep.bEndpointAddress;
						}
					}
				}
			}
			if (!found_cdc_header || !found_data_interface)
				throw new Error.NOT_SUPPORTED ("Failed to find CDC-NCM interface");

			string mac_address_str = yield read_string_descriptor_utf16 (mac_address_index, default_language_id, cancellable);
			if (mac_address_str.length != 12)
				throw new Error.PROTOCOL ("Invalid MAC address");
			for (uint i = 0; i != 6; i++) {
				uint v;
				mac_address_str.substring (i * 2, 2).scanf ("%02X", out v);
				mac_address[i] = (uint8) v;
			}

			check (handle.detach_kernel_driver (data_iface), "Failed to detach kernel driver for USB device");
			check (handle.claim_interface (data_iface), "Failed to claim USB interface");
			check (handle.set_interface_alt_setting (data_iface, data_altsetting), "Failed to set USB interface alt setting");

			return true;
		}

		private static string udid_from_serial_number (string serial) {
			if (serial.length == 24)
				return serial.substring (0, 8) + "-" + serial.substring (8);
			return serial;
		}

		private static void parse_cdc_header (uint8[] header, out uint8 mac_address_index) throws Error {
			var input = new DataInputStream (new MemoryInputStream.from_data (header));
			input.set_byte_order (LITTLE_ENDIAN);

			try {
				for (int offset = 0; offset != header.length;) {
					uint8 length = input.read_byte ();
					if (length < 3)
						throw new Error.PROTOCOL ("Invalid descriptor length");

					uint8 descriptor_type = input.read_byte ();
					if (descriptor_type != (LibUSB.RequestType.CLASS | UsbDescriptorType.INTERFACE))
						throw new Error.PROTOCOL ("Invalid descriptor type");

					uint8 descriptor_subtype = input.read_byte ();
					if (descriptor_subtype == UsbCdcDescriptorSubtype.ETHERNET) {
						mac_address_index = input.read_byte ();
						return;
					}

					input.skip (length - 3);
					offset += length;
				}
			} catch (IOError e) {
				throw new Error.PROTOCOL ("%s", e.message);
			}

			throw new Error.PROTOCOL ("CDC Ethernet descriptor not found");
		}

		private async string read_string_descriptor_utf16 (uint8 index, uint16 language_id, Cancellable? cancellable)
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

		private async Bytes read_string_descriptor_bytes (uint8 index, uint16 language_id, Cancellable? cancellable)
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

		private async Bytes control_transfer (uint8 request_type, uint8 request, uint16 val, uint16 index, uint16 length,
				uint timeout, Cancellable? cancellable) throws Error, IOError {
			var transfer = new LibUSB.Transfer ();
			var ready_closure = new TransferReadyClosure (control_transfer.callback);

			var buffer = new uint8[sizeof (LibUSB.ControlSetup) + length];
			LibUSB.Transfer.fill_control_setup (buffer, request_type, request, val, index, length);
			transfer.fill_control_transfer (handle, buffer, on_transfer_ready, ready_closure, timeout);

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (() => {
				transfer.cancel ();
				return Source.REMOVE;
			});
			cancel_source.attach (MainContext.get_thread_default ());

			try {
				check (transfer.submit (), "Failed to submit transfer");
				yield;
			} finally {
				cancel_source.destroy ();
			}

			if (transfer.status != COMPLETED)
				throw new Error.TRANSPORT ("Control transfer failed");

			return new Bytes (((uint8[]) transfer.control_get_data ())[:transfer.actual_length]);
		}

		private static void on_transfer_ready (LibUSB.Transfer transfer) {
			TransferReadyClosure * closure = transfer.user_data;
			closure->schedule ();
		}

		private static void check (LibUSB.Error error, string prefix) throws Error {
			if (error >= LibUSB.Error.SUCCESS)
				return;

			string message = @"$prefix: $(error.get_description ())";

			if (error == ACCESS)
				throw new Error.PERMISSION_DENIED ("%s", message);

			throw new Error.TRANSPORT ("%s", message);
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
}
