[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
	internal sealed class UsbNcmDriver : Object, AsyncInitable {
		public UsbDevice device {
			get;
			construct;
		}

		private uint8 data_iface;
		private int data_altsetting;
		private uint8 rx_address;
		private uint8 tx_address;

		private VirtualNetworkStack? netstack;
		private uint16 next_outgoing_sequence = 1;

		private Cancellable io_cancellable = new Cancellable ();

		private enum UsbDescriptorType {
			INTERFACE = 0x04,
		}

		private enum UsbCommSubclass {
			NCM = 0x0d,
		}

		private enum UsbDataSubclass {
			UNDEFINED = 0x00,
		}

		private enum UsbCdcDescriptorSubtype {
			ETHERNET = 0x0f,
		}

		public static async UsbNcmDriver open (UsbDevice device, Cancellable? cancellable = null) throws Error, IOError {
			var driver = new UsbNcmDriver (device);

			try {
				yield driver.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return driver;
		}

		private UsbNcmDriver (UsbDevice device) {
			Object (device: device);
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			unowned LibUSB.DeviceHandle handle = device.handle;

			int config_id = -1;
			Usb.check (handle.get_configuration (out config_id), "Failed to get USB device configuration");
			if (config_id != 5 && config_id != 6)
				throw new Error.NOT_SUPPORTED ("Expected USB device in config 5 or 6, device is in %d", config_id);

			LibUSB.ConfigDescriptor config;
			Usb.check (device.raw_device.get_active_config_descriptor (out config),
				"Failed to get active USB config descriptor");

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

			uint8 mac_address[6];
			string mac_address_str = yield device.read_string_descriptor (mac_address_index, device.default_language_id,
				cancellable);
			if (mac_address_str.length != 12)
				throw new Error.PROTOCOL ("Invalid MAC address");
			for (uint i = 0; i != 6; i++) {
				uint v;
				mac_address_str.substring (i * 2, 2).scanf ("%02X", out v);
				mac_address[i] = (uint8) v;
			}

			string ipv6_address = derive_ipv6_link_local_address_from_mac_address (mac_address_str);

			Usb.check (handle.detach_kernel_driver (data_iface), "Failed to detach kernel driver for USB device");
			Usb.check (handle.claim_interface (data_iface), "Failed to claim USB interface");
			Usb.check (handle.set_interface_alt_setting (data_iface, data_altsetting),
				"Failed to set USB interface alt setting");

			netstack = yield VirtualNetworkStack.create (new Bytes (mac_address), new InetAddress.from_string (ipv6_address),
				1500, cancellable);
			netstack.outgoing_datagram.connect (on_netif_outgoing_datagram);

			process_incoming_datagrams.begin ();

			return true;
		}

		private async void process_incoming_datagrams () {
			var data = new uint8[64 * 1024];

			while (true) {
				try {
					size_t n = yield device.bulk_transfer (rx_address, data, uint.MAX, io_cancellable);
					handle_ncm_frame (data[:n]);
				} catch (GLib.Error e) {
					printerr ("Oh noes: %s\n", e.message);
					return;
				}
			}
		}

		private void handle_ncm_frame (uint8[] data) throws GLib.Error {
			var input = new DataInputStream (new MemoryInputStream.from_data (data));
			input.byte_order = LITTLE_ENDIAN;

			uint8 raw_signature[4 + 1];
			unowned string signature = (string) raw_signature;
			size_t bytes_read;

			input.read_all (raw_signature[:4], out bytes_read);
			if (signature != "NCMH")
				throw new Error.PROTOCOL ("Invalid NTH16 signature");
			input.skip (6);
			var ndp_index = input.read_uint16 ();

			do {
				input.seek (ndp_index, SET);
				input.read_all (raw_signature[:4], out bytes_read);
				if (signature != "NCM0")
					throw new Error.PROTOCOL ("Invalid NDP16 signature");
				input.skip (2);
				var next_ndp_index = input.read_uint16 ();

				while (true) {
					var datagram_index = input.read_uint16 ();
					var datagram_length = input.read_uint16 ();
					if (datagram_index == 0 || datagram_length == 0)
						break;

					int64 previous_offset = input.tell ();
					input.seek (datagram_index, SET);
					var datagram = new uint8[datagram_length];
					input.read_all (datagram, out bytes_read);
					input.seek (previous_offset, SET);

					netstack.handle_incoming_datagram (new Bytes.take ((owned) datagram));
				}

				ndp_index = next_ndp_index;
			} while (ndp_index != 0);
		}

		private async void on_netif_outgoing_datagram (Bytes datagram) {
			uint16 transfer_header_length = 12;
			uint16 ndp_header_length = 16;
			uint16 alignment_padding_length = 2;

			uint16 datagram_start_index = transfer_header_length + ndp_header_length + alignment_padding_length;
			uint16 datagram_length = (uint16) datagram.length;

			uint16 sentinel_start_index = 0;
			uint16 sentinel_size = 0;

			uint16 sequence = next_outgoing_sequence++;
			uint16 block_length = datagram_start_index + datagram_length;
			uint16 ndp_index = transfer_header_length;
			uint16 next_ndp_index = 0;

			uint16 alignment_padding_value = 0;

			var frame = new BufferBuilder (LITTLE_ENDIAN)
				.append_string ("NCMH", StringTerminator.NONE)
				.append_uint16 (transfer_header_length)
				.append_uint16 (sequence)
				.append_uint16 (block_length)
				.append_uint16 (ndp_index)
				.append_string ("NCM0", StringTerminator.NONE)
				.append_uint16 (ndp_header_length)
				.append_uint16 (next_ndp_index)
				.append_uint16 (datagram_start_index)
				.append_uint16 (datagram_length)
				.append_uint16 (sentinel_start_index)
				.append_uint16 (sentinel_size)
				.append_uint16 (alignment_padding_value)
				.append_bytes (datagram)
				.build ();

			try {
				yield device.bulk_transfer (tx_address, frame.get_data (), uint.MAX, io_cancellable);
			} catch (GLib.Error e) {
			}
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

		private string derive_ipv6_link_local_address_from_mac_address (string mac_address) {
			uint top_octet;
			mac_address.substring (0, 2).scanf ("%02X", out top_octet);

			return "FE80::%02X%s:%sFF:FE%s:%s".printf (
				top_octet ^ 2,
				mac_address[2:4],
				mac_address[4:6],
				mac_address[6:8],
				mac_address[8:]);
		}
	}
}
