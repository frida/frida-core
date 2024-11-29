[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
	internal sealed class UsbNcmDriver : Object, AsyncInitable {
		public UsbDevice device {
			get;
			construct;
		}

		public UsbNcmConfig config {
			get;
			construct;
		}

		public VirtualNetworkStack netstack {
			get {
				return _netstack;
			}
		}

		public InetAddress? remote_ipv6_address {
			get {
				return _remote_ipv6_address;
			}
		}

		private VirtualNetworkStack? _netstack;
		private Gee.Queue<Bytes> pending_output = new Gee.ArrayQueue<Bytes> ();
		private bool writing = false;
		private uint16 next_outgoing_sequence = 1;

		private InetAddress? _remote_ipv6_address;

		private Cancellable io_cancellable = new Cancellable ();

		private const uint16 TRANSFER_HEADER_SIZE = 4 + 2 + 2 + 2 + 2;

		private enum EtherType {
			IPV6 = 0x86dd,
		}

		private enum IPV6NextHeader {
			UDP = 0x11,
		}

		public static async UsbNcmDriver open (UsbDevice device, UsbNcmConfig config, Cancellable? cancellable = null)
				throws Error, IOError {
			var driver = new UsbNcmDriver (device, config);

			try {
				yield driver.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return driver;
		}

		private UsbNcmDriver (UsbDevice device, UsbNcmConfig config) {
			Object (device: device, config: config);
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			var language_id = yield device.query_default_language_id (cancellable);

			uint8 mac_address[6];
			string mac_address_str = yield device.read_string_descriptor (config.mac_address_index, language_id, cancellable);
			if (mac_address_str.length != 12)
				throw new Error.PROTOCOL ("Invalid MAC address");
			for (uint i = 0; i != 6; i++) {
				uint v;
				mac_address_str.substring (i * 2, 2).scanf ("%02X", out v);
				mac_address[i] = (uint8) v;
			}

			unowned LibUSB.DeviceHandle handle = device.handle;
			try {
				Usb.check (handle.claim_interface (config.data_iface), "Failed to claim USB interface");
			} catch (Error e) {
				throw new Error.PERMISSION_DENIED ("%s",
					make_user_error_message (@"Unable to claim USB CDC-NCM interface ($(e.message))"));
			}
			Usb.check (handle.set_interface_alt_setting (config.data_iface, config.data_altsetting),
				"Failed to set USB interface alt setting");

			_netstack = new VirtualNetworkStack (new Bytes (mac_address), null, 1500);
			_netstack.outgoing_datagram.connect (on_netif_outgoing_datagram);

			process_incoming_datagrams.begin ();

			return true;
		}

		public void close () {
			io_cancellable.cancel ();
			_netstack.stop ();
		}

		private async void process_incoming_datagrams () {
			var data = new uint8[64 * 1024];

			while (true) {
				try {
					size_t n = yield device.bulk_transfer (config.rx_address, data, uint.MAX, io_cancellable);
					handle_ncm_frame (data[:n]);
				} catch (GLib.Error e) {
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
					var datagram_buf = new uint8[datagram_length];
					input.read_all (datagram_buf, out bytes_read);
					input.seek (previous_offset, SET);

					var datagram = new Bytes.take ((owned) datagram_buf);

					if (_remote_ipv6_address == null) {
						_remote_ipv6_address = try_infer_remote_address_from_datagram (datagram);
						if (_remote_ipv6_address != null)
							notify_property ("remote-ipv6-address");
					}

					_netstack.handle_incoming_datagram (datagram);
				}

				ndp_index = next_ndp_index;
			} while (ndp_index != 0);
		}

		private void on_netif_outgoing_datagram (Bytes datagram) {
			pending_output.offer (datagram);

			if (!writing) {
				writing = true;

				var source = new TimeoutSource (1);
				source.set_callback (() => {
					process_pending_output.begin ();
					return false;
				});
				source.attach (MainContext.get_thread_default ());
			}
		}

		private async void process_pending_output () {
			uint16 tx_max_datagrams = 40;
			uint16 tx_max_transfer_size = 32764;

			while (!pending_output.is_empty) {
				uint16 num_datagrams = tx_max_datagrams;
				TransferLayout layout;
				while ((layout = TransferLayout.compute (pending_output, num_datagrams)).size > tx_max_transfer_size)
					num_datagrams--;

				var batch = new Gee.ArrayList<Bytes> ();
				for (var i = 0; i != layout.offsets.size; i++)
					batch.add (pending_output.poll ());

				var transfer = build_output_transfer (batch, layout, next_outgoing_sequence++);

				try {
					yield device.bulk_transfer (config.tx_address, transfer.get_data (), uint.MAX, io_cancellable);
				} catch (GLib.Error e) {
					break;
				}
			}

			writing = false;
		}

		private class TransferLayout {
			public uint16 size;
			public uint16 ndp_header_size;
			public Gee.List<uint16> offsets;

			public static TransferLayout? compute (Gee.Collection<Bytes> datagrams, uint16 max_datagrams) {
				uint16 ndp_header_base_size = 4 + 2 + 2;
				uint16 ndp_entry_size = 2 + 2;
				uint16 ethernet_header_size = 14;
				uint16 alignment = 4;

				uint16 num_datagrams = uint16.min ((uint16) datagrams.size, max_datagrams);

				uint16 ndp_header_size = ndp_header_base_size + ((num_datagrams + 1) * ndp_entry_size);
				uint16 current_transfer_size = TRANSFER_HEADER_SIZE + ndp_header_size;
				var offsets = new Gee.ArrayList<uint16> ();

				uint i = 0;
				foreach (var datagram in datagrams) {
					var size = (uint16) datagram.get_size ();

					uint16 start_offset = current_transfer_size;
					var delta = (start_offset + ethernet_header_size) % alignment;
					if (delta != 0)
						start_offset += alignment - delta;

					uint16 end_offset = start_offset + size;
					if (i == num_datagrams - 1) {
						delta = end_offset % alignment;
						if (delta != 0)
							end_offset += alignment - delta;
					}

					current_transfer_size = end_offset;
					offsets.add (start_offset);

					i++;
					if (i == max_datagrams)
						break;
				}

				return new TransferLayout () {
					size = current_transfer_size,
					ndp_header_size = ndp_header_size,
					offsets = offsets,
				};
			}
		}

		private static Bytes build_output_transfer (Gee.List<Bytes> datagrams, TransferLayout layout, uint16 sequence_number) {
			uint16 ndp_index = TRANSFER_HEADER_SIZE;

			var builder = new BufferBuilder (LITTLE_ENDIAN)
				.append_string ("NCMH", StringTerminator.NONE)
				.append_uint16 (TRANSFER_HEADER_SIZE)
				.append_uint16 (sequence_number)
				.append_uint16 (layout.size)
				.append_uint16 (ndp_index);

			uint16 next_ndp_index = 0;

			builder
				.append_string ("NCM0", StringTerminator.NONE)
				.append_uint16 (layout.ndp_header_size)
				.append_uint16 (next_ndp_index);

			int i;

			i = 0;
			foreach (var datagram in datagrams) {
				builder
					.append_uint16 (layout.offsets[i])
					.append_uint16 ((uint16) datagram.get_size ());
				i++;
			}

			i = 0;
			foreach (var datagram in datagrams) {
				builder
					.seek (layout.offsets[i])
					.append_bytes (datagram);
				i++;
			}

			builder.seek (layout.size);

			return builder.build ();
		}

		private static InetAddress? try_infer_remote_address_from_datagram (Bytes datagram) {
			if (datagram.get_size () < 0x3e)
				return null;

			var buf = new Buffer (datagram, BIG_ENDIAN);

			var ethertype = (EtherType) buf.read_uint16 (12);
			if (ethertype != IPV6)
				return null;

			var next_header = (IPV6NextHeader) buf.read_uint8 (20);
			if (next_header != UDP)
				return null;

			return new InetAddress.from_bytes (datagram[22:22 + 16].get_data (), IPV6);
		}
	}

	internal class UsbNcmConfig {
		public uint8 data_iface;
		public int data_altsetting;
		public uint8 rx_address;
		public uint8 tx_address;
		public uint8 mac_address_index;

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

		public static UsbNcmConfig prepare (UsbDevice device) throws Error {
			unowned LibUSB.Device raw_device = device.raw_device;

			var dev_desc = LibUSB.DeviceDescriptor (raw_device);

			LibUSB.ConfigDescriptor current_config;
			Usb.check (raw_device.get_active_config_descriptor (out current_config), "Failed to get active config descriptor");

			var config = new UsbNcmConfig ();
			int desired_config_value = -1;
			bool found_cdc_header = false;
			bool found_data_interface = false;
			for (uint8 config_value = dev_desc.bNumConfigurations; config_value != 0; config_value--) {
				LibUSB.ConfigDescriptor config_desc;
				Usb.check (raw_device.get_config_descriptor_by_value (config_value, out config_desc),
					"Failed to get config descriptor");

				foreach (var iface in config_desc.@interface) {
					foreach (var setting in iface.altsetting) {
						if (setting.bInterfaceClass == LibUSB.ClassCode.COMM &&
								setting.bInterfaceSubClass == UsbCommSubclass.NCM) {
							try {
								parse_cdc_header (setting.extra, out config.mac_address_index);
								found_cdc_header = true;
							} catch (Error e) {
								break;
							}
						} else if (setting.bInterfaceClass == LibUSB.ClassCode.DATA &&
								setting.bInterfaceSubClass == UsbDataSubclass.UNDEFINED &&
								setting.endpoint.length == 2) {
							found_data_interface = true;

							config.data_iface = setting.bInterfaceNumber;
							config.data_altsetting = setting.bAlternateSetting;

							foreach (var ep in setting.endpoint) {
								if ((ep.bEndpointAddress & LibUSB.EndpointDirection.MASK) ==
										LibUSB.EndpointDirection.IN) {
									config.rx_address = ep.bEndpointAddress;
								} else {
									config.tx_address = ep.bEndpointAddress;
								}
							}
						}
					}
				}

				if (found_cdc_header || found_data_interface) {
					desired_config_value = config_value;
					break;
				}
			}
			if (!found_cdc_header || !found_data_interface)
				throw new Error.NOT_SUPPORTED ("%s", make_user_error_message ("No USB CDC-NCM interface found"));

			if (current_config.bConfigurationValue != desired_config_value) {
				unowned LibUSB.DeviceHandle handle = device.handle;
				foreach (var iface in current_config.@interface) {
					unowned LibUSB.InterfaceDescriptor setting = iface.altsetting[0];
					var res = handle.kernel_driver_active (setting.bInterfaceNumber);
					if (res == 1)
						handle.detach_kernel_driver (setting.bInterfaceNumber);
				}
				printerr ("\n=== changing configuration to %d (was %d)\n", desired_config_value, current_config.bConfigurationValue);
				Usb.check (handle.set_configuration (desired_config_value), "Failed to set configuration");
			}

			return config;
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
	}

	private string make_user_error_message (string message) {
#if WINDOWS
			return message + "; use https://zadig.akeo.ie to switch from Apple's official driver onto Microsoft's WinUSB " +
				"driver, so libusb can access it";
#else
			return message;
#endif
	}
}
