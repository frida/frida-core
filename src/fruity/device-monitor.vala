[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
	public sealed class DeviceMonitor : Object {
		private LibUSB.Context context;

		private NetworkInterface? netif;
		private bool started_tcp_connection = false;
		private uint16 next_outgoing_sequence = 1;

		private LibUSB.DeviceHandle handle;
		private uint8 rx_address;
		private uint8 tx_address;
		private uint8[] our_mac_address = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
		private uint8[]? peer_mac_address;

		private MainContext main_context;

		private DataOutputStream pcap;

		private const uint16 USB_VENDOR_APPLE = 0x05ac;

		private const size_t ETHERNET_HEADER_SIZE = 14;

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

		construct {
			try {
				pcap = new DataOutputStream (File.new_for_path ("C:\\src\\ncm.pcap").create (REPLACE_DESTINATION));
				pcap.set_byte_order (HOST_ENDIAN);
				pcap.put_uint32 (0xa1b2c3d4U);
				pcap.put_uint16 (2);
				pcap.put_uint16 (4);
				pcap.put_uint32 (0);
				pcap.put_uint32 (0);
				pcap.put_uint32 (16384);
				pcap.put_uint32 (1); // Ethernet
				pcap.flush ();
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			main_context = MainContext.ref_thread_default ();

			LibUSB.Context.init (out context);

			printerr (">>>\n");
			foreach (var device in context.get_device_list ()) {
				LibUSB.DeviceDescriptor desc;
				if (device.get_device_descriptor (out desc) != SUCCESS)
					continue;

				if (desc.idVendor != USB_VENDOR_APPLE)
					continue;

				printerr ("Found Apple device with idProduct=0x%04x\n",
					desc.idProduct);

				if (device.open (out handle) != SUCCESS) {
					printerr ("Unable to open device :(\n");
					continue;
				}

				printerr ("Opened device!!!\n");

				int config_id = -1;
				handle.get_configuration (out config_id);
				if (config_id != 5 && config_id != 6) {
					printerr ("Expected config 5 or 6, device is in %d\n", config_id);
					continue;
				}

				LibUSB.ConfigDescriptor config;
				if (device.get_active_config_descriptor (out config) != SUCCESS)
					continue;

				int ncm_iface = -1;
				int ncm_altsetting = -1;
				uint iface_id = 0;
				uint8 mac_address_index = 0;
				foreach (var iface in config.@interface) {
					uint setting_id = 0;
					foreach (var setting in iface.altsetting) {
						printerr ("iface %u setting %u: bInterfaceClass=0x%02x bInterfaceSubClass=0x%02x endpoint.length=%d extra.length=%d\n",
							iface_id, setting_id,
							setting.bInterfaceClass,
							setting.bInterfaceSubClass,
							setting.endpoint.length,
							setting.extra.length);

						if (setting.bInterfaceClass == LibUSB.ClassCode.COMM &&
								setting.bInterfaceSubClass == UsbCommSubclass.NCM) {
							try {
								parse_cdc_header (setting.extra, out mac_address_index);
								printerr ("MAC address index: %u\n", mac_address_index);
							} catch (Error e) {
								printerr ("Uh oh: %s\n", e.message);
								break;
							}
						} else if (setting.bInterfaceClass == LibUSB.ClassCode.DATA &&
								setting.bInterfaceSubClass == UsbDataSubclass.UNDEFINED &&
								setting.endpoint.length == 2) {
							ncm_iface = setting.bInterfaceNumber;
							ncm_altsetting = setting.bAlternateSetting;

							foreach (var ep in setting.endpoint) {
								if ((ep.bEndpointAddress & LibUSB.EndpointDirection.MASK) == LibUSB.EndpointDirection.IN)
									rx_address = ep.bEndpointAddress;
								else
									tx_address = ep.bEndpointAddress;
							}
						}

						setting_id++;
					}
					iface_id++;
				}
				printerr ("ncm_iface=%d ncm_altsetting=%d rx_address=0x%02x tx_address=0x%02x mac_address_index=%u\n",
					ncm_iface, ncm_altsetting, rx_address, tx_address, mac_address_index);
				if (ncm_iface == -1)
					continue;

				uint8 mac_address_buf[13];
				var get_result = handle.get_string_descriptor_ascii (mac_address_index, mac_address_buf);
				unowned string mac_address_str = (string) mac_address_buf;
				printerr ("get_result=%d \"%s\"\n", get_result, mac_address_str);
				for (uint i = 0; i != 6; i++) {
					uint v;
					mac_address_str.substring (i * 2, 2).scanf ("%02X", out v);
					our_mac_address[i] = (uint8) v;
				}

				netif = new NetworkInterface (new Bytes (our_mac_address), "fe80::90fe:2cff:fe3b:e763", 1500);
				netif.outgoing_datagram.connect (on_netif_outgoing_datagram);

				var detach_result = handle.detach_kernel_driver (ncm_iface);
				printerr ("Detach result: %s\n", detach_result.get_name ());

				var claim_result = handle.claim_interface (ncm_iface);
				printerr ("Claim result: %s\n", claim_result.get_name ());

				var altsetting_result = handle.set_interface_alt_setting (ncm_iface, ncm_altsetting);
				printerr ("Altsetting result: %s\n", altsetting_result.get_name ());

				new Thread<void> ("frida-ncm-io", () => {
					while (true) {
						uint8 data[2048];
						int n = -1;
						var transfer_result = handle.bulk_transfer (rx_address, data, out n, 10000);
						if (transfer_result != SUCCESS)
							break;

						try {
							handle_ncm_frame (data[:n]);
						} catch (Error e) {
							printerr ("%s\n", e.message);
							break;
						}
					}
				});
			}
			printerr ("<<<\n");
		}

		private void handle_ncm_frame (uint8[] data) throws Error {
			var buffer = new Buffer (new Bytes (data), LITTLE_ENDIAN);
			var signature = buffer.read_fixed_string (0, 4);
			if (signature != "NCMH")
				throw new Error.PROTOCOL ("Invalid NTH16 signature");
			var header_length = buffer.read_uint16 (4);
			var sequence = buffer.read_uint16 (6);
			var block_length = buffer.read_uint16 (8);
			var ndp_index = buffer.read_uint16 (10);

			size_t ndp_size = 8;
			signature = buffer.read_fixed_string (ndp_index, 4);
			if (signature != "NCM0")
				throw new Error.PROTOCOL ("Invalid NDP16 signature");
			var length = buffer.read_uint16 (ndp_index + 4);
			var next_ndp_index = buffer.read_uint16 (ndp_index + 6);

			size_t dpe_size = 4;
			size_t dpe_cursor = ndp_index + ndp_size;
			while (true) {
				var datagram_index = buffer.read_uint16 (dpe_cursor);
				var datagram_length = buffer.read_uint16 (dpe_cursor + 2);
				if (datagram_index == 0 || datagram_length == 0)
					break;

				unowned uint8[] datagram = data[datagram_index:datagram_index + datagram_length];
				printerr ("\n<<<\n");
				log_datagram (datagram);
				netif.handle_incoming_datagram (new Bytes (datagram));

				if (!started_tcp_connection) {
					started_tcp_connection = true;

					peer_mac_address = datagram[6:12];

					size_t ipv6_source_address_offset = 8;
					size_t start = ETHERNET_HEADER_SIZE + ipv6_source_address_offset;
					var source_address = new InetAddress.from_bytes (datagram[start:start + 16], IPV6);
					printerr ("starting TCP connection with source_address: %s\n", source_address.to_string ());

					var source = new TimeoutSource (15000);
					source.set_callback (() => {
						perform_tcp_connection.begin (source_address);
						return Source.REMOVE;
					});
					source.attach (main_context);
					printerr ("scheduling in 15 seconds\n");
				}

				dpe_cursor += dpe_size;
			}
		}

		private void on_netif_outgoing_datagram (Bytes datagram) {
			printerr ("on_netif_outgoing_datagram()\n");

			printerr ("\n>>>\n");
			log_datagram (datagram.get_data ());

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

			printerr ("\n>>>\n");
			hexdump (frame.get_data ());

			int n;
			var transfer_result = handle.bulk_transfer (tx_address, frame.get_data (), out n, 10000);
			printerr ("transfer_result: %s n=%d\n", transfer_result.get_name (), n);
		}

		private async void perform_tcp_connection (InetAddress address) {
			printerr ("perform_tcp_connection()\n");
			try {
				Cancellable? cancellable = null;

				var bootstrap_disco = yield DiscoveryService.open (
					yield netif.open_tcp_connection (address.to_string (), 58783, cancellable), cancellable);
				printerr ("udid: %s\n", bootstrap_disco.query_udid ());
			} catch (GLib.Error e) {
				printerr ("perform_tcp_connection() failed: %s\n", e.message);
			}
		}

		private void parse_cdc_header (uint8[] header, out uint8 mac_address_index) throws Error {
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

		private void log_datagram (uint8[] datagram) {
			printerr ("\tdestination=%02x:%02x:%02x:%02x:%02x:%02x source=%02x:%02x:%02x:%02x:%02x:%02x type=0x%02x%02x\n",
				datagram[0],
				datagram[1],
				datagram[2],
				datagram[3],
				datagram[4],
				datagram[5],
				datagram[6],
				datagram[7],
				datagram[8],
				datagram[9],
				datagram[10],
				datagram[11],
				datagram[12],
				datagram[13]);

			size_t ipv6_source_address_offset = 8;

			uint8 kind = datagram[ETHERNET_HEADER_SIZE + 6];

			size_t cursor = ETHERNET_HEADER_SIZE + ipv6_source_address_offset;
			var source_address = new InetAddress.from_bytes (datagram[cursor:cursor + 16], IPV6);
			cursor += 16;
			var destination_address = new InetAddress.from_bytes (datagram[cursor:cursor + 16], IPV6);

			printerr ("\t\tIPv6      source=%s\n", source_address.to_string ());
			printerr ("\t\t     destination=%s\n", destination_address.to_string ());
			printerr ("\t\t            kind=%u\n", kind);

			try {
				int64 timestamp = get_real_time ();
				pcap.put_uint32 ((uint32) (timestamp / 1000000));
				pcap.put_uint32 ((uint32) (timestamp % 1000000));
				pcap.put_uint32 (datagram.length);
				pcap.put_uint32 (datagram.length);
				size_t written;
				pcap.write_all (datagram, out written);
				pcap.flush ();
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
		}
	}

	// https://gist.github.com/phako/96b36b5070beaf7eee27
	private void hexdump (uint8[] data) {
		var builder = new StringBuilder.sized (16);
		var i = 0;

		foreach (var c in data) {
			if (i % 16 == 0)
				printerr ("%08x | ", i);

			printerr ("%02x ", c);

			if (((char) c).isprint ())
				builder.append_c ((char) c);
			else
				builder.append (".");

			i++;
			if (i % 16 == 0) {
				printerr ("| %s\n", builder.str);
				builder.erase ();
			}
		}

		if (i % 16 != 0)
			printerr ("%s| %s\n", string.nfill ((16 - (i % 16)) * 3, ' '), builder.str);
	}
}
