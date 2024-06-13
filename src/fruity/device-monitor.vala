[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
	public sealed class DeviceMonitor : Object {
		private LibUSB.Context context;

		private VirtualNetworkStack? netstack;
		private bool started_tcp_connection = false;
		private uint16 next_outgoing_sequence = 1;

		private LibUSB.DeviceHandle handle;
		private uint8 rx_address;
		private uint8 tx_address;
		private uint8[] our_mac_address = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
		private uint8[]? peer_mac_address;

		private MainContext main_context;

		private Cancellable io_cancellable = new Cancellable ();

		private Timer started = new Timer ();

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
			/*
			while (!Gum.Process.is_debugger_attached ()) {
				printerr ("Waiting for debugger...\n");
				Thread.usleep (1000000);
			}
			printerr ("READY!\n");
			started.reset ();
			*/

			main_context = MainContext.ref_thread_default ();

			LibUSB.Context.init (out context);

			foreach (var device in context.get_device_list ()) {
				LibUSB.DeviceDescriptor desc;
				if (device.get_device_descriptor (out desc) != SUCCESS)
					continue;

				if (desc.idVendor != USB_VENDOR_APPLE)
					continue;
				if (desc.idProduct != 0x12a8 && desc.idProduct != 0x12ab)
					continue;

				if (device.open (out handle) != SUCCESS) {
					printerr ("Unable to open device :(\n");
					continue;
				}

				printerr ("Using %04x:%04x\n", desc.idVendor, desc.idProduct);

				int config_id = -1;
				handle.get_configuration (out config_id);
				if (config_id != 5 && config_id != 6) {
					printerr ("Expected config 5 or 6, device is in %d\n", config_id);
					continue;
				}

				LibUSB.ConfigDescriptor config;
				if (device.get_active_config_descriptor (out config) != SUCCESS) {
					printerr ("Failed to get active config descriptor\n");
					continue;
				}

				int ncm_iface = -1;
				int ncm_altsetting = -1;
				uint iface_id = 0;
				uint8 mac_address_index = 0;
				foreach (var iface in config.@interface) {
					uint setting_id = 0;
					foreach (var setting in iface.altsetting) {
						if (setting.bInterfaceClass == LibUSB.ClassCode.COMM &&
								setting.bInterfaceSubClass == UsbCommSubclass.NCM) {
							try {
								parse_cdc_header (setting.extra, out mac_address_index);
							} catch (Error e) {
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
				if (ncm_iface == -1) {
					printerr ("Failed to find NCM interface\n");
					continue;
				}

				uint8 mac_address_buf[13];
				var get_result = handle.get_string_descriptor_ascii (mac_address_index, mac_address_buf);
				unowned string mac_address_str = (string) mac_address_buf;
				for (uint i = 0; i != 6; i++) {
					uint v;
					mac_address_str.substring (i * 2, 2).scanf ("%02X", out v);
					our_mac_address[i] = (uint8) v;
				}

				start.begin (ncm_iface, ncm_altsetting);
			}
		}

		private async void start (int ncm_iface, int ncm_altsetting) throws IOError {
			netstack = yield VirtualNetworkStack.create (new Bytes (our_mac_address),
				new InetAddress.from_string ("fe80::90fe:2cff:fe3b:e763"), 1500, io_cancellable);
			netstack.outgoing_datagram.connect (on_netif_outgoing_datagram);

			var res = handle.detach_kernel_driver (ncm_iface);
			printerr ("detach_kernel_driver() => %s\n", res.get_name ());
			res = handle.claim_interface (ncm_iface);
			printerr ("claim_interface() => %s\n", res.get_name ());
			handle.set_interface_alt_setting (ncm_iface, ncm_altsetting);

			new Thread<void> ("frida-ncm-io", () => {
				uint8 data[64 * 1024];

				while (true) {
					int n = -1;
					var transfer_result = handle.bulk_transfer (rx_address, data, out n, 10000);
					if (transfer_result != SUCCESS)
						break;

					log_event ("\treceived NCM frame, size: %d\n", n);

					try {
						handle_ncm_frame (data[:n]);
					} catch (Error e) {
						printerr ("%s\n", e.message);
						break;
					}
				}
			});
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
				netstack.handle_incoming_datagram (new Bytes (datagram));

				if (!started_tcp_connection) {
					started_tcp_connection = true;

					peer_mac_address = datagram[6:12];

					size_t ipv6_source_address_offset = 8;
					size_t start = ETHERNET_HEADER_SIZE + ipv6_source_address_offset;
					var source_address = new InetAddress.from_bytes (datagram[start:start + 16], IPV6);

					//var source = new IdleSource ();
					// FIXME: We might be connecting before the iDevice-side services are ready for us.
					var source = new TimeoutSource (1000);
					source.set_callback (() => {
						perform_tcp_connection.begin (source_address);
						return Source.REMOVE;
					});
					source.attach (main_context);
				}

				dpe_cursor += dpe_size;
			}
		}

		private void on_netif_outgoing_datagram (Bytes datagram) {
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

			int n;
			var transfer_result = handle.bulk_transfer (tx_address, frame.get_data (), out n, 10000);
			if (transfer_result != SUCCESS)
				printerr ("transfer_result: %s n=%d\n", transfer_result.get_name (), n);

			log_event ("\tsent NCM frame, size: %zu\n", frame.get_size ());
		}

		private async void perform_tcp_connection (InetAddress address) {
			try {
				Cancellable? cancellable = null;

				var stream = yield netstack.open_tcp_connection (new InetSocketAddress (address, 58783), cancellable);

				var bootstrap_disco = yield DiscoveryService.open (stream, cancellable);
				printerr ("udid: %s\n", bootstrap_disco.query_udid ());
				printerr ("took %u ms\n", (uint) (started.elapsed () * 1000.0));

				var tunnel_service = bootstrap_disco.get_service ("com.apple.internal.dt.coredevice.untrusted.tunnelservice");
				var pairing_transport = new XpcPairingTransport (
					yield netstack.open_tcp_connection (new InetSocketAddress (address, tunnel_service.port),
					cancellable));
				var pairing_service = yield PairingService.open (pairing_transport, cancellable);

				TunnelConnection tc = yield pairing_service.open_tunnel (address, netstack, cancellable);

				var rsd_endpoint = (InetSocketAddress) Object.new (typeof (InetSocketAddress),
					address: tc.remote_address,
					port: tc.remote_rsd_port,
					scope_id: tc.tunnel_netstack.scope_id
				);
				var rsd_connection = yield tc.tunnel_netstack.open_tcp_connection (rsd_endpoint, cancellable);
				var disco = yield DiscoveryService.open (rsd_connection, cancellable);

				printerr ("YAY! Took %u ms in total\n", (uint) (started.elapsed () * 1000.0));
			} catch (GLib.Error e) {
				printerr ("Oh noes: %s\n", e.message);
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
