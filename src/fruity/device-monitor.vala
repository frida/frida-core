[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
	public sealed class DeviceMonitor : Object {
		private LibUSB.Context context;

		private NetworkInterface netif = new NetworkInterface ("fe80::90fe:2cff:fe3b:e79b", 1500);
		private bool started_tcp_connection = false;

		private const uint16 USB_VENDOR_APPLE = 0x05ac;

		private const uint8 USB_CLASS_CDC_DATA = 0x0a;
		private const uint8 USB_SUBCLASS_UNDEFINED = 0x00;

		construct {
			netif.outgoing_datagram.connect (on_netif_outgoing_datagram);

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

				LibUSB.DeviceHandle handle;
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
				int rx_address = -1;
				int tx_address = -1;
				uint iface_id = 0;
				foreach (var iface in config.@interface) {
					uint setting_id = 0;
					foreach (var setting in iface.altsetting) {
						printerr ("iface %u setting %u: bInterfaceClass=0x%02x bInterfaceSubClass=0x%02x endpoint.length=%d\n",
							iface_id, setting_id,
							setting.bInterfaceClass,
							setting.bInterfaceSubClass,
							setting.endpoint.length);
						if (setting.bInterfaceClass == USB_CLASS_CDC_DATA &&
								setting.bInterfaceSubClass == USB_SUBCLASS_UNDEFINED &&
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
				printerr ("ncm_iface=%d ncm_altsetting=%d rx_address=0x%02x tx_address=0x%02x\n",
					ncm_iface, ncm_altsetting, rx_address, tx_address);
				if (ncm_iface == -1)
					continue;

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
						var transfer_result = handle.bulk_transfer ((uint8) rx_address, data, out n, 10000);
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
				netif.handle_incoming_datagram (new Bytes (datagram));

				if (!started_tcp_connection) {
					started_tcp_connection = true;

					size_t ethernet_header_size = 14;
					size_t ipv6_source_address_offset = 8;
					size_t start = ethernet_header_size + ipv6_source_address_offset;
					var source_address = new InetAddress.from_bytes (datagram[start:start + 16], IPV6);
					printerr ("source_address: %s\n", source_address.to_string ());

					perform_tcp_connection.begin (source_address);
				}

				dpe_cursor += dpe_size;
			}
		}

		private void on_netif_outgoing_datagram (Bytes datagram) {
			printerr ("on_netif_outgoing_datagram(): TODO\n");
		}

		private async void perform_tcp_connection (InetAddress address) {
			try {
				Cancellable? cancellable = null;

				var bootstrap_disco = yield DiscoveryService.open (
					yield netif.open_tcp_connection (address.to_string (), 58783, cancellable), cancellable);
				printerr ("udid: %s\n", bootstrap_disco.query_udid ());
			} catch (GLib.Error e) {
				printerr ("perform_tcp_connection() failed: %s\n", e.message);
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
