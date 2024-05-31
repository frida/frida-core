[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
	using Darwin.GCD;
	using Darwin.IOKit;

	public sealed class MacOSTunnelFinder : Object, TunnelFinder {
		public async Tunnel? find (string udid, Cancellable? cancellable) throws Error, IOError {
			var main_context = MainContext.ref_thread_default ();
			var event_queue = new DispatchQueue ("re.frida.fruity.tunnel", DispatchQueueAttr.SERIAL);

			Darwin.Xpc.Dictionary? device_info = null;
			bool all_listed = false;
			bool waiting = false;

			var pairingd = XpcClient.make_for_mach_service ("com.apple.CoreDevice.remotepairingd", event_queue);
			pairingd.notify["state"].connect ((obj, pspec) => {
				if (waiting)
					find.callback ();
			});
			pairingd.message.connect (obj => {
				var reader = new XpcObjectReader (obj);

				try {
					reader.read_member ("mangledTypeName");
					if (reader.get_string_value () == "RemotePairing.ServiceEvent") {
						reader
							.end_member ()
							.read_member ("value");
						if (reader.try_read_member ("deviceFound")) {
							reader
								.read_member ("_0")
								.read_member ("deviceInfo")
								.read_member ("udid");
							if (reader.get_string_value () == udid) {
								reader.end_member ();
								device_info = (Darwin.Xpc.Dictionary) reader.current_object;
							}
						} else if (reader.has_member ("allCurrentDevicesListed")) {
							all_listed = true;
						}
					}
				} catch (Error e) {
				}

				var source = new IdleSource ();
				source.set_callback (() => {
					if (waiting)
						find.callback ();
					return Source.REMOVE;
				});
				source.attach (main_context);
			});

			var r = new PairingdRequest ("RemotePairing.BrowseRequest");
			r.body.set_bool ("currentDevicesOnly", true);
			yield pairingd.request (r.message, cancellable);

			while (!all_listed && pairingd.state == OPEN) {
				waiting = true;
				yield;
				waiting = false;
			}

			if (device_info == null) {
				if (all_listed)
					throw new Error.INVALID_ARGUMENT ("Device not found");
				else
					throw new Error.NOT_SUPPORTED ("Unexpectedly lost connection to remotepairingd");
			}

			var pairing_device = new XpcClient (device_info.create_connection ("endpoint"), event_queue);
			var tunnel = new MacOSTunnel (pairing_device);
			yield tunnel.attach (cancellable);
			return tunnel;
		}
	}

	private sealed class MacOSTunnel : Object, Tunnel {
		public DiscoveryService discovery {
			get {
				return _discovery;
			}
		}

		private XpcClient pairing_device;
		private Darwin.Xpc.Object? assertion_identifier;
		private InetAddress? tunnel_device_address;
		private DiscoveryService? _discovery;

		public MacOSTunnel (XpcClient pairing_device) {
			this.pairing_device = pairing_device;
		}

		public async void close (Cancellable? cancellable) throws IOError {
			var r = new PairingdRequest ("RemotePairing.ReleaseAssertionRequest");
			r.body.set_value ("assertionIdentifier", assertion_identifier);
			try {
				yield pairing_device.request (r.message, cancellable);
			} catch (Error e) {
			}
		}

		public async void attach (Cancellable? cancellable) throws Error, IOError {
			var r = new PairingdRequest ("RemotePairing.CreateAssertionCommand");
			r.body.set_int64 ("flags", 0);
			var response = yield pairing_device.request (r.message, cancellable);

			var reader = new XpcObjectReader (response);
			reader.read_member ("response");

			assertion_identifier = reader
				.read_member ("assertionIdentifier")
				.get_object_value (Darwin.Xpc.Uuid.TYPE);
			reader.end_member ();

			string tunnel_ip_address = reader
				.read_member ("info")
				.read_member ("tunnelIPAddress")
				.get_string_value ();
			tunnel_device_address = new InetAddress.from_string (tunnel_ip_address);

			_discovery = yield locate_discovery_service (tunnel_device_address, cancellable);
		}

		public async IOStream open_tcp_connection (uint16 port, Cancellable? cancellable) throws Error, IOError {
			SocketConnection connection;
			try {
				var service_address = new InetSocketAddress (tunnel_device_address, port);

				var client = new SocketClient ();
				connection = yield client.connect_async (service_address, cancellable);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("%s", e.message);
			}

			Tcp.enable_nodelay (connection.socket);

			return connection;
		}

		private static async DiscoveryService locate_discovery_service (InetAddress tunnel_device_address, Cancellable? cancellable)
				throws Error, IOError {
			var path_buf = new char[4096];
			unowned string path = (string) path_buf;

			foreach (var item in XNU.query_active_tcp_connections ()) {
				if (item.family != IPV6)
					continue;
				if (!item.foreign_address.equal (tunnel_device_address))
					continue;
				if (Darwin.XNU.proc_pidpath (item.effective_pid, path_buf) <= 0)
					continue;
				if (path != "/usr/libexec/remoted")
					continue;

				try {
					var connectable = new InetSocketAddress (tunnel_device_address, item.foreign_port);

					var sc = new SocketClient ();
					SocketConnection connection = yield sc.connect_async (connectable, cancellable);
					Tcp.enable_nodelay (connection.socket);

					return yield DiscoveryService.open (connection, cancellable);
				} catch (GLib.Error e) {
				}
			}

			throw new Error.NOT_SUPPORTED ("Unable to detect RSD port");
		}
	}

	private class PairingdRequest {
		public Darwin.Xpc.Dictionary message = new Darwin.Xpc.Dictionary ();
		public Darwin.Xpc.Dictionary body = new Darwin.Xpc.Dictionary ();

		public PairingdRequest (string name) {
			message.set_string ("mangledTypeName", name);
			message.set_value ("value", body);
		}
	}

	public class MacOSFruitFinder : Object, FruitFinder {
		public string? udid_from_iface (string ifname) throws Error {
			var matching_dict = Darwin.IOKit.service_matching (Darwin.IOKit.ETHERNET_INTERFACE_CLASS);
			if (matching_dict == null)
				return null;
			matching_dict.add (CoreFoundation.String.make (Darwin.IOKit.BSD_NAME_KEY), CoreFoundation.String.make (ifname));

			var registry = IORegistry.open ();
			foreach (var service in registry.matching_services (matching_dict)) {
				var usb_serial = find_idevice (service.parent (Darwin.IOKit.IOSERVICE_PLANE));
				if (usb_serial != null)
					return usb_serial;
			}

			return null;
		}

		private string? find_idevice (IORegistryEntry service) throws Error {
			if (service.get_string_property ("CFBundleIdentifier") == "com.apple.driver.usb.cdc.ncm")
				return find_idevice (service.parent (Darwin.IOKit.IOSERVICE_PLANE));

			var props = service.get_properties ();

			var prod = props.get_string_value ("USB Product Name");
			if (prod != "iPhone" && prod != "iPad")
				return null;

			return props.get_string_value ("USB Serial Number");
		}
	}

	namespace XNU {
		public PcbList query_active_tcp_connections () {
			size_t size = 0;
			Darwin.XNU.sysctlbyname ("net.inet.tcp.pcblist_n", null, &size);

			var pcbs = new uint8[size];
			Darwin.XNU.sysctlbyname ("net.inet.tcp.pcblist_n", pcbs, &size);

			return new PcbList (pcbs);
		}

		public class PcbList {
			private uint8[] pcbs;

			internal PcbList (owned uint8[] pcbs) {
				this.pcbs = (owned) pcbs;
			}

			public Iterator iterator () {
				return new Iterator (this);
			}

			public class Iterator {
				private PcbList list;
				private InetItem * cursor;

				internal Iterator (PcbList list) {
					this.list = list;

					var gen = (Darwin.XNU.InetPcbGeneration *) list.pcbs;
					cursor = (InetItem *) ((uint8 *) list.pcbs + gen->length);
				}

				public Item? next_value () {
					InetPcb * pcb = null;
					while (true) {
						if (cursor->length == 24)
							return null;

						switch (cursor->kind) {
							case InetItemKind.PCB:
								pcb = (InetPcb *) cursor;
								break;
							case InetItemKind.SOCKET:
								var item = new Item (*pcb, *((InetSocket *) cursor));
								advance ();
								return item;
						}

						advance ();
					}
				}

				private void advance () {
					uint32 l = cursor->length;
					if (l % 8 != 0)
						l += 8 - (l % 8);
					cursor = (InetItem *) ((uint8 *) cursor + l);
				}
			}

			public class Item {
				public SocketFamily family {
					get {
						return ((pcb.version_flag & Darwin.XNU.InetVersionFlags.IPV6) != 0)
							? SocketFamily.IPV6
							: SocketFamily.IPV4;
					}
				}

				public InetAddress local_address {
					get {
						if (cached_local_address == null)
							cached_local_address = parse_address (pcb.local_address);
						return cached_local_address;
					}
				}

				public uint16 local_port {
					get {
						return uint16.from_big_endian (pcb.local_port);
					}
				}

				public InetAddress foreign_address {
					get {
						if (cached_foreign_address == null)
							cached_foreign_address = parse_address (pcb.foreign_address);
						return cached_foreign_address;
					}
				}

				public uint16 foreign_port {
					get {
						return uint16.from_big_endian (pcb.foreign_port);
					}
				}

				public int32 effective_pid {
					get {
						return sock.effective_pid;
					}
				}

				private InetPcb pcb;
				private InetSocket sock;
				private InetAddress? cached_local_address;
				private InetAddress? cached_foreign_address;

				public Item (InetPcb pcb, InetSocket sock) {
					this.pcb = pcb;
					this.sock = sock;
				}

				private InetAddress parse_address (uint8[] bytes) {
					if ((pcb.version_flag & Darwin.XNU.InetVersionFlags.IPV6) != 0)
						return new InetAddress.from_bytes (bytes, IPV6);
					var addr = (Darwin.XNU.InetAddr4in6 *) bytes;
					return new InetAddress.from_bytes ((uint8[]) &addr->addr4.s_addr, IPV4);
				}
			}
		}

		[SimpleType]
		public struct InetItem {
			public uint32 length;
			public uint32 kind;
		}

		public enum InetItemKind {
			SOCKET	= 0x001,
			PCB	= 0x010,
		}

		[SimpleType]
		public struct InetPcb {
			public uint32 length;
			public uint32 kind;

			public uint64 inpp;
			public uint16 foreign_port;
			public uint16 local_port;
			public uint32 per_protocol_pcb_low;
			public uint32 per_protocol_pcb_high;
			public uint32 generation_count_low;
			public uint32 generation_count_high;
			public int flags;
			public uint32 flow;
			public uint8 version_flag;
			public uint8 ip_ttl;
			public uint8 ip_protocol;
			public uint8 padding;
			public uint8 foreign_address[16];
			public uint8 local_address[16];
			public InetDepend4 depend4;
			public InetDepend6 depend6;
			public uint32 flowhash;
			public uint32 flags2;
		}

		[SimpleType]
		public struct InetSocket {
			public uint32 length;
			public uint32 kind;

			public uint64 so;
			public int16 type;
			public uint16 options_low;
			public uint16 options_high;
			public int16 linger;
			public int16 state;
			public uint16 pcb[4];
			public uint16 protocol_low;
			public uint16 protocol_high;
			public uint16 family_low;
			public uint16 family_high;
			public int16 qlen;
			public int16 incqlen;
			public int16 qlimit;
			public int16 timeo;
			public uint16 error;
			public int32 pgid;
			public uint32 oobmark;
			public uint32 uid;
			public int32 last_pid;
			public int32 effective_pid;
			public uint64 gencnt;
			public uint32 flags;
			public uint32 flags1;
			public int32 usecount;
			public int32 retaincnt;
			public uint32 filter_flags;
		}

		[SimpleType]
		public struct InetDepend4 {
			public uint8 ip_tos;
		}

		[SimpleType]
		public struct InetDepend6 {
			public uint8 hlim;
			public int checksum;
			public uint16 interface_index;
			public int16 hops;
		}
	}
}
