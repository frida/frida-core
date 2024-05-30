[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
	public sealed class LinuxTunnelFinder : Object, TunnelFinder {
		public async Tunnel? find (string udid, Cancellable? cancellable) throws Error, IOError {
			NcmPeer? peer = yield locate_ncm_peer (udid, cancellable);
			if (peer == null)
				return null;

			var bootstrap_disco = yield DiscoveryService.open (
				yield peer.open_tcp_connection (58783, cancellable), cancellable);

			var tunnel_service = bootstrap_disco.get_service ("com.apple.internal.dt.coredevice.untrusted.tunnelservice");
			var pairing_transport = new XpcPairingTransport (yield peer.open_tcp_connection (tunnel_service.port, cancellable));
			var pairing_service = yield PairingService.open (pairing_transport, cancellable);

			TunnelConnection tc = yield pairing_service.open_tunnel (peer.address, cancellable);

			var disco = yield DiscoveryService.open (yield tc.open_connection (tc.remote_rsd_port, cancellable), cancellable);

			return new LinuxTunnel (tc, disco);
		}

		private static async NcmPeer? locate_ncm_peer (string udid, Cancellable? cancellable) throws Error, IOError {
			var device_ifaddrs = new Gee.ArrayList<unowned Linux.Network.IfAddrs> ();
			var fruit_finder = FruitFinder.make_default ();
			string raw_udid = udid.replace ("-", "");
			Linux.Network.IfAddrs ifaddrs;
			Linux.Network.getifaddrs (out ifaddrs);
			for (unowned Linux.Network.IfAddrs candidate = ifaddrs; candidate != null; candidate = candidate.ifa_next) {
				if (candidate.ifa_addr.sa_family != Posix.AF_INET6)
					continue;

				string? candidate_udid = fruit_finder.udid_from_iface (candidate.ifa_name);
				if (candidate_udid != raw_udid)
					continue;

				device_ifaddrs.add (candidate);
			}
			if (device_ifaddrs.is_empty)
				return null;

			var sockets = new Gee.ArrayList<Socket> ();
			var sources = new Gee.ArrayList<Source> ();
			var readable_sockets = new Gee.ArrayQueue<Socket> ();
			bool timed_out = false;
			bool waiting = false;

			var remote_address = new InetSocketAddress.from_string ("ff02::fb", 5353);
			var remoted_mdns_request = make_remoted_mdns_request ();
			var main_context = MainContext.get_thread_default ();

			foreach (unowned Linux.Network.IfAddrs ifaddr in device_ifaddrs) {
				try {
					var sock = new Socket (IPV6, DATAGRAM, UDP);
					sock.bind (SocketAddress.from_native ((void *) ifaddr.ifa_addr, sizeof (Posix.SockAddrIn6)), false);
					sock.send_to (remote_address, remoted_mdns_request.get_data (), cancellable);

					var source = sock.create_source (IN, cancellable);
					source.set_callback (() => {
						readable_sockets.offer (sock);
						if (waiting)
							locate_ncm_peer.callback ();
						return Source.REMOVE;
					});
					source.attach (main_context);

					sockets.add (sock);
					sources.add (source);
				} catch (GLib.Error e) {
				}
			}

			var timeout_source = new TimeoutSource.seconds (2);
			timeout_source.set_callback (() => {
				timed_out = true;
				if (waiting)
					locate_ncm_peer.callback ();
				return Source.REMOVE;
			});
			timeout_source.attach (main_context);
			sources.add (timeout_source);

			Socket? sock;
			while ((sock = readable_sockets.poll ()) == null && !timed_out) {
				waiting = true;
				yield;
				waiting = false;
			}

			foreach (var source in sources)
				source.destroy ();

			if (sock == null && timed_out)
				throw new Error.TIMED_OUT ("Unexpectedly timed out while waiting for mDNS reply");

			InetSocketAddress sender;
			try {
				SocketAddress raw_sender;
				var response_buf = new uint8[2048];
				sock.receive_from (out raw_sender, response_buf, cancellable);
				sender = (InetSocketAddress) raw_sender;
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("%s", e.message);
			}

			return new NcmPeer ("%s%%%u".printf (sender.address.to_string (), sender.scope_id));
		}

		private static Bytes make_remoted_mdns_request () {
			uint16 transaction_id = 0;
			uint16 flags = 0;
			uint16 num_questions = 1;
			uint16 answer_rrs = 0;
			uint16 authority_rrs = 0;
			uint16 additional_rrs = 0;
			string components[] = { "_remoted", "_tcp", "local" };
			uint16 record_type = 12;
			uint16 dns_class = 1;
			return new BufferBuilder (BIG_ENDIAN)
				.append_uint16 (transaction_id)
				.append_uint16 (flags)
				.append_uint16 (num_questions)
				.append_uint16 (answer_rrs)
				.append_uint16 (authority_rrs)
				.append_uint16 (additional_rrs)
				.append_uint8 ((uint8) components[0].length)
				.append_string (components[0], StringTerminator.NONE)
				.append_uint8 ((uint8) components[1].length)
				.append_string (components[1], StringTerminator.NONE)
				.append_uint8 ((uint8) components[2].length)
				.append_string (components[2], StringTerminator.NUL)
				.append_uint16 (record_type)
				.append_uint16 (dns_class)
				.build ();
		}

		private class NcmPeer {
			public string address;

			public class NcmPeer (string address) {
				this.address = address;
			}

			public async IOStream open_tcp_connection (uint16 port, Cancellable? cancellable) throws Error, IOError {
				SocketConnection connection;
				try {
					NetworkAddress service_address = NetworkAddress.parse (address, port);

					var client = new SocketClient ();
					connection = yield client.connect_async (service_address, cancellable);
				} catch (GLib.Error e) {
					throw new Error.TRANSPORT ("%s", e.message);
				}

				Tcp.enable_nodelay (connection.socket);

				return connection;
			}
		}
	}

	private sealed class LinuxTunnel : Object, Tunnel {
		public DiscoveryService discovery {
			get {
				return _discovery;
			}
		}

		private TunnelConnection tunnel_connection;
		private DiscoveryService _discovery;

		public LinuxTunnel (TunnelConnection conn, DiscoveryService disco) {
			tunnel_connection = conn;
			_discovery = disco;
		}

		public async void close (Cancellable? cancellable) throws IOError {
			tunnel_connection.cancel ();
		}

		public async IOStream open_tcp_connection (uint16 port, Cancellable? cancellable) throws Error, IOError {
			return yield tunnel_connection.open_connection (port, cancellable);
		}
	}

	public class LinuxFruitFinder : Object, FruitFinder {
		public string? udid_from_iface (string ifname) throws Error {
			var net = "/sys/class/net";

			var directory = File.new_build_filename (net, ifname);
			if (!directory.query_exists ())
				return null;

			try {
				var info = directory.query_info ("standard::*", 0);
				if (!info.get_is_symlink ())
					return null;
				var dev_path = Path.build_filename (net, info.get_symlink_target ());

				var iface = File.new_build_filename (dev_path, "..", "..", "interface");
				if (!iface.query_exists ())
					return null;
				var iface_stream = new DataInputStream (iface.read ());
				string iface_name = iface_stream.read_line ();
				if (iface_name != "NCM Control" && iface_name != "AppleUSBEthernet")
					return null;

				var serial = File.new_build_filename (dev_path, "..", "..", "..", "serial");
				if (!serial.query_exists ())
					return null;

				var serial_stream = new DataInputStream (serial.read ());
				return serial_stream.read_line ();
			} catch (GLib.Error e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
		}
	}

	public class LinuxPairingBrowser : Object, PairingBrowser {
		private DBusConnection connection;
		private AvahiServer server;
		private AvahiServiceBrowser browser;

		private Gee.List<PairingServiceDetails> current_batch = new Gee.ArrayList<PairingServiceDetails> ();

		private Cancellable io_cancellable = new Cancellable ();

		construct {
			start.begin ();
		}

		private async void start () {
			try {
				connection = yield GLib.Bus.get (BusType.SYSTEM, io_cancellable);

				server = yield connection.get_proxy (AVAHI_SERVICE_NAME, "/", DO_NOT_LOAD_PROPERTIES, io_cancellable);

				GLib.ObjectPath browser_path = yield server.service_browser_prepare (-1, INET6, PAIRING_REGTYPE,
					PAIRING_DOMAIN, 0, io_cancellable);
				browser = yield connection.get_proxy (AVAHI_SERVICE_NAME, browser_path, DO_NOT_LOAD_PROPERTIES,
					io_cancellable);
				browser.item_new.connect (on_item_new);
				browser.all_for_now.connect (on_all_for_now);
				yield browser.start (io_cancellable);
			} catch (GLib.Error e) {
				printerr ("Oopsie: %s\n", e.message);
			}
		}

		private void on_item_new (int interface_index, AvahiProtocol protocol, string name, string type, string domain, uint flags) {
			char raw_interface_name[Linux.Network.INTERFACE_NAME_SIZE];
			Linux.Network.if_indextoname (interface_index, (string) raw_interface_name);
			unowned string interface_name = (string) raw_interface_name;
			current_batch.add (new LinuxPairingServiceDetails (name, interface_index, interface_name, protocol, server));
		}

		private void on_all_for_now () {
			services_discovered (current_batch.to_array ());
			current_batch.clear ();
		}
	}

	private class LinuxPairingServiceDetails : Object, PairingServiceDetails {
		public string name {
			get { return _name; }
		}

		public uint interface_index {
			get { return _interface_index; }
		}

		public string interface_name {
			get { return _interface_name; }
		}

		private string _name;
		private uint _interface_index;
		private string _interface_name;
		private AvahiProtocol protocol;

		private AvahiServer server;

		internal LinuxPairingServiceDetails (string name, uint interface_index, string interface_name, AvahiProtocol protocol,
				AvahiServer server) {
			_name = name;
			_interface_index = interface_index;
			_interface_name = interface_name;
			this.protocol = protocol;

			this.server = server;
		}

		public async Gee.List<PairingServiceHost> resolve (Cancellable? cancellable) throws Error, IOError {
			AvahiServiceResolver resolver;
			try {
				GLib.ObjectPath path = yield server.service_resolver_prepare ((int) interface_index, protocol, name,
					PAIRING_REGTYPE, PAIRING_DOMAIN, INET6, 0, cancellable);
				DBusConnection connection = ((DBusProxy) server).get_connection ();
				resolver = yield connection.get_proxy (AVAHI_SERVICE_NAME, path, DO_NOT_LOAD_PROPERTIES, cancellable);
			} catch (GLib.Error e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}

			var promise = new Promise<Gee.List<PairingServiceHost>> ();
			var hosts = new Gee.ArrayList<PairingServiceHost> ();
			resolver.found.connect ((interface_index, protocol, name, type, domain, host, address_protocol, address, port, txt,
					flags) => {
				var txt_record = new Gee.ArrayList<string> ();
				var iter = new VariantIter (txt);
				Variant? cur;
				while ((cur = iter.next_value ()) != null) {
					unowned string raw_val = (string) cur.get_data ();
					string val = raw_val.make_valid ((ssize_t) cur.get_size ());
					txt_record.add (val);
				}

				hosts.add (new LinuxPairingServiceHost (
					host,
					new InetSocketAddress.from_string (address, port),
					port,
					txt_record));

				if (!promise.future.ready)
					promise.resolve (hosts);
			});
			resolver.failure.connect (error => {
				if (!promise.future.ready)
					promise.reject (new Error.NOT_SUPPORTED ("%s", error));
			});

			try {
				yield resolver.start (cancellable);
			} catch (GLib.Error e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}

			return yield promise.future.wait_async (cancellable);
		}
	}

	public class LinuxPairingServiceHost : Object, PairingServiceHost {
		public string name {
			get { return _name; }
		}

		public InetSocketAddress address {
			get { return _address; }
		}

		public uint16 port {
			get { return _port; }
		}

		public Gee.List<string> txt_record {
			get { return _txt_record; }
		}

		private string _name;
		private InetSocketAddress _address;
		private uint16 _port;
		private Gee.List<string> _txt_record;

		internal LinuxPairingServiceHost (string name, InetSocketAddress address, uint16 port, Gee.List<string> txt_record) {
			_name = name;
			_address = address;
			_port = port;
			_txt_record = txt_record;
		}

		public async Gee.List<InetSocketAddress> resolve (Cancellable? cancellable) throws Error, IOError {
			var result = new Gee.ArrayList<InetSocketAddress> ();
			result.add (address);
			return result;
		}
	}

	private const string AVAHI_SERVICE_NAME = "org.freedesktop.Avahi";

	[DBus (name = "org.freedesktop.Avahi.Server2")]
	private interface AvahiServer : Object {
		public abstract async GLib.ObjectPath service_browser_prepare (int interface_index, AvahiProtocol protocol, string type,
			string domain, uint flags, Cancellable? cancellable) throws GLib.Error;
		public abstract async GLib.ObjectPath service_resolver_prepare (int interface_index, AvahiProtocol protocol, string name,
			string type, string domain, AvahiProtocol aprotocol, AvahiLookupFlags flags, Cancellable? cancellable)
			throws GLib.Error;
	}

	[DBus (name = "org.freedesktop.Avahi.ServiceBrowser")]
	private interface AvahiServiceBrowser : Object {
		public signal void item_new (int interface_index, AvahiProtocol protocol, string name, string type, string domain,
			uint flags);
		public signal void item_remove (int interface_index, AvahiProtocol protocol, string name, string type, string domain,
			uint flags);
		public signal void failure (string error);
		public signal void all_for_now ();
		public signal void cache_exhausted ();

		public abstract async void start (Cancellable? cancellable) throws GLib.Error;
		public abstract async void free (Cancellable? cancellable) throws GLib.Error;
	}

	[DBus (name = "org.freedesktop.Avahi.ServiceResolver")]
	private interface AvahiServiceResolver : Object {
		public signal void found (int interface_index, AvahiProtocol protocol, string name, string type, string domain, string host,
			AvahiProtocol address_protocol, string address, uint16 port, [DBus (signature = "aay")] Variant txt, uint flags);
		public signal void failure (string error);

		public abstract async void start (Cancellable? cancellable) throws GLib.Error;
		public abstract async void free (Cancellable? cancellable) throws GLib.Error;
	}

	private enum AvahiProtocol {
		INET,
		INET6,
		UNSPEC = -1,
	}

	[Flags]
	private enum AvahiLookupFlags {
		USE_WIDE_AREA = 1,
		USE_MULTICAST = 2,
		NO_TXT = 4,
		NO_ADDRESS = 8,
	}
}
