[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
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
