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
		private Resolved.Manager? resolved;
		private Source? timer;

		private Cancellable io_cancellable = new Cancellable ();

		private const size_t IF_NAMESIZE = 16;

		public async void start (Cancellable? cancellable) throws IOError {
			try {
				var connection = yield GLib.Bus.get (BusType.SYSTEM, cancellable);

				resolved = yield connection.get_proxy (Resolved.SERVICE_NAME, Resolved.SERVICE_PATH, DO_NOT_LOAD_PROPERTIES,
					cancellable);

				try {
					yield resolve_services (MDNS_IPV6 | NO_NETWORK, cancellable);
					schedule_next_poll ();
				} catch (Error e) {
					handle_poll_timer_tick.begin ();
				}
			} catch (GLib.Error e) {
			}
		}

		public async void stop (Cancellable? cancellable) throws IOError {
			if (timer != null) {
				timer.destroy ();
				timer = null;
			}

			io_cancellable.cancel ();
		}

		private void schedule_next_poll () {
			timer = new TimeoutSource.seconds (5);
			timer.set_callback (() => {
				timer = null;
				handle_poll_timer_tick.begin ();
				return Source.REMOVE;
			});
			timer.attach (MainContext.get_thread_default ());
		}

		private async void handle_poll_timer_tick () {
			try {
				yield resolve_services (MDNS_IPV6, io_cancellable);
				schedule_next_poll ();
			} catch (GLib.Error e) {
				if (!(e is IOError.CANCELLED))
					schedule_next_poll ();
			}
		}

		private async void resolve_services (Resolved.Flags flags, Cancellable? cancellable) throws Error, IOError {
			Resolved.RRItem[] items;
			uint64 ptr_flags;
			try {
				yield resolved.resolve_record (Resolved.ANY_INTERFACE, PairingService.DNS_SD_NAME, DnsRecordClass.IN,
					DnsRecordType.PTR, flags, cancellable, out items, out ptr_flags);
			} catch (GLib.Error e) {
				throw (Error) parse_error (e);
			}

			var promises = new Gee.ArrayQueue<Promise<PairingServiceDetails?>> ();
			foreach (var item in items) {
				var pr = new DnsPacketReader (new Bytes (item.data));
				DnsPtrRecord ptr = pr.read_ptr ();
				var promise = new Promise<PairingServiceDetails> ();
				resolve_service.begin (ptr, item.ifindex, flags, cancellable, promise);
				promises.offer (promise);
			}

			Promise<PairingServiceDetails?>? p;
			while ((p = promises.poll ()) != null) {
				try {
					yield p.future.wait_async (cancellable);
				} catch (Error e) {
				}
			}
		}

		private async void resolve_service (DnsPtrRecord ptr, int32 ifindex, Resolved.Flags flags, Cancellable? cancellable,
				Promise<PairingServiceDetails?> promise) {
			try {
				PairingServiceDetails? service = yield do_resolve_service (ptr, ifindex, flags, cancellable);
				promise.resolve (service);
			} catch (GLib.Error e) {
				promise.reject (e);
			}
		}

		private async PairingServiceDetails? do_resolve_service (DnsPtrRecord ptr, int32 ifindex, Resolved.Flags flags,
				Cancellable? cancellable) throws Error, IOError {
			Resolved.SrvItem[] srv_items;
			Variant txt_items;
			string canonical_name;
			string canonical_type;
			string canonical_domain;
			uint64 srv_flags;
			try {
				yield resolved.resolve_service (ifindex, "", "", ptr.name, Posix.AF_INET6, flags, cancellable,
					out srv_items, out txt_items, out canonical_name, out canonical_type, out canonical_domain,
					out srv_flags);
			} catch (GLib.Error e) {
				throw (Error) parse_error (e);
			}

			var txt_record = new Gee.ArrayList<string> ();
			foreach (var raw_item in txt_items) {
				string item = ((string *) raw_item.get_data ())->substring (0, (long) raw_item.get_size ());
				if (!item.validate ())
					throw new Error.PROTOCOL ("Invalid TXT item");
				txt_record.add (item);
			}

			var meta = PairingServiceMetadata.from_txt_record (txt_record);
			var ip = new InetAddress.from_bytes (srv_items[0].addresses[0].ip, IPV6);
			var service = new PairingServiceDetails () {
				identifier = meta.identifier,
				auth_tag = meta.auth_tag,
				endpoint = (InetSocketAddress) Object.new (typeof (InetSocketAddress),
					address: ip,
					port: srv_items[0].port,
					scope_id: ip.get_is_link_local () ? ifindex : 0
				),
				interface_address = resolve_interface_address (ifindex),
			};

			service_discovered (service);

			return service;
		}

		private static InetSocketAddress resolve_interface_address (int32 ifindex) throws Error {
			char ifname_buf[IF_NAMESIZE];
			unowned string? ifname = Linux.Network.if_indextoname (ifindex, (string) ifname_buf);
			if (ifname == null)
				throw new Error.INVALID_ARGUMENT ("Unable to resolve interface name");

			Linux.Network.IfAddrs ifaddrs;
			Linux.Network.getifaddrs (out ifaddrs);
			for (unowned Linux.Network.IfAddrs candidate = ifaddrs; candidate != null; candidate = candidate.ifa_next) {
				if (candidate.ifa_name != ifname)
					continue;
				if (candidate.ifa_addr.sa_family != Posix.AF_INET6)
					continue;
				return (InetSocketAddress)
					SocketAddress.from_native ((void *) candidate.ifa_addr, sizeof (Posix.SockAddrIn6));
			}

			throw new Error.NOT_SUPPORTED ("Unable to resolve interface address");
		}

		private static GLib.Error parse_error (GLib.Error e) {
			if (e is Error || e is IOError.CANCELLED)
				return e;
			return new Error.TRANSPORT ("%s", e.message);
		}
	}

	namespace Resolved {
		public const string SERVICE_NAME = "org.freedesktop.resolve1";
		public const string SERVICE_PATH = "/org/freedesktop/resolve1";

		public const int32 ANY_INTERFACE = 0;

		[DBus (name = "org.freedesktop.resolve1.Manager")]
		public interface Manager : Object {
			public abstract async void resolve_record (int32 ifindex, string name, uint16 klass, uint16 type, uint64 flags,
				Cancellable? cancellable, out RRItem[] items, out uint64 result_flags) throws GLib.Error;
			public abstract async void resolve_service (int32 ifindex, string name, string type, string domain, int32 family,
				uint64 flags, Cancellable? cancellable, out SrvItem[] srv_items,
				[DBus (signature = "aay")] out Variant txt_items, out string canonical_name, out string canonical_type,
				out string canonical_domain, out uint64 result_flags) throws GLib.Error;
		}

		[Flags]
		public enum Flags {
			DNS			= 1 << 0,
			LLMNR_IPV4		= 1 << 1,
			LLMNR_IPV6		= 1 << 2,
			MDNS_IPV4		= 1 << 3,
			MDNS_IPV6		= 1 << 4,
			NO_CNAME		= 1 << 5,
			NO_TXT			= 1 << 6,
			NO_ADDRESS		= 1 << 7,
			NO_SEARCH		= 1 << 8,
			AUTHENTICATED		= 1 << 9,
			NO_VALIDATE		= 1 << 10,
			NO_SYNTHESIZE		= 1 << 11,
			NO_CACHE		= 1 << 12,
			NO_ZONE			= 1 << 13,
			NO_TRUST_ANCHOR 	= 1 << 14,
			NO_NETWORK		= 1 << 15,
			REQUIRE_PRIMARY		= 1 << 16,
			CLAMP_TTL		= 1 << 17,
			CONFIDENTIAL		= 1 << 18,
			SYNTHETIC		= 1 << 19,
			FROM_CACHE		= 1 << 20,
			FROM_ZONE		= 1 << 21,
			FROM_TRUST_ANCHOR	= 1 << 22,
			FROM_NETWORK		= 1 << 23,
			NO_STALE		= 1 << 24,
			RELAX_SINGLE_LABEL	= 1 << 25,
		}

		public struct RRItem {
			public int32 ifindex;
			public uint16 klass;
			public uint16 type;
			public uint8[] data;
		}

		public struct SrvItem {
			public uint16 priority;
			public uint16 weight;
			public uint16 port;
			public string name;
			public SrvAddress[] addresses;
			public string canonical_name;
		}

		public struct SrvAddress {
			public int32 ifindex;
			public int32 family;
			public uint8[] ip;
		}
	}
}
