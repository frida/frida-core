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
				yield resolved.resolve_record (Resolved.ANY_INTERFACE, "_remotepairing._tcp.local", DnsRecordClass.IN,
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
			while ((p = promises.poll ()) != null)
				yield p.future.wait_async (cancellable);
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
			char ifname_buf[IF_NAMESIZE];
			unowned string ifname = Linux.Network.if_indextoname (ifindex, (string) ifname_buf);

			InetSocketAddress? interface_address = null;
			Linux.Network.IfAddrs ifaddrs;
			Linux.Network.getifaddrs (out ifaddrs);
			for (unowned Linux.Network.IfAddrs candidate = ifaddrs; candidate != null; candidate = candidate.ifa_next) {
				if (candidate.ifa_name != ifname)
					continue;
				if (candidate.ifa_addr.sa_family != Posix.AF_INET6)
					continue;
				interface_address = (InetSocketAddress)
					SocketAddress.from_native ((void *) candidate.ifa_addr, sizeof (Posix.SockAddrIn6));
			}
			if (interface_address == null)
				return null;

			var address_request = new Promise<InetSocketAddress> ();
			var txt_request = new Promise<DnsTxtRecord> ();
			fetch_address.begin (ptr.name, ifindex, flags, cancellable, address_request);
			fetch_txt_record.begin (ptr.name, ifindex, flags, cancellable, txt_request);

			var address = yield address_request.future.wait_async (cancellable);
			var txt = yield txt_request.future.wait_async (cancellable);

			string? identifier = null;
			Bytes? auth_tag = null;
			foreach (var e in txt.entries) {
				string[] tokens = e.split ("=", 2);
				if (tokens.length != 2)
					continue;

				unowned string key = tokens[0];
				unowned string val = tokens[1];
				if (key == "identifier")
					identifier = val;
				else if (key == "authTag")
					auth_tag = new Bytes (Base64.decode (val));
			}
			if (identifier == null || auth_tag == null)
				return null;

			var service = new PairingServiceDetails () {
				identifier = identifier,
				auth_tag = auth_tag,
				endpoint = address,
				interface_address = interface_address,
			};
			service_discovered (service);
			return service;
		}

		private async void fetch_address (string name, int32 ifindex, Resolved.Flags flags, Cancellable? cancellable,
				Promise<InetSocketAddress> promise) {
			try {
				Resolved.RRItem[] items;
				uint64 output_flags;
				yield resolved.resolve_record (ifindex, name, DnsRecordClass.IN, DnsRecordType.SRV, flags, cancellable,
					out items, out output_flags);
				DnsSrvRecord srv = new DnsPacketReader (new Bytes (items[0].data)).read_srv ();

				yield resolved.resolve_record (ifindex, srv.name, DnsRecordClass.IN, DnsRecordType.AAAA, flags, cancellable,
					out items, out output_flags);
				DnsAaaaRecord aaaa = new DnsPacketReader (new Bytes (items[0].data)).read_aaaa ();

				var scope_id = aaaa.address.get_is_link_local () ? ifindex : 0;

				promise.resolve ((InetSocketAddress) Object.new (typeof (InetSocketAddress),
					address: aaaa.address,
					port: srv.port,
					scope_id: scope_id
				));
			} catch (GLib.Error e) {
				promise.reject (parse_error (e));
			}
		}

		private async void fetch_txt_record (string name, int32 ifindex, Resolved.Flags flags, Cancellable? cancellable,
				Promise<DnsTxtRecord> promise) {
			try {
				Resolved.RRItem[] items;
				uint64 output_flags;
				yield resolved.resolve_record (ifindex, name, DnsRecordClass.IN, DnsRecordType.TXT, flags, cancellable,
					out items, out output_flags);

				var r = new DnsPacketReader (new Bytes (items[0].data));
				promise.resolve (r.read_txt ());
			} catch (GLib.Error e) {
				promise.reject (parse_error (e));
			}
		}

		private static GLib.Error parse_error (GLib.Error e) {
			if (e is Error || e is IOError.CANCELLED)
				return e;
			return new Error.TRANSPORT ("%s", e.message);
		}
	}

	private class DnsPacketReader {
		private BufferReader reader;

		public DnsPacketReader (Bytes packet) {
			reader = new BufferReader (new Buffer (packet, BIG_ENDIAN));
		}

		public DnsPtrRecord read_ptr () throws Error {
			var rr = read_record ();
			if (rr.key.type != PTR)
				throw new Error.PROTOCOL ("Expected a PTR record");
			if (rr.key.klass != IN)
				throw new Error.PROTOCOL ("Expected a PTR record of class IN");
			var subreader = new DnsPacketReader (rr.data);
			var name = subreader.read_name ();
			return new DnsPtrRecord () {
				key = rr.key,
				ttl = rr.ttl,
				data = rr.data,
				name = name,
			};
		}

		public DnsTxtRecord read_txt () throws Error {
			var rr = read_record ();
			if (rr.key.type != TXT)
				throw new Error.PROTOCOL ("Expected a TXT record");
			if (rr.key.klass != IN)
				throw new Error.PROTOCOL ("Expected a TXT record of class IN");
			var entries = new Gee.ArrayList<string> ();
			var subreader = new DnsPacketReader (rr.data);
			while (subreader.reader.available != 0) {
				string text = subreader.read_string ();
				entries.add (text);
			}
			return new DnsTxtRecord () {
				key = rr.key,
				ttl = rr.ttl,
				data = rr.data,
				entries = entries.to_array (),
			};
		}

		public DnsAaaaRecord read_aaaa () throws Error {
			var rr = read_record ();
			if (rr.key.type != AAAA)
				throw new Error.PROTOCOL ("Expected an AAAA record");
			if (rr.key.klass != IN)
				throw new Error.PROTOCOL ("Expected an AAAA record of class IN");
			var subreader = new DnsPacketReader (rr.data);
			var raw_address = subreader.reader.read_bytes (16);
			var address = new InetAddress.from_bytes (raw_address.get_data (), IPV6);
			return new DnsAaaaRecord () {
				key = rr.key,
				ttl = rr.ttl,
				data = rr.data,
				address = address,
			};
		}

		public DnsSrvRecord read_srv () throws Error {
			var rr = read_record ();
			if (rr.key.type != SRV)
				throw new Error.PROTOCOL ("Expected a SRV record");
			if (rr.key.klass != IN)
				throw new Error.PROTOCOL ("Expected a SRV record of class IN");
			var subreader = new DnsPacketReader (rr.data);
			var priority = subreader.reader.read_uint16 ();
			var weight = subreader.reader.read_uint16 ();
			var port = subreader.reader.read_uint16 ();
			var name = subreader.read_name ();
			return new DnsSrvRecord () {
				key = rr.key,
				ttl = rr.ttl,
				data = rr.data,
				priority = priority,
				weight = weight,
				port = port,
				name = name,
			};
		}

		public DnsResourceRecord read_record () throws Error {
			var key = read_key ();
			var ttl = reader.read_uint32 ();
			var size = reader.read_uint16 ();
			var data = reader.read_bytes (size);
			return new DnsResourceRecord () {
				key = key,
				ttl = ttl,
				data = data,
			};
		}

		public DnsResourceKey read_key () throws Error {
			var name = read_name ();
			var type = reader.read_uint16 ();
			var klass = reader.read_uint16 ();
			return new DnsResourceKey () {
				name = name,
				type = type,
				klass = klass,
			};
		}

		public string read_name () throws Error {
			var name = new StringBuilder.sized (256);

			while (true) {
				size_t size = reader.read_uint8 ();
				if (size == 0)
					break;
				if (size > 63)
					throw new Error.PROTOCOL ("Invalid DNS name length");

				var label = reader.read_fixed_string (size);
				if (name.len != 0)
					name.append_c ('.');
				name.append (label);
			}

			return name.str;
		}

		public string read_string () throws Error {
			size_t size = reader.read_uint8 ();
			return reader.read_fixed_string (size);
		}
	}

	public class DnsPtrRecord : DnsResourceRecord {
		public string name;
	}

	public class DnsTxtRecord : DnsResourceRecord {
		public string[] entries;
	}

	public class DnsAaaaRecord : DnsResourceRecord {
		public InetAddress address;
	}

	public class DnsSrvRecord : DnsResourceRecord {
		public uint16 priority;
		public uint16 weight;
		public uint16 port;
		public string name;
	}

	public class DnsResourceRecord {
		public DnsResourceKey key;
		public uint32 ttl;
		public Bytes data;
	}

	public class DnsResourceKey {
		public string name;
		public DnsRecordType type;
		public DnsRecordClass klass;
	}

	public enum DnsRecordType {
		PTR	= 12,
		TXT	= 16,
		AAAA	= 28,
		SRV	= 33,
	}

	public enum DnsRecordClass {
		IN = 1,
	}

	namespace Resolved {
		public const string SERVICE_NAME = "org.freedesktop.resolve1";
		public const string SERVICE_PATH = "/org/freedesktop/resolve1";

		public const int32 ANY_INTERFACE = 0;

		[DBus (name = "org.freedesktop.resolve1.Manager")]
		public interface Manager : Object {
			public abstract async void resolve_record (int32 ifindex, string name, uint16 klass, uint16 type, uint64 flags,
				Cancellable? cancellable, out RRItem[] items, out uint64 result_flags) throws GLib.Error;
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
	}
}
