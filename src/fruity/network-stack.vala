[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
	public interface NetworkStack : Object {
		public abstract InetAddress listener_ip {
			get;
		}

		public abstract uint scope_id {
			get;
		}

		public abstract async IOStream open_tcp_connection (InetSocketAddress address, Cancellable? cancellable)
			throws Error, IOError;

		public async IOStream open_tcp_connection_with_timeout (InetSocketAddress address, uint timeout, Cancellable? cancellable)
				throws Error, IOError {
			bool timed_out = false;
			var open_cancellable = new Cancellable ();

			var main_context = MainContext.get_thread_default ();

			var timeout_source = new TimeoutSource (timeout);
			timeout_source.set_callback (() => {
				timed_out = true;
				open_cancellable.cancel ();
				return Source.REMOVE;
			});
			timeout_source.attach (main_context);

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (() => {
				open_cancellable.cancel ();
				return Source.REMOVE;
			});
			cancel_source.attach (main_context);

			try {
				return yield open_tcp_connection (address, open_cancellable);
			} catch (IOError e) {
				assert (e is IOError.CANCELLED);
				if (timed_out)
					throw new Error.TIMED_OUT ("Networked Apple device is not responding");
				throw e;
			} finally {
				timeout_source.destroy ();
				cancel_source.destroy ();
			}
		}

		public abstract UdpSocket create_udp_socket () throws Error;
	}

	public interface UdpSocket : Object {
		public abstract DatagramBased datagram_based {
			get;
		}

		public abstract void bind (InetSocketAddress address) throws Error;
		public abstract InetSocketAddress get_local_address () throws Error;
		public abstract void socket_connect (InetSocketAddress address, Cancellable? cancellable) throws Error;
	}

	public sealed class SystemNetworkStack : Object, NetworkStack {
		public InetAddress listener_ip {
			get {
				return _listener_ip;
			}
		}

		public uint scope_id {
			get {
				return _scope_id;
			}
		}

		private InetAddress _listener_ip;
		private uint _scope_id;

		public SystemNetworkStack (InetAddress listener_ip, uint scope_id) {
			_listener_ip = listener_ip;
			_scope_id = scope_id;
		}

		public async IOStream open_tcp_connection (InetSocketAddress address, Cancellable? cancellable) throws Error, IOError {
			return yield open_system_tcp_connection (address, cancellable);
		}

		public UdpSocket create_udp_socket () throws Error {
			return create_system_udp_socket ();
		}

		public static async IOStream open_system_tcp_connection (InetSocketAddress address, Cancellable? cancellable)
				throws Error, IOError {
			SocketConnection connection;
			try {
				var client = new SocketClient ();
				connection = yield client.connect_async (address, cancellable);
			} catch (GLib.Error e) {
				if (e is IOError.CONNECTION_REFUSED)
					throw new Error.SERVER_NOT_RUNNING ("%s", e.message);
				throw new Error.TRANSPORT ("%s", e.message);
			}

			Tcp.enable_nodelay (connection.socket);

			return connection;
		}

		public static UdpSocket create_system_udp_socket () throws Error {
			try {
				var handle = new Socket (IPV6, DATAGRAM, UDP);
				return new SystemUdpSocket (handle);
			} catch (GLib.Error e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
		}

		private class SystemUdpSocket : Object, UdpSocket {
			public Socket handle {
				get;
				construct;
			}

			public DatagramBased datagram_based {
				get {
					return handle;
				}
			}

			public SystemUdpSocket (Socket handle) {
				Object (handle: handle);
			}

			public void bind (InetSocketAddress address) throws Error {
				try {
					handle.bind (address, true);
				} catch (GLib.Error e) {
					throw new Error.NOT_SUPPORTED ("%s", e.message);
				}
			}

			public InetSocketAddress get_local_address () throws Error {
				try {
					return (InetSocketAddress) handle.get_local_address ();
				} catch (GLib.Error e) {
					throw new Error.NOT_SUPPORTED ("%s", e.message);
				}
			}

			public void socket_connect (InetSocketAddress address, Cancellable? cancellable) throws Error {
				try {
					handle.connect (address, cancellable);
				} catch (GLib.Error e) {
					throw new Error.TRANSPORT ("%s", e.message);
				}
			}
		}
	}

	public sealed class VirtualNetworkStack : Object, NetworkStack {
		public signal void outgoing_datagram (Bytes datagram);

		public Bytes? ethernet_address {
			get;
			construct;
		}

		public InetAddress? ipv6_address {
			get;
			construct;
		}

		public InetAddress listener_ip {
			get {
				return _listener_ip;
			}
		}

		public uint scope_id {
			get {
				return (ipv6_address == null) ? interface_index : 0;
			}
		}

		public uint16 mtu {
			get;
			construct;
		}

		private uint interface_index;
		private InetAddress _listener_ip;

		private State state = STARTED;

		private UnixInputStream input;
		private UnixOutputStream output;

		private Cancellable io_cancellable = new Cancellable ();

		private enum State {
			STARTED,
			STOPPED
		}

		public class VirtualNetworkStack (Bytes? ethernet_address, InetAddress? ipv6_address, uint16 mtu) {
			Object (
				ethernet_address: ethernet_address,
				ipv6_address: ipv6_address,
				mtu: mtu
			);
		}

		construct {
			var fd = Posix.open ("/dev/net/tun", Posix.O_RDWR);
			assert (fd != -1);

			input = new UnixInputStream (fd, true);
			output = new UnixOutputStream (fd, false);

			var req = Linux.Network.IfReq ();
			req.ifr_flags = ((ipv6_address != null) ? Linux.If.IFF_TUN : Linux.If.IFF_TAP) | Linux.If.IFF_NO_PI;
			Posix.strcpy ((string) ((Linux.Network.IfReq *) &req)->ifr_name, (ipv6_address != null) ? "tun%d" : "tap%d");

			var res = Linux.ioctl (fd, Linux.If.TUNSETIFF, &req);
			if (res == -1) {
				printerr ("TUNSETIFF failed: %s\n", Posix.strerror (errno));
				assert_not_reached ();
			}
			unowned string iface = (string) req.ifr_name;
			interface_index = Linux.Network.if_nametoindex (iface);

			var netfd = Posix.socket (Linux.Socket.AF_NETLINK, Posix.SOCK_RAW | Linux.Socket.SOCK_CLOEXEC,
				Linux.Netlink.NETLINK_ROUTE);

			if (ipv6_address != null) {
				_listener_ip = ipv6_address;
			} else {
				_listener_ip = generate_ipv6_from_mac (ethernet_address.get_data ());

				var mac_request = new NewLinkSetMacRequest (interface_index, ethernet_address.get_data ());
				Posix.write (netfd, mac_request.data, mac_request.size);
			}

			var nar = new NewAddrRequest (interface_index, _listener_ip);
			Posix.write (netfd, nar.data, nar.size);

			if (ipv6_address != null) {
				var nlur = new NewLinkUpRequest (interface_index);
				Posix.write (netfd, nlur.data, nlur.size);
			}

			Posix.close (netfd);

			state = STARTED;

			process_outgoing_datagrams.begin ();
		}

		public override void dispose () {
			stop ();

			base.dispose ();
		}

		public void stop () {
			if (state == STOPPED)
				return;

			io_cancellable.cancel ();

			state = STOPPED;
		}

		public async IOStream open_tcp_connection (InetSocketAddress address, Cancellable? cancellable = null)
				throws Error, IOError {
			return yield SystemNetworkStack.open_system_tcp_connection (address, cancellable);
		}

		public UdpSocket create_udp_socket () throws Error {
			return SystemNetworkStack.create_system_udp_socket ();
		}

		public void handle_incoming_datagram (Bytes datagram) throws Error {
			try {
				output.write_all (datagram.get_data (), null);
			} catch (IOError e) {
				assert_not_reached ();
			}
		}

		private async void process_outgoing_datagrams () {
			try {
				while (true) {
					var datagram = yield input.read_bytes_async (2048, Priority.DEFAULT, io_cancellable);
					outgoing_datagram (datagram);
				}
			} catch (GLib.Error e) {
			}

			try {
				input.close ();
			} catch (IOError e) {
				assert_not_reached ();
			}
		}

		private static InetAddress generate_ipv6_from_mac (uint8[] mac) {
			assert (mac.length == 6);

			uint8 eui64[8];
			eui64[0] = mac[0] ^ 0x02;
			eui64[1] = mac[1];
			eui64[2] = mac[2];
			eui64[3] = 0xff;
			eui64[4] = 0xfe;
			eui64[5] = mac[3];
			eui64[6] = mac[4];
			eui64[7] = mac[5];

			uint8 ipv6[16];
			ipv6[0] = 0xfe;
			ipv6[1] = 0x80;
			Memory.copy ((uint8 *) ipv6 + 8, eui64, eui64.length);

			return new InetAddress.from_bytes (ipv6, SocketFamily.IPV6);
		}

		private class NewLinkSetMacRequest {
			public uint8[] data;
			public size_t size;

			private const uint16 ARPHRD_ETHER = 1;
			private const uint16 IFLA_ADDRESS = 1;

			public NewLinkSetMacRequest (uint interface_index, uint8[] mac_address) {
				assert (mac_address.length == 6);

				data = new uint8[sizeof (Linux.Netlink.NlMsgHdr) + sizeof (Linux.Netlink.IfInfoMsg) +
					Linux.Netlink.RTA_LENGTH (6)];

				var header = (Linux.Netlink.NlMsgHdr *) data;
				header->nlmsg_len = Linux.Netlink.NLMSG_LENGTH ((int) sizeof (Linux.Netlink.IfInfoMsg));
				header->nlmsg_type = Linux.Netlink.RtMessageType.NEWLINK;
				header->nlmsg_flags = (uint16) Linux.Netlink.NLM_F_REQUEST;

				var payload = (Linux.Netlink.IfInfoMsg *) (header + 1);
				payload->ifi_family = (uchar) Linux.Socket.AF_UNSPEC;
				payload->ifi_type = ARPHRD_ETHER;
				payload->ifi_index = (int) interface_index;
				payload->ifi_flags = Linux.Network.IfFlag.BROADCAST | Linux.Network.IfFlag.UP;
				payload->ifi_change = 0xffffffffU;

				var attr = (Linux.Netlink.RtAttr *) (payload + 1);
				attr->rta_len = (ushort) Linux.Netlink.RTA_LENGTH (6);
				attr->rta_type = IFLA_ADDRESS;
				header->nlmsg_len += attr->rta_len;
				Memory.copy (Linux.Netlink.RTA_DATA (attr), mac_address, 6);

				size = header->nlmsg_len;
			}
		}

		private class NewAddrRequest {
			public uint8[] data;
			public size_t size;

			private const uint8 IFA_F_NODAD = 0x02;
			private const uint8 IFA_F_PERMANENT = 0x80;

			public NewAddrRequest (uint interface_index, InetAddress ip) {
				data = new uint8[sizeof (Linux.Netlink.NlMsgHdr) + sizeof (Linux.Network.IfAddrMsg) + 64];

				var header = (Linux.Netlink.NlMsgHdr *) data;
				header->nlmsg_len = Linux.Netlink.NLMSG_LENGTH ((int) sizeof (Linux.Network.IfAddrMsg));
				header->nlmsg_type = Linux.Netlink.RtMessageType.NEWADDR;
				header->nlmsg_flags = (uint16) (Linux.Netlink.NLM_F_REQUEST | Linux.Netlink.NLM_F_EXCL | Linux.Netlink.NLM_F_CREATE);

				var payload = (Linux.Network.IfAddrMsg *) (header + 1);
				payload->ifa_family = (uint8) Posix.AF_INET6;
				payload->ifa_prefixlen = 64;
				payload->ifa_flags = IFA_F_NODAD | IFA_F_PERMANENT;
				payload->ifa_index = interface_index;

				var attr = Linux.Network.IFA_RTA (payload);
				attr->rta_len = (ushort) Linux.Netlink.RTA_LENGTH ((int) sizeof (Posix.In6Addr));
				attr->rta_type = Linux.Network.IfAddrType.ADDRESS;
				header->nlmsg_len += attr->rta_len;
				unowned uint8[] raw_ip = ip.to_bytes ();
				Memory.copy (Linux.Netlink.RTA_DATA (attr), raw_ip, sizeof (Posix.In6Addr));

				size = header->nlmsg_len;
			}
		}

		private class NewLinkUpRequest {
			public uint8[] data;
			public size_t size;

			public NewLinkUpRequest (uint interface_index) {
				data = new uint8[sizeof (Linux.Netlink.NlMsgHdr) + sizeof (Linux.Netlink.IfInfoMsg)];

				var header = (Linux.Netlink.NlMsgHdr *) data;
				header->nlmsg_len = Linux.Netlink.NLMSG_LENGTH ((int) sizeof (Linux.Netlink.IfInfoMsg));
				header->nlmsg_type = Linux.Netlink.RtMessageType.NEWLINK;
				header->nlmsg_flags = (uint16) Linux.Netlink.NLM_F_REQUEST;

				var payload = (Linux.Netlink.IfInfoMsg *) (header + 1);
				payload->ifi_index = (int) interface_index;
				payload->ifi_flags = Linux.Network.IfFlag.UP;
				payload->ifi_change = 1;

				size = header->nlmsg_len;
			}
		}
	}
}
