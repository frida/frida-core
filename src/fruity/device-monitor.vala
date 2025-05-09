[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
	public sealed class DeviceMonitor : Object {
		public signal void device_attached (Device device);
		public signal void device_detached (Device device);

		private State state = CREATED;
		private Gee.List<Backend> backends = new Gee.ArrayList<Backend> ();
		private Gee.Map<string, Device> devices = new Gee.HashMap<string, Device> ();

		private PairingStore pairing_store = new PairingStore ();

		private enum State {
			CREATED,
			STARTING,
			STARTED,
			STOPPED,
		}

		private delegate void NotifyCompleteFunc ();

		construct {
			add_backend (new UsbmuxBackend (pairing_store));
#if MACOS
			add_backend (new MacOSCoreDeviceBackend ());
#else
			add_backend (new PortableCoreDeviceBackend (pairing_store));
#endif
		}

		public async void start (Cancellable? cancellable = null) throws IOError {
			state = STARTING;

			var remaining = backends.size + 1;

			NotifyCompleteFunc on_complete = () => {
				remaining--;
				if (remaining == 0)
					start.callback ();
			};

			foreach (var backend in backends)
				do_start.begin (backend, cancellable, on_complete);

			var source = new IdleSource ();
			source.set_callback (() => {
				on_complete ();
				return Source.REMOVE;
			});
			source.attach (MainContext.get_thread_default ());

			yield;

			on_complete = null;

			var b = (PortableCoreDeviceBackend) backends.first_match (b => b is PortableCoreDeviceBackend);
			if (b != null && b.supports_modeswitch)
				yield b.activate_modeswitch_support (cancellable);

			state = STARTED;

			foreach (var device in devices.values)
				device_attached (device);
		}

		public async void stop (Cancellable? cancellable = null) throws IOError {
			var remaining = backends.size + 1;

			NotifyCompleteFunc on_complete = () => {
				remaining--;
				if (remaining == 0)
					stop.callback ();
			};

			foreach (var backend in backends)
				do_stop.begin (backend, cancellable, on_complete);

			var source = new IdleSource ();
			source.set_callback (() => {
				on_complete ();
				return Source.REMOVE;
			});
			source.attach (MainContext.get_thread_default ());

			yield;

			on_complete = null;

			foreach (var device in devices.values)
				device.close ();
			devices.clear ();

			state = STOPPED;
		}

		private async void do_start (Backend backend, Cancellable? cancellable, NotifyCompleteFunc on_complete) {
			try {
				yield backend.start (cancellable);
			} catch (IOError e) {
			}

			on_complete ();
		}

		private async void do_stop (Backend backend, Cancellable? cancellable, NotifyCompleteFunc on_complete) {
			try {
				yield backend.stop (cancellable);
			} catch (IOError e) {
			}

			on_complete ();
		}

		private void add_backend (Backend backend) {
			backends.add (backend);
			backend.transport_attached.connect (on_transport_attached);
			backend.transport_detached.connect (on_transport_detached);
		}

		private void on_transport_attached (Transport transport) {
			unowned string udid = transport.udid;

			var device = devices[udid];
			if (device == null) {
				device = new Device ();
				devices[udid] = device;
			}

			device.transports.add (transport);

			if (state != STARTING && device.transports.size == 1)
				device_attached (device);
		}

		private void on_transport_detached (Transport transport) {
			unowned string udid = transport.udid;

			var device = devices[udid];
			device.transports.remove (transport);
			if (device.transports.is_empty) {
				devices.unset (udid);

				if (state != STARTING)
					device_detached (device);
			}
		}
	}

	public sealed class Device : Object, HostChannelProvider {
		public ConnectionType connection_type {
			get {
				return (transports.first_match (t => t.connection_type == USB) != null)
					? ConnectionType.USB
					: ConnectionType.NETWORK;
			}
		}

		public string udid {
			get {
				foreach (var transport in transports)
					return transport.udid;
				assert_not_reached ();
			}
		}

		public string name {
			get {
				var transport = transports.first_match (t => t.name != null);
				if (transport == null)
					return "iOS Device";
				return transport.name;
			}
		}

		public Variant? icon {
			get {
				var transport = transports.first_match (t => t.icon != null);
				if (transport == null)
					return null;
				return transport.icon;
			}
		}

		public Gee.Set<Transport> transports {
			get;
			default = new Gee.TreeSet<Transport> (compare_transports);
		}

		private const string[] LOCKDOWN_SERVICES_WITHOUT_ESCROW_BAG_SUPPORT = {
			"com.apple.accessibility.axAuditDaemon.remoteserver",
			"com.apple.afc",
			"com.apple.companion_proxy",
			"com.apple.crashreportcopymobile",
			"com.apple.GPUTools.MobileService",
			"com.apple.idamd",
			"com.apple.PurpleReverseProxy.Conn",
			"com.apple.streaming_zip_conduit",
			"com.apple.webinspector",
		};

		internal void close () {
			transports.clear ();
		}

		public UsbmuxDevice? find_usbmux_device () {
			var t = transports.first_match (t => t.usbmux_device != null);
			return (t != null) ? t.usbmux_device : null;
		}

		private UsbmuxTransport get_usbmux_transport () throws Error {
			var t = transports.first_match (t => t is UsbmuxTransport);
			if (t == null)
				throw new Error.NOT_SUPPORTED ("USB connection not available");
			return (UsbmuxTransport) t;
		}

		public async Tunnel? find_tunnel (Cancellable? cancellable) throws Error, IOError {
			var usbmux_device = find_usbmux_device ();

			var transports_to_try = new Gee.ArrayList<Transport> ();
			transports_to_try.add_all_iterator (transports.filter (t => t.usbmux_device == null));
			transports_to_try.add_all_iterator (transports.filter (t => t.usbmux_device != null));

			foreach (var transport in transports_to_try) {
				Tunnel? tunnel = yield transport.find_tunnel (usbmux_device, cancellable);
				if (tunnel != null)
					return tunnel;
			}

			return null;
		}

		public async LockdownClient get_lockdown_client (Cancellable? cancellable) throws Error, IOError {
			var stream = yield open_lockdown_service ("", cancellable);
			return new LockdownClient (stream);
		}

		public async IOStream open_lockdown_service (string service_name, Cancellable? cancellable) throws Error, IOError {
			var tunnel = yield find_tunnel (cancellable);
			if (tunnel != null) {
				ServiceInfo? service_info = null;
				bool needs_checkin = service_name == "";
				try {
					service_info = tunnel.discovery.get_service (
						(service_name == "") ? "com.apple.mobile.lockdown.remote.trusted" : service_name);
				} catch (Error e) {
					if (!(e is Error.NOT_SUPPORTED))
						throw e;
				}
				if (service_info == null) {
					service_info = tunnel.discovery.get_service (service_name + ".shim.remote");
					needs_checkin = true;
				}

				var stream = yield tunnel.open_tcp_connection (service_info.port, cancellable);

				if (needs_checkin) {
					var service = new PlistServiceClient (stream);

					var checkin = new Plist ();
					checkin.set_string ("Request", "RSDCheckin");
					checkin.set_string ("Label", "Xcode");
					checkin.set_string ("ProtocolVersion", "2");
					unowned Bytes? key = tunnel.remote_unlock_host_key;
					if (key != null && lockdown_service_supports_escrow_bag (service_name))
						checkin.set_bytes ("EscrowBag", key);

					try {
						yield service.query (checkin, cancellable);

						var result = yield service.read_message (cancellable);
						if (result.has ("Error")) {
							var error_type = result.get_string ("Error");
							if (error_type == "ServiceProhibited")
								throw new Error.PERMISSION_DENIED ("Service prohibited");
							throw new Error.NOT_SUPPORTED ("%s", error_type);
						}
					} catch (PlistServiceError e) {
						throw new Error.PROTOCOL ("%s", e.message);
					} catch (PlistError e) {
						throw new Error.PROTOCOL ("%s", e.message);
					}
				}

				return stream;
			}

			return yield get_usbmux_transport ().open_lockdown_service (service_name, cancellable);
		}

		// FIXME: Replace with `element in array`-check once Vala compiler bug has been fixed so generated C code is warning-free.
		private static bool lockdown_service_supports_escrow_bag (string name) {
			foreach (unowned string s in LOCKDOWN_SERVICES_WITHOUT_ESCROW_BAG_SUPPORT) {
				if (s == name)
					return false;
			}
			return true;
		}

		public async IOStream open_channel (string address, Cancellable? cancellable) throws Error, IOError {
			string[] tokens = address.split (":", 2);
			unowned string protocol = tokens[0];
			unowned string location = tokens[1];

			if (protocol == "tcp") {
				var channel = yield open_tcp_channel (location, ALLOW_ANY_TRANSPORT, cancellable);
				return channel.stream;
			}

			if (protocol == "lockdown")
				return yield open_lockdown_service (location, cancellable);

			throw new Error.NOT_SUPPORTED ("Unsupported channel address");
		}

		public async TcpChannel open_tcp_channel (string location, OpenTcpChannelFlags flags, Cancellable? cancellable)
				throws Error, IOError {
			var usbmux_device = find_usbmux_device ();
			var tunnel = yield find_tunnel (cancellable);

			uint16 port;
			ulong raw_port;
			if (ulong.try_parse (location, out raw_port)) {
				if (raw_port == 0 || raw_port > uint16.MAX)
					throw new Error.INVALID_ARGUMENT ("Invalid TCP port");
				port = (uint16) raw_port;
			} else {
				if (tunnel == null)
					throw new Error.NOT_SUPPORTED ("Unable to resolve port name; tunnel not available");
				if ((flags & OpenTcpChannelFlags.ALLOW_TUNNEL) == 0)
					throw new Error.NOT_SUPPORTED ("Connection to tunnel service not allowed by flags");
				var service_info = tunnel.discovery.get_service (location);
				port = service_info.port;
			}

			Error? pending_error = null;

			if ((flags & OpenTcpChannelFlags.ALLOW_TUNNEL) != 0 && tunnel != null) {
				try {
					var stream = yield tunnel.open_tcp_connection (port, cancellable);
					return new TcpChannel () { stream = stream, kind = TUNNEL };
				} catch (Error e) {
					if (e is Error.SERVER_NOT_RUNNING)
						pending_error = e;
					else
						throw e;
				}
			}

			if ((flags & OpenTcpChannelFlags.ALLOW_USBMUX) != 0 && usbmux_device != null) {
				if (usbmux_device.connection_type == USB) {
					UsbmuxClient client = null;
					try {
						client = yield UsbmuxClient.open (cancellable);

						yield client.connect_to_port (usbmux_device.id, port, cancellable);

						return new TcpChannel () { stream = client.connection, kind = USBMUX };
					} catch (GLib.Error e) {
						if (client != null)
							client.close.begin ();

						if (e is UsbmuxError.CONNECTION_REFUSED)
							throw new Error.SERVER_NOT_RUNNING ("%s", e.message);

						throw new Error.TRANSPORT ("%s", e.message);
					}
				}

				InetSocketAddress device_address = usbmux_device.network_address;
				var target_address = (InetSocketAddress) Object.new (typeof (InetSocketAddress),
					address: device_address.address,
					port: port,
					flowinfo: device_address.flowinfo,
					scope_id: device_address.scope_id
				);

				var client = new SocketClient ();
				try {
					var connection = yield client.connect_async (target_address, cancellable);

					Tcp.enable_nodelay (connection.socket);

					return new TcpChannel () { stream = connection, kind = USBMUX };
				} catch (GLib.Error e) {
					if (e is IOError.CONNECTION_REFUSED)
						throw new Error.SERVER_NOT_RUNNING ("%s", e.message);

					throw new Error.TRANSPORT ("%s", e.message);
				}
			}

			if (pending_error != null)
				throw pending_error;
			throw new Error.TRANSPORT ("No viable transport found");
		}

		private static int compare_transports (Transport a, Transport b) {
			return score_transport (b) - score_transport (a);
		}

		private static int score_transport (Transport t) {
			int score = 0;
			if (t.connection_type == USB)
				score++;
			if (t.usbmux_device != null)
				score++;
			return score;
		}
	}

	public class TcpChannel {
		public IOStream stream;
		public Kind kind;

		public enum Kind {
			USBMUX,
			TUNNEL
		}
	}

	[Flags]
	public enum OpenTcpChannelFlags {
		ALLOW_USBMUX,
		ALLOW_TUNNEL,
		ALLOW_ANY_TRANSPORT = ALLOW_USBMUX | ALLOW_TUNNEL,
	}

	public interface Transport : Object {
		public abstract ConnectionType connection_type {
			get;
		}

		public abstract string udid {
			get;
		}

		public abstract string? name {
			get;
		}

		public abstract Variant? icon {
			get;
		}

		public abstract UsbmuxDevice? usbmux_device {
			get;
		}

		public abstract async Tunnel? find_tunnel (UsbmuxDevice? device, Cancellable? cancellable) throws Error, IOError;
	}

	public enum ConnectionType {
		USB,
		NETWORK
	}

	public interface Tunnel : Object {
		public abstract DiscoveryService discovery {
			get;
		}

		public abstract int64 opened_at {
			get;
		}

		public abstract Bytes? remote_unlock_host_key {
			get;
		}

		public abstract async void close (Cancellable? cancellable) throws IOError;
		public abstract async IOStream open_tcp_connection (uint16 port, Cancellable? cancellable) throws Error, IOError;
	}

	public interface Backend : Object {
		public signal void transport_attached (Transport transport);
		public signal void transport_detached (Transport transport);

		public abstract async void start (Cancellable? cancellable) throws IOError;
		public abstract async void stop (Cancellable? cancellable) throws IOError;
	}

	private sealed class UsbmuxBackend : Object, Backend {
		public PairingStore pairing_store {
			get;
			construct;
		}

		public bool available {
			get {
				return usbmux != null;
			}
		}

		private Gee.Map<UsbmuxDevice, UsbmuxTransport> transports = new Gee.HashMap<UsbmuxDevice, UsbmuxTransport> ();

		private UsbmuxClient? usbmux;

		private Promise<bool> start_request;
		private Cancellable start_cancellable;
		private SourceFunc on_start_completed;

		private Cancellable io_cancellable = new Cancellable ();

		public UsbmuxBackend (PairingStore pairing_store) {
			Object (pairing_store: pairing_store);
		}

		public async void start (Cancellable? cancellable) throws IOError {
			start_request = new Promise<bool> ();
			start_cancellable = new Cancellable ();
			on_start_completed = start.callback;

			var main_context = MainContext.get_thread_default ();

			var timeout_source = new TimeoutSource (500);
			timeout_source.set_callback (start.callback);
			timeout_source.attach (main_context);

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (start.callback);
			cancel_source.attach (main_context);

			do_start.begin ();

			yield;

			cancel_source.destroy ();
			timeout_source.destroy ();
			on_start_completed = null;
		}

		private async void do_start () {
			bool success = yield try_open_usbmux_client ();
			if (success) {
				/* Perform a dummy-request to flush out any pending device attach notifications. */
				try {
					yield usbmux.connect_to_port (uint.MAX, 0, start_cancellable);
					assert_not_reached ();
				} catch (GLib.Error expected_error) {
					if (expected_error.code == IOError.CONNECTION_CLOSED) {
						/* Deal with usbmuxd closing the connection when receiving commands in the wrong state. */
						usbmux.close.begin (null);

						success = yield try_open_usbmux_client ();
						if (success) {
							UsbmuxClient flush_client = null;
							try {
								flush_client = yield UsbmuxClient.open (start_cancellable);
								try {
									yield flush_client.connect_to_port (uint.MAX, 0, start_cancellable);
									assert_not_reached ();
								} catch (GLib.Error expected_error) {
								}
							} catch (GLib.Error e) {
								success = false;
							}

							if (flush_client != null)
								flush_client.close.begin (null);

							if (!success && usbmux != null) {
								usbmux.close.begin (null);
								usbmux = null;
							}
						}
					}
				}
			}

			start_request.resolve (success);

			if (on_start_completed != null)
				on_start_completed ();
		}

		private async bool try_open_usbmux_client () {
			bool success = true;

			try {
				usbmux = yield UsbmuxClient.open (start_cancellable);
				usbmux.device_attached.connect (on_device_attached);
				usbmux.device_detached.connect (on_device_detached);

				yield usbmux.enable_listen_mode (start_cancellable);
			} catch (GLib.Error e) {
				success = false;
			}

			if (!success && usbmux != null) {
				usbmux.close.begin (null);
				usbmux = null;
			}

			return success;
		}

		public async void stop (Cancellable? cancellable) throws IOError {
			io_cancellable.cancel ();
			start_cancellable.cancel ();

			try {
				yield start_request.future.wait_async (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}

			if (usbmux != null) {
				yield usbmux.close (cancellable);
				usbmux = null;
			}

			transports.clear ();
		}

		private void on_device_attached (UsbmuxDevice device) {
			add_transport.begin (device);
		}

		private void on_device_detached (UsbmuxDevice device) {
			remove_transport (device);
		}

		private async void add_transport (UsbmuxDevice device) {
			var transport = new UsbmuxTransport (device, pairing_store);
			transports[device] = transport;

			string? name = null;
			Variant? icon = null;
			if (device.connection_type == USB) {
				bool got_details = false;
				for (int i = 1; !got_details && transports.has_key (device); i++) {
					try {
						_extract_details_for_device (device.product_id, device.udid, out name, out icon);
						got_details = true;
					} catch (Error e) {
						if (i != 20) {
							var main_context = MainContext.get_thread_default ();

							var delay_source = new TimeoutSource.seconds (1);
							delay_source.set_callback (add_transport.callback);
							delay_source.attach (main_context);

							var cancel_source = new CancellableSource (io_cancellable);
							cancel_source.set_callback (add_transport.callback);
							cancel_source.attach (main_context);

							yield;

							cancel_source.destroy ();
							delay_source.destroy ();

							if (io_cancellable.is_cancelled ())
								return;
						} else {
							break;
						}
					}
				}
				if (!transports.has_key (device))
					return;
				if (!got_details) {
					remove_transport (device);
					return;
				}
			} else {
				name = "iOS Device [%s]".printf (device.network_address.address.to_string ());
			}
			transport._name = (owned) name;
			transport._icon = (owned) icon;

			transport_attached (transport);
		}

		private void remove_transport (UsbmuxDevice device) {
			UsbmuxTransport transport;
			transports.unset (device, out transport);
			transport_detached (transport);
		}

		public extern static void _extract_details_for_device (int product_id, string udid, out string name,
			out Variant? icon) throws Error;
	}

	private sealed class UsbmuxTransport : Object, Transport {
		public UsbmuxDevice device {
			get;
			construct;
		}

		public PairingStore pairing_store {
			get;
			construct;
		}

		public ConnectionType connection_type {
			get {
				return device.connection_type;
			}
		}

		public string udid {
			get {
				return device.udid;
			}
		}

		public string? name {
			get {
				return _name;
			}
		}

		public Variant? icon {
			get {
				return _icon;
			}
		}

		public UsbmuxDevice? usbmux_device {
			get {
				return device;
			}
		}

		internal string _name;
		internal Variant? _icon;

		private Promise<Tunnel?>? tunnel_request;

		private Gee.Queue<UsbmuxLockdownServiceRequest> lockdown_service_requests =
			new Gee.ArrayQueue<UsbmuxLockdownServiceRequest> ();
		private LockdownClient? cached_lockdown_client;

		public UsbmuxTransport (UsbmuxDevice device, PairingStore store) {
			Object (device: device, pairing_store: store);
		}

		public async Tunnel? find_tunnel (UsbmuxDevice? device, Cancellable? cancellable) throws Error, IOError {
			while (tunnel_request != null) {
				try {
					return yield tunnel_request.future.wait_async (cancellable);
				} catch (Error e) {
					throw e;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}
			tunnel_request = new Promise<Tunnel> ();

			try {
				IOStream? stream = null;
				try {
					stream = yield open_lockdown_service ("com.apple.internal.devicecompute.CoreDeviceProxy", cancellable);
				} catch (Error e) {
					if (!(e is Error.NOT_SUPPORTED))
						throw e;
				}

				UsbmuxTunnel? tunnel = null;
				if (stream != null) {
					tunnel = new UsbmuxTunnel (stream, pairing_store);
					tunnel.lost.connect (on_tunnel_lost);
					try {
						yield tunnel.open (cancellable);
					} catch (Error e) {
						if (e is Error.NOT_SUPPORTED)
							tunnel = null;
						else
							throw e;
					}
				}

				tunnel_request.resolve (tunnel);

				return tunnel;
			} catch (GLib.Error e) {
				tunnel_request.reject (e);
				tunnel_request = null;

				throw_api_error (e);
			}
		}

		private void on_tunnel_lost () {
			tunnel_request = null;
		}

		public async IOStream open_lockdown_service (string service_name, Cancellable? cancellable) throws Error, IOError {
			if (service_name == "") {
				var client = yield open_usbmux_lockdown_client (cancellable);
				return client.service.stream;
			}

			var request = new UsbmuxLockdownServiceRequest (service_name, cancellable);
			bool first_request = lockdown_service_requests.is_empty;
			lockdown_service_requests.offer (request);

			if (first_request)
				process_lockdown_service_requests.begin ();

			return yield request.promise.future.wait_async (cancellable);
		}

		private async void process_lockdown_service_requests () {
			UsbmuxLockdownServiceRequest? req;
			bool already_invalidated = false;
			while ((req = lockdown_service_requests.peek ()) != null) {
				try {
					if (cached_lockdown_client == null)
						cached_lockdown_client = yield open_usbmux_lockdown_client (req.cancellable);
					var stream = yield cached_lockdown_client.start_service (req.service_name, req.cancellable);
					req.promise.resolve (stream);
				} catch (GLib.Error e) {
					if (e is LockdownError.CONNECTION_CLOSED && cached_lockdown_client != null &&
							!already_invalidated) {
						cached_lockdown_client = null;
						already_invalidated = true;
						continue;
					}
					req.promise.reject ((e is LockdownError.INVALID_SERVICE)
						? (Error) new Error.NOT_SUPPORTED ("%s", e.message)
						: (Error) new Error.TRANSPORT ("%s", e.message));
				}

				lockdown_service_requests.poll ();
			}
		}

		private async LockdownClient open_usbmux_lockdown_client (Cancellable? cancellable) throws Error, IOError {
			try {
				var client = yield LockdownClient.open (device, cancellable);
				yield client.start_session (cancellable);
				return client;
			} catch (LockdownError e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
		}

		private class UsbmuxLockdownServiceRequest {
			public string service_name;
			public Cancellable? cancellable;
			public Promise<IOStream> promise = new Promise<IOStream> ();

			public UsbmuxLockdownServiceRequest (string service_name, Cancellable? cancellable) {
				this.service_name = service_name;
				this.cancellable = cancellable;
			}
		}
	}

	private sealed class UsbmuxTunnel : Object, Tunnel {
		public signal void lost ();

		public IOStream stream {
			get;
			construct;
		}

		public PairingStore pairing_store {
			get;
			construct;
		}

		public DiscoveryService discovery {
			get {
				return _discovery_service;
			}
		}

		public int64 opened_at {
			get {
				return _opened_at;
			}
		}

		public Bytes? remote_unlock_host_key {
			get {
				return null;
			}
		}

		private UsbNcmDriver? ncm;
		private TcpTunnelConnection? tunnel_connection;
		private DiscoveryService? _discovery_service;
		private int64 _opened_at = -1;

		public UsbmuxTunnel (IOStream stream, PairingStore store) {
			Object (stream: stream, pairing_store: store);
		}

		public async void open (Cancellable? cancellable) throws Error, IOError {
			var tc = yield TcpTunnelConnection.open_stream (stream, cancellable);
			tunnel_connection = tc;
			tunnel_connection.closed.connect (on_tunnel_connection_close);

			_opened_at = get_monotonic_time ();

			var rsd_endpoint = (InetSocketAddress) Object.new (typeof (InetSocketAddress),
				address: tc.remote_address,
				port: tc.remote_rsd_port,
				scope_id: tc.tunnel_netstack.scope_id
			);
			var rsd_connection = yield tc.tunnel_netstack.open_tcp_connection (rsd_endpoint, cancellable);
			var disco = yield DiscoveryService.open (rsd_connection, cancellable);

			tunnel_connection = tc;
			_discovery_service = disco;
		}

		public async void close (Cancellable? cancellable) throws IOError {
			_discovery_service.close ();

			yield tunnel_connection.close (cancellable);

			if (ncm != null)
				ncm.close ();
		}

		public async IOStream open_tcp_connection (uint16 port, Cancellable? cancellable) throws Error, IOError {
			var netstack = tunnel_connection.tunnel_netstack;
			var endpoint = (InetSocketAddress) Object.new (typeof (InetSocketAddress),
				address: tunnel_connection.remote_address,
				port: port,
				scope_id: netstack.scope_id
			);
			return yield netstack.open_tcp_connection (endpoint, cancellable);
		}

		private void on_tunnel_connection_close () {
			lost ();
		}
	}

	private sealed class PortableCoreDeviceBackend : Object, Backend, UsbDeviceBackend {
		public PairingStore pairing_store {
			get;
			construct;
		}

		public bool supports_modeswitch {
			get {
				return LibUSB.has_capability (HAS_HOTPLUG) != 0;
			}
		}

		public bool modeswitch_allowed {
			get {
				return _modeswitch_allowed;
			}
		}

		private State state = CREATED;

		private Gee.Set<PortableCoreDeviceUsbTransport> usb_transports = new Gee.HashSet<PortableCoreDeviceUsbTransport> ();
		private Promise<bool> usb_started = new Promise<bool> ();
		private Promise<bool> usb_stopped = new Promise<bool> ();
		private bool _modeswitch_allowed = false;

		private Thread<void>? usb_worker;
		private LibUSB.Context? usb_context;
		private LibUSB.HotCallbackHandle iphone_callback;
		private LibUSB.HotCallbackHandle ipad_callback;
		private uint pending_usb_device_arrivals = 0;
		private Gee.Map<uint32, LibUSB.Device> polled_usb_devices = new Gee.HashMap<uint32, LibUSB.Device> ();
		private Source? polled_usb_timer;
		private uint polled_usb_outdated = 0;
		private Gee.Set<unowned PendingUsbOperation> pending_usb_ops = new Gee.HashSet<unowned PendingUsbOperation> ();

		private PairingBrowser network_browser = PairingBrowser.make_default ();
		private Gee.Map<string, PortableCoreDeviceNetworkTransport> network_transports =
			new Gee.HashMap<string, PortableCoreDeviceNetworkTransport> ();

		private MainContext main_context;

		private Cancellable io_cancellable = new Cancellable ();

		private enum State {
			CREATED,
			STARTING,
			STARTED,
			FLUSHING,
			STOPPING,
			STOPPED,
		}

		private const uint16 VENDOR_ID_APPLE = 0x05ac;
		private const uint16 PRODUCT_ID_IPHONE = 0x12a8;
		private const uint16 PRODUCT_ID_IPAD = 0x12ab;

		private delegate void NotifyCompleteFunc ();

		public PortableCoreDeviceBackend (PairingStore pairing_store) {
			Object (pairing_store: pairing_store);
		}

		construct {
			main_context = MainContext.ref_thread_default ();

			network_browser.service_discovered.connect (on_network_pairing_service_discovered);
		}

		public async void start (Cancellable? cancellable) throws IOError {
			lock (state)
				state = STARTING;

			usb_worker = new Thread<void> ("frida-core-device-usb", perform_usb_work);

			yield network_browser.start (cancellable);

			try {
				yield usb_started.future.wait_async (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}

			lock (state)
				state = STARTED;
		}

		public async void stop (Cancellable? cancellable) throws IOError {
			lock (state)
				state = FLUSHING;

			io_cancellable.cancel ();

			if (usb_context != null)
				usb_context.interrupt_event_handler ();

			yield network_browser.stop (cancellable);

			foreach (var transport in network_transports.values.to_array ())
				yield transport.close (cancellable);
			network_transports.clear ();

			foreach (var transport in usb_transports.to_array ())
				yield transport.close (cancellable);
			usb_transports.clear ();

			try {
				yield usb_stopped.future.wait_async (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}

			usb_worker.join ();
			usb_worker = null;

			usb_context = null;

			lock (state)
				state = STOPPED;
		}

		public async void activate_modeswitch_support (Cancellable? cancellable) throws IOError {
			_modeswitch_allowed = true;

			var pending_transports = usb_transports.to_array ();
			var remaining = pending_transports.length + 1;

			NotifyCompleteFunc on_complete = () => {
				remaining--;
				if (remaining == 0)
					activate_modeswitch_support.callback ();
			};

			foreach (var transport in pending_transports)
				do_activate_modeswitch_support.begin (transport, cancellable, on_complete);

			var source = new IdleSource ();
			source.set_callback (() => {
				on_complete ();
				return Source.REMOVE;
			});
			source.attach (MainContext.get_thread_default ());

			yield;

			on_complete = null;
		}

		private async void do_activate_modeswitch_support (PortableCoreDeviceUsbTransport transport, Cancellable? cancellable,
				NotifyCompleteFunc on_complete) {
			try {
				yield transport.open (cancellable);
			} catch (GLib.Error e) {
			}

			on_complete ();
		}

		private void perform_usb_work () {
			if (LibUSB.Context.init (out usb_context) != SUCCESS) {
				schedule_on_frida_thread (() => {
					usb_started.resolve (true);
					usb_stopped.resolve (true);
					return Source.REMOVE;
				});
				return;
			}

			AtomicUint.inc (ref pending_usb_device_arrivals);

			bool callbacks_registered = true;
			if (LibUSB.has_capability (HAS_HOTPLUG) != 0) {
				usb_context.hotplug_register_callback (DEVICE_ARRIVED | DEVICE_LEFT, ENUMERATE, VENDOR_ID_APPLE,
					PRODUCT_ID_IPHONE, LibUSB.HotPlugEvent.MATCH_ANY, on_usb_hotplug_event, out iphone_callback);
				usb_context.hotplug_register_callback (DEVICE_ARRIVED | DEVICE_LEFT, ENUMERATE, VENDOR_ID_APPLE,
					PRODUCT_ID_IPAD, LibUSB.HotPlugEvent.MATCH_ANY, on_usb_hotplug_event, out ipad_callback);
			} else {
				refresh_polled_usb_devices ();

				var source = new TimeoutSource.seconds (2);
				source.set_callback (() => {
					AtomicUint.set (ref polled_usb_outdated, 1);
					usb_context.interrupt_event_handler ();
					return Source.CONTINUE;
				});
				source.attach (main_context);
				polled_usb_timer = source;
			}

			if (AtomicUint.dec_and_test (ref pending_usb_device_arrivals)) {
				schedule_on_frida_thread (() => {
					usb_started.resolve (true);
					return Source.REMOVE;
				});
			}

			while (state != STOPPING) {
				int completed = 0;
				usb_context.handle_events_completed (out completed);

				if (AtomicUint.compare_and_exchange (ref polled_usb_outdated, 1, 0))
					refresh_polled_usb_devices ();

				if (state == FLUSHING) {
					if (callbacks_registered) {
						usb_context.hotplug_deregister_callback (iphone_callback);
						usb_context.hotplug_deregister_callback (ipad_callback);
						callbacks_registered = false;
					}

					if (polled_usb_timer != null) {
						polled_usb_timer.destroy ();
						polled_usb_timer = null;
					}

					lock (state) {
						if (pending_usb_ops.is_empty)
							state = STOPPING;
					}
				}
			}

			schedule_on_frida_thread (() => {
				usb_stopped.resolve (true);
				return Source.REMOVE;
			});
		}

		private int on_usb_hotplug_event (LibUSB.Context ctx, LibUSB.Device device, LibUSB.HotPlugEvent event) {
			if (event == DEVICE_ARRIVED)
				on_usb_device_arrived (device);
			else
				on_usb_device_left (device);
			return 0;
		}

		private void on_usb_device_arrived (LibUSB.Device device) {
			AtomicUint.inc (ref pending_usb_device_arrivals);
			schedule_on_frida_thread (() => {
				handle_usb_device_arrival.begin (device);
				return Source.REMOVE;
			});
		}

		private void on_usb_device_left (LibUSB.Device device) {
			schedule_on_frida_thread (() => {
				handle_usb_device_departure.begin (device);
				return Source.REMOVE;
			});
		}

		private async void handle_usb_device_arrival (LibUSB.Device raw_device) {
			try {
				UsbDevice usb_device;
				try {
					usb_device = new UsbDevice (raw_device, this);
				} catch (Error e) {
					return;
				}

				unowned string udid = usb_device.udid;

				// iPhones before iOS 17 on Windows are sometimes misdetected with an empty udid -> skip those devices
				if (udid.length == 0)
					return;

				var transport = usb_transports.first_match (t => t.udid == udid);

				bool may_need_time_to_settle = state != STARTING && (transport == null || transport.modeswitch_in_progress);
				if (may_need_time_to_settle) {
					try {
						yield sleep (250, io_cancellable);
					} catch (IOError e) {
					}
				}

				if (transport != null) {
					if (!transport.try_complete_modeswitch (raw_device))
						transport = null;
				}

				if (io_cancellable.is_cancelled ())
					return;

				if (transport == null) {
					transport = new PortableCoreDeviceUsbTransport (this, usb_device, pairing_store);
					usb_transports.add (transport);

					if (state != STARTING) {
						try {
							yield transport.open (io_cancellable);
						} catch (GLib.Error e) {
						}
					}

					transport_attached (transport);
				}
			} finally {
				if (AtomicUint.dec_and_test (ref pending_usb_device_arrivals) && state == STARTING)
					usb_started.resolve (true);
			}
		}

		private async void handle_usb_device_departure (LibUSB.Device raw_device) {
			var transport = usb_transports.first_match (t => t.usb_device.raw_device == raw_device && !t.modeswitch_in_progress);
			if (transport == null)
				return;

			transport_detached (transport);
			usb_transports.remove (transport);

			try {
				yield transport.close (io_cancellable);
			} catch (IOError e) {
			}
		}

		private void refresh_polled_usb_devices () {
			var current_devices = new Gee.HashMap<uint32, LibUSB.Device> ();
			foreach (var device in usb_context.get_device_list ()) {
				var desc = LibUSB.DeviceDescriptor (device);

				if (desc.idVendor != VENDOR_ID_APPLE)
					continue;

				if (desc.idProduct != PRODUCT_ID_IPHONE && desc.idProduct != PRODUCT_ID_IPAD)
					continue;

				uint id = make_usb_device_id (device, desc);
				current_devices[id] = device;

				if (!polled_usb_devices.has_key (id))
					on_usb_device_arrived (device);
			}

			foreach (var e in polled_usb_devices.entries) {
				if (!current_devices.has_key (e.key))
					on_usb_device_left (e.value);
			}

			polled_usb_devices = current_devices;
		}

		private UsbOperation allocate_usb_operation () throws Error {
			var op = new PendingUsbOperation (this);

			bool added = false;
			lock (state) {
				switch (state) {
					case CREATED:
						break;
					case STARTING:
					case STARTED:
						pending_usb_ops.add (op);
						added = true;
						break;
					case FLUSHING:
					case STOPPING:
					case STOPPED:
						break;
				}
			}

			if (!added)
				throw new Error.INVALID_OPERATION ("Unable to allocate USB operation in the current state");

			return op;
		}

		private void on_usb_operation_complete (PendingUsbOperation op) {
			lock (state)
				pending_usb_ops.remove (op);

			if (usb_context != null)
				usb_context.interrupt_event_handler ();
		}

		private static uint32 make_usb_device_id (LibUSB.Device device, LibUSB.DeviceDescriptor desc) {
			return ((uint32) device.get_port_number () << 24) |
				((uint32) device.get_device_address () << 16) |
				(uint32) desc.idProduct;
		}

		private void on_network_pairing_service_discovered (PairingServiceDetails service) {
			var peer = pairing_store.find_peer_matching_service (service);
			if (peer == null)
				return;

			var transport = network_transports[peer.udid];
			if (transport == null) {
				transport = new PortableCoreDeviceNetworkTransport (peer, pairing_store, service.endpoint,
					service.interface_address);
				network_transports[peer.udid] = transport;
				transport_attached (transport);
			} else {
				transport.endpoint = service.endpoint;
				transport.interface_address = service.interface_address;
			}
		}

		private void schedule_on_frida_thread (owned SourceFunc function) {
			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (main_context);
		}

		private class PendingUsbOperation : Object, UsbOperation {
			public LibUSB.Transfer transfer {
				get {
					return _transfer;
				}
			}

			private weak PortableCoreDeviceBackend backend;
			private LibUSB.Transfer _transfer;

			public PendingUsbOperation (PortableCoreDeviceBackend backend) {
				this.backend = backend;
			}

			construct {
				_transfer = new LibUSB.Transfer ();
			}

			public override void dispose () {
				if (_transfer != null) {
					_transfer = null;
					backend.on_usb_operation_complete (this);
				}

				base.dispose ();
			}
		}
	}

	private sealed class PortableCoreDeviceUsbTransport : Object, Transport {
		public UsbDevice usb_device {
			get {
				return _usb_device;
			}
		}

		public ConnectionType connection_type {
			get {
				return USB;
			}
		}

		public string udid {
			get {
				return _usb_device.udid;
			}
		}

		public string? name {
			get {
				return _name;
			}
		}

		public Variant? icon {
			get {
				return null;
			}
		}

		public UsbmuxDevice? usbmux_device {
			get {
				return null;
			}
		}

		public PairingStore pairing_store {
			get;
			construct;
		}

		public bool modeswitch_in_progress {
			get {
				return modeswitch_request != null;
			}
		}

		private unowned PortableCoreDeviceBackend parent;
		private UsbDevice _usb_device;
		private Gee.List<InetSocketAddress> ncm_ifaddrs;
		private UsbNcmConfig? ncm_config;
		private string? _name;

		private Promise<UsbDevice>? device_request;
		private Promise<LibUSB.Device>? modeswitch_request;
		private Promise<Tunnel?>? tunnel_request;
		private NcmPeer? ncm_peer;

		public PortableCoreDeviceUsbTransport (PortableCoreDeviceBackend parent, UsbDevice device, PairingStore store) {
			Object (pairing_store: store);

			this.parent = parent;
			_usb_device = device;

			char product[LibUSB.DEVICE_STRING_BYTES_MAX + 1];
			var res = device.raw_device.get_device_string (PRODUCT, product);
			if (res >= LibUSB.Error.SUCCESS) {
				product[res] = '\0';
				_name = (string) product;
			}
		}

		public async UsbDevice open (Cancellable? cancellable) throws Error, IOError {
			while (device_request != null) {
				try {
					return yield device_request.future.wait_async (cancellable);
				} catch (Error e) {
					throw e;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}
			device_request = new Promise<UsbDevice> ();

			try {
				ncm_ifaddrs = yield NcmPeer.detect_ncm_ifaddrs_on_system (_usb_device, cancellable);
				if (ncm_ifaddrs.is_empty) {
					_usb_device.ensure_open ();

					if (parent.modeswitch_allowed) {
						modeswitch_request = new Promise<LibUSB.Device> ();
						if (yield _usb_device.maybe_modeswitch (cancellable)) {
							var source = new TimeoutSource.seconds (2);
							source.set_callback (() => {
								if (modeswitch_request != null) {
									modeswitch_request.reject (new Error.TRANSPORT ("Modeswitch timed out"));
									modeswitch_request = null;
								}
								return Source.REMOVE;
							});
							source.attach (MainContext.get_thread_default ());

							LibUSB.Device raw_device = null;
							try {
								raw_device = yield modeswitch_request.future.wait_async (cancellable);
							} finally {
								source.destroy ();
							}

							_usb_device = new UsbDevice (raw_device, parent);
							_usb_device.ensure_open ();
						} else {
							modeswitch_request = null;
						}
					}

					bool device_configuration_changed;
					try {
						ncm_config = UsbNcmConfig.prepare (_usb_device, out device_configuration_changed);
						if (device_configuration_changed)
							yield sleep (250, cancellable);
					} catch (Error e) {
					}

					ncm_ifaddrs = yield NcmPeer.detect_ncm_ifaddrs_on_system (_usb_device, cancellable);
				}

				device_request.resolve (_usb_device);

				return _usb_device;
			} catch (GLib.Error e) {
				device_request.reject (e);
				device_request = null;

				throw_api_error (e);
			}
		}

		public bool try_complete_modeswitch (LibUSB.Device device) {
			if (modeswitch_request == null)
				return false;
			modeswitch_request.resolve (device);
			modeswitch_request = null;
			return true;
		}

		public async void close (Cancellable? cancellable) throws IOError {
			if (tunnel_request != null) {
				try {
					var tunnel = yield tunnel_request.future.wait_async (cancellable);
					if (tunnel != null)
						yield tunnel.close (cancellable);
				} catch (Error e) {
				} finally {
					tunnel_request = null;
				}
			}

			ncm_peer = null;

			if (device_request != null) {
				try {
					var usb_device = yield device_request.future.wait_async (cancellable);
					yield usb_device.close (cancellable);
				} catch (Error e) {
				} finally {
					device_request = null;
				}
			}
		}

		public async Tunnel? find_tunnel (UsbmuxDevice? device, Cancellable? cancellable) throws Error, IOError {
			while (tunnel_request != null) {
				try {
					return yield tunnel_request.future.wait_async (cancellable);
				} catch (Error e) {
					throw e;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}
			tunnel_request = new Promise<Tunnel> ();

			try {
				var usb_device = yield open (cancellable);

				bool supported_by_os = true;
				if (device != null) {
					try {
						var lockdown = yield LockdownClient.open (device, cancellable);
						yield lockdown.start_session (cancellable);
						var response = yield lockdown.get_value (null, null, cancellable);
						Fruity.PlistDict properties = response.get_dict ("Value");
						if (properties.get_string ("ProductName") == "iPhone OS") {
							uint ios_major_version = uint.parse (properties.get_string ("ProductVersion").split (".")[0]);
							supported_by_os = ios_major_version >= 17;
						}
					} catch (LockdownError e) {
						if (!(e is LockdownError.NOT_PAIRED))
							throw new Error.PERMISSION_DENIED ("%s", e.message);
					}
				}

				PortableUsbTunnel? tunnel = null;
				if (supported_by_os) {
					if (ncm_peer == null) {
						if (!ncm_ifaddrs.is_empty) {
							ncm_peer = yield NcmPeer.locate_on_system_netifs (ncm_ifaddrs, cancellable);
						} else if (ncm_config != null) {
							ncm_peer = yield NcmPeer.establish_using_our_driver (usb_device, ncm_config,
								cancellable);
						}
					}

					if (ncm_peer != null) {
						tunnel = new PortableUsbTunnel (usb_device, ncm_peer, pairing_store);
						tunnel.lost.connect (on_tunnel_lost);
						try {
							yield tunnel.open (cancellable);
						} catch (Error e) {
							if (e is Error.NOT_SUPPORTED)
								tunnel = null;
							else
								throw e;
						}
					}
				}

				tunnel_request.resolve (tunnel);

				return tunnel;
			} catch (GLib.Error e) {
				tunnel_request.reject (e);
				tunnel_request = null;

				throw_api_error (e);
			}
		}

		private void on_tunnel_lost () {
			tunnel_request = null;
		}
	}

	private class NcmPeer {
		public NetworkStack netstack;
		public InetAddress ip;
		public UsbNcmDriver? ncm;

		~NcmPeer () {
			if (ncm != null)
				ncm.close ();
		}

		public static async Gee.List<InetSocketAddress> detect_ncm_ifaddrs_on_system (UsbDevice usb_device,
				Cancellable? cancellable) throws Error, IOError {
			var device_ifaddrs = new Gee.ArrayList<InetSocketAddress> ();

#if LINUX
			var fruit_finder = FruitFinder.make_default ();
			unowned string udid = usb_device.udid;

			var ncm_interfaces = new Gee.HashSet<string> ();
			var names = if_nameindex ();
			try {
				for (Linux.Network.IfNameindex * cur = names; cur->if_index != 0; cur++) {
					string? candidate_udid = fruit_finder.udid_from_iface (cur->if_name);
					if (candidate_udid != udid)
						continue;

					ncm_interfaces.add (cur->if_name);
				}
			} finally {
				if_freenameindex (names);
			}
			if (ncm_interfaces.is_empty)
				return device_ifaddrs;

			yield Network.wait_until_interfaces_ready (ncm_interfaces, cancellable);

			Linux.Network.IfAddrs ifaddrs;
			Linux.Network.getifaddrs (out ifaddrs);
			for (unowned Linux.Network.IfAddrs candidate = ifaddrs; candidate != null; candidate = candidate.ifa_next) {
				unowned Posix.SockAddr? address = candidate.ifa_addr;
				if (address == null || address.sa_family != Posix.AF_INET6)
					continue;

				if (!ncm_interfaces.contains (candidate.ifa_name))
					continue;

				device_ifaddrs.add ((InetSocketAddress) SocketAddress.from_native ((void *) address,
					sizeof (Posix.SockAddrIn6)));
			}
			if (device_ifaddrs.is_empty && !ncm_interfaces.is_empty)
				throw new Error.NOT_SUPPORTED ("no IPv6 address on NCM network interface");
#endif

			return device_ifaddrs;
		}

#if LINUX
		[CCode (cheader_filename = "net/if.h", cname = "if_nameindex")]
		private extern static Linux.Network.IfNameindex* if_nameindex ();

		[CCode (cheader_filename = "net/if.h", cname = "if_freenameindex")]
		private extern static void if_freenameindex (Linux.Network.IfNameindex* index);
#endif

		public static async NcmPeer locate_on_system_netifs (Gee.List<InetSocketAddress> ifaddrs, Cancellable? cancellable)
				throws Error, IOError {
			var main_context = MainContext.ref_thread_default ();

			var probes = new Gee.ArrayList<ActiveMulticastDnsProbe> ();
			var handlers = new Gee.HashMap<ActiveMulticastDnsProbe, ulong> ();
			ActiveMulticastDnsProbe? successful_probe = null;
			InetSocketAddress? observed_sender = null;
			foreach (var addr in ifaddrs) {
				var probe = new ActiveMulticastDnsProbe (addr, main_context, cancellable);
				var handler = probe.response_received.connect ((probe, response, sender) => {
					successful_probe = probe;
					observed_sender = sender;
					locate_on_system_netifs.callback ();
				});
				probes.add (probe);
				handlers[probe] = handler;
			}

			var timeout_source = new TimeoutSource.seconds (2);
			timeout_source.set_callback (locate_on_system_netifs.callback);
			timeout_source.attach (main_context);

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (locate_on_system_netifs.callback);
			cancel_source.attach (main_context);

			yield;

			cancel_source.destroy ();
			timeout_source.destroy ();
			foreach (var e in handlers.entries)
				e.key.disconnect (e.value);
			foreach (var p in probes)
				p.cancel ();

			cancellable.set_error_if_cancelled ();

			if (successful_probe == null)
				throw new Error.TIMED_OUT ("Unexpectedly timed out while waiting for mDNS reply");

			return new NcmPeer () {
				netstack = successful_probe.netstack,
				ip = observed_sender.get_address (),
				ncm = null,
			};
		}

		private class ActiveMulticastDnsProbe : Object {
			public signal void response_received (Bytes response, InetSocketAddress sender);

			public NetworkStack netstack;
			private Cancellable? io_cancellable;

			private UdpSocket sock;
			private DatagramBased sock_datagram;

			private Bytes remoted_mdns_request;
			private InetSocketAddress mdns_address;

			private TimeoutSource retransmit_source;
			private DatagramBasedSource response_source;

			public ActiveMulticastDnsProbe (InetSocketAddress ifaddr, MainContext main_context, Cancellable? cancellable)
					throws Error, IOError {
				var local_ip = ifaddr.get_address ();
				netstack = new SystemNetworkStack (local_ip, ifaddr.scope_id);
				io_cancellable = cancellable;

				sock = netstack.create_udp_socket ();
				sock.bind ((InetSocketAddress) Object.new (typeof (InetSocketAddress),
					address: local_ip,
					scope_id: netstack.scope_id
				));
				sock_datagram = sock.datagram_based;

				remoted_mdns_request = make_remoted_mdns_request ();

				mdns_address = (InetSocketAddress) Object.new (typeof (InetSocketAddress),
					address: new InetAddress.from_string ("ff02::fb"),
					port: 5353,
					scope_id: netstack.scope_id
				);

				retransmit_source = new TimeoutSource (250);
				retransmit_source.set_callback (on_retransmit_tick);
				retransmit_source.attach (main_context);

				response_source = sock_datagram.create_source (IN, cancellable);
				response_source.set_callback (on_socket_readable);
				response_source.attach (main_context);

				transmit_request ();
			}

			public void cancel () {
				response_source.destroy ();
				retransmit_source.destroy ();
			}

			private void transmit_request () throws Error, IOError {
				Udp.send_to (remoted_mdns_request.get_data (), mdns_address, sock_datagram, io_cancellable);
			}

			private bool on_retransmit_tick () {
				try {
					transmit_request ();
				} catch (GLib.Error e) {
				}

				return Source.CONTINUE;
			}

			private bool on_socket_readable () {
				size_t n;
				uint8 response_buf[2048];
				InetSocketAddress sender;
				try {
					n = Udp.recv (response_buf, sock.datagram_based, null, out sender);
				} catch (GLib.Error e) {
					return Source.REMOVE;
				}

				var response = new Bytes (response_buf[:n]);
				response_received (response, sender);

				return Source.CONTINUE;
			}
		}

		public static async NcmPeer establish_using_our_driver (UsbDevice usb_device, UsbNcmConfig ncm_config,
				Cancellable? cancellable) throws Error, IOError {
			var ncm = yield UsbNcmDriver.open (usb_device, ncm_config, cancellable);

			if (ncm.remote_ipv6_address == null) {
				ulong change_handler = ncm.notify["remote-ipv6-address"].connect ((obj, pspec) => {
					establish_using_our_driver.callback ();
				});

				var main_context = MainContext.get_thread_default ();

				var timeout_source = new TimeoutSource.seconds (2);
				timeout_source.set_callback (establish_using_our_driver.callback);
				timeout_source.attach (main_context);

				var cancel_source = new CancellableSource (cancellable);
				cancel_source.set_callback (establish_using_our_driver.callback);
				cancel_source.attach (main_context);

				yield;

				cancel_source.destroy ();
				timeout_source.destroy ();
				ncm.disconnect (change_handler);

				cancellable.set_error_if_cancelled ();

				if (ncm.remote_ipv6_address == null)
					throw new Error.TIMED_OUT ("Unexpectedly timed out while waiting for the NCM remote IPv6 address");
			}

			return new NcmPeer () {
				netstack = ncm.netstack,
				ip = ncm.remote_ipv6_address,
				ncm = ncm,
			};
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
			uint16 dns_class = 1 | 0x8000;
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
	}

	private sealed class PortableUsbTunnel : Object, Tunnel {
		public signal void lost ();

		public UsbDevice usb_device {
			get;
			construct;
		}

		public NcmPeer ncm_peer {
			get;
			construct;
		}

		public PairingStore pairing_store {
			get;
			construct;
		}

		public DiscoveryService discovery {
			get {
				return _discovery_service;
			}
		}

		public int64 opened_at {
			get {
				return _opened_at;
			}
		}

		public Bytes? remote_unlock_host_key {
			get {
				return _remote_unlock_host_key;
			}
		}

		private UsbNcmDriver? ncm;
		private TunnelConnection? tunnel_connection;
		private DiscoveryService? _discovery_service;
		private int64 _opened_at = -1;
		private Bytes? _remote_unlock_host_key;

		public PortableUsbTunnel (UsbDevice device, NcmPeer peer, PairingStore store) {
			Object (
				usb_device: device,
				ncm_peer: peer,
				pairing_store: store
			);
		}

		public async void open (Cancellable? cancellable) throws Error, IOError {
			var netstack = ncm_peer.netstack;

			var bootstrap_rsd_endpoint = (InetSocketAddress) Object.new (typeof (InetSocketAddress),
				address: ncm_peer.ip,
				port: 58783,
				scope_id: netstack.scope_id
			);
			var bootstrap_stream = yield netstack.open_tcp_connection (bootstrap_rsd_endpoint, cancellable);
			var bootstrap_disco = yield DiscoveryService.open (bootstrap_stream, cancellable);

			var tunnel_service = bootstrap_disco.get_service ("com.apple.internal.dt.coredevice.untrusted.tunnelservice");
			var tunnel_endpoint = (InetSocketAddress) Object.new (typeof (InetSocketAddress),
				address: ncm_peer.ip,
				port: tunnel_service.port,
				scope_id: netstack.scope_id
			);
			var pairing_transport = new XpcPairingTransport (yield netstack.open_tcp_connection (tunnel_endpoint, cancellable));
			var pairing_service = yield PairingService.open (pairing_transport, pairing_store, cancellable);
			TunnelConnection tc = yield pairing_service.open_tunnel (ncm_peer.ip, netstack, cancellable);
			tc.closed.connect (on_tunnel_connection_close);

			_opened_at = get_monotonic_time ();
			_remote_unlock_host_key = pairing_service.established_peer.remote_unlock_host_key;

			var rsd_endpoint = (InetSocketAddress) Object.new (typeof (InetSocketAddress),
				address: tc.remote_address,
				port: tc.remote_rsd_port,
				scope_id: tc.tunnel_netstack.scope_id
			);
			var rsd_connection = yield tc.tunnel_netstack.open_tcp_connection (rsd_endpoint, cancellable);
			var disco = yield DiscoveryService.open (rsd_connection, cancellable);

			tunnel_connection = tc;
			_discovery_service = disco;
		}

		public async void close (Cancellable? cancellable) throws IOError {
			_discovery_service.close ();

			yield tunnel_connection.close (cancellable);

			if (ncm != null)
				ncm.close ();
		}

		public async IOStream open_tcp_connection (uint16 port, Cancellable? cancellable) throws Error, IOError {
			var netstack = tunnel_connection.tunnel_netstack;
			var endpoint = (InetSocketAddress) Object.new (typeof (InetSocketAddress),
				address: tunnel_connection.remote_address,
				port: port,
				scope_id: netstack.scope_id
			);
			return yield netstack.open_tcp_connection (endpoint, cancellable);
		}

		private void on_tunnel_connection_close () {
			lost ();
		}
	}

	private sealed class PortableCoreDeviceNetworkTransport : Object, Transport {
		public PairingPeer peer {
			get;
			construct;
		}

		public PairingStore pairing_store {
			get;
			construct;
		}

		public InetSocketAddress endpoint {
			get;
			set;
		}

		public InetSocketAddress interface_address {
			get;
			set;
		}

		public ConnectionType connection_type {
			get {
				return NETWORK;
			}
		}

		public string udid {
			get {
				return peer.udid;
			}
		}

		public string? name {
			get {
				return peer.name;
			}
		}

		public Variant? icon {
			get {
				return null;
			}
		}

		public UsbmuxDevice? usbmux_device {
			get {
				return null;
			}
		}

		private Promise<Tunnel>? tunnel_request;

		public PortableCoreDeviceNetworkTransport (PairingPeer peer, PairingStore store, InetSocketAddress endpoint,
				InetSocketAddress interface_address) {
			Object (
				peer: peer,
				pairing_store: store,
				endpoint: endpoint,
				interface_address: interface_address
			);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			if (tunnel_request != null) {
				try {
					var tunnel = yield tunnel_request.future.wait_async (cancellable);
					yield tunnel.close (cancellable);
				} catch (Error e) {
				} finally {
					tunnel_request = null;
				}
			}
		}

		public async Tunnel? find_tunnel (UsbmuxDevice? device, Cancellable? cancellable) throws Error, IOError {
			while (tunnel_request != null) {
				try {
					return yield tunnel_request.future.wait_async (cancellable);
				} catch (Error e) {
					throw e;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}
			tunnel_request = new Promise<Tunnel> ();

			try {
				var tunnel = new PortableNetworkTunnel (endpoint, interface_address, pairing_store);
				yield tunnel.open (cancellable);

				tunnel_request.resolve (tunnel);

				return tunnel;
			} catch (GLib.Error e) {
				tunnel_request.reject (e);
				tunnel_request = null;

				throw_api_error (e);
			}
		}
	}

	private sealed class PortableNetworkTunnel : Object, Tunnel {
		public InetSocketAddress endpoint {
			get;
			construct;
		}

		public InetSocketAddress interface_address {
			get;
			construct;
		}

		public PairingStore pairing_store {
			get;
			construct;
		}

		public DiscoveryService discovery {
			get {
				return _discovery_service;
			}
		}

		public int64 opened_at {
			get {
				return _opened_at;
			}
		}

		public Bytes? remote_unlock_host_key {
			get {
				return _remote_unlock_host_key;
			}
		}

		private TunnelConnection? tunnel_connection;
		private DiscoveryService? _discovery_service;
		private int64 _opened_at = -1;
		private Bytes? _remote_unlock_host_key;

		private const uint PAIRING_CONNECTION_TIMEOUT = 2000;

		public PortableNetworkTunnel (InetSocketAddress endpoint, InetSocketAddress interface_address, PairingStore store) {
			Object (
				endpoint: endpoint,
				interface_address: interface_address,
				pairing_store: store
			);
		}

		public async void open (Cancellable? cancellable) throws Error, IOError {
			var netstack = new SystemNetworkStack (interface_address.get_address (), interface_address.scope_id);

			var pairing_connection = yield netstack.open_tcp_connection_with_timeout (endpoint, PAIRING_CONNECTION_TIMEOUT,
				cancellable);
			var pairing_transport = new PlainPairingTransport (pairing_connection);
			var pairing_service = yield PairingService.open (pairing_transport, pairing_store, cancellable);

			TunnelConnection tc = yield pairing_service.open_tunnel (endpoint.get_address (), netstack, cancellable);

			_opened_at = get_monotonic_time ();
			_remote_unlock_host_key = pairing_service.established_peer.remote_unlock_host_key;

			var rsd_endpoint = (InetSocketAddress) Object.new (typeof (InetSocketAddress),
				address: tc.remote_address,
				port: tc.remote_rsd_port,
				scope_id: tc.tunnel_netstack.scope_id
			);
			var rsd_connection = yield tc.tunnel_netstack.open_tcp_connection (rsd_endpoint, cancellable);
			var disco = yield DiscoveryService.open (rsd_connection, cancellable);

			tunnel_connection = tc;
			_discovery_service = disco;
		}

		public async void close (Cancellable? cancellable) throws IOError {
			_discovery_service.close ();

			yield tunnel_connection.close (cancellable);
		}

		public async IOStream open_tcp_connection (uint16 port, Cancellable? cancellable) throws Error, IOError {
			var netstack = tunnel_connection.tunnel_netstack;
			var endpoint = (InetSocketAddress) Object.new (typeof (InetSocketAddress),
				address: tunnel_connection.remote_address,
				port: port,
				scope_id: netstack.scope_id
			);
			return yield netstack.open_tcp_connection (endpoint, cancellable);
		}
	}

	public interface FruitFinder : Object {
		public static FruitFinder make_default () {
#if LINUX && !ANDROID
			return new LinuxFruitFinder ();
#else
			return new NullFruitFinder ();
#endif
		}

		public abstract string? udid_from_iface (string ifname) throws Error;
	}

	public sealed class NullFruitFinder : Object, FruitFinder {
		public string? udid_from_iface (string ifname) throws Error {
			return null;
		}
	}

	public interface PairingBrowser : Object {
		public const string SERVICE_NAME = "_remotepairing._tcp.local";

		public signal void service_discovered (PairingServiceDetails service);

		public static PairingBrowser make_default () {
#if WINDOWS
			return new WindowsPairingBrowser ();
#elif LINUX && !ANDROID
			return new LinuxPairingBrowser ();
#else
			return new NullPairingBrowser ();
#endif
		}

		public abstract async void start (Cancellable? cancellable) throws IOError;
		public abstract async void stop (Cancellable? cancellable) throws IOError;
	}

	public sealed class NullPairingBrowser : Object, PairingBrowser {
		public async void start (Cancellable? cancellable) throws IOError {
		}

		public async void stop (Cancellable? cancellable) throws IOError {
		}
	}

	public class PairingServiceDetails {
		public string identifier;
		public Bytes auth_tag;
		public InetSocketAddress endpoint;
		public InetSocketAddress interface_address;
	}

	private async void sleep (uint duration_msec, Cancellable? cancellable) throws IOError {
		var main_context = MainContext.get_thread_default ();

		var delay_source = new TimeoutSource (duration_msec);
		delay_source.set_callback (sleep.callback);
		delay_source.attach (main_context);

		var cancel_source = new CancellableSource (cancellable);
		cancel_source.set_callback (sleep.callback);
		cancel_source.attach (main_context);

		yield;

		cancel_source.destroy ();
		delay_source.destroy ();

		cancellable.set_error_if_cancelled ();
	}
}
