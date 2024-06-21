[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
	public sealed class DeviceMonitor : Object {
		public signal void device_attached (Device device);
		public signal void device_detached (Device device);

		private State state = CREATED;
		private Gee.List<Backend> backends = new Gee.ArrayList<Backend> ();
		private Gee.Map<string, Device> devices = new Gee.HashMap<string, Device> ();

		private enum State {
			CREATED,
			STARTING,
			STARTED,
			STOPPED,
		}

		private delegate void NotifyCompleteFunc ();

		construct {
			add_backend (new UsbmuxBackend ());
			add_backend (new PortableCoreDeviceBackend ());
#if MACOS
			add_backend (new MacOSCoreDeviceBackend ());
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
			default = new Gee.HashSet<Transport> ();
		}

		private Gee.Queue<UsbmuxLockdownServiceRequest> usbmux_lockdown_service_requests =
			new Gee.ArrayQueue<UsbmuxLockdownServiceRequest> ();
		private LockdownClient? cached_usbmux_lockdown_client;

		public UsbmuxDevice? find_usbmux_device () throws Error {
			var transport = transports.first_match (t => t.usbmux_device != null);
			return (transport != null) ? transport.usbmux_device : null;
		}

		public UsbmuxDevice get_usbmux_device () throws Error {
			var d = find_usbmux_device ();
			if (d == null)
				throw new Error.NOT_SUPPORTED ("USB connection not available");
			return d;
		}

		public async Tunnel? find_tunnel (Cancellable? cancellable) throws Error, IOError {
			var transport = transports.first_match (t => t is TunnelFinder);
			if (transport == null)
				return null;
			return yield ((TunnelFinder) transport).find_tunnel (cancellable);
		}

		public async LockdownClient get_lockdown_client (Cancellable? cancellable) throws Error, IOError {
			var stream = yield open_lockdown_service ("", cancellable);
			return new LockdownClient (stream);
		}

		public async IOStream open_lockdown_service (string service_name, Cancellable? cancellable) throws Error, IOError {
			printerr ("\n=== open_lockdown_service() service_name=\"%s\"\n\n", service_name);

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

			if (service_name == "") {
				var client = yield open_usbmux_lockdown_client (cancellable);
				return client.service.stream;
			}

			var request = new UsbmuxLockdownServiceRequest (service_name, cancellable);
			bool first_request = usbmux_lockdown_service_requests.is_empty;
			usbmux_lockdown_service_requests.offer (request);

			if (first_request)
				process_usbmux_lockdown_service_requests.begin ();

			return yield request.promise.future.wait_async (cancellable);
		}

		private async void process_usbmux_lockdown_service_requests () {
			UsbmuxLockdownServiceRequest? req;
			while ((req = usbmux_lockdown_service_requests.peek ()) != null) {
				try {
					if (cached_usbmux_lockdown_client == null)
						cached_usbmux_lockdown_client = yield open_usbmux_lockdown_client (req.cancellable);
					var stream = yield cached_usbmux_lockdown_client.start_service (req.service_name, req.cancellable);
					req.promise.resolve (stream);
				} catch (GLib.Error e) {
					if (e is Error.TRANSPORT && cached_usbmux_lockdown_client != null) {
						printerr ("Invalidating and retrying...\n");
						cached_usbmux_lockdown_client = null;
						continue;
					}
					req.promise.reject ((e is LockdownError.INVALID_SERVICE)
						? (Error) new Error.NOT_SUPPORTED ("%s", e.message)
						: (Error) new Error.TRANSPORT ("%s", e.message));
				}

				usbmux_lockdown_service_requests.poll ();
			}
		}

		private async LockdownClient open_usbmux_lockdown_client (Cancellable? cancellable) throws Error, IOError {
			try {
				var client = yield LockdownClient.open (get_usbmux_device (), cancellable);
				yield client.start_session (cancellable);
				return client;
			} catch (LockdownError e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
		}

		public async IOStream open_channel (string address, Cancellable? cancellable) throws Error, IOError {
			if (address.has_prefix ("tcp:")) {
				ulong raw_port;
				if (!ulong.try_parse (address.substring (4), out raw_port) || raw_port == 0 || raw_port > uint16.MAX)
					throw new Error.INVALID_ARGUMENT ("Invalid TCP port");
				uint16 port = (uint16) raw_port;

				var usbmux_device = find_usbmux_device ();
				if (usbmux_device != null) {
					if (usbmux_device.connection_type == USB) {
						UsbmuxClient client = null;
						try {
							client = yield UsbmuxClient.open (cancellable);

							yield client.connect_to_port (usbmux_device.id, port, cancellable);

							return client.connection;
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

						return connection;
					} catch (GLib.Error e) {
						if (e is IOError.CONNECTION_REFUSED)
							throw new Error.SERVER_NOT_RUNNING ("%s", e.message);

						throw new Error.TRANSPORT ("%s", e.message);
					}
				}
			}

			if (address.has_prefix ("lockdown:")) {
				string service_name = address.substring (9);

				return yield open_lockdown_service (service_name, cancellable);
			}

			throw new Error.NOT_SUPPORTED ("Unsupported channel address");
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
	}

	private interface Backend : Object {
		public signal void transport_attached (Transport transport);
		public signal void transport_detached (Transport transport);

		public abstract async void start (Cancellable? cancellable) throws IOError;
		public abstract async void stop (Cancellable? cancellable) throws IOError;
	}

	public enum ConnectionType {
		USB,
		NETWORK
	}

	private sealed class UsbmuxBackend : Object, Backend {
		private Gee.Map<UsbmuxDevice, UsbmuxTransport> transports = new Gee.HashMap<UsbmuxDevice, UsbmuxTransport> ();

		private UsbmuxClient? usbmux;

		private Promise<bool> start_request;
		private Cancellable start_cancellable;
		private SourceFunc on_start_completed;

		private Cancellable io_cancellable = new Cancellable ();

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
			var transport = new UsbmuxTransport (device);
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

		public UsbmuxTransport (UsbmuxDevice device) {
			Object (device: device);
		}
	}

	private sealed class PortableCoreDeviceBackend : Object, Backend {
		private State state = CREATED;
		private Promise<bool> started = new Promise<bool> ();

		private Thread<void>? usb_worker;
		private LibUSB.Context? usb_context;
		private LibUSB.HotCallbackHandle iphone_callback;
		private LibUSB.HotCallbackHandle ipad_callback;
		private uint pending_device_arrivals = 0;

		private MainContext main_context;

		private Cancellable io_cancellable = new Cancellable ();

		private enum State {
			CREATED,
			STARTING,
			STARTED,
			STOPPING,
			STOPPED,
		}

		private const uint16 VENDOR_ID_APPLE = 0x05ac;
		private const uint16 PRODUCT_ID_IPHONE = 0x12a8;
		private const uint16 PRODUCT_ID_IPAD = 0x12ab;

		construct {
			main_context = MainContext.ref_thread_default ();
		}

		public async void start (Cancellable? cancellable) throws IOError {
			state = STARTING;

			usb_worker = new Thread<void> ("frida-core-device-usb", perform_usb_work);

			try {
				yield started.future.wait_async (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}

			state = STARTED;
		}

		public async void stop (Cancellable? cancellable) throws IOError {
			state = STOPPING;

			io_cancellable.cancel ();
			usb_context.interrupt_event_handler ();

			usb_worker.join ();
			usb_worker = null;

			state = STOPPED;
		}

		private void perform_usb_work () {
			LibUSB.Context.init (out usb_context);

			AtomicUint.inc (ref pending_device_arrivals);
			usb_context.hotplug_register_callback (DEVICE_ARRIVED | DEVICE_LEFT, ENUMERATE, VENDOR_ID_APPLE, PRODUCT_ID_IPHONE,
				LibUSB.HotPlugEvent.MATCH_ANY, on_hotplug_event, out iphone_callback);
			usb_context.hotplug_register_callback (DEVICE_ARRIVED | DEVICE_LEFT, ENUMERATE, VENDOR_ID_APPLE, PRODUCT_ID_IPAD,
				LibUSB.HotPlugEvent.MATCH_ANY, on_hotplug_event, out ipad_callback);
			if (AtomicUint.dec_and_test (ref pending_device_arrivals)) {
				schedule_on_frida_thread (() => {
					started.resolve (true);
					return Source.REMOVE;
				});
			}

			while (state != STOPPING) {
				int completed = 0;
				usb_context.handle_events_completed (out completed);
			}

			usb_context = null;
		}

		private void on_hotplug_event (LibUSB.Context ctx, LibUSB.Device device, LibUSB.HotPlugEvent event) {
			if (event == DEVICE_ARRIVED)
				on_device_arrived (device);
		}

		private void on_device_arrived (LibUSB.Device device) {
			AtomicUint.inc (ref pending_device_arrivals);
			schedule_on_frida_thread (() => {
				handle_device_arrival.begin (device);
				return Source.REMOVE;
			});
		}

		private async void handle_device_arrival (LibUSB.Device raw_device) {
			try {
				var device = yield UsbDevice.open (raw_device, io_cancellable);
				printerr ("Opened device! udid=\"%s\"\n", device.udid);

				transport_attached (new PortableCoreDeviceTransport (device));
			} catch (GLib.Error e) {
				printerr ("domain=%s code=%d %s\n", e.domain.to_string (), e.code, e.message);
			} finally {
				if (AtomicUint.dec_and_test (ref pending_device_arrivals) && state == STARTING)
					started.resolve (true);
			}
		}

		private void schedule_on_frida_thread (owned SourceFunc function) {
			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (main_context);
		}
	}

	private sealed class PortableCoreDeviceTransport : Object, Transport, TunnelFinder {
		public UsbDevice usb_device {
			get;
			construct;
		}

		public ConnectionType connection_type {
			get {
				return USB;
			}
		}

		public string udid {
			get {
				return usb_device.udid;
			}
		}

		public string? name {
			get {
				return null;
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

		public PortableCoreDeviceTransport (UsbDevice usb_device) {
			Object (usb_device: usb_device);
		}

		public async Tunnel? find_tunnel (Cancellable? cancellable) throws Error, IOError {
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
				var tunnel = new PortableTunnel (usb_device);
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

	private sealed class PortableTunnel : Object, Tunnel {
		public UsbDevice usb_device {
			get;
			construct;
		}

		public DiscoveryService discovery {
			get {
				return _discovery_service;
			}
		}

		private UsbNcmDriver? ncm;
		private TunnelConnection? tunnel_connection;
		private DiscoveryService? _discovery_service;

		public PortableTunnel (UsbDevice usb_device) {
			Object (usb_device: usb_device);
		}

		public async void open (Cancellable? cancellable) throws Error, IOError {
			var peer = yield locate_ncm_peer (cancellable);
			printerr ("Found peer: %s\n", peer.ip.to_string ());

			var netstack = peer.netstack;

			var bootstrap_rsd_endpoint = (InetSocketAddress) Object.new (typeof (InetSocketAddress),
				address: peer.ip,
				port: 58783,
				scope_id: netstack.scope_id
			);
			printerr (">>> open_tcp_connection(bootstrap_stream)\n");
			var bootstrap_stream = yield netstack.open_tcp_connection (bootstrap_rsd_endpoint, cancellable);
			printerr ("<<< open_tcp_connection(bootstrap_stream)\n");
			var bootstrap_disco = yield DiscoveryService.open (bootstrap_stream, cancellable);
			printerr ("udid: %s\n", bootstrap_disco.query_udid ());

			var tunnel_service = bootstrap_disco.get_service ("com.apple.internal.dt.coredevice.untrusted.tunnelservice");
			var tunnel_endpoint = (InetSocketAddress) Object.new (typeof (InetSocketAddress),
				address: peer.ip,
				port: tunnel_service.port,
				scope_id: netstack.scope_id
			);
			printerr (">>> open_tcp_connection(tunnel_endpoint)\n");
			var pairing_transport = new XpcPairingTransport (yield netstack.open_tcp_connection (tunnel_endpoint, cancellable));
			printerr ("<<< open_tcp_connection(tunnel_endpoint)\n");
			printerr (">>> PairingService.open()\n");
			var pairing_service = yield PairingService.open (pairing_transport, cancellable);
			printerr ("<<< PairingService.open()\n");

			printerr (">>> open_tunnel\n");
			TunnelConnection tc = yield pairing_service.open_tunnel (peer.ip, netstack, cancellable);
			printerr ("<<< open_tunnel\n");

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

		private async NcmPeer locate_ncm_peer (Cancellable? cancellable) throws Error, IOError {
			var device_ifaddrs = detect_ncm_ifaddrs_on_system ();
			if (!device_ifaddrs.is_empty)
				return yield locate_ncm_peer_on_system_netifs (device_ifaddrs, cancellable);
			return yield establish_ncm_peer_using_our_driver (cancellable);
		}

		private class NcmPeer {
			public NetworkStack netstack;
			public InetAddress ip;
		}

		private Gee.List<InetSocketAddress> detect_ncm_ifaddrs_on_system () {
			var device_ifaddrs = new Gee.ArrayList<InetSocketAddress> ();

#if GRYNTLINUX
			var fruit_finder = FruitFinder.make_default ();
			unowned string udid = usb_device.udid;
			printerr ("Our UDID: %s\n", udid);
			string raw_udid = udid.replace ("-", "");
			Linux.Network.IfAddrs ifaddrs;
			Linux.Network.getifaddrs (out ifaddrs);
			for (unowned Linux.Network.IfAddrs candidate = ifaddrs; candidate != null; candidate = candidate.ifa_next) {
				if (candidate.ifa_addr.sa_family != Posix.AF_INET6)
					continue;

				string? candidate_udid = fruit_finder.udid_from_iface (candidate.ifa_name);
				printerr ("candidate_udid=%s\n", candidate_udid);
				if (candidate_udid != raw_udid) {
					printerr ("Not a match!\n");
					continue;
				}

				printerr ("MATCHES!\n");
				device_ifaddrs.add ((InetSocketAddress) SocketAddress.from_native ((void *) candidate.ifa_addr, sizeof (Posix.SockAddrIn6)));
			}
#endif

			return device_ifaddrs;
		}

		private async NcmPeer locate_ncm_peer_on_system_netifs (Gee.List<InetSocketAddress> ifaddrs, Cancellable? cancellable)
				throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet fully implemented");
#if 0
			var remoted_mdns_request = make_remoted_mdns_request ();
			foreach (var addr in ifaddrs) {
				var local_ip = addr.get_address ();
				var netstack = new SystemNetworkStack (addr.scope_id);

				var sock = netstack.create_udp_socket ();
				sock.bind ((InetSocketAddress) Object.new (typeof (InetSocketAddress),
					address: local_ip,
					scope_id: netstack.scope_id
				));
				DatagramBased sock_datagram = sock.datagram_based;

				var mdns_address = (InetSocketAddress) Object.new (typeof (InetSocketAddress),
					address: new InetAddress.from_string ("ff02::fb"),
					port: 5353,
					scope_id: netstack.scope_id
				);
				Udp.send_to (remoted_mdns_request.get_data (), mdns_address, sock_datagram, cancellable);

				var in_source = sock_datagram.create_source (IN, cancellable);
				in_source.set_callback (() => {
					locate_ncm_peer_on_system_netifs.callback ();
					return Source.REMOVE;
				});
				in_source.attach (main_context);
			}

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (() => {
				open.callback ();
				return Source.REMOVE;
			});
			cancel_source.attach (main_context);

			printerr (">>>\n");
			yield;
			printerr ("<<<\n");

			cancel_source.destroy ();
			in_source.destroy ();

			cancellable.set_error_if_cancelled ();

			uint8 response_buf[2048];
			InetSocketAddress sender;
			Udp.recv (response_buf, sock_datagram, cancellable, out sender);

			printerr ("Detected remote address: %s\n", sender.address.to_string ());
#endif
		}

		private async NcmPeer establish_ncm_peer_using_our_driver (Cancellable? cancellable) throws Error, IOError {
			ncm = yield UsbNcmDriver.open (usb_device, cancellable);

			if (ncm.remote_ipv6_address == null) {
				ulong change_handler = ncm.notify["remote-ipv6-address"].connect ((obj, pspec) => {
					establish_ncm_peer_using_our_driver.callback ();
				});

				var main_context = MainContext.get_thread_default ();

				var timeout_source = new TimeoutSource.seconds (2);
				timeout_source.set_callback (establish_ncm_peer_using_our_driver.callback);
				timeout_source.attach (main_context);

				var cancel_source = new CancellableSource (cancellable);
				cancel_source.set_callback (establish_ncm_peer_using_our_driver.callback);
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
				ip = ncm.remote_ipv6_address
			};
		}

		public async void close (Cancellable? cancellable) throws IOError {
			_discovery_service.close ();
			tunnel_connection.cancel ();
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

#if MACOS
	private sealed class MacOSCoreDeviceBackend : Object, Backend {
		private Gee.Map<string, MacOSCoreDeviceTransport> transports = new Gee.HashMap<string, MacOSCoreDeviceTransport> ();

		private Promise<bool> all_current_devices_listed = new Promise<bool> ();
		private Promise<bool> browse_request = new Promise<bool> ();

		private XpcClient? pairingd;
		private Darwin.GCD.DispatchQueue queue =
			new Darwin.GCD.DispatchQueue ("re.frida.fruity.remotepairing", Darwin.GCD.DispatchQueueAttr.SERIAL);

		public async void start (Cancellable? cancellable) throws IOError {
			pairingd = XpcClient.make_for_mach_service ("com.apple.CoreDevice.remotepairingd", queue);
			pairingd.notify["state"].connect (on_state_changed);
			pairingd.message.connect (on_message);

			do_browse.begin ();

			try {
				yield all_current_devices_listed.future.wait_async (cancellable);
			} catch (Error e) {
			}
		}

		private async void do_browse () {
			try {
				var r = new PairingdRequest ("RemotePairing.BrowseRequest");
				r.body.set_bool ("currentDevicesOnly", false);
				yield pairingd.request (r.message, null);
				browse_request.resolve (true);
			} catch (GLib.Error e) {
				browse_request.reject (e);
			}
		}

		public async void stop (Cancellable? cancellable) throws IOError {
		}

		private void on_state_changed (Object obj, ParamSpec pspec) {
			if (pairingd.state == CLOSED && !all_current_devices_listed.future.ready) {
				all_current_devices_listed.reject (
					new Error.TRANSPORT ("Connection closed while waiting for initial device list"));
			}
		}

		private void on_message (Darwin.Xpc.Object obj) {
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
							.read_member ("deviceInfo");
						var device_info = (Darwin.Xpc.Dictionary) reader.current_object;
						var pairing_device = new XpcClient (device_info.create_connection ("endpoint"), queue);

						bool attached_physically = reader
							.read_member ("connectionState")
							.read_member ("value")
							.read_member ("attachedPhysically")
							.get_bool_value ();
						reader
							.end_member ()
							.end_member ()
							.end_member ();
						var connection_type = attached_physically
							? ConnectionType.USB
							: ConnectionType.NETWORK;

						var udid = reader.read_member ("udid").get_string_value ();
						reader.end_member ();

						var name = reader.read_member ("name").get_string_value ();
						reader.end_member ();

						on_device_found (pairing_device, connection_type, udid, name);
					} else if (reader.try_read_member ("allCurrentDevicesListed")) {
						all_current_devices_listed.resolve (true);
					}
				}
			} catch (Error e) {
			}
		}

		private void on_device_found (XpcClient pairing_device, ConnectionType connection_type, string udid, string name)
				throws Error {
			var transport = new MacOSCoreDeviceTransport (pairing_device, connection_type, udid, name);
			transports[udid] = transport;
			transport_attached (transport);
		}
	}

	private sealed class MacOSCoreDeviceTransport : Object, Transport, TunnelFinder {
		public XpcClient pairing_device {
			get;
			construct;
		}

		public ConnectionType connection_type {
			get {
				return _connection_type;
			}
		}

		public string udid {
			get {
				return _udid;
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

		private ConnectionType _connection_type;
		private string _udid;
		private string _name;

		private Promise<Tunnel>? tunnel_request;

		public MacOSCoreDeviceTransport (XpcClient pairing_device, ConnectionType connection_type, string udid, string name) {
			Object (pairing_device: pairing_device);
			_connection_type = connection_type;
			_udid = udid;
			_name = name;
		}

		construct {
			pairing_device.notify["state"].connect (on_state_changed);
			pairing_device.message.connect (on_message);
		}

		private void on_state_changed (Object obj, ParamSpec pspec) {
			printerr ("[MacOSCoreDeviceTransport] new state: %s\n", pairing_device.state.to_string ());
		}

		private void on_message (Darwin.Xpc.Object obj) {
			// printerr ("[MacOSCoreDeviceTransport] %s\n", obj.to_string ());
		}

		public async Tunnel? find_tunnel (Cancellable? cancellable) throws Error, IOError {
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
				var tunnel = new MacOSTunnel (pairing_device);
				yield tunnel.attach (cancellable);

				tunnel_request.resolve (tunnel);

				return tunnel;
			} catch (GLib.Error e) {
				tunnel_request.reject (e);
				tunnel_request = null;

				throw_api_error (e);
			}
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

	private sealed class PairingdRequest {
		public Darwin.Xpc.Dictionary message = new Darwin.Xpc.Dictionary ();
		public Darwin.Xpc.Dictionary body = new Darwin.Xpc.Dictionary ();

		public PairingdRequest (string name) {
			message.set_string ("mangledTypeName", name);
			message.set_value ("value", body);
		}
	}
#endif
}
