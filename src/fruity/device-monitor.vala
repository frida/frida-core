[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
	public sealed class DeviceMonitor : Object {
		public signal void device_attached (Device device);
		public signal void device_detached (Device device);

		private State state = CREATED;
		private Gee.List<DeviceTransportBackend> backends = new Gee.ArrayList<DeviceTransportBackend> ();
		private Gee.Map<string, Device> devices = new Gee.HashMap<string, Device> ();

		private enum State {
			CREATED,
			STARTING,
			STARTED,
			STOPPED,
		}

		private delegate void NotifyCompleteFunc ();

		construct {
			add_backend (new UsbmuxTransportBackend ());
#if MACOS
			add_backend (new RemotePairingTransportBackend ());
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

		private async void do_start (DeviceTransportBackend backend, Cancellable? cancellable, NotifyCompleteFunc on_complete) {
			try {
				yield backend.start (cancellable);
			} catch (IOError e) {
			}

			on_complete ();
		}

		private async void do_stop (DeviceTransportBackend backend, Cancellable? cancellable, NotifyCompleteFunc on_complete) {
			try {
				yield backend.stop (cancellable);
			} catch (IOError e) {
			}

			on_complete ();
		}

		private void add_backend (DeviceTransportBackend backend) {
			backends.add (backend);
			backend.transport_attached.connect (on_transport_attached);
			backend.transport_detached.connect (on_transport_detached);
		}

		private void on_transport_attached (DeviceTransport transport) {
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

		private void on_transport_detached (DeviceTransport transport) {
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

		public Gee.Set<DeviceTransport> transports {
			get;
			default = new Gee.HashSet<DeviceTransport> ();
		}

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
			try {
				var client = yield LockdownClient.open (get_usbmux_device (), cancellable);
				yield client.start_session (cancellable);
				return client;
			} catch (LockdownError e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
		}

		public async IOStream open_lockdown_service (string service_name, LockdownClient client, Cancellable? cancellable)
				throws Error, IOError {
			var tunnel = yield find_tunnel (cancellable);
			if (tunnel != null) {
				ServiceInfo? service_info = null;
				bool needs_checkin = false;
				try {
					service_info = tunnel.discovery.get_service (service_name);
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

			try {
				return yield client.start_service (service_name, cancellable);
			} catch (GLib.Error e) {
				if (e is LockdownError.INVALID_SERVICE)
					throw new Error.NOT_SUPPORTED ("%s", e.message);
				throw new Error.TRANSPORT ("%s", e.message);
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

				if (service_name == "") {
					try {
						var client = yield LockdownClient.open (get_usbmux_device (), cancellable);
						yield client.start_session (cancellable);
						return client.stream;
					} catch (GLib.Error e) {
						throw new Error.NOT_SUPPORTED ("%s", e.message);
					}
				}

				var client = yield get_lockdown_client (cancellable);
				return yield open_lockdown_service (service_name, client, cancellable);
			}

			throw new Error.NOT_SUPPORTED ("Unsupported channel address");
		}
	}

	public interface DeviceTransport : Object {
		public abstract ConnectionType connection_type {
			get;
		}

		public abstract string udid {
			get;
		}

		public abstract string name {
			get;
		}

		public abstract Variant? icon {
			get;
		}

		public abstract UsbmuxDevice? usbmux_device {
			get;
		}
	}

	private interface DeviceTransportBackend : Object {
		public signal void transport_attached (DeviceTransport transport);
		public signal void transport_detached (DeviceTransport transport);

		public abstract async void start (Cancellable? cancellable) throws IOError;
		public abstract async void stop (Cancellable? cancellable) throws IOError;
	}

	public enum ConnectionType {
		USB,
		NETWORK
	}

	private class UsbmuxTransportBackend : Object, DeviceTransportBackend {
		private Gee.Map<UsbmuxDevice, UsbmuxDeviceTransport> transports = new Gee.HashMap<UsbmuxDevice, UsbmuxDeviceTransport> ();

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
			var transport = new UsbmuxDeviceTransport (device);
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
			UsbmuxDeviceTransport transport;
			transports.unset (device, out transport);
			transport_detached (transport);
		}

		public extern static void _extract_details_for_device (int product_id, string udid, out string name,
			out Variant? icon) throws Error;
	}

	private class UsbmuxDeviceTransport : Object, DeviceTransport {
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

		public string name {
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

		public UsbmuxDeviceTransport (UsbmuxDevice device) {
			Object (device: device);
		}
	}

#if MACOS
	private class RemotePairingTransportBackend : Object, DeviceTransportBackend {
		private Gee.Map<string, RemotePairingDeviceTransport> transports = new Gee.HashMap<string, RemotePairingDeviceTransport> ();

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
						printerr ("%s\n", device_info.to_string ());
						var pairing_device = new XpcClient (device_info.create_connection ("endpoint"), queue);
						ConnectionType connection_type = USB; // FIXME
						var udid = reader.read_member ("udid").get_string_value ();
						var name = reader.read_member ("name").get_string_value ();
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
			var transport = new RemotePairingDeviceTransport (pairing_device, connection_type, udid, name);
			transports[udid] = transport;
			transport_attached (transport);
		}
	}

	private class RemotePairingDeviceTransport : Object, DeviceTransport, TunnelFinder {
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

		public string name {
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

		public RemotePairingDeviceTransport (XpcClient pairing_device, ConnectionType connection_type, string udid, string name) {
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
			printerr ("[RemotePairingDeviceTransport] new state: %s\n", pairing_device.state.to_string ());
		}

		private void on_message (Darwin.Xpc.Object obj) {
			printerr ("[RemotePairingDeviceTransport] %s\n", obj.to_string ());
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

	private class PairingdRequest {
		public Darwin.Xpc.Dictionary message = new Darwin.Xpc.Dictionary ();
		public Darwin.Xpc.Dictionary body = new Darwin.Xpc.Dictionary ();

		public PairingdRequest (string name) {
			message.set_string ("mangledTypeName", name);
			message.set_value ("value", body);
		}
	}
#endif

	public class NcmStuffToBeMoved : Object {
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
