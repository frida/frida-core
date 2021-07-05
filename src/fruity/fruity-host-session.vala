namespace Frida {
	public class FruityHostSessionBackend : Object, HostSessionBackend {
		private Fruity.UsbmuxClient control_client;

		private Gee.HashSet<uint> devices = new Gee.HashSet<uint> ();
		private Gee.HashMap<uint, FruityHostSessionProvider> providers = new Gee.HashMap<uint, FruityHostSessionProvider> ();

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
			bool success = yield try_start_control_connection ();

			if (success) {
				/* Perform a dummy-request to flush out any pending device attach notifications. */
				try {
					yield control_client.connect_to_port (Fruity.DeviceId (uint.MAX), 0, start_cancellable);
					assert_not_reached ();
				} catch (GLib.Error expected_error) {
					if (expected_error.code == IOError.CONNECTION_CLOSED) {
						/* Deal with usbmuxd closing the connection when receiving commands in the wrong state. */
						control_client.close.begin (null);

						success = yield try_start_control_connection ();
						if (success) {
							Fruity.UsbmuxClient flush_client = null;
							try {
								flush_client = yield Fruity.UsbmuxClient.open (start_cancellable);
								try {
									yield flush_client.connect_to_port (
											Fruity.DeviceId (uint.MAX), 0,
											start_cancellable);
									assert_not_reached ();
								} catch (GLib.Error expected_error) {
								}
							} catch (GLib.Error e) {
								success = false;
							}

							if (flush_client != null)
								flush_client.close.begin (null);

							if (!success && control_client != null) {
								control_client.close.begin (null);
								control_client = null;
							}
						}
					}
				}
			}

			start_request.resolve (success);

			if (on_start_completed != null)
				on_start_completed ();
		}

		private async bool try_start_control_connection () {
			bool success = true;

			try {
				control_client = yield Fruity.UsbmuxClient.open (start_cancellable);

				control_client.device_attached.connect ((details) => {
					add_device.begin (details);
				});
				control_client.device_detached.connect ((id) => {
					remove_device (id);
				});

				yield control_client.enable_listen_mode (start_cancellable);
			} catch (GLib.Error e) {
				success = false;
			}

			if (!success && control_client != null) {
				control_client.close.begin (null);
				control_client = null;
			}

			return success;
		}

		public async void stop (Cancellable? cancellable) throws IOError {
			start_cancellable.cancel ();

			try {
				yield start_request.future.wait_async (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}

			if (control_client != null) {
				yield control_client.close (cancellable);
				control_client = null;
			}

			io_cancellable.cancel ();

			devices.clear ();

			foreach (var provider in providers.values) {
				provider_unavailable (provider);
				yield provider.close (cancellable);
			}
			providers.clear ();
		}

		private async void add_device (Fruity.DeviceDetails details) {
			var id = details.id;
			var raw_id = id.raw_value;
			if (devices.contains (raw_id))
				return;
			devices.add (raw_id);

			string? name = null;
			Variant? icon = null;

			if (details.connection_type == USB) {
				bool got_details = false;
				for (int i = 1; !got_details && devices.contains (raw_id); i++) {
					try {
						_extract_details_for_device (details.product_id.raw_value, details.udid.raw_value,
							out name, out icon);
						got_details = true;
					} catch (Error e) {
						if (i != 20) {
							var main_context = MainContext.get_thread_default ();

							var delay_source = new TimeoutSource.seconds (1);
							delay_source.set_callback (add_device.callback);
							delay_source.attach (main_context);

							var cancel_source = new CancellableSource (io_cancellable);
							cancel_source.set_callback (add_device.callback);
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
				if (!devices.contains (raw_id))
					return;
				if (!got_details) {
					remove_device (id);
					return;
				}
			} else {
				name = "iOS Device [%s]".printf (details.network_address.address.to_string ());
			}

			var provider = new FruityHostSessionProvider (name, icon, details);
			providers[raw_id] = provider;

			provider_available (provider);
		}

		private void remove_device (Fruity.DeviceId id) {
			var raw_id = id.raw_value;
			if (!devices.contains (raw_id))
				return;
			devices.remove (raw_id);

			FruityHostSessionProvider provider;
			if (providers.unset (raw_id, out provider)) {
				provider_unavailable (provider);
				provider.close.begin (io_cancellable);
			}
		}

		public extern static void _extract_details_for_device (int product_id, string udid, out string name,
			out Variant? icon) throws Error;
	}

	public class FruityHostSessionProvider : Object, HostSessionProvider, ChannelProvider, FruityLockdownProvider {
		public string id {
			get { return device_details.udid.raw_value; }
		}

		public string name {
			get { return device_name; }
		}

		public Variant? icon {
			get { return device_icon; }
		}

		public HostSessionProviderKind kind {
			get {
				return (device_details.connection_type == USB)
					? HostSessionProviderKind.USB
					: HostSessionProviderKind.REMOTE;
			}
		}

		public string device_name {
			get;
			construct;
		}

		public Variant? device_icon {
			get;
			construct;
		}

		public Fruity.DeviceDetails device_details {
			get;
			construct;
		}

		private FruityHostSession? host_session;
		private Promise<Fruity.LockdownClient>? lockdown_client_request;
		private Timer? lockdown_client_timer;

		private const double MAX_LOCKDOWN_CLIENT_AGE = 30.0;

		public FruityHostSessionProvider (string name, Variant? icon, Fruity.DeviceDetails details) {
			Object (
				device_name: name,
				device_icon: icon,
				device_details: details
			);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			yield Fruity.DTXConnection.close_all (this, cancellable);

			if (lockdown_client_request != null) {
				Fruity.LockdownClient? lockdown = null;
				try {
					lockdown = yield get_lockdown_client (cancellable);
				} catch (Error e) {
				}

				if (lockdown != null) {
					on_lockdown_client_closed (lockdown);
					yield lockdown.close (cancellable);
				}
			}
		}

		public async HostSession create (HostSessionOptions? options, Cancellable? cancellable) throws Error, IOError {
			if (host_session != null)
				throw new Error.INVALID_OPERATION ("Already created");

			host_session = new FruityHostSession (this, this);
			host_session.agent_session_detached.connect (on_agent_session_detached);

			return host_session;
		}

		public async void destroy (HostSession session, Cancellable? cancellable) throws Error, IOError {
			if (session != host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");

			host_session.agent_session_detached.disconnect (on_agent_session_detached);

			yield host_session.close (cancellable);
			host_session = null;
		}

		public async AgentSession link_agent_session (HostSession host_session, AgentSessionId id, AgentMessageSink sink,
				Cancellable? cancellable) throws Error, IOError {
			if (host_session != this.host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");

			return yield this.host_session.link_agent_session (id, sink, cancellable);
		}

		private void on_agent_session_detached (AgentSessionId id, SessionDetachReason reason, CrashInfo crash) {
			agent_session_detached (id, reason, crash);
		}

		public async IOStream open_channel (string address, Cancellable? cancellable = null) throws Error, IOError {
			if (address.has_prefix ("tcp:")) {
				ulong raw_port;
				if (!ulong.try_parse (address.substring (4), out raw_port) || raw_port == 0 || raw_port > uint16.MAX)
					throw new Error.INVALID_ARGUMENT ("Invalid TCP port");
				uint16 port = (uint16) raw_port;

				if (device_details.connection_type == USB) {
					Fruity.UsbmuxClient client = null;
					try {
						client = yield Fruity.UsbmuxClient.open (cancellable);

						yield client.connect_to_port (device_details.id, port, cancellable);

						return client.connection;
					} catch (GLib.Error e) {
						if (client != null)
							client.close.begin ();

						if (e is Fruity.UsbmuxError.CONNECTION_REFUSED)
							throw new Error.SERVER_NOT_RUNNING ("%s", e.message);

						throw new Error.TRANSPORT ("%s", e.message);
					}
				} else {
					try {
						InetSocketAddress device_address = device_details.network_address;
						var target_address = (InetSocketAddress) Object.new (typeof (InetSocketAddress),
							address: device_address.address,
							port: port,
							flowinfo: device_address.flowinfo,
							scope_id: device_address.scope_id
						);

						var client = new SocketClient ();
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

				if (service_name.length != 0) {
					var client = yield get_lockdown_client (cancellable);

					try {
						return yield client.start_service (service_name, cancellable);
					} catch (GLib.Error e) {
						if (e is Fruity.LockdownError.INVALID_SERVICE)
							throw new Error.NOT_SUPPORTED ("%s", e.message);
						throw new Error.TRANSPORT ("%s", e.message);
					}
				} else {
					try {
						var client = yield Fruity.LockdownClient.open (device_details, cancellable);
						return client.stream;
					} catch (GLib.Error e) {
						throw new Error.NOT_SUPPORTED ("%s", e.message);
					}
				}
			}

			throw new Error.NOT_SUPPORTED ("Unsupported channel address");
		}

		private async Fruity.LockdownClient get_lockdown_client (Cancellable? cancellable) throws Error, IOError {
			if (lockdown_client_timer != null) {
				if (lockdown_client_timer.elapsed () > MAX_LOCKDOWN_CLIENT_AGE)
					on_lockdown_client_closed (lockdown_client_request.future.value);
				else
					lockdown_client_timer.start ();
			}

			while (lockdown_client_request != null) {
				try {
					return yield lockdown_client_request.future.wait_async (cancellable);
				} catch (Error e) {
					throw e;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}
			lockdown_client_request = new Promise<Fruity.LockdownClient> ();

			try {
				var client = yield Fruity.LockdownClient.open (device_details, cancellable);
				client.closed.connect (on_lockdown_client_closed);

				lockdown_client_request.resolve (client);
				lockdown_client_timer = new Timer ();

				return client;
			} catch (GLib.Error e) {
				var api_error = new Error.NOT_SUPPORTED ("%s", e.message);

				lockdown_client_request.reject (api_error);
				lockdown_client_request = null;
				lockdown_client_timer = null;

				throw_api_error (api_error);
			}
		}

		private void on_lockdown_client_closed (Fruity.LockdownClient client) {
			client.closed.disconnect (on_lockdown_client_closed);
			lockdown_client_request = null;
			lockdown_client_timer = null;
		}
	}

	public interface FruityLockdownProvider : Object {
		public abstract async Fruity.LockdownClient get_lockdown_client (Cancellable? cancellable) throws Error, IOError;
	}

	public class FruityHostSession : Object, HostSession {
		public weak ChannelProvider channel_provider {
			get;
			construct;
		}

		public weak FruityLockdownProvider lockdown_provider {
			get;
			construct;
		}

		private Gee.HashMap<uint, LLDBSession> lldb_sessions = new Gee.HashMap<uint, LLDBSession> ();
		private Gee.HashMap<AgentSessionId?, GadgetEntry> gadget_entries =
			new Gee.HashMap<AgentSessionId?, GadgetEntry> (AgentSessionId.hash, AgentSessionId.equal);

		private Promise<RemoteServer>? remote_server_request;
		private RemoteServer? current_remote_server;
		private Timer? last_server_check_timer;
		private Error? last_server_check_error;
		private Gee.HashMap<AgentSessionId?, AgentSessionId?> remote_agent_sessions =
			new Gee.HashMap<AgentSessionId?, AgentSessionId?> (AgentSessionId.hash, AgentSessionId.equal);

		private Gee.HashMap<AgentSessionId?, AgentSessionEntry> agent_sessions =
			new Gee.HashMap<AgentSessionId?, AgentSessionEntry> (AgentSessionId.hash, AgentSessionId.equal);

		private Cancellable io_cancellable = new Cancellable ();

		private const double MIN_SERVER_CHECK_INTERVAL = 5.0;
		private const string GADGET_APP_ID = "re.frida.Gadget";
		private const string DEBUGSERVER_ENDPOINT_MODERN = "com.apple.debugserver.DVTSecureSocketProxy";
		private const string DEBUGSERVER_ENDPOINT_LEGACY = "com.apple.debugserver?tls=handshake-only";
		private const string[] DEBUGSERVER_ENDPOINT_CANDIDATES = {
			DEBUGSERVER_ENDPOINT_MODERN,
			DEBUGSERVER_ENDPOINT_LEGACY,
		};

		public FruityHostSession (ChannelProvider channel_provider, FruityLockdownProvider lockdown_provider) {
			Object (
				channel_provider: channel_provider,
				lockdown_provider: lockdown_provider
			);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			if (remote_server_request != null) {
				var server = yield try_get_remote_server (cancellable);
				if (server != null) {
					try {
						yield server.connection.close (cancellable);
					} catch (GLib.Error e) {
					}
				}
			}

			while (!gadget_entries.is_empty) {
				var iterator = gadget_entries.values.iterator ();
				iterator.next ();
				var entry = iterator.get ();
				yield entry.close (cancellable);
			}

			while (!lldb_sessions.is_empty) {
				var iterator = lldb_sessions.values.iterator ();
				iterator.next ();
				var session = iterator.get ();
				yield session.close (cancellable);
			}

			io_cancellable.cancel ();
		}

		public async void ping (uint interval_seconds, Cancellable? cancellable) throws Error, IOError {
			throw new Error.INVALID_OPERATION ("Only meant to be implemented by services");
		}

		public async HashTable<string, Variant> query_system_parameters (Cancellable? cancellable) throws Error, IOError {
			var server = yield try_get_remote_server (cancellable);
			if (server != null && server.flavor == REGULAR) {
				try {
					return yield server.session.query_system_parameters (cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
			}

			var parameters = new HashTable<string, Variant> (str_hash, str_equal);

			try {
				var lockdown = yield lockdown_provider.get_lockdown_client (cancellable);
				var response = yield lockdown.get_value (null, null, cancellable);
				Fruity.PlistDict properties = response.get_dict ("Value");

				var os = new HashTable<string, Variant> (str_hash, str_equal);
				os["id"] = "ios";
				os["name"] = properties.get_string ("ProductName");
				os["version"] = properties.get_string ("ProductVersion");
				parameters["os"] = os;

				parameters["platform"] = "darwin";

				parameters["arch"] = properties.get_string ("CPUArchitecture").has_prefix ("arm64") ? "arm64" : "arm";

				parameters["access"] = "jailed";

				parameters["name"] = properties.get_string ("DeviceName");
				parameters["udid"] = properties.get_string ("UniqueDeviceID");

				add_interfaces (parameters, properties);
			} catch (Fruity.LockdownError e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			} catch (Fruity.PlistError e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}

			return parameters;
		}

		private static void add_interfaces (HashTable<string, Variant> parameters,
				Fruity.PlistDict properties) throws Fruity.PlistError {
			var ifaces = new VariantBuilder (new VariantType.array (VariantType.VARDICT));

			add_network_interface (ifaces, "ethernet", properties.get_string ("EthernetAddress"));
			add_network_interface (ifaces, "wifi", properties.get_string ("WiFiAddress"));
			add_network_interface (ifaces, "bluetooth", properties.get_string ("BluetoothAddress"));

			if (properties.has ("PhoneNumber")) {
				ifaces.open (VariantType.VARDICT);
				ifaces.add ("{sv}", "type", new Variant.string ("cellular"));
				ifaces.add ("{sv}", "phone-number", new Variant.string (properties.get_string ("PhoneNumber")));
				ifaces.close ();
			}

			parameters["interfaces"] = ifaces.end ();
		}

		private static void add_network_interface (VariantBuilder ifaces, string type, string address) {
			ifaces.open (VariantType.VARDICT);
			ifaces.add ("{sv}", "type", new Variant.string (type));
			ifaces.add ("{sv}", "address", new Variant.string (address));
			ifaces.close ();
		}

		public async HostApplicationInfo get_frontmost_application (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			var server = yield try_get_remote_server (cancellable);
			if (server != null && server.flavor == REGULAR) {
				try {
					return yield server.session.get_frontmost_application (options, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
			}

			var opts = FrontmostQueryOptions._deserialize (options);
			var scope = opts.scope;

			var processes_request = new Promise<Gee.List<Fruity.ProcessInfo>> ();
			var apps_request = new Promise<Gee.List<Fruity.ApplicationDetails>> ();
			fetch_processes.begin (processes_request, cancellable);
			fetch_apps.begin (apps_request, cancellable);

			Gee.List<Fruity.ProcessInfo> processes = yield processes_request.future.wait_async (cancellable);
			Fruity.ProcessInfo? process = null;
			string? app_path = null;
			foreach (Fruity.ProcessInfo candidate in processes) {
				if (!candidate.foreground_running)
					continue;

				if (!candidate.is_application)
					continue;

				bool is_main_process;
				string path = compute_app_path_from_executable_path (candidate.real_app_name, out is_main_process);
				if (!is_main_process)
					continue;

				process = candidate;
				app_path = path;
				break;
			}
			if (process == null)
				return HostApplicationInfo.empty ();

			Gee.List<Fruity.ApplicationDetails> apps = yield apps_request.future.wait_async (cancellable);
			Fruity.ApplicationDetails? app = apps.first_match (app => app.path == app_path);
			if (app == null)
				return HostApplicationInfo.empty ();

			unowned string identifier = app.identifier;

			var info = HostApplicationInfo (identifier, app.name, process.pid, make_parameters_dict ());

			if (scope != MINIMAL) {
				add_app_metadata (info.parameters, app);

				add_process_metadata (info.parameters, process);

				if (scope == FULL) {
					try {
						var lockdown = yield lockdown_provider.get_lockdown_client (cancellable);
						var springboard = yield Fruity.SpringboardServicesClient.open (lockdown, cancellable);

						Bytes png = yield springboard.get_icon_png_data (identifier);
						add_app_icons (info.parameters, png);
					} catch (Fruity.SpringboardServicesError e) {
						throw new Error.NOT_SUPPORTED ("%s", e.message);
					}
				}
			}

			return info;
		}

		public async HostApplicationInfo[] enumerate_applications (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			var server = yield try_get_remote_server (cancellable);
			if (server != null && server.flavor == REGULAR) {
				try {
					return yield server.session.enumerate_applications (options, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
			}

			var opts = ApplicationQueryOptions._deserialize (options);
			var scope = opts.scope;

			var apps_request = new Promise<Gee.List<Fruity.ApplicationDetails>> ();
			var processes_request = new Promise<Gee.List<Fruity.ProcessInfo>> ();
			fetch_apps.begin (apps_request, cancellable);
			fetch_processes.begin (processes_request, cancellable);

			Gee.List<Fruity.ApplicationDetails> apps = yield apps_request.future.wait_async (cancellable);
			apps = maybe_filter_apps (apps, opts);

			Gee.Map<string, Bytes>? icons = null;
			if (scope == FULL) {
				try {
					var lockdown = yield lockdown_provider.get_lockdown_client (cancellable);
					var springboard = yield Fruity.SpringboardServicesClient.open (lockdown, cancellable);

					var app_ids = new Gee.ArrayList<string> ();
					foreach (var app in apps)
						app_ids.add (app.identifier);

					icons = yield springboard.get_icon_png_data_batch (app_ids.to_array (), cancellable);
				} catch (Fruity.SpringboardServicesError e) {
					throw new Error.NOT_SUPPORTED ("%s", e.message);
				}
			}

			Gee.List<Fruity.ProcessInfo> processes = yield processes_request.future.wait_async (cancellable);
			var process_by_app_path = new Gee.HashMap<string, Fruity.ProcessInfo> ();
			foreach (Fruity.ProcessInfo process in processes) {
				bool is_main_process;
				string app_path = compute_app_path_from_executable_path (process.real_app_name, out is_main_process);
				if (is_main_process)
					process_by_app_path[app_path] = process;
			}

			var result = new HostApplicationInfo[0];

			foreach (Fruity.ApplicationDetails app in apps) {
				unowned string identifier = app.identifier;
				Fruity.ProcessInfo? process = process_by_app_path[app.path];

				var info = HostApplicationInfo (identifier, app.name, (process != null) ? process.pid : 0,
					make_parameters_dict ());

				if (scope != MINIMAL) {
					add_app_metadata (info.parameters, app);

					if (process != null) {
						add_app_state (info.parameters, process);

						add_process_metadata (info.parameters, process);
					}
				}

				if (scope == FULL)
					add_app_icons (info.parameters, icons[identifier]);

				result += info;
			}

			if (server != null && server.flavor == GADGET) {
				try {
					foreach (var app in yield server.session.enumerate_applications (options, cancellable))
						result += app;
				} catch (GLib.Error e) {
				}
			}

			return result;
		}

		public async HostProcessInfo[] enumerate_processes (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			var server = yield try_get_remote_server (cancellable);
			if (server != null && server.flavor == REGULAR) {
				try {
					return yield server.session.enumerate_processes (options, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
			}

			var opts = ProcessQueryOptions._deserialize (options);
			var scope = opts.scope;

			var processes_request = new Promise<Gee.List<Fruity.ProcessInfo>> ();
			var apps_request = new Promise<Gee.List<Fruity.ApplicationDetails>> ();
			fetch_processes.begin (processes_request, cancellable);
			fetch_apps.begin (apps_request, cancellable);

			Gee.List<Fruity.ProcessInfo> processes = yield processes_request.future.wait_async (cancellable);
			processes = maybe_filter_processes (processes, opts);

			Gee.List<Fruity.ApplicationDetails> apps = yield apps_request.future.wait_async (cancellable);
			var app_by_path = new Gee.HashMap<string, Fruity.ApplicationDetails> ();
			foreach (var app in apps)
				app_by_path[app.path] = app;

			var app_ids = new Gee.ArrayList<string> ();
			var app_pids = new Gee.ArrayList<uint> ();
			var app_by_main_pid = new Gee.HashMap<uint, Fruity.ApplicationDetails> ();
			var app_by_related_pid = new Gee.HashMap<uint, Fruity.ApplicationDetails> ();
			foreach (Fruity.ProcessInfo process in processes) {
				unowned string executable_path = process.real_app_name;

				bool is_main_process;
				string app_path = compute_app_path_from_executable_path (executable_path, out is_main_process);

				Fruity.ApplicationDetails? app = app_by_path[app_path];
				if (app != null) {
					uint pid = process.pid;

					if (is_main_process) {
						app_ids.add (app.identifier);
						app_pids.add (pid);
						app_by_main_pid[pid] = app;
					} else {
						app_by_related_pid[pid] = app;
					}
				}
			}

			Gee.Map<uint, Bytes>? icon_by_pid = null;
			if (scope == FULL) {
				icon_by_pid = new Gee.HashMap<uint, Bytes> ();

				var lockdown = yield lockdown_provider.get_lockdown_client (cancellable);
				try {
					var springboard = yield Fruity.SpringboardServicesClient.open (lockdown, cancellable);

					var pngs = yield springboard.get_icon_png_data_batch (app_ids.to_array (), cancellable);

					int i = 0;
					foreach (string app_id in app_ids) {
						icon_by_pid[app_pids[i]] = pngs[app_id];
						i++;
					}
				} catch (Fruity.SpringboardServicesError e) {
					throw new Error.NOT_SUPPORTED ("%s", e.message);
				}
			}

			var result = new HostProcessInfo[0];

			foreach (Fruity.ProcessInfo process in processes) {
				uint pid = process.pid;
				if (pid == 0)
					continue;

				Fruity.ApplicationDetails? app = app_by_main_pid[pid];
				string name = (app != null) ? app.name : process.name;

				var info = HostProcessInfo (pid, name, make_parameters_dict ());

				if (scope != MINIMAL) {
					var parameters = info.parameters;

					add_process_metadata (parameters, process);

					parameters["path"] = process.real_app_name;

					Fruity.ApplicationDetails? related_app = (app != null) ? app : app_by_related_pid[pid];
					if (related_app != null) {
						string[] applications = { related_app.identifier };
						parameters["applications"] = applications;
					}

					if (app != null && process.foreground_running)
						parameters["frontmost"] = true;
				}

				if (scope == FULL) {
					Bytes? png = icon_by_pid[pid];
					if (png != null)
						add_app_icons (info.parameters, png);
				}

				result += info;
			}

			if (server != null && server.flavor == GADGET) {
				try {
					foreach (var process in yield server.session.enumerate_processes (options, cancellable))
						result += process;
				} catch (GLib.Error e) {
				}
			}

			return result;
		}

		private async void fetch_apps (Promise<Gee.List<Fruity.ApplicationDetails>> promise, Cancellable? cancellable) {
			try {
				var lockdown = yield lockdown_provider.get_lockdown_client (cancellable);
				var installation_proxy = yield Fruity.InstallationProxyClient.open (lockdown, cancellable);

				var apps = yield installation_proxy.browse (cancellable);

				promise.resolve (apps);
			} catch (Error e) {
				promise.reject (e);
			} catch (IOError e) {
				promise.reject (e);
			} catch (Fruity.InstallationProxyError e) {
				promise.reject (new Error.NOT_SUPPORTED ("%s", e.message));
			}
		}

		private async void fetch_processes (Promise<Gee.List<Fruity.ProcessInfo>> promise, Cancellable? cancellable) {
			try {
				var device_info = yield Fruity.DeviceInfoService.open (channel_provider, cancellable);

				var processes = yield device_info.enumerate_processes (cancellable);

				promise.resolve (processes);
			} catch (Error e) {
				promise.reject (e);
			} catch (IOError e) {
				promise.reject (e);
			}
		}

		private Gee.List<Fruity.ApplicationDetails> maybe_filter_apps (Gee.List<Fruity.ApplicationDetails> apps,
				ApplicationQueryOptions options) {
			if (!options.has_selected_identifiers ())
				return apps;

			var app_by_identifier = new Gee.HashMap<string, Fruity.ApplicationDetails> ();
			foreach (Fruity.ApplicationDetails app in apps)
				app_by_identifier[app.identifier] = app;

			var filtered_apps = new Gee.ArrayList<Fruity.ApplicationDetails> ();
			options.enumerate_selected_identifiers (identifier => {
				Fruity.ApplicationDetails? app = app_by_identifier[identifier];
				if (app != null)
					filtered_apps.add (app);
			});

			return filtered_apps;
		}

		private Gee.List<Fruity.ProcessInfo> maybe_filter_processes (Gee.List<Fruity.ProcessInfo> processes,
				ProcessQueryOptions options) {
			if (!options.has_selected_pids ())
				return processes;

			var process_by_pid = new Gee.HashMap<uint, Fruity.ProcessInfo> ();
			foreach (Fruity.ProcessInfo process in processes)
				process_by_pid[process.pid] = process;

			var filtered_processes = new Gee.ArrayList<Fruity.ProcessInfo> ();
			options.enumerate_selected_pids (pid => {
				Fruity.ProcessInfo? process = process_by_pid[pid];
				if (process != null)
					filtered_processes.add (process);
			});

			return filtered_processes;
		}

		private static string compute_app_path_from_executable_path (string executable_path, out bool is_main_process) {
			string app_path = executable_path;

			int dot_app_start = app_path.last_index_of (".app/");
			if (dot_app_start != -1) {
				app_path = app_path[0:dot_app_start + 4];

				string subpath = executable_path[app_path.length + 1:];
				is_main_process = !("/" in subpath);
			} else {
				is_main_process = false;
			}

			return app_path;
		}

		private void add_app_metadata (HashTable<string, Variant> parameters, Fruity.ApplicationDetails app) {
			string? version = app.version;
			if (version != null)
				parameters["version"] = version;

			string? build = app.build;
			if (build != null)
				parameters["build"] = build;

			parameters["path"] = app.path;

			Gee.Map<string, string> containers = app.containers;
			if (!containers.is_empty) {
				var containers_dict = new VariantBuilder (VariantType.VARDICT);
				foreach (var entry in containers.entries)
					containers_dict.add ("{sv}", entry.key, new Variant.string (entry.value));
				parameters["containers"] = containers_dict.end ();
			}

			if (app.debuggable)
				parameters["debuggable"] = true;
		}

		private void add_app_state (HashTable<string, Variant> parameters, Fruity.ProcessInfo process) {
			if (process.foreground_running)
				parameters["frontmost"] = true;
		}

		private void add_app_icons (HashTable<string, Variant> parameters, Bytes png) {
			var icons = new VariantBuilder (new VariantType.array (VariantType.VARDICT));

			icons.open (VariantType.VARDICT);
			icons.add ("{sv}", "format", new Variant.string ("png"));
			icons.add ("{sv}", "image", Variant.new_from_data (new VariantType ("ay"), png.get_data (), true, png));
			icons.close ();

			parameters["icons"] = icons.end ();
		}

		private void add_process_metadata (HashTable<string, Variant> parameters, Fruity.ProcessInfo? process) {
			DateTime? started = process.start_date;
			if (started != null)
				parameters["started"] = started.format_iso8601 ();
		}

		public async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			var server = yield get_remote_server (cancellable);
			try {
				yield server.session.enable_spawn_gating (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			var server = yield get_remote_server (cancellable);
			try {
				yield server.session.disable_spawn_gating (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws Error, IOError {
			var server = yield get_remote_server (cancellable);
			try {
				return yield server.session.enumerate_pending_spawn (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async HostChildInfo[] enumerate_pending_children (Cancellable? cancellable) throws Error, IOError {
			var server = yield get_remote_server (cancellable);
			try {
				return yield server.session.enumerate_pending_children (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError {
			var server = yield try_get_remote_server (cancellable);
			if (server != null && (server.flavor != GADGET || program == GADGET_APP_ID)) {
				try {
					return yield server.session.spawn (program, options, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
			}

			if (program[0] == '/')
				throw new Error.NOT_SUPPORTED ("Only able to spawn apps");

			var launch_options = new LLDB.LaunchOptions ();

			if (options.has_envp)
				throw new Error.NOT_SUPPORTED ("The 'envp' option is not supported when spawning iOS apps");

			if (options.has_env)
				launch_options.env = options.env;

			if (options.cwd.length > 0)
				throw new Error.NOT_SUPPORTED ("The 'cwd' option is not supported when spawning iOS apps");

			HashTable<string, Variant> aux = options.aux;

			Variant? aslr = aux["aslr"];
			if (aslr != null) {
				if (!aslr.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'aslr' option must be a string");
				launch_options.aslr = LLDB.ASLR.from_nick (aslr.get_string ());
			}

			string? gadget_path = null;
			Variant? gadget_value = aux["gadget"];
			if (gadget_value != null) {
				if (!gadget_value.is_of_type (VariantType.STRING)) {
					throw new Error.INVALID_ARGUMENT ("The 'gadget' option must be a string pointing at the " +
						"frida-gadget.dylib to use");
				}
				gadget_path = gadget_value.get_string ();
			}

			try {
				var lockdown = yield lockdown_provider.get_lockdown_client (cancellable);

				var installation_proxy = yield Fruity.InstallationProxyClient.open (lockdown, cancellable);

				var query = new Fruity.PlistDict ();
				var ids = new Fruity.PlistArray ();
				ids.add_string (program);
				query.set_array ("BundleIDs", ids);

				var matches = yield installation_proxy.lookup (query, cancellable);
				var app = matches[program];
				if (app == null)
					throw new Error.INVALID_ARGUMENT ("Unable to find app with bundle identifier “%s”", program);

				string[] argv = { app.path };
				if (options.has_argv) {
					var provided_argv = options.argv;
					var length = provided_argv.length;
					for (int i = 1; i < length; i++)
						argv += provided_argv[i];
				}

				var lldb = yield start_lldb_service (lockdown, cancellable);
				var process = yield lldb.launch (argv, launch_options, cancellable);
				if (process.observed_state == ALREADY_RUNNING) {
					yield lldb.kill (cancellable);
					yield lldb.close (cancellable);

					lldb = yield start_lldb_service (lockdown, cancellable);
					process = yield lldb.launch (argv, launch_options, cancellable);
				}

				var session = new LLDBSession (lldb, process, gadget_path, channel_provider);
				add_lldb_session (session);

				return process.pid;
			} catch (Fruity.InstallationProxyError e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			} catch (LLDB.Error e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
		}

		public async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError {
			var server = yield get_remote_server (cancellable);
			try {
				yield server.session.input (pid, data, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void resume (uint pid, Cancellable? cancellable) throws Error, IOError {
			var session = lldb_sessions[pid];
			if (session != null) {
				yield session.resume (cancellable);
				return;
			}

			var server = yield get_remote_server (cancellable);
			try {
				yield server.session.resume (pid, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void kill (uint pid, Cancellable? cancellable) throws Error, IOError {
			var lldb_session = lldb_sessions[pid];
			if (lldb_session != null) {
				yield lldb_session.kill (cancellable);
				return;
			}

			var server = yield try_get_remote_server (cancellable);
			if (server != null) {
				try {
					yield server.session.kill (pid, cancellable);
					return;
				} catch (GLib.Error e) {
					if (server.flavor == REGULAR)
						throw_dbus_error (e);
				}
			}

			try {
				var lockdown = yield lockdown_provider.get_lockdown_client (cancellable);
				var lldb = yield start_lldb_service (lockdown, cancellable);
				var process = yield lldb.attach_by_pid (pid, cancellable);

				lldb_session = new LLDBSession (lldb, process, null, channel_provider);
				yield lldb_session.kill (cancellable);
				yield lldb_session.close (cancellable);

			} catch (LLDB.Error e) {
				var process_control = yield Fruity.ProcessControlService.open (channel_provider, cancellable);
				yield process_control.kill (pid, cancellable);
			}
		}

		public async AgentSessionId attach (uint pid, HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			var lldb_session = lldb_sessions[pid];
			if (lldb_session != null) {
				var gadget_details = yield lldb_session.query_gadget_details (cancellable);

				return yield attach_via_gadget (pid, options, gadget_details, cancellable);
			}

			var server = yield try_get_remote_server (cancellable);
			if (server != null) {
				try {
					return yield attach_via_remote (pid, options, server, cancellable);
				} catch (Error e) {
					if (server.flavor == REGULAR)
						throw_api_error (e);
				}
			}

			if (pid == 0)
				throw new Error.NOT_SUPPORTED ("The Frida system session is not available on jailed iOS");

			try {
				var lockdown = yield lockdown_provider.get_lockdown_client (cancellable);
				var lldb = yield start_lldb_service (lockdown, cancellable);
				var process = yield lldb.attach_by_pid (pid, cancellable);

				string? gadget_path = null;

				lldb_session = new LLDBSession (lldb, process, gadget_path, channel_provider);
				add_lldb_session (lldb_session);
			} catch (LLDB.Error e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}

			var gadget_details = yield lldb_session.query_gadget_details (cancellable);

			return yield attach_via_gadget (pid, options, gadget_details, cancellable);
		}

		public async void reattach (AgentSessionId id, Cancellable? cancellable) throws Error, IOError {
			throw new Error.INVALID_OPERATION ("Only meant to be implemented by services");
		}

		private async LLDB.Client start_lldb_service (Fruity.LockdownClient lockdown, Cancellable? cancellable)
				throws Error, LLDB.Error, IOError {
			foreach (unowned string endpoint in DEBUGSERVER_ENDPOINT_CANDIDATES) {
				try {
					var lldb_stream = yield lockdown.start_service (endpoint, cancellable);
					return yield LLDB.Client.open (lldb_stream, cancellable);
				} catch (Fruity.LockdownError e) {
					if (!(e is Fruity.LockdownError.INVALID_SERVICE))
						throw new Error.NOT_SUPPORTED ("%s", e.message);
				}
			}

			throw new Error.NOT_SUPPORTED ("This feature requires an iOS Developer Disk Image to be mounted; " +
				"run Xcode briefly or use ideviceimagemounter to mount one manually");
		}

		private async AgentSessionId attach_via_gadget (uint pid, HashTable<string, Variant> options,
				Fruity.Injector.GadgetDetails gadget_details, Cancellable? cancellable) throws Error, IOError {
			try {
				var stream = yield channel_provider.open_channel (
					("tcp:%" + uint16.FORMAT_MODIFIER + "u").printf (gadget_details.port),
					cancellable);

				var connection = yield new DBusConnection (stream, null, DBusConnectionFlags.NONE, null, cancellable);

				HostSession host_session = yield connection.get_proxy (null, ObjectPath.HOST_SESSION,
					DO_NOT_LOAD_PROPERTIES, cancellable);

				AgentSessionId remote_session_id;
				try {
					remote_session_id = yield host_session.attach (pid, options, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}

				var local_session_id = AgentSessionId.generate ();
				var gadget_entry = new GadgetEntry (local_session_id, host_session, connection);
				gadget_entry.detached.connect (on_gadget_entry_detached);
				gadget_entries[local_session_id] = gadget_entry;
				agent_sessions[local_session_id] = new AgentSessionEntry (remote_session_id, connection);

				return local_session_id;
			} catch (GLib.Error e) {
				if (e is Error)
					throw (Error) e;
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
		}

		private async AgentSessionId attach_via_remote (uint pid, HashTable<string, Variant> options, RemoteServer server,
				Cancellable? cancellable) throws Error, IOError {
			AgentSessionId remote_session_id;
			try {
				remote_session_id = yield server.session.attach (pid, options, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
			var local_session_id = AgentSessionId.generate ();

			var entry = new AgentSessionEntry (remote_session_id, server.connection);

			remote_agent_sessions[remote_session_id] = local_session_id;
			agent_sessions[local_session_id] = entry;

			var transport_broker = server.transport_broker;
			if (transport_broker != null) {
				try {
					entry.connection = yield establish_direct_connection (transport_broker, remote_session_id,
						channel_provider, cancellable);
				} catch (Error e) {
					if (e is Error.NOT_SUPPORTED)
						server.transport_broker = null;
				}
			}

			return local_session_id;
		}

		public async AgentSession link_agent_session (AgentSessionId id, AgentMessageSink sink,
				Cancellable? cancellable) throws Error, IOError {
			AgentSessionEntry entry = agent_sessions[id];
			if (entry == null)
				throw new Error.INVALID_ARGUMENT ("Invalid session ID");

			DBusConnection connection = entry.connection;
			AgentSessionId remote_id = entry.remote_session_id;

			AgentSession session = yield connection.get_proxy (null, ObjectPath.for_agent_session (remote_id),
				DO_NOT_LOAD_PROPERTIES, cancellable);

			entry.sink_registration_id = connection.register_object (ObjectPath.for_agent_message_sink (remote_id), sink);

			return session;
		}

		public async InjectorPayloadId inject_library_file (uint pid, string path, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			var server = yield get_remote_server (cancellable);
			try {
				return yield server.session.inject_library_file (pid, path, entrypoint, data, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async InjectorPayloadId inject_library_blob (uint pid, uint8[] blob, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			var server = yield get_remote_server (cancellable);
			try {
				return yield server.session.inject_library_blob (pid, blob, entrypoint, data, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		private void add_lldb_session (LLDBSession session) {
			lldb_sessions[session.process.pid] = session;

			session.closed.connect (on_lldb_session_closed);
			session.output.connect (on_lldb_session_output);
		}

		private void remove_lldb_session (LLDBSession session) {
			lldb_sessions.unset (session.process.pid);

			session.closed.disconnect (on_lldb_session_closed);
			session.output.disconnect (on_lldb_session_output);
		}

		private void on_lldb_session_closed (LLDBSession session) {
			remove_lldb_session (session);
		}

		private void on_lldb_session_output (LLDBSession session, Bytes bytes) {
			output (session.process.pid, 1, bytes.get_data ());
		}

		private void on_gadget_entry_detached (GadgetEntry entry, SessionDetachReason reason) {
			AgentSessionId id = entry.local_session_id;
			var no_crash = CrashInfo.empty ();

			gadget_entries.unset (id);
			agent_sessions.unset (id);

			entry.detached.disconnect (on_gadget_entry_detached);

			agent_session_detached (id, reason, no_crash);

			entry.close.begin (io_cancellable);
		}

		private async RemoteServer? try_get_remote_server (Cancellable? cancellable) throws IOError {
			try {
				return yield get_remote_server (cancellable);
			} catch (Error e) {
				return null;
			}
		}

		private async RemoteServer get_remote_server (Cancellable? cancellable) throws Error, IOError {
			if (current_remote_server != null)
				return current_remote_server;

			while (remote_server_request != null) {
				try {
					return yield remote_server_request.future.wait_async (cancellable);
				} catch (Error e) {
					throw e;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}

			if (last_server_check_timer != null && last_server_check_timer.elapsed () < MIN_SERVER_CHECK_INTERVAL)
				throw last_server_check_error;
			last_server_check_timer = new Timer ();

			remote_server_request = new Promise<RemoteServer> ();

			DBusConnection? connection = null;
			try {
				var stream = yield channel_provider.open_channel (
					("tcp:%" + uint16.FORMAT_MODIFIER + "u").printf (DEFAULT_CONTROL_PORT),
					cancellable);

				connection = yield new DBusConnection (stream, null, DBusConnectionFlags.NONE, null, cancellable);

				HostSession session = yield connection.get_proxy (null, ObjectPath.HOST_SESSION, DO_NOT_LOAD_PROPERTIES,
					cancellable);

				RemoteServer.Flavor flavor = REGULAR;
				try {
					var app = yield session.get_frontmost_application (make_parameters_dict (), cancellable);
					if (app.identifier == GADGET_APP_ID)
						flavor = GADGET;
				} catch (GLib.Error e) {
				}

				TransportBroker? transport_broker = null;
				if (flavor == REGULAR) {
					transport_broker = yield connection.get_proxy (null, ObjectPath.TRANSPORT_BROKER,
						DO_NOT_LOAD_PROPERTIES, cancellable);
				}

				if (connection.closed)
					throw new Error.SERVER_NOT_RUNNING ("Unable to connect to remote frida-server");

				var server = new RemoteServer (session, connection, flavor, transport_broker);
				attach_remote_server (server);
				current_remote_server = server;
				last_server_check_timer = null;
				last_server_check_error = null;

				remote_server_request.resolve (server);

				return server;
			} catch (GLib.Error e) {
				GLib.Error api_error;

				if (e is IOError.CANCELLED) {
					api_error = new IOError.CANCELLED ("%s", e.message);

					last_server_check_timer = null;
					last_server_check_error = null;
				} else {
					if (e is Error.SERVER_NOT_RUNNING) {
						api_error = new Error.SERVER_NOT_RUNNING ("Unable to connect to remote frida-server");
					} else if (connection != null) {
						api_error = new Error.PROTOCOL ("Incompatible frida-server version");
					} else {
						api_error = new Error.SERVER_NOT_RUNNING ("Unable to connect to remote frida-server: %s",
							e.message);
					}

					last_server_check_error = (Error) api_error;
				}

				remote_server_request.reject (api_error);
				remote_server_request = null;

				throw_api_error (api_error);
			}
		}

		private void attach_remote_server (RemoteServer server) {
			server.connection.on_closed.connect (on_remote_connection_closed);

			var session = server.session;
			session.spawn_added.connect (on_remote_spawn_added);
			session.spawn_removed.connect (on_remote_spawn_removed);
			session.child_added.connect (on_remote_child_added);
			session.child_removed.connect (on_remote_child_removed);
			session.process_crashed.connect (on_remote_process_crashed);
			session.output.connect (on_remote_output);
			session.agent_session_detached.connect (on_remote_agent_session_detached);
			session.uninjected.connect (on_remote_uninjected);
		}

		private void detach_remote_server (RemoteServer server) {
			server.connection.on_closed.disconnect (on_remote_connection_closed);

			var session = server.session;
			session.spawn_added.disconnect (on_remote_spawn_added);
			session.spawn_removed.disconnect (on_remote_spawn_removed);
			session.child_added.disconnect (on_remote_child_added);
			session.child_removed.disconnect (on_remote_child_removed);
			session.process_crashed.disconnect (on_remote_process_crashed);
			session.output.disconnect (on_remote_output);
			session.agent_session_detached.disconnect (on_remote_agent_session_detached);
			session.uninjected.disconnect (on_remote_uninjected);
		}

		private void on_remote_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			detach_remote_server (current_remote_server);
			current_remote_server = null;
			remote_server_request = null;

			var no_crash = CrashInfo.empty ();
			foreach (var remote_id in remote_agent_sessions.keys.to_array ())
				on_remote_agent_session_detached (remote_id, CONNECTION_TERMINATED, no_crash);
		}

		private void on_remote_spawn_added (HostSpawnInfo info) {
			spawn_added (info);
		}

		private void on_remote_spawn_removed (HostSpawnInfo info) {
			spawn_removed (info);
		}

		private void on_remote_child_added (HostChildInfo info) {
			child_added (info);
		}

		private void on_remote_child_removed (HostChildInfo info) {
			child_removed (info);
		}

		private void on_remote_process_crashed (CrashInfo crash) {
			process_crashed (crash);
		}

		private void on_remote_output (uint pid, int fd, uint8[] data) {
			output (pid, fd, data);
		}

		private void on_remote_agent_session_detached (AgentSessionId remote_id, SessionDetachReason reason, CrashInfo crash) {
			AgentSessionId? local_id;
			if (!remote_agent_sessions.unset (remote_id, out local_id))
				return;

			bool agent_session_found = agent_sessions.unset (local_id);
			assert (agent_session_found);

			agent_session_detached (local_id, reason, crash);
		}

		private void on_remote_uninjected (InjectorPayloadId id) {
			uninjected (id);
		}

		private class LLDBSession : Object {
			public signal void closed ();
			public signal void output (Bytes bytes);

			public LLDB.Client lldb {
				get;
				construct;
			}

			public LLDB.Process process {
				get;
				construct;
			}

			public string? gadget_path {
				get;
				construct;
			}

			public weak ChannelProvider channel_provider {
				get;
				construct;
			}

			private Promise<Fruity.Injector.GadgetDetails>? gadget_request;

			public LLDBSession (LLDB.Client lldb, LLDB.Process process, string? gadget_path, ChannelProvider channel_provider) {
				Object (
					lldb: lldb,
					process: process,
					gadget_path: gadget_path,
					channel_provider: channel_provider
				);
			}

			construct {
				lldb.closed.connect (on_lldb_closed);
				lldb.console_output.connect (on_lldb_console_output);
			}

			~LLDBSession () {
				lldb.closed.disconnect (on_lldb_closed);
				lldb.console_output.disconnect (on_lldb_console_output);
			}

			public async void close (Cancellable? cancellable) throws IOError {
				yield lldb.close (cancellable);
			}

			public async void resume (Cancellable? cancellable) throws Error, IOError {
				try {
					yield lldb.detach (cancellable);
				} catch (LLDB.Error e) {
					throw new Error.NOT_SUPPORTED ("%s", e.message);
				}
			}

			public async void kill (Cancellable? cancellable) throws Error, IOError {
				try {
					yield lldb.kill (cancellable);
				} catch (LLDB.Error e) {
					throw new Error.NOT_SUPPORTED ("%s", e.message);
				}
			}

			public async Fruity.Injector.GadgetDetails query_gadget_details (Cancellable? cancellable) throws Error, IOError {
				while (gadget_request != null) {
					try {
						return yield gadget_request.future.wait_async (cancellable);
					} catch (Error e) {
						throw e;
					} catch (IOError e) {
						cancellable.set_error_if_cancelled ();
					}
				}
				gadget_request = new Promise<Fruity.Injector.GadgetDetails> ();

				try {
					string? path = gadget_path;
					if (path == null) {
						path = Path.build_filename (Environment.get_user_cache_dir (), "frida", "gadget-ios.dylib");
						if (!FileUtils.test (path, FileTest.EXISTS)) {
							throw new Error.NOT_SUPPORTED ("Need Gadget to attach on jailed iOS; its default location is: %s",
								path);
						}
					}

					if (process.cpu_type != ARM64)
						throw new Error.NOT_SUPPORTED ("Unsupported CPU; only arm64 is supported on jailed iOS");

					var ptrauth_support = (process.cpu_subtype == ARM64E)
						? Gum.PtrauthSupport.SUPPORTED
						: Gum.PtrauthSupport.UNSUPPORTED;
					var module = new Gum.DarwinModule.from_file (path, Gum.CpuType.ARM64, ptrauth_support);

					var details = yield Fruity.Injector.inject ((owned) module, lldb, channel_provider, cancellable);

					gadget_request.resolve (details);

					return details;
				} catch (GLib.Error e) {
					var api_error = new Error.NOT_SUPPORTED ("%s", e.message);

					gadget_request.reject (api_error);
					gadget_request = null;

					throw api_error;
				}
			}

			private void on_lldb_closed () {
				closed ();
			}

			private void on_lldb_console_output (Bytes bytes) {
				output (bytes);
			}
		}

		private class GadgetEntry : Object {
			public signal void detached (SessionDetachReason reason);

			public AgentSessionId local_session_id {
				get;
				construct;
			}

			public HostSession host_session {
				get;
				construct;
			}

			public DBusConnection connection {
				get;
				construct;
			}

			private Promise<bool>? close_request;

			public GadgetEntry (AgentSessionId local_session_id, HostSession host_session, DBusConnection connection) {
				Object (
					local_session_id: local_session_id,
					host_session: host_session,
					connection: connection
				);
			}

			construct {
				connection.on_closed.connect (on_connection_closed);
				host_session.agent_session_detached.connect (on_session_detached);
			}

			~GadgetEntry () {
				connection.on_closed.disconnect (on_connection_closed);
				host_session.agent_session_detached.disconnect (on_session_detached);
			}

			public async void close (Cancellable? cancellable) throws IOError {
				while (close_request != null) {
					try {
						yield close_request.future.wait_async (cancellable);
						return;
					} catch (Error e) {
						assert_not_reached ();
					} catch (IOError e) {
						cancellable.set_error_if_cancelled ();
					}
				}
				close_request = new Promise<bool> ();

				try {
					yield connection.close (cancellable);
				} catch (GLib.Error e) {
					if (e is IOError.CANCELLED) {
						close_request.reject (e);
						close_request = null;

						throw (IOError) e;
					}
				}

				close_request.resolve (true);
			}

			private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
				if (close_request == null) {
					close_request = new Promise<bool> ();
					close_request.resolve (true);
				}

				detached (PROCESS_TERMINATED);
			}

			private void on_session_detached (AgentSessionId id, SessionDetachReason reason) {
				detached (reason);
			}
		}

		private class AgentSessionEntry {
			public AgentSessionId remote_session_id {
				get;
				private set;
			}

			public DBusConnection connection {
				get;
				set;
			}

			public uint sink_registration_id {
				get;
				set;
			}

			public AgentSessionEntry (AgentSessionId remote_session_id, DBusConnection connection) {
				this.remote_session_id = remote_session_id;
				this.connection = connection;
			}

			~AgentSessionEntry () {
				if (sink_registration_id != 0)
					connection.unregister_object (sink_registration_id);
			}
		}

		private class RemoteServer : Object {
			public HostSession session {
				get;
				construct;
			}

			public DBusConnection connection {
				get;
				construct;
			}

			public Flavor flavor {
				get;
				construct;
			}

			public enum Flavor {
				REGULAR,
				GADGET
			}

			public TransportBroker? transport_broker {
				get;
				set;
			}

			public RemoteServer (HostSession session, DBusConnection connection, Flavor flavor,
					TransportBroker? transport_broker) {
				Object (
					session: session,
					connection: connection,
					flavor: flavor,
					transport_broker: transport_broker
				);
			}
		}
	}
}
