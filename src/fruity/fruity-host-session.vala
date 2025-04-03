namespace Frida {
	public sealed class FruityHostSessionBackend : Object, HostSessionBackend {
		private Fruity.DeviceMonitor device_monitor = new Fruity.DeviceMonitor ();
		private Gee.Map<Fruity.Device, FruityHostSessionProvider> providers =
			new Gee.HashMap<Fruity.Device, FruityHostSessionProvider> ();

		private Cancellable io_cancellable = new Cancellable ();

		construct {
			device_monitor.device_attached.connect (on_device_attached);
			device_monitor.device_detached.connect (on_device_detached);
		}

		public async void start (Cancellable? cancellable) throws IOError {
			yield device_monitor.start (cancellable);
		}

		public async void stop (Cancellable? cancellable) throws IOError {
			io_cancellable.cancel ();

			yield device_monitor.stop (cancellable);

			foreach (var provider in providers.values) {
				provider_unavailable (provider);
				yield provider.close (cancellable);
			}
			providers.clear ();
		}

		private void on_device_attached (Fruity.Device device) {
			var provider = new FruityHostSessionProvider (device);
			providers[device] = provider;
			provider_available (provider);
		}

		private void on_device_detached (Fruity.Device device) {
			FruityHostSessionProvider provider;
			if (providers.unset (device, out provider)) {
				provider_unavailable (provider);
				provider.close.begin (io_cancellable);
			}
		}
	}

	public sealed class FruityHostSessionProvider : Object, HostSessionProvider, HostChannelProvider, Pairable {
		public Fruity.Device device {
			get;
			construct;
		}

		public string id {
			get { return device.udid; }
		}

		public string name {
			get { return _name; }
		}

		public Variant? icon {
			get { return device.icon; }
		}

		public HostSessionProviderKind kind {
			get {
				return (device.connection_type == USB)
					? HostSessionProviderKind.USB
					: HostSessionProviderKind.REMOTE;
			}
		}

		private FruityHostSession? host_session;
		private string _name;

		public FruityHostSessionProvider (Fruity.Device device) {
			Object (device: device);
			_name = device.name;
		}

		public async void close (Cancellable? cancellable) throws IOError {
			yield Fruity.DTXConnection.close_all (device, cancellable);
		}

		public async HostSession create (HostSessionOptions? options, Cancellable? cancellable) throws Error, IOError {
			if (host_session != null)
				throw new Error.INVALID_OPERATION ("Already created");

			host_session = new FruityHostSession (device);
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

		public void unlink_agent_session (HostSession host_session, AgentSessionId id) {
			if (host_session != this.host_session)
				return;

			this.host_session.unlink_agent_session (id);
		}

		public async IOStream link_channel (HostSession host_session, ChannelId id, Cancellable? cancellable)
				throws Error, IOError {
			if (host_session != this.host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");

			return this.host_session.link_channel (id);
		}

		public void unlink_channel (HostSession host_session, ChannelId id) {
			if (host_session != this.host_session)
				return;

			this.host_session.unlink_channel (id);
		}

		public async ServiceSession link_service_session (HostSession host_session, ServiceSessionId id, Cancellable? cancellable)
				throws Error, IOError {
			if (host_session != this.host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");

			return this.host_session.link_service_session (id);
		}

		public void unlink_service_session (HostSession host_session, ServiceSessionId id) {
			if (host_session != this.host_session)
				return;

			this.host_session.unlink_service_session (id);
		}

		private void on_agent_session_detached (AgentSessionId id, SessionDetachReason reason, CrashInfo crash) {
			agent_session_detached (id, reason, crash);
		}

		public async IOStream open_channel (string address, Cancellable? cancellable) throws Error, IOError {
			return yield device.open_channel (address, cancellable);
		}

		private async void unpair (Cancellable? cancellable) throws Error, IOError {
			try {
				var client = yield device.get_lockdown_client (cancellable);
				yield client.unpair (cancellable);
			} catch (Fruity.LockdownError e) {
				if (e is Fruity.LockdownError.NOT_PAIRED)
					return;
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
		}
	}

	public sealed class FruityHostSession : Object, HostSession {
		public Fruity.Device device {
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

		private ChannelRegistry channel_registry = new ChannelRegistry ();

		private ServiceSessionRegistry service_session_registry = new ServiceSessionRegistry ();

		private Cancellable io_cancellable = new Cancellable ();

		private const double MIN_SERVER_CHECK_INTERVAL = 5.0;
		private const string GADGET_APP_ID = "re.frida.Gadget";
		private const string DEBUGSERVER_ENDPOINT_17PLUS = "com.apple.internal.dt.remote.debugproxy";
		private const string DEBUGSERVER_ENDPOINT_14PLUS = "com.apple.debugserver.DVTSecureSocketProxy";
		private const string DEBUGSERVER_ENDPOINT_LEGACY = "com.apple.debugserver?tls=handshake-only";
		private const string[] DEBUGSERVER_ENDPOINT_CANDIDATES = {
			DEBUGSERVER_ENDPOINT_17PLUS,
			DEBUGSERVER_ENDPOINT_14PLUS,
			DEBUGSERVER_ENDPOINT_LEGACY,
		};

		public FruityHostSession (Fruity.Device device) {
			Object (device: device);
		}

		construct {
			channel_registry.channel_closed.connect (on_channel_closed);
			service_session_registry.session_closed.connect (on_service_session_closed);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			if (remote_server_request != null) {
				try {
					var server = yield try_get_remote_server (cancellable);
					if (server != null) {
						try {
							yield server.connection.close (cancellable);
						} catch (GLib.Error e) {
						}
					}
				} catch (Error e) {
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
				var lockdown = yield device.get_lockdown_client (cancellable);
				var response = yield lockdown.get_value (null, null, cancellable);
				Fruity.PlistDict properties = response.get_dict ("Value");

				var os = new HashTable<string, Variant> (str_hash, str_equal);
				os["id"] = "ios";
				os["name"] = properties.get_string ("ProductName");
				os["version"] = properties.get_string ("ProductVersion");
				os["build"] = properties.get_string ("BuildVersion");
				parameters["os"] = os;

				parameters["platform"] = "darwin";

				parameters["arch"] = properties.get_string ("CPUArchitecture").has_prefix ("arm64") ? "arm64" : "arm";

				var hardware = new HashTable<string, Variant> (str_hash, str_equal);
				hardware["product"] = properties.get_string ("ProductType");
				hardware["platform"] = properties.get_string ("HardwarePlatform");
				hardware["model"] = properties.get_string ("HardwareModel");
				parameters["hardware"] = hardware;

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

			var processes_request = new Promise<Gee.List<Fruity.DeviceInfoService.ProcessInfo>> ();
			var apps_request = new Promise<Gee.List<Fruity.ApplicationDetails>> ();
			fetch_processes.begin (processes_request, cancellable);
			fetch_apps.begin (apps_request, cancellable);

			Gee.List<Fruity.DeviceInfoService.ProcessInfo> processes =
				yield processes_request.future.wait_async (cancellable);
			Fruity.DeviceInfoService.ProcessInfo? process = null;
			string? app_path = null;
			foreach (Fruity.DeviceInfoService.ProcessInfo candidate in processes) {
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
					var springboard = yield Fruity.SpringboardServicesClient.open (device, cancellable);

					Bytes png = yield springboard.get_icon_png_data (identifier);
					add_app_icons (info.parameters, png);
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
			var processes_request = new Promise<Gee.List<Fruity.DeviceInfoService.ProcessInfo>> ();
			fetch_apps.begin (apps_request, cancellable);
			fetch_processes.begin (processes_request, cancellable);

			Gee.List<Fruity.ApplicationDetails> apps = yield apps_request.future.wait_async (cancellable);
			apps = maybe_filter_apps (apps, opts);

			Gee.Map<string, Bytes>? icons = null;
			if (scope == FULL) {
				var springboard = yield Fruity.SpringboardServicesClient.open (device, cancellable);

				var app_ids = new Gee.ArrayList<string> ();
				foreach (var app in apps)
					app_ids.add (app.identifier);

				icons = yield springboard.get_icon_png_data_batch (app_ids.to_array (), cancellable);
			}

			Gee.List<Fruity.DeviceInfoService.ProcessInfo> processes =
				yield processes_request.future.wait_async (cancellable);
			var process_by_app_path = new Gee.HashMap<string, Fruity.DeviceInfoService.ProcessInfo> ();
			foreach (Fruity.DeviceInfoService.ProcessInfo process in processes) {
				bool is_main_process;
				string app_path = compute_app_path_from_executable_path (process.real_app_name, out is_main_process);
				if (is_main_process)
					process_by_app_path[app_path] = process;
			}

			var result = new HostApplicationInfo[0];

			foreach (Fruity.ApplicationDetails app in apps) {
				unowned string identifier = app.identifier;
				Fruity.DeviceInfoService.ProcessInfo? process = process_by_app_path[app.path];

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

			var processes_request = new Promise<Gee.List<Fruity.DeviceInfoService.ProcessInfo>> ();
			var apps_request = new Promise<Gee.List<Fruity.ApplicationDetails>> ();
			fetch_processes.begin (processes_request, cancellable);
			fetch_apps.begin (apps_request, cancellable);

			Gee.List<Fruity.DeviceInfoService.ProcessInfo> processes =
				yield processes_request.future.wait_async (cancellable);
			processes = maybe_filter_processes (processes, opts);

			Gee.List<Fruity.ApplicationDetails> apps = yield apps_request.future.wait_async (cancellable);
			var app_by_path = new Gee.HashMap<string, Fruity.ApplicationDetails> ();
			foreach (var app in apps)
				app_by_path[app.path] = app;

			var app_ids = new Gee.ArrayList<string> ();
			var app_pids = new Gee.ArrayList<uint> ();
			var app_by_main_pid = new Gee.HashMap<uint, Fruity.ApplicationDetails> ();
			var app_by_related_pid = new Gee.HashMap<uint, Fruity.ApplicationDetails> ();
			foreach (Fruity.DeviceInfoService.ProcessInfo process in processes) {
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

				var springboard = yield Fruity.SpringboardServicesClient.open (device, cancellable);

				var pngs = yield springboard.get_icon_png_data_batch (app_ids.to_array (), cancellable);

				int i = 0;
				foreach (string app_id in app_ids) {
					icon_by_pid[app_pids[i]] = pngs[app_id];
					i++;
				}
			}

			var result = new HostProcessInfo[0];

			foreach (Fruity.DeviceInfoService.ProcessInfo process in processes) {
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
				var installation_proxy = yield Fruity.InstallationProxyClient.open (device, cancellable);

				var apps = yield installation_proxy.browse (cancellable);

				promise.resolve (apps);
			} catch (GLib.Error e) {
				promise.reject (e);
			}
		}

		private async void fetch_processes (Promise<Gee.List<Fruity.DeviceInfoService.ProcessInfo>> promise,
				Cancellable? cancellable) {
			try {
				var device_info = yield Fruity.DeviceInfoService.open (device, cancellable);

				var processes = yield device_info.enumerate_processes (cancellable);

				promise.resolve (processes);
			} catch (GLib.Error e) {
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

		private Gee.List<Fruity.DeviceInfoService.ProcessInfo> maybe_filter_processes (
				Gee.List<Fruity.DeviceInfoService.ProcessInfo> processes, ProcessQueryOptions options) {
			if (!options.has_selected_pids ())
				return processes;

			var process_by_pid = new Gee.HashMap<uint, Fruity.DeviceInfoService.ProcessInfo> ();
			foreach (Fruity.DeviceInfoService.ProcessInfo process in processes)
				process_by_pid[process.pid] = process;

			var filtered_processes = new Gee.ArrayList<Fruity.DeviceInfoService.ProcessInfo> ();
			options.enumerate_selected_pids (pid => {
				Fruity.DeviceInfoService.ProcessInfo? process = process_by_pid[pid];
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

		private void add_app_state (HashTable<string, Variant> parameters, Fruity.DeviceInfoService.ProcessInfo process) {
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

		private void add_process_metadata (HashTable<string, Variant> parameters, Fruity.DeviceInfoService.ProcessInfo? process) {
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

			var installation_proxy = yield Fruity.InstallationProxyClient.open (device, cancellable);

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

			var lldb = yield start_lldb_service (cancellable);
			var process = yield lldb.launch (argv, launch_options, cancellable);
			if (process.observed_state == ALREADY_RUNNING) {
				yield lldb.kill (cancellable);
				yield lldb.close (cancellable);

				lldb = yield start_lldb_service (cancellable);
				process = yield lldb.launch (argv, launch_options, cancellable);
			}

			var session = new LLDBSession (lldb, process, gadget_path, device);
			add_lldb_session (session);

			return process.pid;
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
				var lldb = yield start_lldb_service (cancellable);
				var process = yield lldb.attach_by_pid (pid, cancellable);

				lldb_session = new LLDBSession (lldb, process, null, device);
				yield lldb_session.kill (cancellable);
				yield lldb_session.close (cancellable);
			} catch (Error e) {
				var process_control = yield Fruity.ProcessControlService.open (device, cancellable);
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

			var lldb = yield start_lldb_service (cancellable);
			var process = yield lldb.attach_by_pid (pid, cancellable);

			string? gadget_path = null;

			lldb_session = new LLDBSession (lldb, process, gadget_path, device);
			add_lldb_session (lldb_session);

			var gadget_details = yield lldb_session.query_gadget_details (cancellable);

			return yield attach_via_gadget (pid, options, gadget_details, cancellable);
		}

		public async void reattach (AgentSessionId id, Cancellable? cancellable) throws Error, IOError {
			throw new Error.INVALID_OPERATION ("Only meant to be implemented by services");
		}

		private async LLDB.Client start_lldb_service (Cancellable? cancellable) throws Error, IOError {
			foreach (unowned string endpoint in DEBUGSERVER_ENDPOINT_CANDIDATES) {
				try {
					var lldb_stream = yield device.open_lockdown_service (endpoint, cancellable);
					return yield LLDB.Client.open (lldb_stream, cancellable);
				} catch (Error e) {
					if (!(e is Error.NOT_SUPPORTED))
						throw new Error.NOT_SUPPORTED ("%s", e.message);
				}
			}

			throw new Error.NOT_SUPPORTED ("This feature requires an iOS Developer Disk Image to be mounted; " +
				"run Xcode briefly or use ideviceimagemounter to mount one manually");
		}

		private async AgentSessionId attach_via_gadget (uint pid, HashTable<string, Variant> options,
				Fruity.Injector.GadgetDetails gadget_details, Cancellable? cancellable) throws Error, IOError {
			try {
				var stream = yield device.open_channel (
					("tcp:%" + uint16.FORMAT_MODIFIER + "u").printf (gadget_details.port),
					cancellable);

				WebServiceTransport transport = PLAIN;
				string? origin = null;

				stream = yield negotiate_connection (stream, transport, "lolcathost", origin, cancellable);

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
					entry.connection = yield establish_direct_connection (transport_broker, remote_session_id, server,
						cancellable);
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

		public void unlink_agent_session (AgentSessionId id) {
			AgentSessionEntry? entry = agent_sessions[id];
			if (entry == null || entry.sink_registration_id == 0)
				return;

			entry.connection.unregister_object (entry.sink_registration_id);
			entry.sink_registration_id = 0;
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

		public async ChannelId open_channel (string address, Cancellable? cancellable) throws Error, IOError {
			var stream = yield device.open_channel (address, cancellable);

			var id = ChannelId.generate ();
			channel_registry.register (id, stream);

			return id;
		}

		public IOStream link_channel (ChannelId id) throws Error {
			return channel_registry.link (id);
		}

		public void unlink_channel (ChannelId id) {
			channel_registry.unlink (id);
		}

		private void on_channel_closed (ChannelId id) {
			channel_closed (id);
		}

		private void on_service_session_closed (ServiceSessionId id) {
			service_session_closed (id);
		}

		public async ServiceSessionId open_service (string address, Cancellable? cancellable) throws Error, IOError {
			var session = yield do_open_service (address, cancellable);

			var id = ServiceSessionId.generate ();
			service_session_registry.register (id, session);

			return id;
		}

		private async ServiceSession do_open_service (string address, Cancellable? cancellable) throws Error, IOError {
			string[] tokens = address.split (":", 2);
			unowned string protocol = tokens[0];
			unowned string service_name = tokens[1];

			if (protocol == "plist") {
				var stream = yield device.open_lockdown_service (service_name, cancellable);

				return new PlistServiceSession (stream);
			}

			if (protocol == "dtx") {
				var connection = yield Fruity.DTXConnection.obtain (device, cancellable);

				return new DTXServiceSession (service_name, connection);
			}

			if (protocol == "xpc") {
				var tunnel = yield device.find_tunnel (cancellable);
				if (tunnel == null)
					throw new Error.NOT_SUPPORTED ("RemoteXPC not supported by device");

				var service_info = tunnel.discovery.get_service (service_name);
				var stream = yield tunnel.open_tcp_connection (service_info.port, cancellable);

				return new XpcServiceSession (new Fruity.XpcConnection (stream));
			}

			throw new Error.NOT_SUPPORTED ("Unsupported service address");
		}

		public ServiceSession link_service_session (ServiceSessionId id) throws Error {
			return service_session_registry.link (id);
		}

		public void unlink_service_session (ServiceSessionId id) {
			service_session_registry.unlink (id);
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

		private async RemoteServer? try_get_remote_server (Cancellable? cancellable) throws Error, IOError {
			try {
				return yield get_remote_server (cancellable);
			} catch (Error e) {
				if (e is Error.SERVER_NOT_RUNNING)
					return null;
				throw e;
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
				var channel = yield connect_to_remote_server (cancellable);

				IOStream stream = channel.stream;
				WebServiceTransport transport = PLAIN;
				string? origin = null;

				stream = yield negotiate_connection (stream, transport, "lolcathost", origin, cancellable);

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

				var server = new RemoteServer (flavor, session, connection, channel, device, transport_broker);
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
					if (e is Error) {
						api_error = e;
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

		private async Fruity.TcpChannel connect_to_remote_server (Cancellable? cancellable) throws Error, IOError {
			var tunnel = yield device.find_tunnel (cancellable);
			bool tunnel_recently_opened = tunnel != null && get_monotonic_time () - tunnel.opened_at < 1000000;

			uint delays[] = { 0, 50, 250 };
			uint max_attempts = tunnel_recently_opened ? delays.length : 1;
			var main_context = MainContext.ref_thread_default ();

			Error? pending_error = null;
			for (uint attempts = 0; attempts != max_attempts; attempts++) {
				uint delay = delays[attempts];
				if (delay != 0) {
					var timeout_source = new TimeoutSource (delay);
					timeout_source.set_callback (connect_to_remote_server.callback);
					timeout_source.attach (main_context);

					var cancel_source = new CancellableSource (cancellable);
					cancel_source.set_callback (connect_to_remote_server.callback);
					cancel_source.attach (main_context);

					yield;

					cancel_source.destroy ();
					timeout_source.destroy ();

					if (cancellable.is_cancelled ())
						break;
				}

				bool is_last_attempt = attempts == max_attempts - 1;
				var open_flags = is_last_attempt
					? Fruity.OpenTcpChannelFlags.ALLOW_ANY_TRANSPORT
					: Fruity.OpenTcpChannelFlags.ALLOW_TUNNEL;

				try {
					return yield device.open_tcp_channel (DEFAULT_CONTROL_PORT.to_string (), open_flags, cancellable);
				} catch (Error e) {
					pending_error = e;
					if (!(e is Error.SERVER_NOT_RUNNING))
						break;
				}
			}
			throw pending_error;
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

			public weak HostChannelProvider channel_provider {
				get;
				construct;
			}

			private Promise<Fruity.Injector.GadgetDetails>? gadget_request;

			public LLDBSession (LLDB.Client lldb, LLDB.Process process, string? gadget_path,
					HostChannelProvider channel_provider) {
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
				yield lldb.detach (cancellable);
			}

			public async void kill (Cancellable? cancellable) throws Error, IOError {
				yield lldb.kill (cancellable);
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

		private class RemoteServer : Object, HostChannelProvider {
			public Flavor flavor {
				get;
				construct;
			}

			public HostSession session {
				get;
				construct;
			}

			public DBusConnection connection {
				get;
				construct;
			}

			public Fruity.TcpChannel channel {
				get;
				construct;
			}

			public Fruity.Device device {
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

			public RemoteServer (Flavor flavor, HostSession session, DBusConnection connection, Fruity.TcpChannel channel,
					Fruity.Device device, TransportBroker? transport_broker) {
				Object (
					flavor: flavor,
					session: session,
					connection: connection,
					channel: channel,
					device: device,
					transport_broker: transport_broker
				);
			}

			public async IOStream open_channel (string address, Cancellable? cancellable) throws Error, IOError {
				if (!address.has_prefix ("tcp:"))
					throw new Error.NOT_SUPPORTED ("Unsupported channel address");
				var flags = (channel.kind == TUNNEL)
					? Fruity.OpenTcpChannelFlags.ALLOW_TUNNEL
					: Fruity.OpenTcpChannelFlags.ALLOW_USBMUX;
				var channel = yield device.open_tcp_channel (address[4:], flags, cancellable);
				return channel.stream;
			}
		}
	}

	private sealed class PlistServiceSession : Object, ServiceSession {
		public IOStream stream {
			get;
			construct;
		}

		private Fruity.PlistServiceClient client;
		private bool client_closed = false;

		public PlistServiceSession (IOStream stream) {
			Object (stream: stream);
		}

		construct {
			client = new Fruity.PlistServiceClient (stream);
			client.closed.connect (on_client_closed);
		}

		~PlistServiceSession () {
			client.closed.disconnect (on_client_closed);
		}

		public async void activate (Cancellable? cancellable) throws Error, IOError {
			ensure_active ();
		}

		private void ensure_active () throws Error {
			if (client_closed)
				throw new Error.INVALID_OPERATION ("Service is closed");
		}

		public async void cancel (Cancellable? cancellable) throws IOError {
			if (client_closed)
				return;
			client_closed = true;

			yield client.close (cancellable);

			close ();
		}

		public async Variant request (Variant parameters, Cancellable? cancellable = null) throws Error, IOError {
			ensure_active ();

			var reader = new VariantReader (parameters);

			string type = reader.read_member ("type").get_string_value ();
			reader.end_member ();

			try {
				if (type == "query") {
					reader.read_member ("payload");
					var payload = plist_from_variant (reader.current_object);
					var raw_response = yield client.query (payload, cancellable);
					return plist_to_variant (raw_response);
				} else if (type == "read") {
					var plist = yield client.read_message (cancellable);
					return plist_to_variant (plist);
				} else {
					throw new Error.INVALID_ARGUMENT ("Unsupported request type: %s", type);
				}
			} catch (Fruity.PlistServiceError e) {
				if (e is Fruity.PlistServiceError.CONNECTION_CLOSED)
					throw new Error.TRANSPORT ("Connection closed during request");
				throw new Error.PROTOCOL ("%s", e.message);
			}
		}

		private void on_client_closed () {
			client_closed = true;
			close ();
		}

		private Fruity.Plist plist_from_variant (Variant val) throws Error {
			if (!val.is_of_type (VariantType.VARDICT))
				throw new Error.INVALID_ARGUMENT ("Expected a dictionary");

			var plist = new Fruity.Plist ();

			foreach (var item in val) {
				string k;
				Variant v;
				item.get ("{sv}", out k, out v);

				plist.set_value (k, plist_value_from_variant (v));
			}

			return plist;
		}

		private Value plist_value_from_variant (Variant val) throws Error {
			switch (val.classify ()) {
				case BOOLEAN:
					return val.get_boolean ();
				case INT64:
					return val.get_int64 ();
				case DOUBLE:
					return val.get_double ();
				case STRING:
					return val.get_string ();
				case ARRAY:
					if (val.is_of_type (new VariantType ("ay")))
						return val.get_data_as_bytes ();

					if (val.is_of_type (VariantType.VARDICT)) {
						var dict = new Fruity.PlistDict ();

						foreach (var item in val) {
							string k;
							Variant v;
							item.get ("{sv}", out k, out v);

							dict.set_value (k, plist_value_from_variant (v));
						}

						return dict;
					}

					if (val.is_of_type (new VariantType ("av"))) {
						var arr = new Fruity.PlistArray ();

						foreach (var item in val) {
							Variant v;
							item.get ("v", out v);

							arr.add_value (plist_value_from_variant (v));
						}

						return arr;
					}

					break;
				default:
					break;
			}

			throw new Error.INVALID_ARGUMENT ("Unsupported type: %s", (string) val.get_type ().peek_string ());
		}

		private Variant plist_to_variant (Fruity.Plist plist) {
			return plist_dict_to_variant (plist);
		}

		private Variant plist_dict_to_variant (Fruity.PlistDict dict) {
			var builder = new VariantBuilder (VariantType.VARDICT);
			foreach (var e in dict.entries)
				builder.add ("{sv}", e.key, plist_value_to_variant (e.value));
			return builder.end ();
		}

		private Variant plist_array_to_variant (Fruity.PlistArray arr) {
			var builder = new VariantBuilder (new VariantType.array (VariantType.VARIANT));
			foreach (var e in arr.elements)
				builder.add ("v", plist_value_to_variant (e));
			return builder.end ();
		}

		private Variant plist_value_to_variant (Value * v) {
			Type t = v.type ();

			if (t == typeof (bool))
				return v.get_boolean ();

			if (t == typeof (int64))
				return v.get_int64 ();

			if (t == typeof (float))
				return (double) v.get_float ();

			if (t == typeof (double))
				return v.get_double ();

			if (t == typeof (string))
				return v.get_string ();

			if (t == typeof (Bytes)) {
				var bytes = (Bytes) v.get_boxed ();
				return Variant.new_from_data (new VariantType.array (VariantType.BYTE), bytes.get_data (), true, bytes);
			}

			if (t == typeof (Fruity.PlistDict))
				return plist_dict_to_variant ((Fruity.PlistDict) v.get_object ());

			if (t == typeof (Fruity.PlistArray))
				return plist_array_to_variant ((Fruity.PlistArray) v.get_object ());

			if (t == typeof (Fruity.PlistUid))
				return ((Fruity.PlistUid) v.get_object ()).uid;

			assert_not_reached ();
		}
	}

	private sealed class DTXServiceSession : Object, ServiceSession {
		public string identifier {
			get;
			construct;
		}

		public Fruity.DTXConnection connection {
			get;
			construct;
		}

		private State state = INACTIVE;
		private bool connection_closed = false;
		private Fruity.DTXChannel? channel;

		private enum State {
			INACTIVE,
			ACTIVE,
		}

		public DTXServiceSession (string identifier, Fruity.DTXConnection connection) {
			Object (identifier: identifier, connection: connection);
		}

		construct {
			connection.notify["state"].connect (on_connection_state_changed);
		}

		~DTXServiceSession () {
			connection.notify["state"].disconnect (on_connection_state_changed);
		}

		public async void activate (Cancellable? cancellable) throws Error, IOError {
			ensure_active ();
		}

		private void ensure_active () throws Error {
			if (connection_closed)
				throw new Error.INVALID_OPERATION ("Service is closed");

			if (state == INACTIVE) {
				state = ACTIVE;

				channel = connection.make_channel (identifier);
				channel.invocation.connect (on_channel_invocation);
				channel.notification.connect (on_channel_notification);
			}
		}

		private void ensure_closed () {
			if (connection_closed)
				return;
			connection_closed = true;

			if (channel != null) {
				channel.invocation.disconnect (on_channel_invocation);
				channel.notification.disconnect (on_channel_notification);
				channel = null;
			}

			close ();
		}

		public async void cancel (Cancellable? cancellable) throws IOError {
			ensure_closed ();
		}

		public async Variant request (Variant parameters, Cancellable? cancellable = null) throws Error, IOError {
			ensure_active ();

			var reader = new VariantReader (parameters);

			string method_name = reader.read_member ("method").get_string_value ();
			reader.end_member ();

			Fruity.DTXArgumentListBuilder? args = null;
			if (reader.has_member ("args")) {
				reader.read_member ("args");
				args = new Fruity.DTXArgumentListBuilder ();
				uint n = reader.count_elements ();
				for (uint i = 0; i != n; i++) {
					reader.read_element (i);
					args.append_object (nsobject_from_variant (reader.current_object));
					reader.end_element ();
				}
			}

			var result = yield channel.invoke (method_name, args, cancellable);

			return nsobject_to_variant (result);
		}

		private void on_connection_state_changed (Object obj, ParamSpec pspec) {
			if (connection.state == CLOSED)
				ensure_closed ();
		}

		private void on_channel_invocation (string method_name, Fruity.DTXArgumentList args,
				Fruity.DTXMessageTransportFlags transport_flags) {
			var envelope = new HashTable<string, Variant> (str_hash, str_equal);
			envelope["type"] = "invocation";
			envelope["payload"] = invocation_to_variant (method_name, args);
			envelope["expects-reply"] = (transport_flags & Fruity.DTXMessageTransportFlags.EXPECTS_REPLY) != 0;
			message (envelope);
		}

		private void on_channel_notification (Fruity.NSObject obj) {
			var envelope = new HashTable<string, Variant> (str_hash, str_equal);
			envelope["type"] = "notification";
			envelope["payload"] = nsobject_to_variant (obj);
			message (envelope);
		}

		private Fruity.NSObject? nsobject_from_variant (Variant val) throws Error {
			switch (val.classify ()) {
				case BOOLEAN:
					return new Fruity.NSNumber.from_boolean (val.get_boolean ());
				case INT64:
					return new Fruity.NSNumber.from_integer (val.get_int64 ());
				case DOUBLE:
					return new Fruity.NSNumber.from_double (val.get_double ());
				case STRING:
					return new Fruity.NSString (val.get_string ());
				case ARRAY:
					if (val.is_of_type (new VariantType ("ay")))
						return new Fruity.NSData (val.get_data_as_bytes ());

					if (val.is_of_type (VariantType.VARDICT)) {
						var dict = new Fruity.NSDictionary ();

						foreach (var item in val) {
							string k;
							Variant v;
							item.get ("{sv}", out k, out v);

							dict.set_value (k, nsobject_from_variant (v));
						}

						return dict;
					}

					if (val.is_of_type (new VariantType ("av"))) {
						var arr = new Fruity.NSArray ();

						foreach (var item in val) {
							Variant v;
							item.get ("v", out v);

							arr.add_object (nsobject_from_variant (v));
						}

						return arr;
					}

					break;
				default:
					break;
			}

			throw new Error.INVALID_ARGUMENT ("Unsupported type: %s", (string) val.get_type ().peek_string ());
		}

		private Variant nsobject_to_variant (Fruity.NSObject? obj) {
			if (obj == null)
				return new Variant ("()");

			var num = obj as Fruity.NSNumber;
			if (num != null)
				return num.integer;

			var str = obj as Fruity.NSString;
			if (str != null)
				return str.str;

			var data = obj as Fruity.NSData;
			if (data != null) {
				Bytes bytes = data.bytes;
				return Variant.new_from_data (new VariantType.array (VariantType.BYTE), bytes.get_data (), true, bytes);
			}

			var dict = obj as Fruity.NSDictionary;
			if (dict != null)
				return nsdictionary_to_variant (dict);

			var dict_raw = obj as Fruity.NSDictionaryRaw;
			if (dict_raw != null)
				return nsdictionary_raw_to_variant (dict_raw);

			var arr = obj as Fruity.NSArray;
			if (arr != null)
				return nsarray_to_variant (arr);

			var date = obj as Fruity.NSDate;
			if (date != null)
				return date.to_date_time ().format_iso8601 ();

			var err = obj as Fruity.NSError;
			if (err != null)
				return nserror_to_variant (err);

			var msg = obj as Fruity.DTTapMessage;
			if (msg != null)
				return nsdictionary_to_variant (msg.plist);

			assert_not_reached ();
		}

		private Variant nsdictionary_to_variant (Fruity.NSDictionary dict) {
			var builder = new VariantBuilder (VariantType.VARDICT);
			foreach (var e in dict.entries)
				builder.add ("{sv}", e.key, nsobject_to_variant (e.value));
			return builder.end ();
		}

		private Variant nsdictionary_raw_to_variant (Fruity.NSDictionaryRaw dict) {
			var builder = new VariantBuilder (
				new VariantType.array (new VariantType.dict_entry (VariantType.VARIANT, VariantType.VARIANT)));
			foreach (var e in dict.entries)
				builder.add ("{vv}", nsobject_to_variant (e.key), nsobject_to_variant (e.value));
			return builder.end ();
		}

		private Variant nsarray_to_variant (Fruity.NSArray arr) {
			var builder = new VariantBuilder (new VariantType.array (VariantType.VARIANT));
			foreach (var e in arr.elements)
				builder.add ("v", nsobject_to_variant (e));
			return builder.end ();
		}

		private Variant nserror_to_variant (Fruity.NSError e) {
			var result = new HashTable<string, Variant> (str_hash, str_equal);
			result["domain"] = e.domain.str;
			result["code"] = e.code;
			result["user-info"] = nsdictionary_to_variant (e.user_info);
			return result;
		}

		private Variant invocation_to_variant (string method_name, Fruity.DTXArgumentList args) {
			var invocation = new HashTable<string, Variant> (str_hash, str_equal);
			invocation["method"] = method_name;
			invocation["args"] = invocation_args_to_variant (args);
			return invocation;
		}

		private Variant invocation_args_to_variant (Fruity.DTXArgumentList args) {
			var builder = new VariantBuilder (new VariantType.array (VariantType.VARIANT));
			foreach (var e in args.elements)
				builder.add ("v", value_to_variant (e));
			return builder.end ();
		}

		private Variant value_to_variant (Value v) {
			Type t = v.type ();

			if (t == typeof (int))
				return v.get_int ();

			if (t == typeof (int64))
				return v.get_int64 ();

			if (t == typeof (double))
				return v.get_double ();

			if (t == typeof (string))
				return v.get_string ();

			if (t.is_a (typeof (Fruity.NSObject)))
				return nsobject_to_variant ((Fruity.NSObject) v.get_boxed ());

			assert_not_reached ();
		}
	}

	private sealed class XpcServiceSession : Object, ServiceSession {
		public Fruity.XpcConnection connection {
			get;
			construct;
		}

		private State state = INACTIVE;
		private bool connection_closed = false;

		private enum State {
			INACTIVE,
			ACTIVE,
		}

		public XpcServiceSession (Fruity.XpcConnection connection) {
			Object (connection: connection);
		}

		construct {
			connection.close.connect (on_close);
			connection.message.connect (on_message);
		}

		~XpcServiceSession () {
			connection.close.disconnect (on_close);
			connection.message.disconnect (on_message);

			connection.cancel ();
		}

		public async void activate (Cancellable? cancellable) throws Error, IOError {
			ensure_active ();
		}

		private void ensure_active () throws Error {
			if (connection_closed)
				throw new Error.INVALID_OPERATION ("Service is closed");

			if (state == INACTIVE) {
				state = ACTIVE;

				connection.activate ();
			}
		}

		public async void cancel (Cancellable? cancellable) throws IOError {
			if (state == ACTIVE)
				connection.cancel ();
			else if (!connection_closed)
				on_close (null);
		}

		public async Variant request (Variant parameters, Cancellable? cancellable = null) throws Error, IOError {
			ensure_active ();

			yield connection.wait_until_ready (cancellable);

			if (!parameters.is_of_type (VariantType.VARDICT))
				throw new Error.INVALID_ARGUMENT ("Expected a dictionary");

			var builder = new Fruity.XpcBodyBuilder ();
			builder.begin_dictionary ();
			add_vardict_values (parameters, builder);
			Fruity.TrustedService.add_standard_request_values (builder);
			builder.end_dictionary ();

			Fruity.XpcMessage response = yield connection.request (builder.build (), cancellable);

			return response.body;
		}

		private void on_close (Error? error) {
			connection_closed = true;

			close ();
		}

		private void on_message (Fruity.XpcMessage msg) {
			message (msg.body);
		}

		private static void add_vardict_values (Variant dict, Fruity.XpcBodyBuilder builder) throws Error {
			foreach (var item in dict) {
				string key;
				Variant val;
				item.get ("{sv}", out key, out val);

				builder.set_member_name (key);
				add_variant_value (val, builder);
			}
		}

		private static void add_vararray_values (Variant arr, Fruity.XpcBodyBuilder builder) throws Error {
			foreach (var item in arr) {
				Variant val;
				item.get ("v", out val);

				add_variant_value (val, builder);
			}
		}

		private static void add_variant_value (Variant val, Fruity.XpcBodyBuilder builder) throws Error {
			switch (val.classify ()) {
				case BOOLEAN:
					builder.add_bool_value (val.get_boolean ());
					return;
				case INT64:
					builder.add_int64_value (val.get_int64 ());
					return;
				case STRING:
					builder.add_string_value (val.get_string ());
					return;
				case ARRAY:
					if (val.is_of_type (new VariantType ("ay"))) {
						builder.add_data_value (val.get_data_as_bytes ());
						return;
					}

					if (val.is_of_type (VariantType.VARDICT)) {
						builder.begin_dictionary ();
						add_vardict_values (val, builder);
						builder.end_dictionary ();
						return;
					}

					if (val.is_of_type (new VariantType ("av"))) {
						builder.begin_array ();
						add_vararray_values (val, builder);
						builder.end_array ();
						return;
					}

					break;
				case TUPLE:
					if (val.n_children () != 2) {
						throw new Error.INVALID_ARGUMENT ("Invalid type annotation: %s",
							(string) val.get_type ().peek_string ());
					}

					var type = val.get_child_value (0);
					if (!type.is_of_type (VariantType.STRING)) {
						throw new Error.INVALID_ARGUMENT ("Invalid type annotation: %s",
							(string) val.get_type ().peek_string ());
					}
					unowned string type_str = type.get_string ();

					add_variant_value_of_type (val.get_child_value (1), type_str, builder);
					return;
				default:
					break;
			}

			throw new Error.INVALID_ARGUMENT ("Unsupported type: %s", (string) val.get_type ().peek_string ());
		}

		private static void add_variant_value_of_type (Variant val, string type, Fruity.XpcBodyBuilder builder) throws Error {
			switch (type) {
				case "bool":
					check_type (val, VariantType.BOOLEAN);
					builder.add_bool_value (val.get_boolean ());
					break;
				case "int64":
					check_type (val, VariantType.INT64);
					builder.add_int64_value (val.get_int64 ());
					break;
				case "uint64":
					check_type (val, VariantType.UINT64);
					builder.add_uint64_value (val.get_uint64 ());
					break;
				case "data":
					check_type (val, new VariantType ("ay"));
					builder.add_data_value (val.get_data_as_bytes ());
					break;
				case "string":
					check_type (val, VariantType.STRING);
					builder.add_string_value (val.get_string ());
					break;
				case "uuid":
					check_type (val, new VariantType ("ay"));
					if (val.get_size () != 16)
						throw new Error.INVALID_ARGUMENT ("Invalid UUID");
					unowned uint8[] data = (uint8[]) val.get_data ();
					builder.add_uuid_value (data[:16]);
					break;
				default:
					throw new Error.INVALID_ARGUMENT ("Unsupported type: %s", type);
			}
		}

		private static void check_type (Variant v, VariantType t) throws Error {
			if (!v.is_of_type (t)) {
				throw new Error.INVALID_ARGUMENT ("Invalid %s: %s",
					(string) t.peek_string (),
					(string) v.get_type ().peek_string ());
			}
		}
	}
}
