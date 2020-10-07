namespace Frida {
	public class FruityHostSessionBackend : Object, HostSessionBackend {
		private Fruity.UsbmuxClient control_client;

		private Gee.HashSet<uint> devices = new Gee.HashSet<uint> ();
		private Gee.HashMap<uint, FruityHostSessionProvider> providers = new Gee.HashMap<uint, FruityHostSessionProvider> ();

		private Promise<bool> start_request;
		private Cancellable start_cancellable;
		private SourceFunc on_start_completed;

		private Cancellable io_cancellable = new Cancellable ();

		static construct {
#if HAVE_GIOSCHANNEL
			GIOSChannel.register ();
#endif
#if HAVE_GIOOPENSSL
			GIOOpenSSL.register ();
#endif
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
			ImageData? icon_data = null;

			bool got_details = false;
			for (int i = 1; !got_details && devices.contains (raw_id); i++) {
				try {
					_extract_details_for_device (details.product_id.raw_value, details.udid.raw_value,
						out name, out icon_data);
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

			var icon = Image.from_data (icon_data);

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

		public extern static void _extract_details_for_device (int product_id, string udid, out string name, out ImageData? icon)
			throws Error;
	}

	public class FruityHostSessionProvider : Object, HostSessionProvider, ChannelProvider, FruityLockdownProvider {
		public string id {
			get { return device_details.udid.raw_value; }
		}

		public string name {
			get { return device_name; }
		}

		public Image? icon {
			get { return device_icon; }
		}

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.USB; }
		}

		public string device_name {
			get;
			construct;
		}

		public Image? device_icon {
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

		public FruityHostSessionProvider (string name, Image? icon, Fruity.DeviceDetails details) {
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

		public async HostSession create (string? location, Cancellable? cancellable) throws Error, IOError {
			if (host_session != null)
				throw new Error.INVALID_ARGUMENT ("Invalid location: already created");

			host_session = new FruityHostSession (this, this);
			host_session.agent_session_closed.connect (on_agent_session_closed);

			return host_session;
		}

		public async void destroy (HostSession session, Cancellable? cancellable) throws Error, IOError {
			if (session != host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");
			host_session.agent_session_closed.disconnect (on_agent_session_closed);
			yield host_session.close (cancellable);
			host_session = null;
		}

		public async AgentSession obtain_agent_session (HostSession host_session, AgentSessionId agent_session_id,
				Cancellable? cancellable) throws Error, IOError {
			if (host_session != this.host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");
			return this.host_session.obtain_agent_session (agent_session_id);
		}

		private void on_agent_session_closed (AgentSessionId id, AgentSession session, SessionDetachReason reason,
				CrashInfo? crash) {
			agent_session_closed (id, reason, crash);
		}

		public async IOStream open_channel (string address, Cancellable? cancellable = null) throws Error, IOError {
			if (address.has_prefix ("tcp:")) {
				ulong raw_port;
				if (!ulong.try_parse (address.substring (4), out raw_port) || raw_port == 0 || raw_port > uint16.MAX)
					throw new Error.INVALID_ARGUMENT ("Invalid TCP port");
				uint16 port = (uint16) raw_port;

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
		public signal void agent_session_closed (AgentSessionId id, AgentSession session, SessionDetachReason reason,
			CrashInfo? crash);

		public weak ChannelProvider channel_provider {
			get;
			construct;
		}

		public weak FruityLockdownProvider lockdown_provider {
			get;
			construct;
		}

		private Gee.HashMap<uint, LLDBSession> lldb_sessions = new Gee.HashMap<uint, LLDBSession> ();
		private Gee.HashMap<AgentSessionId?, AgentEntry> agent_entries =
			new Gee.HashMap<AgentSessionId?, AgentEntry> (AgentSessionId.hash, AgentSessionId.equal);

		private Promise<RemoteServer>? remote_server_request;
		private RemoteServer? current_remote_server;
		private Timer? last_server_check_timer;
		private Error? last_server_check_error;
		private Gee.HashMap<AgentSessionId?, AgentSessionId?> remote_agent_sessions =
			new Gee.HashMap<AgentSessionId?, AgentSessionId?> (AgentSessionId.hash, AgentSessionId.equal);

		private Gee.HashMap<AgentSessionId?, AgentSession> agent_sessions =
			new Gee.HashMap<AgentSessionId?, AgentSession> (AgentSessionId.hash, AgentSessionId.equal);
		private uint next_agent_session_id = 1;

		private Cancellable io_cancellable = new Cancellable ();

		private const uint16 DEFAULT_SERVER_PORT = 27042;
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

			while (!agent_entries.is_empty) {
				var iterator = agent_entries.values.iterator ();
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

		public async HostApplicationInfo get_frontmost_application (Cancellable? cancellable) throws Error, IOError {
			var server = yield try_get_remote_server (cancellable);
			if (server != null && server.flavor == REGULAR) {
				try {
					return yield server.session.get_frontmost_application (cancellable);
				} catch (GLib.Error e) {
					throw_api_error (e);
				}
			}

			var device_info = yield Fruity.DeviceInfoService.open (channel_provider, cancellable);
			var processes = yield device_info.enumerate_processes (cancellable);

			var process = processes.first_match (p => p.foreground_running && p.is_application &&
					!p.real_app_name.contains (".appex"));
			if (process == null)
				return HostApplicationInfo.empty ();

			string app_path = compute_app_path_from_executable_path (process.real_app_name);

			var application_listing = yield Fruity.ApplicationListingService.open (channel_provider, cancellable);
			var query = new Fruity.NSDictionary ();
			query.set_value ("BundlePath", new Fruity.NSString (app_path));
			var apps = yield application_listing.enumerate_applications (query, cancellable);
			if (apps.is_empty)
				throw new Error.NOT_SUPPORTED ("Unable to resolve bundle path to bundle ID");
			unowned string identifier = apps[0].bundle_identifier;
			var no_icon = ImageData.empty ();

			return HostApplicationInfo (identifier, process.name, process.pid, no_icon, no_icon);
		}

		public async HostApplicationInfo[] enumerate_applications (Cancellable? cancellable) throws Error, IOError {
			var server = yield try_get_remote_server (cancellable);
			if (server != null && server.flavor == REGULAR) {
				try {
					return yield server.session.enumerate_applications (cancellable);
				} catch (GLib.Error e) {
					throw_api_error (e);
				}
			}

			var apps_request = new Promise<Gee.ArrayList<Fruity.ApplicationDetails>> ();
			fetch_apps.begin (apps_request, cancellable);

			var pids_request = new Promise<Gee.HashMap<string, uint>> ();
			fetch_pids.begin (pids_request, cancellable);

			var apps = yield apps_request.future.wait_async (cancellable);
			var pids = yield pids_request.future.wait_async (cancellable);

			var no_icon = ImageData.empty ();

			var result = new HostApplicationInfo[apps.size];
			int i = 0;
			foreach (var app in apps) {
				uint pid = pids[app.path];
				result[i] = HostApplicationInfo (app.identifier, app.name, pid, no_icon, no_icon);
				i++;
			}

			if (server != null && server.flavor == GADGET) {
				try {
					foreach (var app in yield server.session.enumerate_applications (cancellable))
						result += app;
				} catch (GLib.Error e) {
				}
			}

			return result;
		}

		private async void fetch_apps (Promise<Gee.ArrayList<Fruity.ApplicationDetails>> promise, Cancellable? cancellable) {
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

		private async void fetch_pids (Promise<Gee.HashMap<string, uint>> promise, Cancellable? cancellable) {
			try {
				var device_info = yield Fruity.DeviceInfoService.open (channel_provider, cancellable);

				var processes = yield device_info.enumerate_processes (cancellable);

				var pids = new Gee.HashMap<string, uint> ();
				foreach (var process in processes)
					pids[compute_app_path_from_executable_path (process.real_app_name)] = process.pid;

				promise.resolve (pids);
			} catch (Error e) {
				promise.reject (e);
			} catch (IOError e) {
				promise.reject (e);
			}
		}

		private static string compute_app_path_from_executable_path (string executable_path) {
			string app_path = executable_path;
			if (app_path.has_prefix ("/var/containers"))
				app_path = "/private" + app_path;

			int dot_app_start = app_path.last_index_of (".app/");
			if (dot_app_start != -1)
				app_path = app_path[0:dot_app_start + 4];

			return app_path;
		}

		public async HostProcessInfo[] enumerate_processes (Cancellable? cancellable) throws Error, IOError {
			var server = yield try_get_remote_server (cancellable);
			if (server != null && server.flavor == REGULAR) {
				try {
					return yield server.session.enumerate_processes (cancellable);
				} catch (GLib.Error e) {
					throw_api_error (e);
				}
			}

			var device_info = yield Fruity.DeviceInfoService.open (channel_provider, cancellable);

			var processes = yield device_info.enumerate_processes (cancellable);

			var no_icon = ImageData.empty ();

			var result = new HostProcessInfo[processes.size];
			int i = 0;
			foreach (var process in processes) {
				var pid = process.pid;
				if (pid == 0)
					continue;
				result[i] = HostProcessInfo (pid, process.name, no_icon, no_icon);
				i++;
			}
			if (i < processes.size)
				result.resize (i);

			if (server != null && server.flavor == GADGET) {
				try {
					foreach (var process in yield server.session.enumerate_processes (cancellable))
						result += process;
				} catch (GLib.Error e) {
				}
			}

			return result;
		}

		public async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			var server = yield get_remote_server (cancellable);
			try {
				yield server.session.enable_spawn_gating (cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}
		}

		public async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			var server = yield get_remote_server (cancellable);
			try {
				yield server.session.disable_spawn_gating (cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}
		}

		public async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws Error, IOError {
			var server = yield get_remote_server (cancellable);
			try {
				return yield server.session.enumerate_pending_spawn (cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}
		}

		public async HostChildInfo[] enumerate_pending_children (Cancellable? cancellable) throws Error, IOError {
			var server = yield get_remote_server (cancellable);
			try {
				return yield server.session.enumerate_pending_children (cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}
		}

		public async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError {
			var server = yield try_get_remote_server (cancellable);
			if (server != null && (server.flavor != GADGET || program == GADGET_APP_ID)) {
				try {
					return yield server.session.spawn (program, options, cancellable);
				} catch (GLib.Error e) {
					throw_api_error (e);
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

			var aux_options = options.load_aux ();

			if (aux_options.contains ("aslr")) {
				string? aslr = null;
				if (!aux_options.lookup ("aslr", "s", out aslr) || (aslr != "auto" && aslr != "disable")) {
					throw new Error.INVALID_ARGUMENT (
						"The 'aslr' option must be a string set to either 'auto' or 'disable'");
				}
				launch_options.aslr = (aslr == "auto") ? LLDB.ASLR.AUTO : LLDB.ASLR.DISABLE;
			}

			string? gadget_path = null;
			if (aux_options.contains ("gadget")) {
				if (!aux_options.lookup ("gadget", "s", out gadget_path)) {
					throw new Error.INVALID_ARGUMENT (
						"The 'gadget' option must be a string pointing at the frida-gadget.dylib to use");
				}
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
				throw_api_error (e);
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
				throw_api_error (e);
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
						throw_api_error (e);
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

		public async AgentSessionId attach_to (uint pid, Cancellable? cancellable) throws Error, IOError {
			var lldb_session = lldb_sessions[pid];
			if (lldb_session != null) {
				var gadget_details = yield lldb_session.query_gadget_details (cancellable);

				return yield attach_via_gadget (pid, gadget_details, cancellable);
			}

			var server = yield try_get_remote_server (cancellable);
			if (server != null) {
				try {
					return yield attach_via_remote (pid, server, cancellable);
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

			return yield attach_via_gadget (pid, gadget_details, cancellable);
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

		private async AgentSessionId attach_via_gadget (uint pid, Fruity.Injector.GadgetDetails gadget_details,
				Cancellable? cancellable) throws Error, IOError {
			try {
				var stream = yield channel_provider.open_channel (
					("tcp:%" + uint16.FORMAT_MODIFIER + "u").printf (gadget_details.port),
					cancellable);

				var connection = yield new DBusConnection (stream, null, AUTHENTICATION_CLIENT, null, cancellable);

				HostSession host_session = yield connection.get_proxy (null, ObjectPath.HOST_SESSION,
					DBusProxyFlags.NONE, cancellable);

				AgentSessionId remote_session_id = yield host_session.attach_to (pid, cancellable);

				AgentSession agent_session = yield connection.get_proxy (null,
					ObjectPath.from_agent_session_id (remote_session_id), DBusProxyFlags.NONE, cancellable);

				var local_session_id = AgentSessionId (next_agent_session_id++);
				var agent_entry = new AgentEntry (local_session_id, agent_session, host_session, connection);
				agent_entry.detached.connect (on_agent_entry_detached);
				agent_entries[local_session_id] = agent_entry;
				agent_sessions[local_session_id] = agent_session;

				return local_session_id;
			} catch (GLib.Error e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
		}

		private async AgentSessionId attach_via_remote (uint pid, RemoteServer server, Cancellable? cancellable)
				throws Error, IOError {
			AgentSessionId remote_session_id;
			try {
				remote_session_id = yield server.session.attach_to (pid, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}
			var local_session_id = AgentSessionId (next_agent_session_id++);

			AgentSession agent_session;
			try {
				agent_session = yield server.connection.get_proxy (null,
					ObjectPath.from_agent_session_id (remote_session_id), DBusProxyFlags.NONE, cancellable);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("%s", e.message);
			}

			remote_agent_sessions[remote_session_id] = local_session_id;
			agent_sessions[local_session_id] = agent_session;

			var transport_broker = server.transport_broker;
			if (transport_broker != null) {
				try {
					AgentSession direct_session = yield establish_direct_session (transport_broker, remote_session_id,
						channel_provider, cancellable);
					agent_sessions[local_session_id] = direct_session;
				} catch (Error e) {
					if (e is Error.NOT_SUPPORTED)
						server.transport_broker = null;
				}
			}

			return local_session_id;
		}

		public AgentSession obtain_agent_session (AgentSessionId id) throws Error {
			var session = agent_sessions[id];
			if (session == null)
				throw new Error.INVALID_ARGUMENT ("Invalid session ID");
			return session;
		}

		public async InjectorPayloadId inject_library_file (uint pid, string path, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			var server = yield get_remote_server (cancellable);
			try {
				return yield server.session.inject_library_file (pid, path, entrypoint, data, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}
		}

		public async InjectorPayloadId inject_library_blob (uint pid, uint8[] blob, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			var server = yield get_remote_server (cancellable);
			try {
				return yield server.session.inject_library_blob (pid, blob, entrypoint, data, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
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

		private void on_agent_entry_detached (AgentEntry entry, SessionDetachReason reason) {
			var id = AgentSessionId (entry.id);
			CrashInfo? crash = null;

			agent_entries.unset (id);
			agent_sessions.unset (id);

			entry.detached.disconnect (on_agent_entry_detached);

			agent_session_closed (id, entry.agent_session, reason, crash);
			agent_session_destroyed (id, reason);

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
					("tcp:%" + uint16.FORMAT_MODIFIER + "u").printf (DEFAULT_SERVER_PORT),
					cancellable);

				connection = yield new DBusConnection (stream, null, AUTHENTICATION_CLIENT, null, cancellable);

				HostSession session = yield connection.get_proxy (null, ObjectPath.HOST_SESSION, DBusProxyFlags.NONE,
					cancellable);

				RemoteServer.Flavor flavor = REGULAR;
				try {
					var app = yield session.get_frontmost_application (cancellable);
					if (app.identifier == GADGET_APP_ID)
						flavor = GADGET;
				} catch (GLib.Error e) {
				}

				TransportBroker? transport_broker = null;
				if (flavor == REGULAR) {
					transport_broker = yield connection.get_proxy (null, ObjectPath.TRANSPORT_BROKER,
						DBusProxyFlags.NONE, cancellable);
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
			session.agent_session_destroyed.connect (on_remote_agent_session_destroyed);
			session.agent_session_crashed.connect (on_remote_agent_session_crashed);
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
			session.agent_session_destroyed.disconnect (on_remote_agent_session_destroyed);
			session.agent_session_crashed.disconnect (on_remote_agent_session_crashed);
			session.uninjected.disconnect (on_remote_uninjected);
		}

		private void on_remote_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			detach_remote_server (current_remote_server);
			current_remote_server = null;
			remote_server_request = null;

			foreach (var remote_id in remote_agent_sessions.keys.to_array ())
				on_remote_agent_session_destroyed (remote_id, SERVER_TERMINATED);
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

		private void on_remote_agent_session_destroyed (AgentSessionId remote_id, SessionDetachReason reason) {
			AgentSessionId? local_id;
			if (!remote_agent_sessions.unset (remote_id, out local_id))
				return;

			AgentSession agent_session = null;
			agent_sessions.unset (local_id, out agent_session);
			assert (agent_session != null);

			CrashInfo? crash = null;

			agent_session_closed (local_id, agent_session, reason, crash);
			agent_session_destroyed (local_id, reason);
		}

		private void on_remote_agent_session_crashed (AgentSessionId remote_id, CrashInfo crash) {
			AgentSessionId? local_id;
			if (!remote_agent_sessions.unset (remote_id, out local_id))
				return;

			AgentSession agent_session = null;
			agent_sessions.unset (local_id, out agent_session);
			assert (agent_session != null);

			SessionDetachReason reason = PROCESS_TERMINATED;

			agent_session_closed (local_id, agent_session, reason, crash);
			agent_session_crashed (local_id, crash);
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

		private class AgentEntry : Object {
			public signal void detached (SessionDetachReason reason);

			public uint id {
				get;
				construct;
			}

			public AgentSession agent_session {
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

			public AgentEntry (AgentSessionId? id, AgentSession agent_session, HostSession host_session,
					DBusConnection connection) {
				Object (
					id: id.handle,
					agent_session: agent_session,
					host_session: host_session,
					connection: connection
				);
			}

			construct {
				connection.on_closed.connect (on_connection_closed);
				host_session.agent_session_destroyed.connect (on_session_destroyed);
			}

			~AgentEntry () {
				connection.on_closed.disconnect (on_connection_closed);
				host_session.agent_session_destroyed.disconnect (on_session_destroyed);
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

			private void on_session_destroyed (AgentSessionId id, SessionDetachReason reason) {
				detached (reason);
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
