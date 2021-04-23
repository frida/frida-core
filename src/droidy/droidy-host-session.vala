namespace Frida {
	public class DroidyHostSessionBackend : Object, HostSessionBackend {
		private Droidy.DeviceTracker tracker;

		private Gee.HashMap<string, DroidyHostSessionProvider> providers = new Gee.HashMap<string, DroidyHostSessionProvider> ();

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
			bool success = true;

			tracker = new Droidy.DeviceTracker ();
			tracker.device_attached.connect (details => {
				var provider = new DroidyHostSessionProvider (details);
				providers[details.serial] = provider;
				provider_available (provider);
			});
			tracker.device_detached.connect (serial => {
				DroidyHostSessionProvider provider;
				providers.unset (serial, out provider);
				provider_unavailable (provider);
				provider.close.begin (io_cancellable);
			});

			try {
				yield tracker.open (start_cancellable);
			} catch (GLib.Error e) {
				success = false;
			}

			start_request.resolve (success);

			if (on_start_completed != null)
				on_start_completed ();
		}

		public async void stop (Cancellable? cancellable) throws IOError {
			start_cancellable.cancel ();

			try {
				yield start_request.future.wait_async (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}

			if (tracker != null) {
				yield tracker.close (cancellable);
				tracker = null;
			}

			io_cancellable.cancel ();

			foreach (var provider in providers.values) {
				provider_unavailable (provider);
				yield provider.close (cancellable);
			}
			providers.clear ();
		}
	}

	public class DroidyHostSessionProvider : Object, HostSessionProvider, ChannelProvider {
		public string id {
			get { return device_details.serial; }
		}

		public string name {
			get { return device_details.name; }
		}

		public Image? icon {
			get { return _icon; }
		}
		private Image _icon = new Image (ImageData (16, 16, 16 * 4, "AAAAAAAAAAAAAAAAAAAAAP///0DS4pz/////MP///0D///9A////MNflqP////9AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD///8QzN6Q/7vTa/+vy1L/r8tS/7vTa//O4JXv////EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1eSkz6TEOf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/9XkpM8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8vfjcKrIRf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/6TEOf+qyEX/8PXeYAAAAAAAAAAAAAAAAAAAAAAAAAAA////QNLinL+kxDn/pMQ5/6TEOf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/97qt6////9AAAAAAAAAAAAAAAAA2eatv7vTa//G2oP/pMQ5/6TEOf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/6TEOf/M3pD/u9Nr/9nmrb8AAAAAAAAAANLinP+kxDn/u9Nr/6TEOf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/6TEOf+kxDn/u9Nr/6TEOf/S4pz/AAAAAAAAAADS4pz/pMQ5/7vTa/+kxDn/pMQ5/6TEOf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/7vTa/+kxDn/0uKc/wAAAAAAAAAA0uKc/6TEOf+702v/pMQ5/6TEOf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/6TEOf+702v/pMQ5/9LinP8AAAAAAAAAANLinP+kxDn/u9Nr/6TEOf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/6TEOf+kxDn/u9Nr/6TEOf/S4pz/AAAAAAAAAADO4JXvpMQ5/8DWd/+kxDn/pMQ5/6TEOf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/8DWd/+kxDn/zuCV7wAAAAAAAAAA7fPXUNLinIDl7sbfpMQ5/6TEOf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/6TEOf/l7sbf0uKcgO3z11AAAAAAAAAAAAAAAAAAAAAA8PXeYMDWd/+qyEX/pMQ5/6/LUv+vy1L/pMQ5/6rIRf/A1nf/7fPXUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAu9Nr/6TEOf/C2Hu/wth7v6TEOf+702v/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALvTa/+kxDn/wth7v8LYe7+kxDn/u9Nr/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADc6LPPu9Nr/+HrvY/h672Pu9Nr/9nmrb8AAAAAAAAAAAAAAAAAAAAAAAAAAA=="));

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.USB; }
		}

		public Droidy.DeviceDetails device_details {
			get;
			construct;
		}

		private DroidyHostSession? host_session;

		private const double MAX_CLIENT_AGE = 30.0;

		public DroidyHostSessionProvider (Droidy.DeviceDetails details) {
			Object (device_details: details);
		}

		public async void close (Cancellable? cancellable) throws IOError {
		}

		public async HostSession create (HostSessionOptions? options, Cancellable? cancellable) throws Error, IOError {
			if (host_session != null)
				throw new Error.INVALID_ARGUMENT ("Already created");

			host_session = new DroidyHostSession (device_details, this);
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

		public async AgentSession obtain_agent_session (HostSession host_session, AgentSessionId id,
				Cancellable? cancellable) throws Error, IOError {
			if (host_session != this.host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");

			return this.host_session.obtain_agent_session (id);
		}

		public void migrate_agent_session (HostSession host_session, AgentSessionId id, AgentSession new_session) throws Error {
			if (host_session != this.host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");

			this.host_session.migrate_agent_session (id, new_session);
		}

		private void on_agent_session_detached (AgentSessionId id, SessionDetachReason reason, CrashInfo crash) {
			agent_session_detached (id, reason, crash);
		}

		public async IOStream open_channel (string address, Cancellable? cancellable = null) throws Error, IOError {
			if (address.contains (":")) {
				Droidy.Client client = null;
				try {
					client = yield Droidy.Client.open (cancellable);
					yield client.request ("host:transport:" + device_details.serial, cancellable);
					yield client.request_protocol_change (address, cancellable);
					return client.stream;
				} catch (GLib.Error e) {
					if (client != null)
						client.close.begin ();

					throw new Error.TRANSPORT ("%s", e.message);
				}
			}

			throw new Error.NOT_SUPPORTED ("Unsupported channel address");
		}
	}

	public class DroidyHostSession : Object, HostSession {
		public Droidy.DeviceDetails device_details {
			get;
			construct;
		}

		public weak ChannelProvider channel_provider {
			get;
			construct;
		}

		private Gee.HashMap<uint, Droidy.Injector.GadgetDetails> gadgets =
			new Gee.HashMap<uint, Droidy.Injector.GadgetDetails> ();
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

		private const double MIN_SERVER_CHECK_INTERVAL = 5.0;
		private const string GADGET_APP_ID = "re.frida.Gadget";

		public DroidyHostSession (Droidy.DeviceDetails device_details, ChannelProvider channel_provider) {
			Object (
				device_details: device_details,
				channel_provider: channel_provider
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

			io_cancellable.cancel ();
		}

		public async HostApplicationInfo get_frontmost_application (Cancellable? cancellable) throws Error, IOError {
			var server = yield try_get_remote_server (cancellable);
			if (server != null && server.flavor == REGULAR) {
				try {
					return yield server.session.get_frontmost_application (cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
			}

			unowned string serial = device_details.serial;

			string raw_activities = yield Droidy.ShellCommand.run ("dumpsys activity activities", serial, cancellable);
			MatchInfo info;
			if (!/^  ResumedActivity: ActivityRecord{\w+ \w+ (.+)\//m.match (raw_activities, 0, out info))
				return HostApplicationInfo.empty ();
			string package = info.fetch (1);

			// TODO: Detect launcher generically.
			if (package == "com.google.android.apps.nexuslauncher")
				return HostApplicationInfo.empty ();

			// TODO: Fetch app name.
			unowned string name = package;

			/*
			 * XXX: This will fail if the app has changed its cmdline or has multiple processes
			 *      with the same name.
			 */
			string raw_pid = yield Droidy.ShellCommand.run ("pidof -s '%s'".printf (package), serial, cancellable);
			uint pid = uint.parse (raw_pid);

			var no_icon = ImageData.empty ();

			return HostApplicationInfo (package, name, pid, no_icon, no_icon);
		}

		public async HostApplicationInfo[] enumerate_applications (Cancellable? cancellable) throws Error, IOError {
			var server = yield try_get_remote_server (cancellable);
			if (server != null && server.flavor == REGULAR) {
				try {
					return yield server.session.enumerate_applications (cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
			}

			unowned string serial = device_details.serial;

			string raw_apps = yield Droidy.ShellCommand.run ("pm list packages -U", serial, cancellable);
			string raw_processes = yield Droidy.ShellCommand.run ("ps -A -o UID:1=,PID:1=,ARGS:1= -n", serial, cancellable);

			var pids_by_name = new Gee.HashMultiMap<string, uint> ();
			var pids_by_uid = new Gee.HashMultiMap<uint, uint> ();
			foreach (string line in raw_processes.split ("\n")) {
				string[] tokens = line.split (" ", 3);
				if (tokens.length != 3)
					continue;

				uint uid = uint.parse (tokens[0]);
				uint pid = uint.parse (tokens[1]);
				unowned string cmdline = tokens[2];

				pids_by_name[cmdline] = pid;
				pids_by_uid[uid] = pid;
			}

			var result = new HostApplicationInfo[0];
			var no_icon = ImageData.empty ();

			foreach (string line in raw_apps.chomp ().split ("\n")) {
				string[] fields = line.split (" ");

				string? package = null;
				string? raw_uid = null;
				foreach (unowned string field in fields) {
					if (field.has_prefix ("package:"))
						package = field[8:];
					else if (field.has_prefix ("uid:"))
						raw_uid = field[4:];
				}
				if (package == null || raw_uid == null)
					continue;
				uint uid = uint.parse (raw_uid);

				// TODO: Fetch app name.
				unowned string name = package;

				uint pid = 0;
				Gee.Collection<uint> pids = pids_by_uid[uid];
				var iterator = pids_by_name[package].filter (p => pids.contains (p));
				if (iterator.next ()) {
					/*
					 * XXX: This will fail if the app has changed its cmdline or has multiple processes
					 *      with the same name.
					 */
					pid = iterator.get ();
				}

				result += HostApplicationInfo (package, name, pid, no_icon, no_icon);
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

		public async HostProcessInfo[] enumerate_processes (Cancellable? cancellable) throws Error, IOError {
			var server = yield try_get_remote_server (cancellable);
			if (server != null && server.flavor == REGULAR) {
				try {
					return yield server.session.enumerate_processes (cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
			}

			string raw_output = yield Droidy.ShellCommand.run ("ps -A -o PID:1=,PPID:1=,ARGS:1= -wn",
				device_details.serial, cancellable);

			var result = new HostProcessInfo[0];
			var no_icon = ImageData.empty ();

			foreach (string line in raw_output.split ("\n")) {
				string[] tokens = line.split (" ", 3);
				if (tokens.length != 3)
					continue;

				uint pid = uint.parse (tokens[0]);
				uint parent_pid = uint.parse (tokens[1]);
				unowned string cmdline = tokens[2];

				bool is_kernel_process = pid == 0 || pid == 2 || parent_pid == 2;
				if (is_kernel_process)
					continue;

				result += HostProcessInfo (pid, cmdline, no_icon, no_icon);
			}

			return result;
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

			unowned string package = program;

			var aux_options = options.load_aux ();

			string? user_gadget_path = null;
			if (aux_options.contains ("gadget")) {
				if (!aux_options.lookup ("gadget", "s", out user_gadget_path)) {
					throw new Error.INVALID_ARGUMENT (
						"The 'gadget' option must be a string pointing at the frida-gadget.so to use");
				}
			}

			string gadget_path;
			if (user_gadget_path != null) {
				gadget_path = user_gadget_path;
			} else {
				gadget_path = Path.build_filename (Environment.get_user_cache_dir (), "frida", "gadget-android-arm64.so");
			}

			InputStream gadget;
			try {
				var gadget_file = File.new_for_path (gadget_path);
				gadget = yield gadget_file.read_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				if (e is IOError.NOT_FOUND && user_gadget_path == null) {
					throw new Error.NOT_SUPPORTED (
						"Need Gadget to attach on jailed Android; its default location is: %s", gadget_path);
				} else {
					throw new Error.NOT_SUPPORTED ("%s", e.message);
				}
			}

			var details = yield Droidy.Injector.inject (gadget, package, device_details.serial, cancellable);
			gadgets[details.pid] = details;

			return details.pid;
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
			var gadget = gadgets[pid];
			if (gadget != null) {
				yield gadget.jdwp.resume (cancellable);
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
			var server = yield get_remote_server (cancellable);
			try {
				yield server.session.kill (pid, cancellable);
				return;
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async AgentSessionId attach (uint pid, AgentSessionOptions options, Cancellable? cancellable) throws Error, IOError {
			var gadget = gadgets[pid];
			if (gadget != null)
				return yield attach_via_gadget (pid, options, gadget, cancellable);

			var server = yield get_remote_server (cancellable);
			try {
				return yield attach_via_remote (pid, options, server, cancellable);
			} catch (Error e) {
				throw_dbus_error (e);
			}
		}

		private async AgentSessionId attach_via_gadget (uint pid, AgentSessionOptions options, Droidy.Injector.GadgetDetails gadget,
				Cancellable? cancellable) throws Error, IOError {
			try {
				var stream = yield channel_provider.open_channel ("localabstract:" + gadget.unix_socket_path, cancellable);

				var connection = yield new DBusConnection (stream, null, DBusConnectionFlags.NONE, null, cancellable);

				HostSession host_session = yield connection.get_proxy (null, ObjectPath.HOST_SESSION,
					DBusProxyFlags.NONE, cancellable);

				AgentSessionId remote_session_id;
				try {
					remote_session_id = yield host_session.attach (pid, options, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}

				AgentSession agent_session = yield connection.get_proxy (null,
					ObjectPath.from_agent_session_id (remote_session_id), DBusProxyFlags.NONE, cancellable);

				var local_session_id = AgentSessionId (next_agent_session_id++);
				var agent_entry = new AgentEntry (local_session_id, agent_session, host_session, connection);
				agent_entry.detached.connect (on_agent_entry_detached);
				agent_entries[local_session_id] = agent_entry;
				agent_sessions[local_session_id] = agent_session;

				return local_session_id;
			} catch (GLib.Error e) {
				if (e is Error)
					throw (Error) e;
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
		}

		private async AgentSessionId attach_via_remote (uint pid, AgentSessionOptions options, RemoteServer server,
				Cancellable? cancellable) throws Error, IOError {
			AgentSessionId remote_session_id;
			try {
				remote_session_id = yield server.session.attach (pid, options, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
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

		public void migrate_agent_session (AgentSessionId id, AgentSession new_session) throws Error {
			if (!agent_sessions.has_key (id))
				throw new Error.INVALID_ARGUMENT ("Invalid session ID");
			agent_sessions[id] = new_session;
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

		private void on_agent_entry_detached (AgentEntry entry, SessionDetachReason reason) {
			var id = AgentSessionId (entry.id);
			var no_crash = CrashInfo.empty ();

			agent_entries.unset (id);
			agent_sessions.unset (id);

			entry.detached.disconnect (on_agent_entry_detached);

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
				on_remote_agent_session_detached (remote_id, SERVER_TERMINATED, no_crash);
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

			AgentSession agent_session = null;
			agent_sessions.unset (local_id, out agent_session);
			assert (agent_session != null);

			agent_session_detached (local_id, reason, crash);
		}

		private void on_remote_uninjected (InjectorPayloadId id) {
			uninjected (id);
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
				host_session.agent_session_detached.connect (on_session_detached);
			}

			~AgentEntry () {
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
