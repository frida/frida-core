namespace Frida {
	public class FruityLockdownProvider : Object, HostSessionProvider, ChannelProvider {
		public string id {
			get { return _id; }
		}
		private string _id;

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

		private FruityLockdownSession? host_session;
		private Promise<Fruity.LockdownClient>? lockdown_client_request;

		public FruityLockdownProvider (string name, Image? icon, Fruity.DeviceDetails details) {
			Object (
				device_name: name + " [lockdown]",
				device_icon: icon,
				device_details: details
			);
		}

		construct {
			_id = device_details.udid.raw_value + ":lockdown";
		}

		public async void close (Cancellable? cancellable) throws IOError {
		}

		public async HostSession create (string? location, Cancellable? cancellable) throws Error, IOError {
			if (host_session != null)
				throw new Error.INVALID_ARGUMENT ("Invalid location: already created");

			var client = yield get_lockdown_client (cancellable);

			host_session = new FruityLockdownSession (client, this);
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

					throw new Error.TRANSPORT ("%s", e.message);
				}
			}

			if (address.has_prefix ("lockdown:")) {
				string service_name = address.substring (9);

				var client = yield get_lockdown_client (cancellable);

				try {
					return yield client.start_service (service_name, cancellable);
				} catch (GLib.Error e) {
					throw new Error.TRANSPORT ("%s", e.message);
				}
			}

			throw new Error.NOT_SUPPORTED ("Unsupported channel address");
		}

		private async Fruity.LockdownClient get_lockdown_client (Cancellable? cancellable) throws Error, IOError {
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

				lockdown_client_request.resolve (client);

				return client;
			} catch (GLib.Error e) {
				var api_error = new Error.NOT_SUPPORTED ("%s", e.message);

				lockdown_client_request.reject (api_error);
				lockdown_client_request = null;

				throw_api_error (api_error);
			}
		}
	}

	public class FruityLockdownSession : Object, HostSession {
		public signal void agent_session_closed (AgentSessionId id, AgentSession session, SessionDetachReason reason,
			CrashInfo? crash);

		public Fruity.LockdownClient lockdown {
			get;
			construct;
		}

		public ChannelProvider channel_provider {
			get;
			construct;
		}

		private Gee.HashMap<uint, SpawnEntry> spawn_entries = new Gee.HashMap<uint, SpawnEntry> ();

		private Gee.HashMap<AgentSessionId?, AgentEntry> agent_entries =
			new Gee.HashMap<AgentSessionId?, AgentEntry> (AgentSessionId.hash, AgentSessionId.equal);
		private uint next_agent_session_id = 1;

		private Cancellable io_cancellable = new Cancellable ();

		private const string DEBUGSERVER_SERVICE_NAME = "com.apple.debugserver";

		public FruityLockdownSession (Fruity.LockdownClient lockdown, ChannelProvider channel_provider) {
			Object (
				lockdown: lockdown,
				channel_provider: channel_provider
			);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			while (!agent_entries.is_empty) {
				var iterator = agent_entries.values.iterator ();
				iterator.next ();
				var entry = iterator.get ();
				yield entry.close (cancellable);
			}

			while (!spawn_entries.is_empty) {
				var iterator = spawn_entries.values.iterator ();
				iterator.next ();
				var entry = iterator.get ();
				yield entry.close (cancellable);
			}

			yield lockdown.close (cancellable);

			io_cancellable.cancel ();
		}

		public async HostApplicationInfo get_frontmost_application (Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet supported on jailed iOS");
		}

		public async HostApplicationInfo[] enumerate_applications (Cancellable? cancellable) throws Error, IOError {
			try {
				var installation_proxy = yield Fruity.InstallationProxyClient.open (lockdown, cancellable);

				var apps = yield installation_proxy.browse (cancellable);

				uint no_pid = 0;
				var no_icon = ImageData (0, 0, 0, "");

				var result = new HostApplicationInfo[apps.size];
				int i = 0;
				foreach (var app in apps) {
					result[i] = HostApplicationInfo (app.identifier, app.name, no_pid, no_icon, no_icon);
					i++;
				}

				return result;
			} catch (Fruity.InstallationProxyError e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
		}

		public async HostProcessInfo[] enumerate_processes (Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet supported on jailed iOS");
		}

		public async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet supported on jailed iOS");
		}

		public async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet supported on jailed iOS");
		}

		public async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet supported on jailed iOS");
		}

		public async HostChildInfo[] enumerate_pending_children (Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet supported on jailed iOS");
		}

		public async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError {
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
				var installation_proxy = yield Fruity.InstallationProxyClient.open (lockdown, cancellable);

				var app = yield installation_proxy.lookup_one (program, cancellable);
				if (app == null)
					throw new Error.INVALID_ARGUMENT ("Unable to find app with bundle identifier '%s'", program);

				string[] argv = { app.path };
				if (options.has_argv) {
					var provided_argv = options.argv;
					var length = provided_argv.length;
					for (int i = 1; i < length; i++)
						argv += provided_argv[i];
				}

				var lldb_stream = yield lockdown.start_service (DEBUGSERVER_SERVICE_NAME, cancellable);
				var lldb = yield LLDB.Client.open (lldb_stream, cancellable);
				var process = yield lldb.launch (argv, launch_options, cancellable);
				if (process.observed_state == ALREADY_RUNNING) {
					yield lldb.kill (cancellable);
					yield lldb.close (cancellable);

					lldb_stream = yield lockdown.start_service (DEBUGSERVER_SERVICE_NAME, cancellable);
					lldb = yield LLDB.Client.open (lldb_stream, cancellable);
					process = yield lldb.launch (argv, launch_options, cancellable);
				}

				var pid = process.pid;

				var entry = new SpawnEntry (lldb, process, gadget_path, channel_provider);
				entry.closed.connect (on_spawn_entry_closed);
				entry.output.connect (on_spawn_entry_output);
				spawn_entries[pid] = entry;

				return pid;
			} catch (Fruity.InstallationProxyError e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			} catch (Fruity.LockdownError e) {
				if (e is Fruity.LockdownError.INVALID_SERVICE)
					throw new Error.NOT_SUPPORTED ("Developer Disk Image not mounted");
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			} catch (LLDB.Error e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
		}

		public async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet supported on jailed iOS");
		}

		public async void resume (uint pid, Cancellable? cancellable) throws Error, IOError {
			var entry = spawn_entries[pid];
			if (entry == null)
				throw new Error.INVALID_ARGUMENT ("Invalid PID");

			yield entry.resume (cancellable);
		}

		public async void kill (uint pid, Cancellable? cancellable) throws Error, IOError {
			var spawn_entry = spawn_entries[pid];
			if (spawn_entry == null)
				throw new Error.NOT_SUPPORTED ("Only able to kill spawned processes on jailed iOS");

			yield spawn_entry.kill (cancellable);
		}

		public async AgentSessionId attach_to (uint pid, Cancellable? cancellable) throws Error, IOError {
			var spawn_entry = spawn_entries[pid];
			if (spawn_entry == null)
				throw new Error.NOT_SUPPORTED ("Only able to attach to spawned processes on jailed iOS");

			var gadget_details = yield spawn_entry.query_gadget_details (cancellable);

			try {
				var stream = yield channel_provider.open_channel (
					("tcp:%" + uint16.FORMAT_MODIFIER + "u").printf (gadget_details.port),
					cancellable);

				var connection = yield new DBusConnection (stream, null, AUTHENTICATION_CLIENT, null, cancellable);

				HostSession host_session = yield connection.get_proxy (null, ObjectPath.HOST_SESSION, DBusProxyFlags.NONE,
					cancellable);

				AgentSessionId remote_session_id = yield host_session.attach_to (pid, cancellable);

				AgentSession agent_session = yield connection.get_proxy (null,
					ObjectPath.from_agent_session_id (remote_session_id), DBusProxyFlags.NONE, cancellable);

				var local_session_id = AgentSessionId (next_agent_session_id++);
				var agent_entry = new AgentEntry (local_session_id, agent_session, host_session, connection);
				agent_entry.detached.connect (on_agent_entry_detached);
				agent_entries[local_session_id] = agent_entry;

				return local_session_id;
			} catch (GLib.Error e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
		}

		public AgentSession obtain_agent_session (AgentSessionId id) throws Error {
			var entry = agent_entries[id];
			if (entry == null)
				throw new Error.INVALID_ARGUMENT ("Invalid session ID");
			return entry.agent_session;
		}

		public async InjectorPayloadId inject_library_file (uint pid, string path, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet supported on jailed iOS");
		}

		public async InjectorPayloadId inject_library_blob (uint pid, uint8[] blob, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet supported on jailed iOS");
		}

		private void on_spawn_entry_closed (SpawnEntry entry) {
			spawn_entries.unset (entry.process.pid);

			entry.closed.disconnect (on_spawn_entry_closed);
			entry.output.disconnect (on_spawn_entry_output);
		}

		private void on_spawn_entry_output (SpawnEntry entry, Bytes bytes) {
			output (entry.process.pid, 1, bytes.get_data ());
		}

		private void on_agent_entry_detached (AgentEntry entry, SessionDetachReason reason) {
			var id = AgentSessionId (entry.id);
			CrashInfo? crash = null;

			agent_entries.unset (id);

			entry.detached.disconnect (on_agent_entry_detached);

			agent_session_closed (id, entry.agent_session, reason, crash);
			agent_session_destroyed (id, reason);

			entry.close.begin (io_cancellable);
		}

		private class SpawnEntry : Object {
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

			public ChannelProvider channel_provider {
				get;
				construct;
			}

			private Promise<Fruity.Injector.GadgetDetails>? gadget_request;

			public SpawnEntry (LLDB.Client lldb, LLDB.Process process, string? gadget_path, ChannelProvider channel_provider) {
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

			~SpawnEntry () {
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
							throw new Error.NOT_SUPPORTED ("Need gadget to attach; its default location is: %s",
								path);
						}
					}

					const uint page_size = 16384;
					var module = new Gum.DarwinModule.from_file (path, 0, ARM64, page_size);

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
	}
}
