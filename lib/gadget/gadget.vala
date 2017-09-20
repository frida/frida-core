namespace Frida.Gadget {
	private const string DEFAULT_LISTEN_ADDRESS = "127.0.0.1";
	private const uint16 DEFAULT_LISTEN_PORT = 27042;

	private class Config : Object {
		public Env env {
			get;
			set;
			default = Env.PRODUCTION;
		}

		public string? script_file {
			get;
			set;
			default = null;
		}

		public string? listen_address {
			get;
			set;
			default = null;
		}

		public bool jit_enabled {
			get;
			set;
			default = false;
		}
	}

	private class Location : Object {
		public string path {
			get;
			construct;
		}

		public Gum.MemoryRange range {
			get;
			construct;
		}

		public Location (string path, Gum.MemoryRange range) {
			Object (path: path, range: range);
		}
	}

	private enum Env {
		PRODUCTION,
		DEVELOPMENT
	}

	private enum State {
		CREATED,
		STARTED,
		RUNNING,
		STOPPED
	}

	private bool loaded = false;
	private State state = State.CREATED;
	private Config config;
	private Location location;
	private MainLoop wait_for_resume_loop;
	private MainContext wait_for_resume_context;
	private ThreadIgnoreScope worker_ignore_scope;
	private ScriptRunner script_runner;
	private Server server;
	private Gum.Exceptor exceptor;
	private Mutex mutex;
	private Cond cond;

	public void load () {
		if (loaded)
			return;
		loaded = true;

		Environment.init ();

		location = detect_location ();

		try {
			config = load_config (location);
		} catch (IOError e) {
			log_error (e.message);
			return;
		}

		Gum.Cloak.add_range (location.range);

		if (Environment.can_block_at_load_time ()) {
			var scheduler = Environment.obtain_script_backend (config.jit_enabled).get_scheduler ();

			if (!Environment.has_system_loop ()) {
				scheduler.disable_background_thread ();

				wait_for_resume_context = scheduler.get_js_context ();
			}

			var ignore_scope = new ThreadIgnoreScope ();

			schedule_start ();

			var context = wait_for_resume_context;
			if (context != null) {
				var loop = new MainLoop (context, true);
				wait_for_resume_loop = loop;

				context.push_thread_default ();
				loop.run ();
				context.pop_thread_default ();

				scheduler.enable_background_thread ();
			} else {
				Environment.run_system_loop ();
			}

			ignore_scope = null;
		} else {
			schedule_start ();
		}
	}

	public void wait_for_permission_to_resume () {
		mutex.lock ();
		while (state != State.RUNNING)
			cond.wait (mutex);
		mutex.unlock ();
	}

	public void unload () {
		if (!loaded)
			return;
		loaded = false;

		{
			var source = new IdleSource ();
			source.set_callback (() => {
				stop.begin ();
				return false;
			});
			source.attach (Environment.get_main_context ());
		}

		mutex.lock ();
		while (state != State.STOPPED)
			cond.wait (mutex);
		mutex.unlock ();

		if (config.env == Env.DEVELOPMENT) {
			config = null;

			Environment.deinit ();
		}
	}

	public void resume () {
		mutex.lock ();
		state = State.RUNNING;
		cond.signal ();
		mutex.unlock ();

		if (wait_for_resume_context != null) {
			var source = new IdleSource ();
			source.set_callback (() => {
				wait_for_resume_loop.quit ();
				return false;
			});
			source.attach (wait_for_resume_context);
		} else {
			Environment.stop_system_loop ();
		}
	}

	private void schedule_start () {
		var source = new IdleSource ();
		source.set_callback (() => {
			start.begin ();
			return false;
		});
		source.attach (Environment.get_main_context ());
	}

	private async void start () {
		worker_ignore_scope = new ThreadIgnoreScope ();

		exceptor = Gum.Exceptor.obtain ();

		if (config.script_file != null) {
			var r = new ScriptRunner (config, location);
			try {
				yield r.start ();
				script_runner = r;
			} catch (Error e) {
				log_error ("Failed to load script: " + e.message);
			}
			resume ();
		} else {
			try {
					var s = new Server (config, location);
					yield s.start ();
					server = s;
					log_info ("Listening on %s TCP port %hu".printf (s.listen_host, s.listen_port));
			} catch (GLib.Error e) {
				log_error ("Failed to start: " + e.message);
			}
		}
	}

	private async void stop () {
		if (config.env == Env.PRODUCTION) {
			if (script_runner != null)
				yield script_runner.flush ();
		} else {
			if (script_runner != null) {
				yield script_runner.stop ();
				script_runner = null;
			} else {
				yield server.stop ();
				server = null;
			}

			exceptor = null;
		}

		worker_ignore_scope = null;

		mutex.lock ();
		state = State.STOPPED;
		cond.signal ();
		mutex.unlock ();
	}

	private Config load_config (Location location) throws IOError {
		var config = try_load_config_from_file (location);
		if (config == null)
			config = load_config_from_environment ();
		return config;
	}

	private Config? try_load_config_from_file (Location location) throws IOError {
		var config_path = derive_config_path_from_location (location);

		try {
			string config_data;
			FileUtils.get_contents (config_path, out config_data);

			try {
				return Json.gobject_from_data (typeof (Config), config_data) as Config;
			} catch (GLib.Error e) {
				throw new IOError.INVALID_ARGUMENT ("Invalid config: %s", e.message);
			}
		} catch (FileError e) {
			if (e is FileError.NOENT)
				return null;
			throw new IOError.FAILED ("%s", e.message);
		}
	}

	private Config load_config_from_environment () throws IOError {
		var config = new Config ();
		config.env = parse_env (GLib.Environment.get_variable ("FRIDA_GADGET_ENV"));
		config.script_file = GLib.Environment.get_variable ("FRIDA_GADGET_SCRIPT");
		config.listen_address = GLib.Environment.get_variable ("FRIDA_GADGET_LISTEN_ADDRESS");
		config.jit_enabled = parse_enable_jit (GLib.Environment.get_variable ("FRIDA_GADGET_ENABLE_JIT"));
		return config;
	}

	private string derive_config_path_from_location (Location location) {
		var path = location.path;
		var dirname = Path.get_dirname (path);
		var filename = Path.get_basename (path);

		string stem;
		var ext_index = filename.last_index_of_char ('.');
		if (ext_index != -1)
			stem = filename[0:ext_index];
		else
			stem = filename;

		return Path.build_filename (dirname, stem + ".config");
	}

	private Env parse_env (string? nick) throws IOError {
		if (nick == null)
			return Env.PRODUCTION;

		var klass = (EnumClass) typeof (Env).class_ref ();
		var enum_value = klass.get_value_by_nick (nick);
		if (enum_value == null)
			throw new IOError.INVALID_ARGUMENT ("Invalid environment");

		return (Env) enum_value.value;
	}

	private bool parse_enable_jit (string? enable_jit) throws IOError {
		if (enable_jit == null)
			return false;

		switch (enable_jit) {
			case "yes":
			case "1":
				return true;
			case "no":
			case "0":
				return false;
		}

		throw new IOError.INVALID_ARGUMENT ("Invalid JIT preference");
	}

	private Location detect_location () {
		string? our_path = null;
		Gum.MemoryRange? our_range = null;

		Gum.Address our_address = (Gum.Address) detect_location;

		Gum.Process.enumerate_modules ((details) => {
			var range = details.range;

			if (our_address >= range.base_address && our_address < range.base_address + range.size) {
				our_path = details.path;
				our_range = range;
				return false;
			}

			return true;
		});
		assert (our_path != null && our_range != null);

		return new Location (our_path, our_range);
	}

	private class ScriptRunner : Object {
		public Config config {
			get;
			construct;
		}

		public Location location {
			get;
			construct;
		}

		private AgentScriptId script;
		private GLib.FileMonitor script_monitor;
		private Source script_unchanged_timeout;
		private ScriptEngine script_engine;
		private bool load_in_progress = false;

		private Gee.HashMap<string, PendingResponse> pending = new Gee.HashMap<string, PendingResponse> ();
		private int64 next_request_id = 1;

		public ScriptRunner (Config config, Location location) {
			Object (config: config, location: location);
		}

		construct {
			script_engine = new ScriptEngine (Environment.obtain_script_backend (config.jit_enabled), location.range);
			script_engine.message_from_script.connect (on_message);
		}

		public async void start () throws Error {
			yield load ();

			if (config.env == Env.DEVELOPMENT) {
				try {
					script_monitor = File.new_for_path (config.script_file).monitor_file (FileMonitorFlags.NONE);
					script_monitor.changed.connect (on_script_file_changed);
				} catch (GLib.Error e) {
					printerr (e.message);
				}
			}
		}

		public async void flush () {
			if (script.handle != 0) {
				try {
					yield call ("dispose", new Json.Node[] {});
				} catch (Error e) {
				}
			}
		}

		public async void stop () {
			yield flush ();

			if (script_monitor != null) {
				script_monitor.changed.disconnect (on_script_file_changed);
				script_monitor.cancel ();
				script_monitor = null;
			}

			yield script_engine.shutdown ();
		}

		private async void try_reload () {
			try {
				yield load ();
			} catch (Error e) {
				printerr ("Failed to reload script: %s\n", e.message);
			}
		}

		private async void load () throws Error {
			load_in_progress = true;

			try {
				var script_file = config.script_file;

				var name = Path.get_basename (script_file).split (".", 2)[0];

				string source;
				try {
					FileUtils.get_contents (script_file, out source);
				} catch (FileError e) {
					throw new Error.INVALID_ARGUMENT (e.message);
				}

				var instance = yield script_engine.create_script (name, source, null);

				if (script.handle != 0) {
					try {
						yield call ("dispose", new Json.Node[] {});
					} catch (Error e) {
					}

					yield script_engine.destroy_script (script);
					script = AgentScriptId (0);
				}
				script = instance.sid;

				yield script_engine.load_script (script);

				try {
					yield call ("init", new Json.Node[] {});
				} catch (Error e) {
				}
			} finally {
				load_in_progress = false;
			}
		}

		private async Json.Node call (string method, Json.Node[] args) throws Error {
			var request_id = next_request_id++;

			var builder = new Json.Builder ();
			builder
			.begin_array ()
			.add_string_value ("frida:rpc")
			.add_int_value (request_id)
			.add_string_value ("call")
			.add_string_value (method)
			.begin_array ();
			foreach (var arg in args)
				builder.add_value (arg);
			builder
			.end_array ()
			.end_array ();

			var generator = new Json.Generator ();
			generator.set_root (builder.get_root ());
			size_t length;
			var request = generator.to_data (out length);

			var response = new PendingResponse (() => call.callback ());
			pending[request_id.to_string ()] = response;

			post_call_request.begin (request, response);

			yield;

			if (response.error != null)
				throw response.error;

			return response.result;
		}

		private async void post_call_request (string request, PendingResponse response) {
			try {
				script_engine.post_to_script (script, request);
			} catch (GLib.Error e) {
				response.complete_with_error (Marshal.from_dbus (e));
			}
		}

		private void on_script_file_changed (File file, File? other_file, FileMonitorEvent event_type) {
			if (event_type == FileMonitorEvent.CHANGES_DONE_HINT)
				return;

			var source = new TimeoutSource (50);
			source.set_callback (() => {
				if (load_in_progress)
					return true;
				try_reload.begin ();
				return false;
			});
			source.attach (Environment.get_main_context ());

			if (script_unchanged_timeout != null)
				script_unchanged_timeout.destroy ();
			script_unchanged_timeout = source;
		}

		private void on_message (AgentScriptId sid, string raw_message, Bytes? data) {
			var parser = new Json.Parser ();
			try {
				parser.load_from_data (raw_message);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
			var message = parser.get_root ().get_object ();

			bool handled = false;
			var type = message.get_string_member ("type");
			if (type == "send")
				handled = try_handle_rpc_message (message);
			else if (type == "log")
				handled = try_handle_log_message (message);

			if (!handled) {
				stdout.puts (raw_message);
				stdout.putc ('\n');
			}
		}

		private bool try_handle_rpc_message (Json.Object message) {
			var payload = message.get_member ("payload");
			if (payload == null || payload.get_node_type () != Json.NodeType.ARRAY)
				return false;
			var rpc_message = payload.get_array ();
			if (rpc_message.get_length () < 4)
				return false;
			else if (rpc_message.get_element (0).get_string () != "frida:rpc")
				return false;

			var request_id = rpc_message.get_int_element (1);
			PendingResponse response;
			pending.unset (request_id.to_string (), out response);
			var status = rpc_message.get_string_element (2);
			if (status == "ok")
				response.complete_with_result (rpc_message.get_element (3));
			else
				response.complete_with_error (new Error.NOT_SUPPORTED (rpc_message.get_string_element (3)));
			return true;
		}

		private bool try_handle_log_message (Json.Object message) {
			var level = message.get_string_member ("level");
			var payload = message.get_string_member ("payload");
			switch (level) {
				case "info":
					print ("%s\n", payload);
					break;

				case "warning":
					printerr ("\033[0;33m%s\033[0m\n", payload);
					break;

				case "error":
					printerr ("\033[0;31m%s\033[0m\n", payload);
					break;
			}
			return true;
		}

		private class PendingResponse {
			public delegate void CompletionHandler ();
			private CompletionHandler handler;

			public Json.Node? result {
				get;
				private set;
			}

			public Error? error {
				get;
				private set;
			}

			public PendingResponse (owned CompletionHandler handler) {
				this.handler = (owned) handler;
			}

			public void complete_with_result (Json.Node r) {
				result = r;
				handler ();
			}

			public void complete_with_error (Error e) {
				error = e;
				handler ();
			}
		}
	}

	private class Server : Object {
		public Config config {
			get;
			construct;
		}

		public Location location {
			get;
			construct;
		}

		public InetSocketAddress listen_address {
			get;
			construct;
		}

		public string listen_host {
			owned get {
				return listen_address.get_address ().to_string ();
			}
		}

		public uint16 listen_port {
			get {
				return listen_address.get_port ();
			}
		}

		public string listen_uri {
			owned get {
				var listen_address = listen_address;
				var inet_address = listen_address.get_address ();

				var family = (inet_address.get_family () == SocketFamily.IPV6) ? "ipv6" : "ipv4";
				var host = inet_address.to_string ();
				var port = listen_address.get_port ();

				return "tcp:family=%s,host=%s,port=%hu".printf (family, host, port);
			}
		}

		private unowned Gum.ScriptBackend script_backend = null;
		private DBusServer server;
		private Gee.HashMap<DBusConnection, Client> clients = new Gee.HashMap<DBusConnection, Client> ();

		public Server (Config config, Location location) throws Error {
			Object (
				config: config,
				location: location,
				listen_address: parse_listen_address (config.listen_address)
			);
		}

		private static InetSocketAddress parse_listen_address (string? listen_address) throws Error {
			var raw_address = (listen_address != null) ? listen_address : DEFAULT_LISTEN_ADDRESS;

			SocketConnectable connectable;
			try {
				connectable = NetworkAddress.parse (raw_address, DEFAULT_LISTEN_PORT).enumerate ().next ();
			} catch (GLib.Error e) {
				throw new Error.INVALID_ARGUMENT ("Invalid listen address");
			}

			if (!(connectable is InetSocketAddress))
				throw new Error.INVALID_ARGUMENT ("Invalid listen address");

			return connectable as InetSocketAddress;
		}

		public async void start () throws Error {
			try {
				server = new DBusServer.sync (listen_uri, DBusServerFlags.AUTHENTICATION_ALLOW_ANONYMOUS, DBus.generate_guid ());
			} catch (GLib.Error listen_error) {
				throw new Error.ADDRESS_IN_USE (listen_error.message);
			}

			server.new_connection.connect ((connection) => {
				if (server == null)
					return false;

				clients[connection] = new Client (this, connection);
				connection.closed.connect (on_connection_closed);

				return true;
			});

			server.start ();
		}

		public async void stop () {
			if (server == null)
				return;

			server.stop ();
			server = null;

			while (!clients.is_empty) {
				var iterator = clients.keys.iterator ();
				iterator.next ();
				var connection = iterator.get ();

				Client client;
				clients.unset (connection, out client);
				yield client.shutdown ();
			}
		}

		public ScriptEngine create_script_engine () {
			if (script_backend == null)
				script_backend = Environment.obtain_script_backend (config.jit_enabled);

			return new ScriptEngine (script_backend, location.range);
		}

		public void enable_jit () throws Error {
			if (config.jit_enabled)
				return;

			if (script_backend != null)
				throw new Error.INVALID_OPERATION ("JIT may only be enabled before the first script is created");

			config.jit_enabled = true;
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			Client client;
			if (clients.unset (connection, out client))
				client.shutdown.begin ();
		}

		private class Client : Object, HostSession {
			private unowned Server server;
			private DBusConnection connection;
			private uint host_registration_id;
			private HostApplicationInfo this_app;
			private HostProcessInfo this_process;
			private Gee.HashSet<ClientSession> sessions = new Gee.HashSet<ClientSession> ();
			private uint next_session_id = 1;
			private bool resume_on_attach = true;

			public Client (Server s, DBusConnection c) {
				server = s;
				connection = c;

				try {
					host_registration_id = connection.register_object (Frida.ObjectPath.HOST_SESSION, this as HostSession);
				} catch (IOError e) {
					assert_not_reached ();
				}

				var pid = _getpid ();
				var identifier = "re.frida.Gadget";
				var name = "Gadget";
				var no_icon = ImageData (0, 0, 0, "");
				this_app = HostApplicationInfo (identifier, name, pid, no_icon, no_icon);
				this_process = HostProcessInfo (pid, name, no_icon, no_icon);
			}

			public async void shutdown () {
				foreach (var session in sessions.to_array ()) {
					try {
						yield session.close ();
					} catch (GLib.Error e) {
						assert_not_reached ();
					}
				}
				assert (sessions.is_empty);

				if (host_registration_id != 0) {
					connection.unregister_object (host_registration_id);
					host_registration_id = 0;
				}
			}

			public async HostApplicationInfo get_frontmost_application () throws Error {
				return this_app;
			}

			public async HostApplicationInfo[] enumerate_applications () throws Error {
				return new HostApplicationInfo[] { this_app };
			}

			public async HostProcessInfo[] enumerate_processes () throws Error {
				return new HostProcessInfo[] { this_process };
			}

			public async void enable_spawn_gating () throws Error {
				throw new Error.NOT_SUPPORTED ("Not possible when embedded");
			}

			public async void disable_spawn_gating () throws Error {
				throw new Error.NOT_SUPPORTED ("Not possible when embedded");
			}

			public async HostSpawnInfo[] enumerate_pending_spawns () throws Error {
				throw new Error.NOT_SUPPORTED ("Not possible when embedded");
			}

			public async uint spawn (string path, string[] argv, string[] envp) throws Error {
				if (argv.length < 1 || argv[0] != this_app.identifier)
					throw new Error.NOT_SUPPORTED ("Unable to spawn other apps when embedded");

				resume_on_attach = false;

				return this_process.pid;
			}

			public async void input (uint pid, uint8[] data) throws Error {
				throw new Error.NOT_SUPPORTED ("Not possible when embedded");
			}

			public async void resume (uint pid) throws Error {
				validate_pid (pid);

				Frida.Gadget.resume ();
			}

			public async void kill (uint pid) throws Error {
				validate_pid (pid);

				suicide.begin ();
			}

			private async void suicide () {
				try {
					yield connection.flush ();
				} catch (GLib.Error e) {
				}

				_kill (this_process.pid);
			}

			public async AgentSessionId attach_to (uint pid) throws Error {
				validate_pid (pid);

				if (resume_on_attach)
					Frida.Gadget.resume ();

				var id = AgentSessionId (next_session_id++);

				var session = new ClientSession (server, id);
				sessions.add (session);
				session.closed.connect (on_session_closed);

				try {
					AgentSession s = session;
					session.registration_id = connection.register_object (ObjectPath.from_agent_session_id (id), s);
				} catch (IOError io_error) {
					assert_not_reached ();
				}

				return id;
			}

			public async InjectorPayloadId inject_library_file (uint pid, string path, string entrypoint, string data) throws Error {
				throw new Error.NOT_SUPPORTED ("Unable to inject libraries when embedded");
			}

			public async InjectorPayloadId inject_library_blob (uint pid, uint8[] blob, string entrypoint, string data) throws Error {
				throw new Error.NOT_SUPPORTED ("Unable to inject libraries when embedded");
			}

			private void on_session_closed (ClientSession session) {
				connection.unregister_object (session.registration_id);

				session.closed.disconnect (on_session_closed);
				sessions.remove (session);

				agent_session_destroyed (session.id, SessionDetachReason.APPLICATION_REQUESTED);
			}

			private void validate_pid (uint pid) throws Error {
				if (pid != this_process.pid)
					throw new Error.NOT_SUPPORTED ("Unable to act on other processes when embedded");
			}
		}

		private class ClientSession : Object, AgentSession {
			public signal void closed (ClientSession session);

			public weak Server server {
				get;
				construct;
			}

			public AgentSessionId id {
				get;
				construct;
			}

			public uint registration_id {
				get;
				set;
			}

			private Gee.Promise<bool> close_request;

			private ScriptEngine script_engine;

			public ClientSession (Server server, AgentSessionId id) {
				Object (server: server, id: id);
			}

			public async void close () throws Error {
				if (close_request != null) {
					try {
						yield close_request.future.wait_async ();
					} catch (Gee.FutureError e) {
						assert_not_reached ();
					}
					return;
				}
				close_request = new Gee.Promise<bool> ();

				if (script_engine != null) {
					yield script_engine.shutdown ();
					script_engine = null;
				}

				closed (this);

				close_request.set_value (true);
			}

			public async AgentScriptId create_script (string name, string source) throws Error {
				var engine = get_script_engine ();
				var instance = yield engine.create_script ((name != "") ? name : null, source, null);
				return instance.sid;
			}

			public async AgentScriptId create_script_from_bytes (uint8[] bytes) throws Error {
				var engine = get_script_engine ();
				var instance = yield engine.create_script (null, null, new Bytes (bytes));
				return instance.sid;
			}

			public async uint8[] compile_script (string name, string source) throws Error {
				var engine = get_script_engine ();
				var bytes = yield engine.compile_script ((name != "") ? name : null, source);
				return bytes.get_data ();
			}

			public async void destroy_script (AgentScriptId sid) throws Error {
				var engine = get_script_engine ();
				yield engine.destroy_script (sid);
			}

			public async void load_script (AgentScriptId sid) throws Error {
				var engine = get_script_engine ();
				yield engine.load_script (sid);
			}

			public async void post_to_script (AgentScriptId sid, string message, bool has_data, uint8[] data) throws Error {
				get_script_engine ().post_to_script (sid, message, has_data ? new Bytes (data) : null);
			}

			public async void enable_debugger () throws Error {
				get_script_engine ().enable_debugger ();
			}

			public async void disable_debugger () throws Error {
				get_script_engine ().disable_debugger ();
			}

			public async void post_message_to_debugger (string message) throws Error {
				get_script_engine ().post_message_to_debugger (message);
			}

			public async void enable_jit () throws GLib.Error {
				server.enable_jit ();
			}

			private ScriptEngine get_script_engine () throws Error {
				check_open ();

				if (script_engine == null) {
					script_engine = server.create_script_engine ();
					script_engine.message_from_script.connect ((script_id, message, data) => {
						var has_data = data != null;
						var data_param = has_data ? data.get_data () : new uint8[0];
						this.message_from_script (script_id, message, has_data, data_param);
					});
					script_engine.message_from_debugger.connect ((message) => this.message_from_debugger (message));
				}

				return script_engine;
			}

			private void check_open () throws Error {
				if (close_request != null)
					throw new Error.INVALID_OPERATION ("Session is closing");
			}
		}
	}

	private class ThreadIgnoreScope {
		private Gum.Interceptor interceptor;

		private Gum.ThreadId thread_id;

		private bool stack_known;
		private Gum.MemoryRange stack;

		public ThreadIgnoreScope () {
			interceptor = Gum.Interceptor.obtain ();
			interceptor.ignore_current_thread ();

			thread_id = Gum.Process.get_current_thread_id ();
			Gum.Cloak.add_thread (thread_id);

			stack_known = Gum.Thread.try_get_range (out stack);
			if (stack_known)
				Gum.Cloak.add_range (stack);

		}

		~ThreadIgnoreScope () {
			if (stack_known)
				Gum.Cloak.remove_range (stack);

			Gum.Cloak.remove_thread (thread_id);

			interceptor.unignore_current_thread ();
		}
	}

	namespace Environment {
		private extern void init ();
		private extern void deinit ();
		private extern bool can_block_at_load_time ();
		private extern bool has_system_loop ();
		private extern void run_system_loop ();
		private extern void stop_system_loop ();
		private extern unowned MainContext get_main_context ();
		private extern unowned Gum.ScriptBackend obtain_script_backend (bool jit_enabled);
	}

	public extern uint _getpid ();
	public extern void _kill (uint pid);

	private extern void log_info (string message);
	private extern void log_error (string message);

	private Mutex gc_mutex;
	private uint gc_generation = 0;
	private bool gc_scheduled = false;

	public void on_pending_garbage (void * data) {
		gc_mutex.lock ();
		gc_generation++;
		bool already_scheduled = gc_scheduled;
		gc_scheduled = true;
		gc_mutex.unlock ();

		if (already_scheduled)
			return;

		Timeout.add (50, () => {
			gc_mutex.lock ();
			uint generation = gc_generation;
			gc_mutex.unlock ();

			bool collected_everything = garbage_collect ();

			gc_mutex.lock ();
			bool same_generation = generation == gc_generation;
			bool repeat = !collected_everything || !same_generation;
			if (!repeat)
				gc_scheduled = false;
			gc_mutex.unlock ();

			return repeat;
		});
	}

	[CCode (cname = "g_thread_garbage_collect")]
	private extern bool garbage_collect ();
}
