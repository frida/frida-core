namespace Frida.Gadget {
	private enum State {
		CREATED,
		STARTED,
		RUNNING,
		STOPPED
	}
	private bool loaded = false;
	private State state = State.CREATED;
	private ScriptRunner script_runner;
	private Server server;
	private Gum.Interceptor interceptor;
	private AutoIgnorer ignorer;
	private Mutex mutex;
	private Cond cond;

	public void load () {
		if (loaded)
			return;
		loaded = true;

		Environment.init ();

		var source = new IdleSource ();
		source.set_callback (() => {
			start.begin ();
			return false;
		});
		source.attach (Environment.get_main_context ());

		mutex.lock ();
		while (state != State.RUNNING)
			cond.wait (mutex);
		mutex.unlock ();
	}

	public void unload () {
		if (!loaded)
			return;
		loaded = false;

		var ign = ignorer;

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

		Environment.deinit ((owned) ign);
	}

	public void resume () {
		mutex.lock ();
		state = State.RUNNING;
		cond.signal ();
		mutex.unlock ();
	}

	private async void start () {
		Gum.init ();

		var script_backend = obtain_script_backend ();
		var gadget_range = memory_range ();

		interceptor = Gum.Interceptor.obtain ();

		ignorer = new AutoIgnorer (script_backend, interceptor, gadget_range);
		ignorer.enable ();
		ignorer.ignore (Gum.Process.get_current_thread_id (), 0);

		var script_file = GLib.Environment.get_variable ("FRIDA_GADGET_SCRIPT");
		if (script_file != null) {
			var r = new ScriptRunner (script_file, script_backend, gadget_range);
			try {
				yield r.start ();
				script_runner = r;
			} catch (Error e) {
				log_error ("Failed to load script: " + e.message);
			}
		} else {
			var s = new Server (script_backend, gadget_range);
			try {
				yield s.start ();
				server = s;
				log_info ("Listening on TCP port 27042");
			} catch (Error e) {
				log_error ("Failed to start: " + e.message);
			}
		}
	}

	private async void stop () {
		if (script_runner != null) {
			yield script_runner.stop ();
			script_runner = null;
		} else {
			yield server.stop ();
			server = null;
		}

		ignorer.unignore (Gum.Process.get_current_thread_id (), 0);
		ignorer.disable ();
		ignorer = null;
		interceptor = null;

		Environment.shutdown ();
		Gum.deinit ();

		mutex.lock ();
		state = State.STOPPED;
		cond.signal ();
		mutex.unlock ();
	}

	private class ScriptRunner : Object {
		private AgentScriptId script;
		private string script_file;
		private ScriptEngine script_engine;

		public ScriptRunner (string script_file, Gum.ScriptBackend script_backend, Gum.MemoryRange gadget_range) {
			this.script_file = script_file;

			script_engine = new ScriptEngine (script_backend, gadget_range);
			script_engine.message_from_script.connect (on_message);
		}

		public async void start () throws Error {
			var name = Path.get_basename (script_file).split (".", 2)[0];

			string source;
			try {
				FileUtils.get_contents (script_file, out source);
			} catch (FileError e) {
				throw new Error.INVALID_ARGUMENT (e.message);
			}

			var instance = yield script_engine.create_script (name, source);
			script = instance.sid;
			yield script_engine.load_script (script);
		}

		public async void stop () {
			yield script_engine.shutdown ();
		}

		private void on_message (AgentScriptId sid, string message, uint8[] data) {
			// TODO: implement basic RPC so we know when the script has finished initializing
		}
	}

	private class Server : Object {
		private const string LISTEN_ADDRESS = "tcp:host=127.0.0.1,port=27042";

		private Gum.ScriptBackend script_backend;
		private Gum.MemoryRange gadget_range;
		private DBusServer server;
		private Gee.HashMap<DBusConnection, Session> sessions = new Gee.HashMap<DBusConnection, Session> ();

		public Server (Gum.ScriptBackend script_backend, Gum.MemoryRange gadget_range) {
			this.script_backend = script_backend;
			this.gadget_range = gadget_range;
		}

		public async void start () throws Error {
			try {
				server = new DBusServer.sync (LISTEN_ADDRESS, DBusServerFlags.AUTHENTICATION_ALLOW_ANONYMOUS, DBus.generate_guid ());
			} catch (GLib.Error listen_error) {
				throw new Error.ADDRESS_IN_USE (listen_error.message);
			}

			server.new_connection.connect ((connection) => {
				if (server == null)
					return false;

				sessions[connection] = new Session (connection, script_backend, gadget_range);
				connection.closed.connect (on_connection_closed);

				return true;
			});

			server.start ();
		}

		public async void stop () {
			if (server == null)
				return;

			foreach (var session in sessions.values)
				session.shutdown ();
			sessions.clear ();

			server.stop ();
			server = null;
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			Session session;
			if (sessions.unset (connection, out session))
				session.shutdown ();
		}

		private class Session : Object, HostSession, AgentSession {
			private DBusConnection connection;
			private uint host_registration_id;
			private uint agent_registration_id;
			private HostApplicationInfo this_app;
			private HostProcessInfo this_process;
			private ScriptEngine script_engine;
			private bool resume_on_attach = true;
			private bool close_requested = false;

			public Session (DBusConnection c, Gum.ScriptBackend script_backend, Gum.MemoryRange gadget_range) {
				connection = c;

				try {
					host_registration_id = connection.register_object (Frida.ObjectPath.HOST_SESSION, this as HostSession);
					agent_registration_id = connection.register_object (Frida.ObjectPath.from_agent_session_id (AgentSessionId (1)), this as AgentSession);
				} catch (IOError e) {
					assert_not_reached ();
				}

				var pid = Posix.getpid ();
				var identifier = "re.frida.Gadget";
				var name = "Gadget";
				var no_icon = ImageData (0, 0, 0, "");
				this_app = HostApplicationInfo (identifier, name, pid, no_icon, no_icon);
				this_process = HostProcessInfo (pid, name, no_icon, no_icon);

				script_engine = new ScriptEngine (script_backend, gadget_range);
				script_engine.message_from_script.connect ((script_id, message, data) => this.message_from_script (script_id, message, data));
			}

			~Session () {
				shutdown ();
			}

			public void shutdown () {
				if (script_engine != null) {
					script_engine.shutdown.begin ();
					script_engine = null;
				}

				if (agent_registration_id != 0) {
					connection.unregister_object (agent_registration_id);
					agent_registration_id = 0;
				}
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

			public async void resume (uint pid) throws Error {
				validate_pid (pid);

				Frida.Gadget.resume ();
			}

			public async void kill (uint pid) throws Error {
				validate_pid (pid);

				yield script_engine.shutdown ();
				suicide.begin ();
			}

			private async void suicide () {
				try {
					yield connection.flush ();
				} catch (GLib.Error e) {
				}

				Posix.kill ((Posix.pid_t) this_process.pid, Posix.SIGKILL);
			}

			public async AgentSessionId attach_to (uint pid) throws Error {
				validate_pid (pid);

				if (resume_on_attach)
					Frida.Gadget.resume ();

				return AgentSessionId (1);
			}

			private void validate_pid (uint pid) throws Error {
				if (pid != this_process.pid)
					throw new Error.NOT_SUPPORTED ("Unable to act on other processes when embedded");
			}

			public async void close () throws Error {
				if (close_requested)
					return;
				close_requested = true;

				var source = new TimeoutSource (50);
				source.set_callback (() => {
					connection.close.begin ();
					return false;
				});
				source.attach (Environment.get_main_context ());
			}

			public async void ping () throws Error {
			}

			public async AgentScriptId create_script (string name, string source) throws Error {
				var instance = yield script_engine.create_script (name, source);
				return instance.sid;
			}

			public async void destroy_script (AgentScriptId sid) throws Error {
				yield script_engine.destroy_script (sid);
			}

			public async void load_script (AgentScriptId sid) throws Error {
				yield script_engine.load_script (sid);
			}

			public async void post_message_to_script (AgentScriptId sid, string message) throws Error {
				script_engine.post_message_to_script (sid, message);
			}

			public async void enable_debugger () throws Error {
				script_engine.enable_debugger ();
			}

			public async void disable_debugger () throws Error {
				script_engine.disable_debugger ();
			}

			public async void post_message_to_debugger (string message) throws Error {
				script_engine.post_message_to_debugger (message);
			}
		}
	}

	protected class AutoIgnorer : Object {
		protected weak Gum.ScriptBackend script_backend;
		protected Gum.Interceptor interceptor;
		protected Gum.MemoryRange gadget_range;
		protected SList tls_contexts;
		protected Mutex mutex;

		public AutoIgnorer (Gum.ScriptBackend script_backend, Gum.Interceptor interceptor, Gum.MemoryRange gadget_range) {
			this.script_backend = script_backend;
			this.interceptor = interceptor;
			this.gadget_range = gadget_range;
		}

		public void enable () {
			replace_apis ();
		}

		public void disable () {
			revert_apis ();
		}

		public void ignore (Gum.ThreadId agent_thread_id, Gum.ThreadId parent_thread_id) {
			if (parent_thread_id != 0)
				script_backend.ignore (parent_thread_id);
			script_backend.ignore (agent_thread_id);
		}

		public void unignore (Gum.ThreadId agent_thread_id, Gum.ThreadId parent_thread_id) {
			script_backend.unignore (agent_thread_id);
			if (parent_thread_id != 0)
				script_backend.unignore (parent_thread_id);
		}

		private extern void replace_apis ();
		private extern void revert_apis ();
	}

	private Gum.MemoryRange memory_range () {
		Gum.MemoryRange? result = null;

		Gum.Process.enumerate_modules ((details) => {
			var name = details.name;
			if (name.index_of ("FridaGadget") != -1 || name.index_of ("frida-gadget") != -1) {
				result = details.range;
				return false;
			}
			return true;
		});
		assert (result != null);

		return result;
	}

	namespace Environment {
		private extern void init ();
		private extern void shutdown ();
		private extern void deinit (owned AutoIgnorer ignorer);
		private extern unowned MainContext get_main_context ();
	}

	// TODO: use Vala's preprocessor when the build system has been fixed
	private extern unowned Gum.ScriptBackend obtain_script_backend ();

	private extern void log_info (string message);
	private extern void log_error (string message);
}
