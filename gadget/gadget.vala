namespace Frida.Gadget {
	private class Server : Object {
		private const string LISTEN_ADDRESS = "tcp:host=127.0.0.1,port=27042";

		private Gum.MemoryRange agent_range;
		private DBusServer server;
		private Gee.HashMap<DBusConnection, Session> sessions = new Gee.HashMap<DBusConnection, Session> ();

		public Server (Gum.MemoryRange agent_range) {
			this.agent_range = agent_range;
		}

		public async void start () throws Error {
			server = new DBusServer.sync (LISTEN_ADDRESS, DBusServerFlags.AUTHENTICATION_ALLOW_ANONYMOUS, DBus.generate_guid ());
			server.new_connection.connect ((connection) => {
				if (server == null)
					return false;

				try {
					sessions[connection] = new Session (connection, agent_range);
				} catch (IOError e) {
					return false;
				}
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
			private HostProcessInfo this_process;
			private Frida.Agent.ScriptEngine script_engine;
			private bool close_requested = false;

			public Session (DBusConnection c, Gum.MemoryRange agent_range) throws IOError {
				connection = c;
				host_registration_id = connection.register_object (Frida.ObjectPath.HOST_SESSION, this as HostSession);
				agent_registration_id = connection.register_object (Frida.ObjectPath.AGENT_SESSION, this as AgentSession);

				this_process = get_process_info ();

				script_engine = new Frida.Agent.ScriptEngine (agent_range);
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

			public async HostProcessInfo[] enumerate_processes () throws IOError {
				return new HostProcessInfo[] { this_process };
			}

			public async uint spawn (string path, string[] argv, string[] envp) throws IOError {
				throw new IOError.NOT_SUPPORTED ("Gadget cannot spawn processes");
			}

			public async void resume (uint pid) throws IOError {
				validate_pid (pid);
			}

			public async void kill (uint pid) throws IOError {
				validate_pid (pid);
			}

			public async AgentSessionId attach_to (uint pid) throws IOError {
				validate_pid (pid);
				return AgentSessionId (27042);
			}

			private void validate_pid (uint pid) throws IOError {
				if (pid != this_process.pid)
					throw new IOError.NOT_SUPPORTED ("Gadget cannot act on other processes");
			}

			public async void close () throws IOError {
				if (close_requested)
					return;
				close_requested = true;

				var source = new TimeoutSource (50);
				source.set_callback (() => {
					connection.close.begin ();
					return false;
				});
				source.attach (Frida.get_main_context ());
			}

			public async AgentScriptId create_script (string source) throws IOError {
				var instance = script_engine.create_script (source);
				return instance.sid;
			}

			public async void destroy_script (AgentScriptId sid) throws IOError {
				yield script_engine.destroy_script (sid);
			}

			public async void load_script (AgentScriptId sid) throws IOError {
				script_engine.load_script (sid);
			}

			public async void post_message_to_script (AgentScriptId sid, string message) throws IOError {
				script_engine.post_message_to_script (sid, message);
			}
		}
	}

	private bool loaded = false;
	private Server server;
	private Gum.Interceptor interceptor;
	private Frida.Agent.AutoIgnorer ignorer;
	private Mutex mutex;
	private Cond cond;

	public void load () {
		if (loaded)
			return;
		loaded = true;

		Environment.set_variable ("G_DEBUG", "fatal-warnings:fatal-criticals", true);
		Frida.init ();

		var source = new IdleSource ();
		source.set_callback (() => {
			create_server.begin ();
			return false;
		});
		source.attach (Frida.get_main_context ());

		mutex.lock ();
		while (server == null)
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
				destroy_server.begin ();
				return false;
			});
			source.attach (Frida.get_main_context ());
		}

		mutex.lock ();
		while (server != null)
			cond.wait (mutex);
		mutex.unlock ();

		Frida.deinit ();
	}

	private async void create_server () {
		Gum.init_with_features (Gum.FeatureFlags.ALL & ~Gum.FeatureFlags.SYMBOL_LOOKUP);

		var agent_range = memory_range ();

		interceptor = Gum.Interceptor.obtain ();
		interceptor.ignore_current_thread ();

		ignorer = new Frida.Agent.AutoIgnorer (interceptor, agent_range, 0);
		ignorer.enable ();

		var s = new Server (agent_range);
		try {
			yield s.start ();
		} catch (Error e) {
			log_error ("Failed to start: " + e.message);
		}

		mutex.lock ();
		server = s;
		cond.signal ();
		mutex.unlock ();

		log_info ("Listening on TCP port 27042");
	}

	private async void destroy_server () {
		yield server.stop ();

		ignorer.disable ();
		ignorer = null;
		interceptor.unignore_current_thread ();
		interceptor = null;

		Gum.deinit ();

		mutex.lock ();
		server = null;
		cond.signal ();
		mutex.unlock ();
	}

	internal Gum.MemoryRange memory_range () {
		Gum.MemoryRange? result = null;

		Gum.Process.enumerate_modules ((details) => {
			if (details.name.index_of ("frida-gadget") != -1) {
				result = details.range;
				return false;
			}
			return true;
		});
		assert (result != null);

		return result;
	}

	private extern HostProcessInfo get_process_info ();
	private extern void log_info (string message);
	private extern void log_error (string message);
}
