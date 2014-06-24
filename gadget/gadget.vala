namespace Frida.Gadget {
	private class Server : Object, HostSession, AgentSession {
		private const string LISTEN_ADDRESS = "tcp:host=127.0.0.1,port=27042";

		private HostProcessInfo this_process;
		private DBusServer server;
		private Gee.ArrayList<DBusConnection> connections = new Gee.ArrayList<DBusConnection> ();
		private Gee.HashMap<DBusConnection, uint> registration_id_by_connection = new Gee.HashMap<DBusConnection, uint> ();
		private Frida.Agent.ScriptEngine script_engine;

		construct {
			this_process = get_process_info ();
		}

		public async void start () throws Error {
			server = new DBusServer.sync (LISTEN_ADDRESS, DBusServerFlags.AUTHENTICATION_ALLOW_ANONYMOUS, DBus.generate_guid ());
			server.new_connection.connect ((connection) => {
				if (server == null)
					return false;

				connection.closed.connect (on_connection_closed);

				try {
					var registration_id = connection.register_object (Frida.ObjectPath.HOST_SESSION, this as HostSession);
					registration_id_by_connection[connection] = registration_id;
				} catch (IOError e) {
					return false;
				}

				connections.add (connection);

				return true;
			});

			script_engine = new Frida.Agent.ScriptEngine ();
			script_engine.message_from_script.connect ((script_id, message, data) => this.message_from_script (script_id, message, data));

			server.start ();
		}

		public async void stop () {
			if (server == null)
				return;

			server.stop ();
			server = null;

			yield script_engine.shutdown ();
			script_engine = null;
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			bool closed_by_us = (!remote_peer_vanished && error == null);
			if (closed_by_us)
				return;
			unregister (connection);
			connections.remove (connection);
		}

		private async void unregister (DBusConnection connection) {
			uint registration_id;
			if (registration_id_by_connection.unset (connection, out registration_id))
				connection.unregister_object (registration_id);
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

		public async void close () throws IOError {
			// Nothing to do. Host application decides the lifetime.
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

		private void validate_pid (uint pid) throws IOError {
			if (pid != this_process.pid)
				throw new IOError.NOT_SUPPORTED ("Gadget cannot act on other processes");
		}
	}

	private Server server;
	private Gum.Interceptor interceptor;
	private Frida.Agent.AutoIgnorer ignorer;
	private Mutex mutex;
	private Cond cond;

	public void load () {
		if (mutex != null)
			return;

		Environment.set_variable ("G_DEBUG", "fatal-warnings:fatal-criticals", true);
		Frida.init ();
		Gum.init_with_features (Gum.FeatureFlags.ALL & ~Gum.FeatureFlags.SYMBOL_LOOKUP);

		mutex = new Mutex ();
		cond = new Cond ();

		var source = new IdleSource ();
		source.set_callback (() => {
			create_server ();
			return false;
		});
		source.attach (Frida.get_main_context ());

		mutex.lock ();
		while (server == null)
			cond.wait (mutex);
		mutex.unlock ();
	}

	public void unload () {
		if (mutex == null)
			return;

		var source = new IdleSource ();
		source.set_callback (() => {
			destroy_server ();
			return false;
		});
		source.attach (Frida.get_main_context ());

		mutex.lock ();
		while (server != null)
			cond.wait (mutex);
		mutex.unlock ();

		cond = null;
		mutex = null;

		Frida.shutdown ();
		Gum.deinit ();
		Frida.deinit ();
	}

	private async void create_server () {
		interceptor = Gum.Interceptor.obtain ();
		interceptor.ignore_current_thread ();

		ignorer = new Frida.Agent.AutoIgnorer (interceptor);
		ignorer.enable ();

		var s = new Server ();
		try {
			yield s.start ();
		} catch (Error e) {
			log_error ("Failed to start: " + e.message);
		}

		mutex.lock ();
		server = s;
		cond.signal ();
		mutex.unlock ();
	}

	private async void destroy_server () {
		yield server.stop ();

		ignorer.disable ();
		ignorer = null;
		interceptor.unignore_current_thread ();
		interceptor = null;

		mutex.lock ();
		server = null;
		cond.signal ();
		mutex.unlock ();
	}

	private extern HostProcessInfo get_process_info ();
	private extern void log_error (string message);
}
