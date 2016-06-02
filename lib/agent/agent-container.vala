namespace Frida {
	public class AgentContainer : Object, AgentSession {
		private Module module;
		[CCode (has_target = false)]
		private delegate void AgentMainFunc (string data_string, Gum.MemoryRange? mapped_range, Gum.ThreadId parent_thread_id);
		private AgentMainFunc main_impl;
		private PipeTransport transport;
		private Thread<bool> thread;
		private DBusConnection connection;
		private AgentSession session;

		public static async AgentContainer create (string agent_filename) throws Error {
			var container = new AgentContainer ();

			container.module = Module.open (agent_filename, 0);
			assert (container.module != null);

			void * main_func_symbol;
			var main_func_found = container.module.symbol ("frida_agent_main", out main_func_symbol);
			assert (main_func_found);
			container.main_impl = (AgentMainFunc) main_func_symbol;

			PipeTransport transport;
			try {
				transport = new PipeTransport ();
			} catch (IOError transport_error) {
				assert_not_reached ();
			}
			container.transport = transport;

			container.thread = new Thread<bool> ("frida-agent-container", container.run);

			DBusConnection connection;
			AgentSession session;
			try {
				connection = yield DBusConnection.new (new Pipe (transport.local_address), null, DBusConnectionFlags.NONE);
				session = yield connection.get_proxy (null, ObjectPath.AGENT_SESSION);
				session.message_from_script.connect (container.on_message_from_script);
				session.message_from_debugger.connect (container.on_message_from_debugger);
			} catch (GLib.Error dbus_error) {
				assert_not_reached ();
			}

			container.connection = connection;
			container.session = session;

			return container;
		}

		public async void destroy () {
			session.message_from_script.disconnect (on_message_from_script);
			session.message_from_debugger.disconnect (on_message_from_debugger);

			try {
				yield session.close ();
			} catch (GLib.Error session_error) {
			}
			session = null;

			try {
				yield connection.close ();
			} catch (GLib.Error connection_error) {
			}
			connection = null;

			Thread<bool> t = thread;
			t.join ();
			thread = null;

			module = null;
		}

		private bool run () {
			main_impl (transport.remote_address, null, 0);
			return true;
		}

		public async void close () throws GLib.Error {
		}

		public async void ping () throws GLib.Error {
		}

		public async AgentScriptId create_script (string name, string source) throws GLib.Error {
			return yield session.create_script (name, source);
		}

		public async AgentScriptId create_script_from_bytes (string name, uint8[] bytes) throws GLib.Error {
			return yield session.create_script_from_bytes (name, bytes);
		}

		public async uint8[] compile_script (string source) throws GLib.Error {
			return yield session.compile_script (source);
		}

		public async void destroy_script (AgentScriptId sid) throws GLib.Error {
			yield session.destroy_script (sid);
		}

		public async void load_script (AgentScriptId sid) throws GLib.Error {
			yield session.load_script (sid);
		}

		public async void post_message_to_script (AgentScriptId sid, string message) throws GLib.Error {
			yield session.post_message_to_script (sid, message);
		}

		public async void enable_debugger () throws GLib.Error {
			yield session.enable_debugger ();
		}

		public async void disable_debugger () throws GLib.Error {
			yield session.disable_debugger ();
		}

		public async void post_message_to_debugger (string message) throws GLib.Error {
			yield session.post_message_to_debugger (message);
		}

		public async void disable_jit () throws GLib.Error {
			yield session.disable_jit ();
		}

		private void on_message_from_script (AgentScriptId sid, string message, uint8[] data) {
			message_from_script (sid, message, data);
		}

		private void on_message_from_debugger (string message) {
			message_from_debugger (message);
		}
	}
}
