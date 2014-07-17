namespace Frida.Agent {
	public class AgentServer : Object, AgentSession {
		public string pipe_address {
			get;
			construct;
		}

		private MainLoop main_loop = new MainLoop ();
		private DBusConnection connection;
		private bool closing = false;
		private uint registration_id = 0;
		private ScriptEngine script_engine = new ScriptEngine ();

		public AgentServer (string pipe_address) {
			Object (pipe_address: pipe_address);
		}

		construct {
			script_engine.message_from_script.connect ((script_id, message, data) => this.message_from_script (script_id, message, data));
		}

		public async void close () throws IOError {
			if (closing)
				throw new IOError.FAILED ("close already in progress");
			closing = true;
			perform_close.begin ();
		}

		private async void perform_close () {
			yield script_engine.shutdown ();
			script_engine = null;

			Timeout.add (30, () => {
				teardown_connection_and_schedule_shutdown.begin ();
				return false;
			});
		}

		private async void teardown_connection_and_schedule_shutdown () {
			yield teardown_connection ();

			Timeout.add (20, () => {
				main_loop.quit ();
				return false;
			});
		}

		public async AgentScriptId create_script (string source) throws IOError {
			validate_state ();
			var instance = script_engine.create_script (source);
			return instance.sid;
		}

		public async void destroy_script (AgentScriptId sid) throws IOError {
			validate_state ();
			yield script_engine.destroy_script (sid);
		}

		public async void load_script (AgentScriptId sid) throws IOError {
			validate_state ();
			script_engine.load_script (sid);
		}

		public async void post_message_to_script (AgentScriptId sid, string message) throws IOError {
			validate_state ();
			script_engine.post_message_to_script (sid, message);
		}

		private void validate_state () throws IOError {
			if (closing)
				throw new IOError.FAILED ("close in progress");
		}

		public void run () throws Error {
			setup_connection.begin ();
			main_loop = new MainLoop ();
			main_loop.run ();
		}

		private async void setup_connection () {
			try {
				connection = yield DBusConnection.new (new Pipe (pipe_address), null, DBusConnectionFlags.DELAY_MESSAGE_PROCESSING);
			} catch (Error error) {
				printerr ("failed to create connection: %s\n", error.message);
				return;
			}
			connection.closed.connect (on_connection_closed);
			try {
				Frida.AgentSession session = this;
				registration_id = connection.register_object (Frida.ObjectPath.AGENT_SESSION, session);
				connection.start_message_processing ();
			} catch (IOError io_error) {
				printerr ("failed to register object: %s\n", io_error.message);
				close.begin ();
			}
		}

		private async void teardown_connection () {
			if (connection != null) {
				if (registration_id != 0) {
					connection.unregister_object (registration_id);
				}
				try {
					yield connection.close ();
				} catch (Error e) {
				}
				connection.closed.disconnect (on_connection_closed);
				connection = null;
			}
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			bool closed_by_us = (!remote_peer_vanished && error == null);
			if (!closed_by_us)
				close.begin ();
		}
	}

	public class AutoIgnorer : Object, Gum.InvocationListener {
		protected Gum.Interceptor interceptor;
		protected Gum.MemoryRange? agent_range;

		construct {
			Gum.Process.enumerate_modules ((details) => {
				if (details.name.index_of ("frida-agent") != -1 || details.name.index_of ("frida-gadget") != -1) {
					agent_range = details.range;
					return false;
				}
				return true;
			});
		}

		public AutoIgnorer (Gum.Interceptor interceptor) {
			this.interceptor = interceptor;
		}

		public void enable () {
			Gum.Script.ignore_current_thread ();

			interceptor.attach_listener (get_address_of_thread_create_func (), this);
		}

		public void disable () {
			interceptor.detach_listener (this);

			Gum.Script.unignore_current_thread ();
		}

		private void on_enter (Gum.InvocationContext context) {
			intercept_thread_creation (context);
		}

		private void on_leave (Gum.InvocationContext context) {
		}

		private static extern void * get_address_of_thread_create_func ();
		private extern void intercept_thread_creation (Gum.InvocationContext context);
	}

	public void main (string pipe_address) {
		Environment.init ();
		run_server_listening_on (pipe_address);
		Environment.deinit ();
	}

	private void run_server_listening_on (string pipe_address) {
		var interceptor = Gum.Interceptor.obtain ();

		var ignorer = new AutoIgnorer (interceptor);
		ignorer.enable ();

		var server = new AgentServer (pipe_address);

		try {
			server.run ();
		} catch (Error e) {
			printerr ("error: %s\n", e.message);
		}

		ignorer.disable ();
	}

	namespace Environment {
		public extern void init ();
		public extern void deinit ();
	}

}
