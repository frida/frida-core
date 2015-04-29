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
		private ScriptEngine script_engine;

		public AgentServer (string pipe_address, Gum.MemoryRange agent_range) {
			Object (pipe_address: pipe_address);
			script_engine = new ScriptEngine (agent_range);
			script_engine.message_from_script.connect ((script_id, message, data) => this.message_from_script (script_id, message, data));
			script_engine.message_from_debugger.connect ((message) => this.message_from_debugger (message));
		}

		public async void close () throws Error {
			if (closing)
				throw new Error.INVALID_OPERATION ("Agent is already closing");
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

		public async AgentScriptId create_script (string name, string source) throws Error {
			check_open ();
			var instance = yield script_engine.create_script ((name != "") ? name : null, source);
			return instance.sid;
		}

		public async void destroy_script (AgentScriptId sid) throws Error {
			check_open ();
			yield script_engine.destroy_script (sid);
		}

		public async void load_script (AgentScriptId sid) throws Error {
			check_open ();
			yield script_engine.load_script (sid);
		}

		public async void post_message_to_script (AgentScriptId sid, string message) throws Error {
			check_open ();
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

		private void check_open () throws Error {
			if (closing)
				throw new Error.INVALID_OPERATION ("Agent is closing");
		}

		public void run () throws Error {
			setup_connection.begin ();
			main_loop = new MainLoop ();
			main_loop.run ();
		}

		private async void setup_connection () {
			try {
				connection = yield DBusConnection.new (new Pipe (pipe_address), null, DBusConnectionFlags.DELAY_MESSAGE_PROCESSING);
			} catch (GLib.Error connection_error) {
				printerr ("Unable to create connection: %s\n", connection_error.message);
				return;
			}
			connection.closed.connect (on_connection_closed);
			try {
				Frida.AgentSession session = this;
				registration_id = connection.register_object (Frida.ObjectPath.AGENT_SESSION, session);
				connection.start_message_processing ();
			} catch (IOError io_error) {
				assert_not_reached ();
			}
		}

		private async void teardown_connection () {
			if (connection != null) {
				if (registration_id != 0) {
					connection.unregister_object (registration_id);
				}
				try {
					yield connection.close ();
				} catch (GLib.Error e) {
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
		protected Gum.MemoryRange agent_range;
		private Gum.ThreadId parent_thread_id;

		public AutoIgnorer (Gum.Interceptor interceptor, Gum.MemoryRange agent_range, Gum.ThreadId parent_thread_id) {
			this.interceptor = interceptor;
			this.agent_range = agent_range;
			this.parent_thread_id = parent_thread_id;
		}

		public void enable () {
			if (parent_thread_id != 0)
				Gum.Script.ignore (parent_thread_id);
			Gum.Script.ignore (Gum.Process.get_current_thread_id ());

			interceptor.attach_listener (get_address_of_thread_create_func (), this);
		}

		public void disable () {
			interceptor.detach_listener (this);

			Gum.Script.unignore (Gum.Process.get_current_thread_id ());
			if (parent_thread_id != 0)
				Gum.Script.unignore (parent_thread_id);
		}

		private void on_enter (Gum.InvocationContext context) {
			intercept_thread_creation (context);
		}

		private void on_leave (Gum.InvocationContext context) {
		}

		private static extern void * get_address_of_thread_create_func ();
		private extern void intercept_thread_creation (Gum.InvocationContext context);
	}

	public void main (string pipe_address, Gum.MemoryRange? mapped_range, Gum.ThreadId parent_thread_id) {
		Environment.init ();

		{
			var agent_range = memory_range (mapped_range);

			var interceptor = Gum.Interceptor.obtain ();

			var ignorer = new AutoIgnorer (interceptor, agent_range, parent_thread_id);
			ignorer.enable ();

			var server = new AgentServer (pipe_address, agent_range);

			try {
				server.run ();
			} catch (Error e) {
				printerr ("Unable to start agent server: %s\n", e.message);
			}

			ignorer.disable ();
		}

		Environment.deinit ();
	}

	internal Gum.MemoryRange memory_range (Gum.MemoryRange? mapped_range) {
		Gum.MemoryRange? result = mapped_range;

		if (result == null) {
			Gum.Process.enumerate_modules ((details) => {
				if (details.name.index_of ("frida-agent") != -1) {
					result = details.range;
					return false;
				}
				return true;
			});
			assert (result != null);
		}

		return result;
	}

	namespace Environment {
		public extern void init ();
		public extern void deinit ();
	}

}
