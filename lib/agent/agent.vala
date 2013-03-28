namespace Zed.Agent {
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

			script_engine.shutdown ();
			script_engine = null;

			Timeout.add (100, () => {
				teardown_connection_and_schedule_shutdown ();
				return false;
			});
		}

		private async void teardown_connection_and_schedule_shutdown () {
			yield teardown_connection ();

			Timeout.add (100, () => {
				main_loop.quit ();
				return false;
			});
		}

		public async AgentScriptId create_script (string source) throws IOError {
			var instance = script_engine.create_script (source);
			return instance.sid;
		}

		public async void destroy_script (AgentScriptId sid) throws IOError {
			script_engine.destroy_script (sid);
		}

		public async void load_script (AgentScriptId sid) throws IOError {
			script_engine.load_script (sid);
		}

		public async void post_message_to_script (AgentScriptId sid, string message) throws IOError {
			script_engine.post_message_to_script (sid, message);
		}

		public void run () throws Error {
			setup_connection ();
			main_loop = new MainLoop ();
			main_loop.run ();
		}

		private async void setup_connection () {
			try {
				connection = yield DBusConnection.new_for_stream (new Pipe (pipe_address), null, DBusConnectionFlags.NONE);
			} catch (Error error) {
				printerr ("failed to create connection: %s\n", error.message);
				return;
			}
			connection.closed.connect (on_connection_closed);
			try {
				Zed.AgentSession session = this;
				registration_id = connection.register_object (Zed.ObjectPath.AGENT_SESSION, session);
			} catch (IOError io_error) {
				printerr ("failed to register object: %s\n", io_error.message);
				close ();
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
				close ();
		}
	}

	public class AutoIgnorer : Object, Gum.InvocationListener {
		protected Gum.Interceptor interceptor;

		public AutoIgnorer (Gum.Interceptor interceptor) {
			this.interceptor = interceptor;
		}

		public void enable () {
			interceptor.attach_listener ((void *) Thread.create_full, this);
		}

		public void disable () {
			interceptor.detach_listener (this);
		}

		private void on_enter (Gum.InvocationContext context) {
			intercept_thread_creation (context);
		}

		private void on_leave (Gum.InvocationContext context) {
		}

		private extern void intercept_thread_creation (Gum.InvocationContext context);
	}

	public void main (string pipe_address) {
		Environment.init ();
		run_server_listening_on (pipe_address);
		Environment.deinit ();
	}

	private void run_server_listening_on (string pipe_address) {
		var interceptor = Gum.Interceptor.obtain ();
		interceptor.ignore_current_thread ();

		var ignorer = new AutoIgnorer (interceptor);
		ignorer.enable ();

		var server = new AgentServer (pipe_address);

		try {
			server.run ();
		} catch (Error e) {
			printerr ("error: %s\n", e.message);
		}

		ignorer.disable ();
		interceptor.unignore_current_thread ();
	}

	namespace Environment {
		public extern void init ();
		public extern void deinit ();
	}

}
