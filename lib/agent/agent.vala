namespace Frida.Agent {
	public void main (string pipe_address, Gum.MemoryRange? mapped_range, Gum.ThreadId parent_thread_id) {
		Environment.init ();

		AutoIgnorer ignorer;
		{
			var agent_range = memory_range (mapped_range);
			var agent_thread_id = Gum.Process.get_current_thread_id ();

			var interceptor = Gum.Interceptor.obtain ();
			ignorer = new AutoIgnorer (interceptor, agent_range);
			ignorer.enable ();
			ignorer.ignore (agent_thread_id, parent_thread_id);

			var server = new AgentServer (pipe_address, agent_range);

			try {
				server.run ();
			} catch (Error e) {
				printerr ("Unable to start agent server: %s\n", e.message);
			}

			ignorer.unignore (agent_thread_id, parent_thread_id);
			ignorer.disable ();
		}

		Environment.deinit ((owned) ignorer);
	}

	private class AgentServer : Object, AgentSession {
		public string pipe_address {
			get;
			construct;
		}

		private MainLoop main_loop = new MainLoop ();
		private DBusConnection connection;
		private bool closing = false;
		private uint registration_id = 0;
		private int pending_calls = 0;
		private Gee.Promise<bool> pending_close = null;

		private ScriptEngine script_engine = null;
		private bool jit_enabled = true;
		protected Gum.MemoryRange agent_range;

		public AgentServer (string pipe_address, Gum.MemoryRange agent_range) {
			Object (pipe_address: pipe_address);

			this.agent_range = agent_range;
		}

		public async void close () throws Error {
			if (closing)
				throw new Error.INVALID_OPERATION ("Agent is already closing");
			closing = true;
			perform_close.begin ();
		}

		private async void perform_close () {
			if (AtomicInt.get (ref pending_calls) > 0) {
				pending_close = new Gee.Promise<bool> ();
				try {
					yield pending_close.future.wait_async ();
				} catch (Gee.FutureError e) {
					assert_not_reached ();
				}
				pending_close = null;
			}

			if (script_engine != null) {
				yield script_engine.shutdown ();
				script_engine = null;
			}

			yield teardown_connection ();

			Idle.add (() => {
				main_loop.quit ();
				return false;
			});
		}

		public async void ping () throws Error {
		}

		public async AgentScriptId create_script (string name, string source) throws Error {
			var engine = get_script_engine ();
			var instance = yield engine.create_script ((name != "") ? name : null, source, null);
			return instance.sid;
		}

		public async AgentScriptId create_script_from_bytes (string name, uint8[] bytes) throws Error {
			var engine = get_script_engine ();
			var instance = yield engine.create_script ((name != "") ? name : null, null, new Bytes (bytes));
			return instance.sid;
		}

		public async uint8[] compile_script (string source) throws Error {
			var engine = get_script_engine ();
			var bytes = yield engine.compile_script (source);
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

		public async void post_message_to_script (AgentScriptId sid, string message) throws Error {
			var engine = get_script_engine ();
			engine.post_message_to_script (sid, message);
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

		public async void disable_jit () throws GLib.Error {
			if (script_engine != null)
				throw new Error.INVALID_OPERATION ("JIT may only be disabled before the first script is created");
			jit_enabled = false;
		}

		private ScriptEngine get_script_engine () throws Error {
			check_open ();

			if (script_engine == null) {
				script_engine = new ScriptEngine (Environment.obtain_script_backend (jit_enabled), agent_range);
				script_engine.message_from_script.connect ((script_id, message, data) => this.message_from_script (script_id, message, data));
				script_engine.message_from_debugger.connect ((message) => this.message_from_debugger (message));
			}

			return script_engine;
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
			connection.add_filter (on_connection_message);
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
				connection.closed.disconnect (on_connection_closed);

				try {
					yield connection.flush ();
				} catch (GLib.Error e) {
				}

				if (registration_id != 0) {
					connection.unregister_object (registration_id);
				}

				try {
					yield connection.close ();
				} catch (GLib.Error e) {
				}

				connection = null;
			}
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			bool closed_by_us = (!remote_peer_vanished && error == null);
			if (!closed_by_us)
				close.begin ();
		}

		private GLib.DBusMessage on_connection_message (DBusConnection connection, owned DBusMessage message, bool incoming) {
			switch (message.get_message_type ()) {
				case DBusMessageType.METHOD_CALL:
					if (incoming)
						AtomicInt.inc (ref pending_calls);
					break;
				case DBusMessageType.METHOD_RETURN:
				case DBusMessageType.ERROR:
					if (!incoming && AtomicInt.dec_and_test (ref pending_calls) && pending_close != null) {
						Idle.add (() => {
							if (pending_close != null)
								pending_close.set_value (true);
							return false;
						});
					}
					break;
				default:
					break;
			}

			return message;
		}
	}

	protected class AutoIgnorer : Object {
		protected Gum.Interceptor interceptor;
		protected Gum.MemoryRange agent_range;
		protected SList tls_contexts;
		protected Mutex mutex;

		public AutoIgnorer (Gum.Interceptor interceptor, Gum.MemoryRange agent_range) {
			this.interceptor = interceptor;
			this.agent_range = agent_range;
		}

		public void enable () {
			replace_apis ();
		}

		public void disable () {
			revert_apis ();
		}

		public void ignore (Gum.ThreadId agent_thread_id, Gum.ThreadId parent_thread_id) {
			if (parent_thread_id != 0)
				Gum.ScriptBackend.ignore (parent_thread_id);
			Gum.ScriptBackend.ignore (agent_thread_id);
		}

		public void unignore (Gum.ThreadId agent_thread_id, Gum.ThreadId parent_thread_id) {
			Gum.ScriptBackend.unignore (agent_thread_id);
			if (parent_thread_id != 0)
				Gum.ScriptBackend.unignore (parent_thread_id);
		}

		private extern void replace_apis ();
		private extern void revert_apis ();
	}

	private Gum.MemoryRange memory_range (Gum.MemoryRange? mapped_range) {
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
		private extern void init ();
		private extern void deinit (owned AutoIgnorer ignorer);
		private extern unowned Gum.ScriptBackend obtain_script_backend (bool jit_enabled);
	}
}
