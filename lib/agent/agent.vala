namespace Frida.Agent {
	public void main (string pipe_address, ref bool stay_resident, Gum.MemoryRange? mapped_range) {
		Environment.init ();

		AutoIgnorer ignorer;
		{
			var agent_range = memory_range (mapped_range);
			var agent_thread_id = Gum.Process.get_current_thread_id ();

			var interceptor = Gum.Interceptor.obtain ();

			ignorer = new AutoIgnorer (interceptor, agent_range);
			ignorer.enable ();
			ignorer.ignore (agent_thread_id);

			var exceptor = Gum.Exceptor.obtain ();

			var server = new AgentServer (pipe_address, agent_range);

			try {
				server.run ();
			} catch (Error e) {
				printerr ("Unable to start agent server: %s\n", e.message);
			}

			interceptor.begin_transaction ();

			exceptor = null;

			ignorer.unignore (agent_thread_id);
			ignorer.disable ();

			interceptor.end_transaction ();
		}

		Environment.deinit ((owned) ignorer);
	}

	private class AgentServer : Object, AgentSessionProvider {
		public string pipe_address {
			get;
			construct;
		}

		private MainLoop main_loop = new MainLoop ();
		private DBusConnection connection;
		private bool unloading = false;
		private uint registration_id = 0;
		private uint pending_calls = 0;
		private Gee.Promise<bool> pending_close = null;
		private Gee.HashSet<AgentClient> clients = new Gee.HashSet<AgentClient> ();

		private Gum.ScriptBackend script_backend = null;
		private bool jit_enabled = false;
		protected Gum.MemoryRange agent_range;

		public AgentServer (string pipe_address, Gum.MemoryRange agent_range) {
			Object (pipe_address: pipe_address);

			this.agent_range = agent_range;
		}

		public async void open (AgentSessionId id) throws Error {
			if (unloading)
				throw new Error.INVALID_OPERATION ("Agent is unloading");

			var client = new AgentClient (this, id);
			clients.add (client);
			client.closed.connect (on_client_closed);

			try {
				AgentSession session = client;
				client.registration_id = connection.register_object (ObjectPath.from_agent_session_id (id), session);
			} catch (IOError io_error) {
				assert_not_reached ();
			}

			opened (id);
		}

		private void on_client_closed (AgentClient client) {
			closed (client.id);

			connection.unregister_object (client.registration_id);

			client.closed.disconnect (on_client_closed);
			clients.remove (client);
		}

		public async void unload () throws Error {
			if (unloading)
				throw new Error.INVALID_OPERATION ("Agent is already unloading");
			unloading = true;
			perform_unload.begin ();
		}

		private async void perform_unload () {
			Gee.Promise<bool> operation = null;

			lock (pending_calls) {
				if (pending_calls > 0) {
					pending_close = new Gee.Promise<bool> ();
					operation = pending_close;
				}
			}

			if (operation != null) {
				try {
					yield operation.future.wait_async ();
				} catch (Gee.FutureError e) {
					assert_not_reached ();
				}
			}

			foreach (var client in clients.to_array ()) {
				try {
					yield client.close ();
				} catch (GLib.Error e) {
					assert_not_reached ();
				}
			}
			assert (clients.is_empty);

			yield teardown_connection ();

			Idle.add (() => {
				main_loop.quit ();
				return false;
			});
		}

		public ScriptEngine create_script_engine () {
			if (script_backend == null)
				script_backend = Environment.obtain_script_backend (jit_enabled);

			return new ScriptEngine (script_backend, agent_range);
		}

		public void enable_jit () throws Error {
			if (script_backend != null)
				throw new Error.INVALID_OPERATION ("JIT may only be enabled before the first script is created");
			jit_enabled = true;
		}

		public void run () throws Error {
			setup_connection.begin ();
			main_loop = new MainLoop ();
			main_loop.run ();
		}

		private async void setup_connection () {
			try {
				connection = yield new DBusConnection (new Pipe (pipe_address), null, DBusConnectionFlags.DELAY_MESSAGE_PROCESSING);
			} catch (GLib.Error connection_error) {
				printerr ("Unable to create connection: %s\n", connection_error.message);
				return;
			}
			connection.closed.connect (on_connection_closed);
			connection.add_filter (on_connection_message);
			try {
				AgentSessionProvider provider = this;
				registration_id = connection.register_object (ObjectPath.AGENT_SESSION_PROVIDER, provider);
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
				unload.begin ();

			Gee.Promise<bool> operation = null;
			lock (pending_calls) {
				pending_calls = 0;
				operation = pending_close;
				pending_close = null;
			}
			if (operation != null)
				operation.set_value (true);
		}

		private GLib.DBusMessage on_connection_message (DBusConnection connection, owned DBusMessage message, bool incoming) {
			switch (message.get_message_type ()) {
				case DBusMessageType.METHOD_CALL:
					if (incoming) {
						lock (pending_calls) {
							pending_calls++;
						}
					}
					break;
				case DBusMessageType.METHOD_RETURN:
				case DBusMessageType.ERROR:
					if (!incoming) {
						lock (pending_calls) {
							pending_calls--;
							var operation = pending_close;
							if (pending_calls == 0 && operation != null) {
								pending_close = null;
								Idle.add (() => {
									operation.set_value (true);
									return false;
								});
							}
						}
					}
					break;
				default:
					break;
			}

			return message;
		}
	}

	private class AgentClient : Object, AgentSession {
		public signal void closed (AgentClient client);

		public weak AgentServer server {
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

		public AgentClient (AgentServer server, AgentSessionId id) {
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

		public void ignore (Gum.ThreadId agent_thread_id) {
			Gum.ScriptBackend.ignore (agent_thread_id);
		}

		public void unignore (Gum.ThreadId agent_thread_id) {
			Gum.ScriptBackend.unignore (agent_thread_id);
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
