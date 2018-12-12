namespace Frida.Gadget {
	public class ScriptEngine : Object {
		public signal void message_from_script (AgentScriptId script_id, string message, Bytes? data);
		public signal void message_from_debugger (string message);

		private Gum.ScriptBackend backend;
		private Gum.MemoryRange agent_range;

		private Gee.HashMap<AgentScriptId?, ScriptInstance> instances =
			new Gee.HashMap<AgentScriptId?, ScriptInstance> (AgentScriptId.hash, AgentScriptId.equal);
		private Gee.HashSet<ScriptInstance> dying_instances = new Gee.HashSet<ScriptInstance> ();
		private uint next_script_id = 1;

		private bool debugger_enabled = false;

		public ScriptEngine (Gum.ScriptBackend backend, Gum.MemoryRange agent_range) {
			this.backend = backend;
			this.agent_range = agent_range;
		}

		public async void prepare_for_termination () {
			foreach (var instance in instances.values.to_array ())
				yield instance.prepare_for_termination ();
		}

		public async void shutdown () {
			do {
				while (!instances.is_empty) {
					var iterator = instances.keys.iterator ();
					iterator.next ();
					var id = iterator.get ();
					try {
						yield destroy_script (id);
					} catch (Error e) {
						assert_not_reached ();
					}
				}

				while (!dying_instances.is_empty) {
					var iterator = dying_instances.iterator ();
					iterator.next ();
					var instance = iterator.get ();
					yield instance.destroy ();
				}
			} while (!instances.is_empty || !dying_instances.is_empty);

			if (debugger_enabled) {
				backend.set_debug_message_handler (null);
				debugger_enabled = false;
			}
		}

		public async ScriptInstance create_script (string? name, string? source, Bytes? bytes) throws Error {
			var script_id = AgentScriptId (next_script_id++);

			Gum.Script script;
			try {
				if (source != null) {
					string script_name;
					if (name != null)
						script_name = name;
					else
						script_name = "script%u".printf (script_id.handle);
					script = yield backend.create (script_name, source);
				} else {
					script = yield backend.create_from_bytes (bytes);
				}
			} catch (IOError e) {
				throw new Error.INVALID_ARGUMENT (e.message);
			}
			script.get_stalker ().exclude (agent_range);

			var instance = new ScriptInstance (script_id, script);
			instances[script_id] = instance;

			instance.message.connect (on_message);

			return instance;
		}

		public async Bytes compile_script (string? name, string source) throws Error {
			try {
				return yield backend.compile ((name != null) ? name : "agent", source);
			} catch (IOError e) {
				throw new Error.INVALID_ARGUMENT (e.message);
			}
		}

		public async void destroy_script (AgentScriptId script_id) throws Error {
			ScriptInstance instance;
			if (!instances.unset (script_id, out instance))
				throw new Error.INVALID_ARGUMENT ("Invalid script ID");
			dying_instances.add (instance);
			yield instance.destroy ();
			dying_instances.remove (instance);
		}

		public async void load_script (AgentScriptId script_id) throws Error {
			var instance = instances[script_id];
			if (instance == null)
				throw new Error.INVALID_ARGUMENT ("Invalid script ID");
			yield instance.load ();
		}

		public Gum.Script eternalize_script (AgentScriptId script_id) throws Error {
			var instance = instances[script_id];
			if (instance == null)
				throw new Error.INVALID_ARGUMENT ("Invalid script ID");
			var script = instance.eternalize ();
			instances.unset (script_id);
			return script;
		}

		public void post_to_script (AgentScriptId script_id, string message, Bytes? data = null) throws Error {
			var instance = instances[script_id];
			if (instance == null)
				throw new Error.INVALID_ARGUMENT ("Invalid script ID");
			instance.script.post (message, data);
		}

		private void on_message (ScriptInstance instance, string message, GLib.Bytes? data) {
			message_from_script (instance.script_id, message, data);
		}

		public void enable_debugger () throws Error {
			backend.set_debug_message_handler (on_debug_message);
			debugger_enabled = true;
		}

		public void disable_debugger () throws Error {
			backend.set_debug_message_handler (null);
			debugger_enabled = false;
		}

		public void post_message_to_debugger (string message) {
			backend.post_debug_message (message);
		}

		private void on_debug_message (string message) {
			message_from_debugger (message);
		}

		public class ScriptInstance : Object {
			public signal void message (string message, Bytes? data);

			public AgentScriptId script_id {
				get;
				construct;
			}

			public Gum.Script script {
				get {
					return _script;
				}
				set {
					if (_script != null)
						_script.set_message_handler (null);
					_script = value;
					if (_script != null)
						_script.set_message_handler (on_message);
				}
			}
			private Gum.Script _script;

			private State state = CREATED;

			private enum State {
				CREATED,
				LOADED,
				ETERNALIZED,
				DISPOSED,
				UNLOADED,
				DESTROYED
			}

			private Gee.Promise<bool> load_request;
			private Gee.Promise<bool> destroy_request;
			private Gee.Promise<bool> dispose_request;

			private Gee.HashMap<string, PendingResponse> pending_responses = new Gee.HashMap<string, PendingResponse> ();
			private int64 next_request_id = -1;

			public ScriptInstance (AgentScriptId script_id, Gum.Script script) {
				Object (script_id: script_id, script: script);
			}

			public async void load () {
				if (load_request != null) {
					try {
						yield load_request.future.wait_async ();
					} catch (Gee.FutureError e) {
						assert_not_reached ();
					}
					return;
				}
				load_request = new Gee.Promise<bool> ();

				yield script.load ();

				state = LOADED;

				load_request.set_value (true);
			}

			public async void destroy () {
				if (destroy_request != null) {
					try {
						yield destroy_request.future.wait_async ();
					} catch (Gee.FutureError e) {
						assert_not_reached ();
					}
					return;
				}
				destroy_request = new Gee.Promise<bool> ();

				var main_context = MainContext.get_thread_default ();

				yield ensure_dispose_called ();

				if (state == DISPOSED) {
					yield script.unload ();

					state = UNLOADED;
				}

				script.weak_ref (() => {
					var source = new IdleSource ();
					source.set_callback (() => {
						destroy.callback ();
						return false;
					});
					source.attach (main_context);
				});
				script = null;
				yield;

				state = DESTROYED;

				destroy_request.set_value (true);
			}

			public Gum.Script eternalize () throws Error {
				if (state != LOADED)
					throw new Error.INVALID_OPERATION ("Only loaded scripts may be eternalized");

				state = ETERNALIZED;

				var result = script;
				script = null;
				return result;
			}

			public async void prepare_for_termination () {
				if (state == LOADED)
					script.get_stalker ().flush ();

				yield ensure_dispose_called ();
			}

			private async void ensure_dispose_called () {
				if (dispose_request != null) {
					try {
						yield dispose_request.future.wait_async ();
					} catch (Gee.FutureError e) {
						assert_not_reached ();
					}
					return;
				}
				dispose_request = new Gee.Promise<bool> ();

				if (load_request != null)
					yield load ();

				if (state == LOADED) {
					try {
						yield call ("dispose", new Json.Node[] {});
					} catch (Error e) {
					}

					state = DISPOSED;
				}

				dispose_request.set_value (true);
			}

			private async Json.Node call (string method, Json.Node[] args) throws Error {
				if (script == null)
					throw new Error.INVALID_OPERATION ("Script is destroyed");

				var request_id = next_request_id;
				if (next_request_id != int32.MIN)
					next_request_id--;
				else
					next_request_id = -1;

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
				pending_responses[request_id.to_string ()] = response;

				script.post (request);

				yield;

				if (response.error != null)
					throw response.error;

				return response.result;
			}

			private void on_message (Gum.Script script, string raw_message, Bytes? data) {
				bool handled = false;

				if (raw_message.index_of ("\"frida:rpc\",-") != -1) {
					var parser = new Json.Parser ();
					try {
						parser.load_from_data (raw_message);
					} catch (GLib.Error e) {
						assert_not_reached ();
					}
					var message = parser.get_root ().get_object ();

					var type = message.get_string_member ("type");
					if (type == "send")
						handled = try_handle_rpc_message (message);
				}

				if (!handled)
					this.message (raw_message, data);
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
				if (!pending_responses.unset (request_id.to_string (), out response))
					return false;

				var status = rpc_message.get_string_element (2);
				if (status == "ok")
					response.complete_with_result (rpc_message.get_element (3));
				else
					response.complete_with_error (new Error.NOT_SUPPORTED (rpc_message.get_string_element (3)));

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
	}
}
