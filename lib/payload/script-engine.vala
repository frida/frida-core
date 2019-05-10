namespace Frida {
	public class ScriptEngine : Object {
		public signal void message_from_script (AgentScriptId script_id, string message, Bytes? data);
		public signal void message_from_debugger (string message);

		public weak ProcessInvader invader {
			get;
			construct;
		}

		private Gee.HashMap<AgentScriptId?, ScriptInstance> instances =
			new Gee.HashMap<AgentScriptId?, ScriptInstance> (AgentScriptId.hash, AgentScriptId.equal);
		private Gee.HashSet<ScriptInstance> dying_instances = new Gee.HashSet<ScriptInstance> ();
		private uint next_script_id = 1;

		private ScriptRuntime preferred_runtime = DEFAULT;
		private bool debugger_enabled = false;

		public ScriptEngine (ProcessInvader invader) {
			Object (invader: invader);
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
				try {
					invader.get_script_backend (V8).set_debug_message_handler (null);
				} catch (Error e) {
					assert_not_reached ();
				}
				debugger_enabled = false;
			}
		}

		public async ScriptInstance create_script (string? source, Bytes? bytes, ScriptOptions options) throws Error {
			var script_id = AgentScriptId (next_script_id++);

			string? name = options.name;
			if (name == null)
				name = "script%u".printf (script_id.handle);

			ScriptRuntime runtime = options.runtime;
			if (runtime == DEFAULT)
				runtime = preferred_runtime;

			Gum.ScriptBackend backend = invader.get_script_backend (runtime);

			Gum.Script script;
			try {
				if (source != null)
					script = yield backend.create (name, source);
				else
					script = yield backend.create_from_bytes (bytes);
			} catch (IOError e) {
				throw new Error.INVALID_ARGUMENT (e.message);
			}
			script.get_stalker ().exclude (invader.get_memory_range ());

			var instance = new ScriptInstance (script_id, script);
			instances[script_id] = instance;

			instance.message.connect (on_message);

			return instance;
		}

		public async Bytes compile_script (string? name, string source) throws Error {
			try {
				return yield invader.get_script_backend (DUK).compile ((name != null) ? name : "agent", source);
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
			invader.get_script_backend (V8).set_debug_message_handler (on_debug_message);
			debugger_enabled = true;
		}

		public void disable_debugger () throws Error {
			invader.get_script_backend (V8).set_debug_message_handler (null);
			debugger_enabled = false;
		}

		public void post_message_to_debugger (string message) {
			Gum.ScriptBackend backend;
			try {
				backend = invader.get_script_backend (V8);
			} catch (Error e) {
				return;
			}

			backend.post_debug_message (message);
		}

		public void enable_jit () throws Error {
			invader.get_script_backend (V8); // Will throw if not available.

			preferred_runtime = V8;
		}

		private void on_debug_message (string message) {
			message_from_debugger (message);
		}

		public class ScriptInstance : Object, RpcPeer {
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

			private RpcClient rpc_client;

			public ScriptInstance (AgentScriptId script_id, Gum.Script script) {
				Object (script_id: script_id, script: script);
			}

			construct {
				rpc_client = new RpcClient (this);
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
						yield rpc_client.call ("dispose", new Json.Node[] {});
					} catch (Error e) {
					}

					state = DISPOSED;
				}

				dispose_request.set_value (true);
			}

			private void on_message (Gum.Script script, string raw_message, Bytes? data) {
				bool handled = rpc_client.try_handle_message (raw_message);
				if (!handled)
					this.message (raw_message, data);
			}

			private async void post_rpc_message (string raw_message) throws Error {
				if (script == null)
					throw new Error.INVALID_OPERATION ("Script is destroyed");

				script.post (raw_message);
			}
		}
	}
}
