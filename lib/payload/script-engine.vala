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
		private uint next_script_id = 1;

		private ScriptRuntime preferred_runtime = DEFAULT;
		private bool debugger_enabled = false;

		private delegate void CompletionNotify ();

		public ScriptEngine (ProcessInvader invader) {
			Object (invader: invader);
		}

		public async void close () {
			uint pending = 1;

			CompletionNotify on_complete = () => {
				pending--;
				if (pending == 0)
					schedule_idle (close.callback);
			};

			foreach (var instance in instances.values.to_array ()) {
				pending++;
				close_instance.begin (instance, on_complete);
			}

			on_complete ();

			yield;

			if (debugger_enabled) {
				try {
					invader.get_script_backend (V8).set_debug_message_handler (null);
				} catch (Error e) {
					assert_not_reached ();
				}
				debugger_enabled = false;
			}
		}

		private async void close_instance (ScriptInstance instance, CompletionNotify on_complete) {
			yield instance.close ();

			on_complete ();
		}

		public async void flush () {
			uint pending = 1;

			CompletionNotify on_complete = () => {
				pending--;
				if (pending == 0)
					schedule_idle (flush.callback);
			};

			foreach (var instance in instances.values.to_array ()) {
				pending++;
				flush_instance.begin (instance, on_complete);
			}

			on_complete ();

			yield;
		}

		private async void flush_instance (ScriptInstance instance, CompletionNotify on_complete) {
			yield instance.flush ();

			on_complete ();
		}

		public async void prepare_for_termination (TerminationReason reason) {
			foreach (var instance in instances.values.to_array ())
				yield instance.prepare_for_termination (reason);
		}

		public void unprepare_for_termination () {
			foreach (var instance in instances.values.to_array ())
				instance.unprepare_for_termination ();
		}

		public async ScriptInstance create_script (string? source, Bytes? bytes, ScriptOptions options) throws Error {
			var script_id = AgentScriptId (next_script_id++);

			string? name = options.name;
			if (name == null)
				name = "script%u".printf (script_id.handle);

			Gum.ScriptBackend backend = pick_backend (options);

			Gum.Script script;
			try {
				if (source != null)
					script = yield backend.create (name, source);
				else
					script = yield backend.create_from_bytes (bytes);
			} catch (IOError e) {
				throw new Error.INVALID_ARGUMENT ("%s", e.message);
			}
			script.get_stalker ().exclude (invader.get_memory_range ());

			var instance = new ScriptInstance (script_id, script);
			instances[script_id] = instance;

			instance.closed.connect (on_instance_closed);
			instance.message.connect (on_instance_message);

			return instance;
		}

		private void detach_instance (ScriptInstance instance) {
			instance.closed.disconnect (on_instance_closed);
			instance.message.disconnect (on_instance_message);

			instances.unset (instance.script_id);
		}

		public async Bytes compile_script (string source, ScriptOptions options) throws Error {
			string? name = options.name;
			if (name == null)
				name = "agent";

			Gum.ScriptBackend backend = pick_backend (options);

			try {
				return yield backend.compile (name, source);
			} catch (IOError e) {
				throw new Error.INVALID_ARGUMENT ("%s", e.message);
			}
		}

		private Gum.ScriptBackend pick_backend (ScriptOptions options) throws Error {
			ScriptRuntime runtime = options.runtime;
			if (runtime == DEFAULT)
				runtime = preferred_runtime;

			return invader.get_script_backend (runtime);
		}

		public async void destroy_script (AgentScriptId script_id) throws Error {
			var instance = instances[script_id];
			if (instance == null)
				throw new Error.INVALID_ARGUMENT ("Invalid script ID");

			yield instance.close ();
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

			detach_instance (instance);

			return script;
		}

		public void post_to_script (AgentScriptId script_id, string message, Bytes? data = null) throws Error {
			var instance = instances[script_id];
			if (instance == null)
				throw new Error.INVALID_ARGUMENT ("Invalid script ID");

			instance.post (message, data);
		}

		private void on_instance_closed (ScriptInstance instance) {
			detach_instance (instance);
		}

		private void on_instance_message (ScriptInstance instance, string message, GLib.Bytes? data) {
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

		private static void schedule_idle (owned SourceFunc function) {
			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (MainContext.get_thread_default ());
		}

		public class ScriptInstance : Object, RpcPeer {
			public signal void closed ();
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
				LOADING,
				LOADED,
				ETERNALIZED,
				DISPOSED,
				UNLOADED,
				DESTROYED
			}

			private Promise<bool> load_request;
			private Promise<bool> close_request;
			private Promise<bool> dispose_request;
			private Promise<bool> flush_complete = new Promise<bool> ();

			private RpcClient rpc_client;

			public ScriptInstance (AgentScriptId script_id, Gum.Script script) {
				Object (script_id: script_id, script: script);
			}

			construct {
				rpc_client = new RpcClient (this);
			}

			public async void close () {
				if (close_request != null) {
					try {
						yield close_request.future.wait_async (null);
					} catch (GLib.Error e) {
						assert_not_reached ();
					}
					return;
				}
				close_request = new Promise<bool> ();

				var main_context = MainContext.get_thread_default ();

				yield ensure_dispose_called (TerminationReason.UNLOAD);

				if (state == DISPOSED) {
					var unload_operation = unload ();

					var js_source = new IdleSource ();
					js_source.set_callback (() => {
						var agent_source = new IdleSource ();
						agent_source.set_callback (close.callback);
						agent_source.attach (main_context);
						return false;
					});
					js_source.attach (Gum.ScriptBackend.get_scheduler ().get_js_context ());
					yield;

					flush_complete.resolve (true);

					try {
						yield unload_operation.future.wait_async (null);
					} catch (GLib.Error e) {
						assert_not_reached ();
					}

					state = UNLOADED;
				} else {
					flush_complete.resolve (true);
				}

				script.weak_ref (() => {
					var source = new IdleSource ();
					source.set_callback (close.callback);
					source.attach (main_context);
				});
				script = null;
				yield;

				state = DESTROYED;

				closed ();

				close_request.resolve (true);
			}

			public async void flush () {
				if (close_request == null)
					close.begin ();

				try {
					yield flush_complete.future.wait_async (null);
				} catch (GLib.Error e) {
					assert_not_reached ();
				}
			}

			public async void load () throws Error {
				if (state != CREATED)
					throw new Error.INVALID_OPERATION ("Script cannot be loaded in its current state");

				load_request = new Promise<bool> ();
				state = LOADING;

				yield script.load ();

				state = LOADED;
				load_request.resolve (true);
			}

			private Promise<bool> unload () {
				var request = new Promise<bool> ();

				perform_unload.begin (request);

				return request;
			}

			private async void perform_unload (Promise<bool> request) {
				yield script.unload ();

				request.resolve (true);
			}

			public Gum.Script eternalize () throws Error {
				if (state != LOADED && state != DISPOSED)
					throw new Error.INVALID_OPERATION ("Only loaded scripts may be eternalized");

				state = ETERNALIZED;

				var result = script;
				script = null;
				return result;
			}

			public async void prepare_for_termination (TerminationReason reason) {
				if (state == LOADED)
					script.get_stalker ().flush ();

				yield ensure_dispose_called (reason);
			}

			public void unprepare_for_termination () {
				if (state == DISPOSED) {
					state = LOADED;
					dispose_request = null;
				}
			}

			private async void ensure_dispose_called (TerminationReason reason) {
				if (dispose_request != null) {
					try {
						yield dispose_request.future.wait_async (null);
					} catch (GLib.Error e) {
						assert_not_reached ();
					}
					return;
				}
				dispose_request = new Promise<bool> ();

				if (state == LOADING) {
					try {
						yield load_request.future.wait_async (null);
					} catch (GLib.Error e) {
						assert_not_reached ();
					}
				}

				if (state == LOADED) {
					var reason_value = new Json.Node.alloc ().init_string (reason.to_nick ());

					try {
						yield rpc_client.call ("dispose", new Json.Node[] { reason_value }, null);
					} catch (GLib.Error e) {
					}

					state = DISPOSED;
				}

				dispose_request.resolve (true);
			}

			public void post (string message, Bytes? data) throws Error {
				switch (state) {
					case LOADING:
					case LOADED:
					case DISPOSED:
						script.post (message, data);
						break;
					default:
						throw new Error.INVALID_OPERATION ("Only active scripts may be posted to");
				}
			}

			private void on_message (Gum.Script script, string raw_message, Bytes? data) {
				bool handled = rpc_client.try_handle_message (raw_message);
				if (!handled)
					this.message (raw_message, data);
			}

			private async void post_rpc_message (string raw_message, Cancellable? cancellable) throws Error, IOError {
				if (script == null)
					throw new Error.INVALID_OPERATION ("Script is destroyed");

				script.post (raw_message);
			}
		}
	}
}
