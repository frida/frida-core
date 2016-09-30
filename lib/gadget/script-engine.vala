using Gee;

namespace Frida.Gadget {
	public class ScriptEngine : Object {
		public signal void message_from_script (AgentScriptId sid, string message, Bytes? data);
		public signal void message_from_debugger (string message);

		private Gum.ScriptBackend backend;
		private Gum.MemoryRange agent_range;
		private uint last_script_id = 0;
		private HashMap<uint, ScriptInstance> instance_by_id = new HashMap<uint, ScriptInstance> ();
		private bool debugger_enabled = false;

		public ScriptEngine (Gum.ScriptBackend backend, Gum.MemoryRange agent_range) {
			this.backend = backend;
			this.agent_range = agent_range;
		}

		public async void shutdown () {
			foreach (var instance in instance_by_id.values) {
				yield instance.destroy ();
			}
			instance_by_id.clear ();

			if (debugger_enabled) {
				backend.set_debug_message_handler (null);
				debugger_enabled = false;
			}
		}

		public async ScriptInstance create_script (string? name, string? source, Bytes? bytes) throws Error {
			var sid = AgentScriptId (++last_script_id);

			string script_name;
			if (name != null)
				script_name = name;
			else
				script_name = "script%u".printf (sid.handle);

			Gum.Script script;
			try {
				if (source != null)
					script = yield backend.create (script_name, source);
				else
					script = yield backend.create_from_bytes (script_name, bytes);
			} catch (IOError e) {
				throw new Error.INVALID_ARGUMENT (e.message);
			}
			script.get_stalker ().exclude (agent_range);
			script.set_message_handler ((script, message, data) => this.message_from_script (sid, message, data));

			var instance = new ScriptInstance (sid, script);
			instance_by_id[sid.handle] = instance;

			return instance;
		}

		public async Bytes compile_script (string source) throws Error {
			try {
				return yield backend.compile (source);
			} catch (IOError e) {
				throw new Error.INVALID_ARGUMENT (e.message);
			}
		}

		public async void destroy_script (AgentScriptId sid) throws Error {
			ScriptInstance instance;
			if (!instance_by_id.unset (sid.handle, out instance))
				throw new Error.INVALID_ARGUMENT ("Invalid script ID");
			yield instance.destroy ();
		}

		public async void load_script (AgentScriptId sid) throws Error {
			var instance = instance_by_id[sid.handle];
			if (instance == null)
				throw new Error.INVALID_ARGUMENT ("Invalid script ID");
			yield instance.script.load ();
		}

		public void post_to_script (AgentScriptId sid, string message, Bytes? data = null) throws Error {
			var instance = instance_by_id[sid.handle];
			if (instance == null)
				throw new Error.INVALID_ARGUMENT ("Invalid script ID");
			instance.script.post (message, data);
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
			public AgentScriptId sid {
				get;
				construct;
			}

			public Gum.Script script {
				get;
				construct;
			}

			public ScriptInstance (AgentScriptId sid, Gum.Script script) {
				Object (sid: sid, script: script);
			}

			public async void destroy () {
				Gum.Stalker stalker = script.get_stalker ();
				yield script.unload ();
				while (stalker.garbage_collect ()) {
					var source = new TimeoutSource (50);
					source.set_callback (() => {
						destroy.callback ();
						return false;
					});
					source.attach (MainContext.get_thread_default ());
					yield;
				}
			}
		}
	}
}
