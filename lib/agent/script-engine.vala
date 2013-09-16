using Gee;

namespace Frida.Agent {
	public class ScriptEngine : Object {
		public signal void message_from_script (AgentScriptId sid, string message, uint8[] data);

		private Gum.MemoryRange? agent_range;
		private uint last_script_id = 0;
		private HashMap<uint, ScriptInstance> instance_by_id = new HashMap<uint, ScriptInstance> ();

		construct {
			Gum.Process.enumerate_modules ((name, range, path) => {
				if (name.index_of ("frida-agent.") != -1) {
					agent_range = range;
					return false;
				}
				return true;
			});
		}

		~ScriptEngine () {
			shutdown ();
		}

		public void shutdown () {
			foreach (var instance in instance_by_id.values)
				instance.script.unload ();
			instance_by_id.clear ();
		}

		public ScriptInstance create_script (string source) throws IOError {
			var script = Gum.Script.from_string (source);
			var sid = AgentScriptId (++last_script_id);
			if (agent_range != null)
				script.get_stalker ().exclude (agent_range);
			script.set_message_handler ((script, message, data) => {
				Idle.add (() => {
					this.message_from_script (sid, message, data);
					return false;
				});
			});

			var instance = new ScriptInstance (sid, script);
			instance_by_id[sid.handle] = instance;

			return instance;
		}

		public void destroy_script (AgentScriptId sid) throws IOError {
			ScriptInstance instance;
			if (!instance_by_id.unset (sid.handle, out instance))
				throw new IOError.FAILED ("invalid script id");
			instance.script.unload ();
		}

		public void load_script (AgentScriptId sid) throws IOError {
			var instance = instance_by_id[sid.handle];
			if (instance == null)
				throw new IOError.FAILED ("invalid script id");
			instance.script.load ();
		}

		public void post_message_to_script (AgentScriptId sid, string message) throws IOError {
			var instance = instance_by_id[sid.handle];
			if (instance == null)
				throw new IOError.FAILED ("invalid script id");
			instance.script.post_message (message);
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
		}
	}
}
