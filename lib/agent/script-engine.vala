using Gee;

namespace Zed.Agent {
	public class ScriptEngine : Object {
		public signal void message_from_script (AgentScriptId sid, string msg);

		private uint last_script_id = 0;
		private HashMap<uint, ScriptInstance> instance_by_id = new HashMap<uint, ScriptInstance> ();

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
			script.set_message_handler ((script, msg) => on_message_from_script (sid, msg));

			var instance = new ScriptInstance (sid, script);
			instance_by_id[sid.handle] = instance;

			return instance;
		}

		public async void destroy_script (AgentScriptId sid) throws IOError {
			ScriptInstance instance;
			if (!instance_by_id.unset (sid.handle, out instance))
				throw new IOError.FAILED ("invalid script id");
			instance.script.unload ();
		}

		public async void load_script (AgentScriptId sid) throws IOError {
			var instance = instance_by_id[sid.handle];
			if (instance == null)
				throw new IOError.FAILED ("invalid script id");
			instance.script.load ();
		}

		public void redirect_script_messages_to (AgentScriptId sid, string folder, uint keep_last_n) throws IOError {
			ScriptInstance instance = instance_by_id[sid.handle];
			if (instance == null)
				throw new IOError.FAILED ("invalid script id");
			instance.redirect_future_messages_to (folder, keep_last_n);
		}

		private void on_message_from_script (AgentScriptId sid, string msg) {
			Idle.add (() => {
				var instance = instance_by_id[sid.handle];
				if (!instance.handle_message (msg))
					this.message_from_script (sid, msg);
				return false;
			});
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

			public string? redirect_folder {
				get;
				private set;
			}

			public uint keep_last_n {
				get;
				private set;
			}

			private uint last_sequence_number = 1;

			public ScriptInstance (AgentScriptId sid, Gum.Script script) {
				Object (sid: sid, script: script);
			}

			public void redirect_future_messages_to (string folder, uint keep_last_n) {
				this.redirect_folder = folder;
				this.keep_last_n = keep_last_n;
			}

			public bool handle_message (string msg) {
				if (redirect_folder == null)
					return false;

				delete_expired ();

				var seqno = last_sequence_number++;
				var outpath = path_for_seqno (seqno);

				try {
					FileUtils.set_contents (outpath, msg);
				} catch (FileError e) {
				}

				return true;
			}

			private void delete_expired () {
				if (keep_last_n == 0 || last_sequence_number <= keep_last_n)
					return;
				var expired_seqno = last_sequence_number - keep_last_n;
				FileUtils.unlink (path_for_seqno (expired_seqno));
			}

			private string path_for_seqno (uint seqno) {
				return Path.build_filename (redirect_folder, "script_%u_%07u.dat".printf (sid.handle, seqno));
			}
		}
	}
}
