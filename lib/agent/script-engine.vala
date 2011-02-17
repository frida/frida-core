using Gee;

namespace Zed.Agent {
	public class ScriptEngine : Object {
		public signal void message_from_script (AgentScriptId sid, Variant msg);

		private Gum.Interceptor interceptor;

		private uint last_script_id = 0;
		private HashMap<uint, ScriptInstance> instance_by_id = new HashMap<uint, ScriptInstance> ();

		construct {
			interceptor = Gum.Interceptor.obtain ();
		}

		~ScriptEngine () {
			shutdown ();
		}

		public void shutdown () {
			foreach (var instance in instance_by_id.values)
				interceptor.detach_listener (instance);
			instance_by_id.clear ();
		}

		public ScriptInstance compile_script (string script_text) throws IOError {
			var script = Gum.Script.from_string (script_text);
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
			interceptor.detach_listener (instance);
		}

		public void attach_script_to (AgentScriptId sid, uint64 address) throws IOError {
			var instance = instance_by_id[sid.handle];
			if (instance == null)
				throw new IOError.FAILED ("invalid script id");

			var ret = interceptor.attach_listener ((void *) address, instance, null);
			switch (ret) {
				case Gum.AttachReturn.OK:
					break;
				case Gum.AttachReturn.WRONG_SIGNATURE:
					throw new IOError.NOT_SUPPORTED ("Gum.Interceptor does not support the function specified");
				case Gum.AttachReturn.ALREADY_ATTACHED:
					throw new IOError.NOT_SUPPORTED ("Gum.Interceptor reports listener is already attached");
			}
		}

		public void redirect_script_messages_to (AgentScriptId sid, string folder, uint keep_last_n) throws IOError {
			ScriptInstance instance = instance_by_id[sid.handle];
			if (instance == null)
				throw new IOError.FAILED ("invalid script id");
			instance.redirect_future_messages_to (folder, keep_last_n);
		}

		private void on_message_from_script (AgentScriptId sid, Variant msg) {
			Idle.add (() => {
				var instance = instance_by_id[sid.handle];
				if (!instance.handle_message (msg))
					this.message_from_script (sid, msg);
				return false;
			});
		}

		public class ScriptInstance : Object, Gum.InvocationListener {
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

			public void on_enter (Gum.InvocationContext ctx) {
				script.execute (ctx);
			}

			public void on_leave (Gum.InvocationContext ctx) {
				script.execute (ctx);
			}

			public void redirect_future_messages_to (string folder, uint keep_last_n) {
				this.redirect_folder = folder;
				this.keep_last_n = keep_last_n;
			}

			public bool handle_message (Variant msg) {
				if (redirect_folder == null)
					return false;

				delete_expired ();

				var seqno = last_sequence_number++;
				var outpath = path_for_seqno (seqno);

				try {
					FileUtils.set_contents (outpath, (string) msg.get_data (), (ssize_t) msg.get_size ());
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
