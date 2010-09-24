using Gee;

namespace Zed.Agent {
	public class ScriptEngine : Object {
		public signal void message_from_script (uint script_id, Variant msg);

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
			foreach (var entry in instance_by_id)
				interceptor.detach_listener (entry.@value);
			instance_by_id.clear ();
		}

		/* FIXME: Gum.Script is piggy-backing on IOError for now */

		public ScriptInstance attach_script_to (string script_text, uint64 address) throws IOError {
			uint script_id = ++last_script_id;

			var script = Gum.Script.from_string (script_text);
			script.set_message_handler ((script, msg) => message_from_script (script_id, msg));
			var instance = new ScriptInstance (script);

			var ret = interceptor.attach_listener ((void *) address, instance, null);
			switch (ret) {
				case Gum.AttachReturn.OK:
					break;
				case Gum.AttachReturn.WRONG_SIGNATURE:
					throw new IOError.NOT_SUPPORTED ("Gum.Interceptor does not support the function specified");
				case Gum.AttachReturn.ALREADY_ATTACHED:
					throw new IOError.NOT_SUPPORTED ("Gum.Interceptor reports listener is already attached");
			}

			instance.id = script_id;
			instance_by_id[script_id] = instance;

			return instance;
		}

		public void detach_script (uint script_id) throws IOError {
			ScriptInstance instance;
			if (!instance_by_id.unset (script_id, out instance))
				throw new IOError.FAILED ("invalid script id");
			interceptor.detach_listener (instance);
		}

		public class ScriptInstance : Object, Gum.InvocationListener {
			public uint id {
				get;
				set;
			}

			public Gum.Script script {
				get;
				construct;
			}

			public ScriptInstance (Gum.Script script) {
				Object (script: script);
			}

			public void on_enter (Gum.InvocationContext ctx) {
				script.execute (ctx);
			}

			public void on_leave (Gum.InvocationContext ctx) {
			}
		}
	}
}
