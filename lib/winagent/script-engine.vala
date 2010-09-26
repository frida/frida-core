using Gee;

namespace Zed {
	public class ScriptEngine : Object {
		private WinIpc.Proxy proxy;
		private uint attach_handler_id;
		private uint detach_handler_id;

		private Gum.Interceptor interceptor;

		private uint last_script_id = 0;
		private HashMap<uint, ScriptInstance> instance_by_id = new HashMap<uint, ScriptInstance> ();

		public ScriptEngine (WinIpc.Proxy proxy) {
			this.proxy = proxy;
			register_query_handlers ();

			interceptor = Gum.Interceptor.obtain ();
		}

		~ScriptEngine () {
			shutdown ();

			unregister_query_handlers ();
		}

		public void shutdown () {
			foreach (var instance in instance_by_id.values)
				interceptor.detach_listener (instance);
			instance_by_id.clear ();
		}

		/* FIXME: Gum.Script is piggy-backing on IOError for now */

		private ScriptInstance attach_script_to (string script_text, uint64 address) throws IOError {
			uint script_id = ++last_script_id;

			var script = Gum.Script.from_string (script_text);
			script.set_message_handler ((script, msg) => on_message_from_script (script_id, msg));
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

		private void detach_script (uint script_id) throws IOError {
			ScriptInstance instance;
			if (!instance_by_id.unset (script_id, out instance))
				throw new IOError.FAILED ("invalid script id");
			interceptor.detach_listener (instance);
		}

		private void register_query_handlers () {
			attach_handler_id = proxy.register_query_sync_handler ("AttachScriptTo", "(st)", (arg) => {
				string script_text;
				uint64 address;
				arg.@get ("(st)", out script_text, out address);

				uint id = 0;
				string error_message = "";
				uint64 code_address = 0;
				uint32 code_size = 0;
				try {
					var instance = attach_script_to (script_text, address);
					id = instance.id;
					code_address = (uint64) instance.script.get_code_address ();
					code_size = instance.script.get_code_size ();
				} catch (IOError e) {
					error_message = e.message;
				}

				return new Variant ("(ustu)", id, error_message, code_address, code_size);
			});

			detach_handler_id = proxy.register_query_sync_handler ("DetachScript", "u", (arg) => {
				uint script_id;
				arg.@get ("u", out script_id);

				bool succeeded = true;
				string error_message = "";
				try {
					detach_script (script_id);
				} catch (IOError e) {
					succeeded = false;
					error_message = e.message;
				}

				return new Variant ("(bs)", succeeded, error_message);
			});
		}

		private void unregister_query_handlers () {
			proxy.unregister_query_handler (detach_handler_id);
			proxy.unregister_query_handler (attach_handler_id);
		}

		private void on_message_from_script (uint script_id, Variant msg) {
			Idle.add (() => {
				send_message_from_script (script_id, msg);
				return false;
			});
		}

		private async void send_message_from_script (uint script_id, Variant msg) {
			try {
				var arg = new Variant ("(uv)", script_id, new Variant.variant (msg));
				yield proxy.emit ("MessageFromScript", arg);
			} catch (WinIpc.ProxyError e) {
			}
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
