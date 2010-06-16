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
			foreach (var entry in instance_by_id)
				interceptor.detach_listener (entry.@value);

			unregister_query_handlers ();
		}

		/* FIXME: Gum.Script is piggy-backing on IOError for now */

		private uint attach_script_to (string script_text, uint64 address) throws IOError {
			var script = Gum.Script.from_string (script_text);
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

			uint script_id = ++last_script_id;
			instance_by_id[script_id] = instance;
			return script_id;
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

				uint script_id = 0;
				string error_message = "";
				try {
					script_id = attach_script_to (script_text, address);
				} catch (IOError e) {
					error_message = e.message;
				}

				return new Variant ("(us)", script_id, error_message);
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

		public class ScriptInstance : Object, Gum.InvocationListener {
			private Gum.Script script;

			public ScriptInstance (Gum.Script script) {
				this.script = script;
			}

			public void on_enter (Gum.InvocationContext context, Gum.InvocationContext parent_context, void * cpu_context, void * function_arguments) {
				script.execute (cpu_context, function_arguments);
			}

			public void on_leave (Gum.InvocationContext context, Gum.InvocationContext parent_context, void * function_return_value) {
			}

			public void * provide_thread_data (void * function_instance_data, uint thread_id) {
				return null;
			}
		}
	}
}
