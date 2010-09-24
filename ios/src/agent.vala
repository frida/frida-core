namespace Zed.Agent {
	public class FruityServer : Object, AgentSession {
		public string listen_address {
			get;
			construct;
		}

		private MainLoop main_loop = new MainLoop ();
		private DBusServer server;
		private Gee.ArrayList<DBusConnection> connections = new Gee.ArrayList<DBusConnection> ();
		private ScriptEngine script_engine = new ScriptEngine ();

		public FruityServer (string listen_address) {
			Object (listen_address: listen_address);
		}

		construct {
			script_engine.message_from_script.connect ((script_id, msg) => this.message_from_script (script_id, msg));
		}

		public async void close () throws IOError {
			if (script_engine != null) {
				script_engine.shutdown ();
				script_engine = null;
			}

			Timeout.add (500, () => {
				main_loop.quit ();
				return false;
			});
		}

		public async AgentModuleInfo[] query_modules () throws IOError {
			var modules = new AgentModuleInfo[0];
			Gum.Process.enumerate_modules ((name, address, path) => {
				modules += AgentModuleInfo (name, path, 42, (uint64) address);
				return true;
			});
			return modules;
		}

		public async AgentFunctionInfo[] query_module_functions (string module_name) throws IOError {
			var functions = new AgentFunctionInfo[0];
			Gum.Module.enumerate_exports (module_name, (name, address) => {
				functions += AgentFunctionInfo (name, (uint64) address);
				return true;
			});
			if (functions.length == 0)
				functions += AgentFunctionInfo ("<placeholdertotemporarilyworkaroundemptylistbug>", 1337);
			return functions;
		}

		public async uint8[] read_memory (uint64 address, uint size) throws IOError {
			return Gum.Memory.read ((void *) address, size);
		}

		public async void start_investigation (AgentTriggerInfo start_trigger, AgentTriggerInfo stop_trigger) throws IOError {
			throw new IOError.FAILED ("not implemented");
		}

		public async void stop_investigation () throws IOError {
			throw new IOError.FAILED ("not implemented");
		}

		public async AgentScriptInfo attach_script_to (string script_text, uint64 address) throws IOError {
			var instance = script_engine.attach_script_to (script_text, address);
			var script = instance.script;
			return AgentScriptInfo (instance.id, (uint64) script.get_code_address (), script.get_code_size ());
		}

		public async void detach_script (uint script_id) throws IOError {
			script_engine.detach_script (script_id);
		}

		public async void begin_instance_trace () throws IOError {
			throw new IOError.FAILED ("not implemented");
		}

		public async void end_instance_trace () throws IOError {
			throw new IOError.FAILED ("not implemented");
		}

		public async AgentInstanceInfo[] peek_instances () throws IOError {
			throw new IOError.FAILED ("not implemented");
		}

		public void run () throws Error {
			server = new DBusServer.sync (listen_address, DBusServerFlags.AUTHENTICATION_ALLOW_ANONYMOUS, DBus.generate_guid ());
			server.new_connection.connect ((connection) => {
				try {
					Zed.AgentSession session = this;
					connection.register_object (Zed.ObjectPath.AGENT_SESSION, session);
				} catch (IOError e) {
					printerr ("failed to register object: %s\n", e.message);
					return;
				}

				connections.add (connection);
			});

			server.start ();

			main_loop = new MainLoop ();
			main_loop.run ();
		}
	}

	public void main (string data_string) {
		var server = new FruityServer (data_string);

		try {
			server.run ();
		} catch (Error e) {
			printerr ("error: %s\n", e.message);
		}
	}
}
