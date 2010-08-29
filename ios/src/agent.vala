namespace Zed.Agent {
	public class FruityServer : Object, AgentSession {
		public string listen_address {
			get;
			construct;
		}

		private MainLoop main_loop = new MainLoop ();
		private DBusServer server;
		private Gee.ArrayList<DBusConnection> connections = new Gee.ArrayList<DBusConnection> ();

		public FruityServer (string listen_address) {
			Object (listen_address: listen_address);
		}

		public async void close () throws IOError {
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
			stdout.printf ("enumeration of %s yielded %d results\n", module_name, functions.length);
			return functions;
		}

		public async uint8[] read_memory (uint64 address, uint size) throws IOError {
			throw new IOError.FAILED ("not implemented");
		}

		public async void start_investigation (AgentTriggerInfo start_trigger, AgentTriggerInfo stop_trigger) throws IOError {
			throw new IOError.FAILED ("not implemented");
		}

		public async void stop_investigation () throws IOError {
			throw new IOError.FAILED ("not implemented");
		}

		public async AgentScriptInfo attach_script_to (string script_text, uint64 address) throws IOError {
			throw new IOError.FAILED ("not implemented");
		}

		public async void detach_script (uint script_id) throws IOError {
			throw new IOError.FAILED ("not implemented");
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
