namespace Zid {
	public class Application : Object, Zed.HostSession {
		private Fruitjector injector = new Fruitjector ();
		private DBusServer server;
		private Gee.ArrayList<DBusConnection> connections = new Gee.ArrayList<DBusConnection> ();

		private const uint LISTEN_PORT = 27042;
		private uint last_agent_port = LISTEN_PORT + 1;

		public async Zed.HostProcessInfo[] enumerate_processes () throws IOError {
			return System.enumerate_processes ();
		}

		public async Zed.AgentSessionId attach_to (uint pid) throws IOError {
			var agent_path = Path.build_filename (Config.PKGLIBDIR, "zid-agent.dylib");
			var port = last_agent_port++;
			var listen_address = "tcp:host=127.0.0.1,port=%u".printf (port);
			stdout.printf ("injecting into pid %u, agent_path '%s', listen_address '%s'\n", pid, agent_path, listen_address);
			injector.inject (pid, agent_path, listen_address);

			return Zed.AgentSessionId (port);
		}

		public void run () throws Error {
			server = new DBusServer.sync ("tcp:host=127.0.0.1,port=%u".printf (LISTEN_PORT), DBusServerFlags.AUTHENTICATION_ALLOW_ANONYMOUS, DBus.generate_guid ());
			server.new_connection.connect ((connection) => {
				try {
					Zed.HostSession session = this;
					connection.register_object (Zed.ObjectPath.HOST_SESSION, session);
				} catch (IOError e) {
					printerr ("failed to register object: %s\n", e.message);
					return;
				}

				connections.add (connection);
			});

			server.start ();

			var loop = new MainLoop ();
			loop.run ();

			server.stop ();
		}
	}

	public static int main (string[] args) {
		var app = new Application ();

		try {
			app.run ();
		} catch (Error e) {
			printerr ("error: %s\n", e.message);
			return 1;
		}

		return 0;
	}
}
