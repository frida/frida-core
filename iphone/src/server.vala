namespace Zid {
	public class Application : Object, Zed.HostSession {
		private DBusServer server;
		private Gee.ArrayList<DBusConnection> connections = new Gee.ArrayList<DBusConnection> ();

		public async Zed.HostProcessInfo[] enumerate_processes () throws IOError {
			return System.enumerate_processes ();
		}

		public async Zed.AgentSessionId attach_to (uint pid) throws IOError {
			System.kill (pid);
			throw new IOError.FAILED ("not yet implemented, so I killed your process instead");
		}

		public void run () throws Error {
			server = new DBusServer.sync ("tcp:host=127.0.0.1,port=27042", DBusServerFlags.AUTHENTICATION_ALLOW_ANONYMOUS, DBus.generate_guid ());
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

	namespace System {
		public static extern Zed.HostProcessInfo[] enumerate_processes ();
		public static extern void kill (uint pid);
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
