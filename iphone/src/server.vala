namespace Zid {
	public class Application : Object, Controller {
		private DBusServer server;
		private Gee.ArrayList<DBusConnection> connections = new Gee.ArrayList<DBusConnection> ();

		public void say (string message) throws IOError {
			stdout.printf ("say: %s\n", message);
		}

		public void run () throws Error {
			server = new DBusServer.sync ("tcp:host=0.0.0.0,port=1337", DBusServerFlags.AUTHENTICATION_ALLOW_ANONYMOUS, DBus.generate_guid ());
			server.new_connection.connect ((connection) => {
				try {
					Controller controller = this;
					connection.register_object (Zid.ObjectPath.CONTROLLER, controller);
				} catch (IOError e) {
					stderr.printf ("failed to register object: %s\n", e.message);
					return;
				}

				connections.add (connection);
				stdout.printf ("yay, new connection handled!\n");
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
			stderr.printf ("error: %s\n", e.message);
			return 1;
		}

		return 0;
	}
}
