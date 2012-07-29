namespace Zed {
	private const string DEFAULT_LISTEN_ADDRESS = "tcp:host=127.0.0.1,port=27042";

	public class Application : Object {
		private BaseDBusHostSession host_session;
		private DBusServer server;
		private Gee.ArrayList<DBusConnection> connections = new Gee.ArrayList<DBusConnection> ();
		private Gee.HashMap<DBusConnection, uint> registration_id_by_connection = new Gee.HashMap<DBusConnection, uint> ();

		private MainLoop loop;
		private uint shutdown_timeout = 0;

		construct {
#if WINDOWS
			host_session = new WindowsHostSession ();
#endif
#if DARWIN
			host_session = new DarwinHostSession ();
#endif
		}

		public void run (string address) throws Error {
			server = new DBusServer.sync (address, DBusServerFlags.AUTHENTICATION_ALLOW_ANONYMOUS, DBus.generate_guid ());
			server.new_connection.connect ((connection) => {
				if (server == null)
					return false;

				connection.closed.connect (on_connection_closed);

				try {
					var registration_id = connection.register_object (Zed.ObjectPath.HOST_SESSION, host_session as HostSession);
					registration_id_by_connection[connection] = registration_id;
				} catch (IOError e) {
					printerr ("failed to register object: %s\n", e.message);
					return false;
				}

				connections.add (connection);

				if (connections.size == 1)
					cancel_shutdown ();

				return true;
			});

			server.start ();

			schedule_shutdown ();

			loop = new MainLoop ();
			loop.run ();
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			bool closed_by_us = (!remote_peer_vanished && error == null);
			if (closed_by_us)
				return;
			unregister (connection);
			connections.remove (connection);

			if (connections.is_empty)
				schedule_shutdown ();
		}

		private async void unregister (DBusConnection connection) {
			uint registration_id;
			if (registration_id_by_connection.unset (connection, out registration_id))
				connection.unregister_object (registration_id);
		}

		private void schedule_shutdown () {
			cancel_shutdown ();
			shutdown_timeout = Timeout.add (3000, () => {
				server.stop ();
				server = null;
				perform_shutdown ();
				return false;
			});
		}

		private void cancel_shutdown () {
			if (shutdown_timeout != 0) {
				Source.remove (shutdown_timeout);
				shutdown_timeout = 0;
			}
		}

		private async void perform_shutdown () {
			yield host_session.close ();
			host_session = null;

			loop.quit ();
		}
	}

	public static int main (string[] args) {
		var app = new Application ();

		string address;
		if (args.length == 1) {
			address = DEFAULT_LISTEN_ADDRESS;
		} else if (args.length == 2) {
			address = args[1];
		} else {
			printerr ("usage: %s [<address>]\n", args[0]);
			return 1;
		}

		try {
			app.run (address);
		} catch (Error e) {
			printerr ("ERROR: %s\n", e.message);
			return 1;
		}

		return 0;
	}
}
