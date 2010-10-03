namespace Zid {
	public class Application : Object, Zed.HostSession {
		private Fruitjector injector = new Fruitjector ();
		private DBusServer server;
		private Gee.ArrayList<DBusConnection> connections = new Gee.ArrayList<DBusConnection> ();
		private Gee.HashMap<DBusConnection, uint> registration_id_by_connection = new Gee.HashMap<DBusConnection, uint> ();

		private const uint LISTEN_PORT = 27042;
		private uint last_agent_port = LISTEN_PORT + 1;

		public async Zed.HostProcessInfo[] enumerate_processes () throws IOError {
			return System.enumerate_processes ();
		}

		public async Zed.AgentSessionId attach_to (uint pid) throws IOError {
			var agent_path = Path.build_filename (Config.PKGLIBDIR, "zid-agent.dylib");
			var port = last_agent_port++;
			var listen_address = "tcp:host=127.0.0.1,port=%u".printf (port);
			injector.inject (pid, agent_path, listen_address);

			return Zed.AgentSessionId (port);
		}

		public void run () throws Error {
			server = new DBusServer.sync ("tcp:host=127.0.0.1,port=%u".printf (LISTEN_PORT), DBusServerFlags.AUTHENTICATION_ALLOW_ANONYMOUS, DBus.generate_guid ());
			server.new_connection.connect ((connection) => {
				connection.closed.connect (on_connection_closed);

				try {
					Zed.HostSession session = this;
					var registration_id = connection.register_object (Zed.ObjectPath.HOST_SESSION, session);
					registration_id_by_connection[connection] = registration_id;
				} catch (IOError e) {
					printerr ("failed to register object: %s\n", e.message);
					return false;
				}

				connections.add (connection);
				return true;
			});

			server.start ();

			var loop = new MainLoop ();
			loop.run ();

			server.stop ();
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			bool closed_by_us = (!remote_peer_vanished && error == null);
			if (closed_by_us)
				return;
			unregister (connection);
			connections.remove (connection);
		}

		private async void unregister (DBusConnection connection) {
			uint registration_id;
			if (registration_id_by_connection.unset (connection, out registration_id))
				connection.unregister_object (registration_id);
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
