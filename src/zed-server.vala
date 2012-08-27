namespace Zed {
	public class Application : Object {
		private BaseDBusHostSession host_session;
		private DBusServer server;
		private Gee.ArrayList<DBusConnection> connections = new Gee.ArrayList<DBusConnection> ();
		private Gee.HashMap<DBusConnection, uint> registration_id_by_connection = new Gee.HashMap<DBusConnection, uint> ();

		private MainLoop loop;
		private int timeout;
		private uint shutdown_source = 0;

		construct {
#if WINDOWS
			host_session = new WindowsHostSession ();
#endif
#if DARWIN
			host_session = new DarwinHostSession ();
#endif
		}

		public void run (string address, int timeout) throws Error {
			this.timeout = timeout;

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
			if (timeout > 0) {
				shutdown_source = Timeout.add (timeout, () => {
					server.stop ();
					server = null;
					perform_shutdown ();
					return false;
				});
			}
		}

		private void cancel_shutdown () {
			if (shutdown_source != 0) {
				Source.remove (shutdown_source);
				shutdown_source = 0;
			}
		}

		private async void perform_shutdown () {
			yield host_session.close ();
			host_session = null;

			loop.quit ();
		}

		private const string DEFAULT_LISTEN_ADDRESS = "tcp:host=127.0.0.1,port=27042";
		[CCode (array_length = false, array_null_terminated = true)]
		private static string[] listen_addresses;
		private static int idle_timeout = 3000;

		static const OptionEntry[] options = {
			{ "timeout", 't', 0, OptionArg.INT, ref idle_timeout, "Set idle timeout to TIMEOUT milliseconds", "TIMEOUT" },
			{ "", 0, 0, OptionArg.STRING_ARRAY, ref listen_addresses, null, "[LISTEN_ADDRESS]" },
			{ null }
		};

		private static int main (string[] args) {
			try {
				var ctx = new OptionContext ("- zed-server");
				ctx.set_help_enabled (true);
				ctx.add_main_entries (options, null);
				ctx.parse (ref args);
			} catch (OptionError e) {
				stdout.printf ("%s\n", e.message);
				stdout.printf ("Run '%s --help' to see a full list of available command line options.\n", args[0]);
				return 1;
			}

			var listen_address = DEFAULT_LISTEN_ADDRESS;
			if (listen_addresses.length > 0)
				listen_address = listen_addresses[0];

			var app = new Application ();

			try {
				app.run (listen_address, idle_timeout);
			} catch (Error e) {
				printerr ("ERROR: %s\n", e.message);
				return 1;
			}

			return 0;
		}
	}
}
