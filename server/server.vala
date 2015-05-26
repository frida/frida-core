namespace Frida {
	public class Server : Object {
		private BaseDBusHostSession host_session;
		private Gee.HashMap<AgentSessionId?, AgentSession> agent_sessions = new Gee.HashMap<AgentSessionId?, AgentSession> ();
		private DBusServer server;
		private Gee.HashMap<DBusConnection, Client> clients = new Gee.HashMap<DBusConnection, Client> ();

		private MainLoop loop;

		construct {
#if LINUX
			host_session = new LinuxHostSession ();
#endif
#if DARWIN
			host_session = new DarwinHostSession ();
#endif
#if WINDOWS
			host_session = new WindowsHostSession ();
#endif
#if QNX
			host_session = new QnxHostSession ();
#endif
			host_session.agent_session_opened.connect (on_agent_session_opened);
			host_session.agent_session_closed.connect (on_agent_session_closed);
		}

		public void run (string address) throws Error {
			try {
				server = new DBusServer.sync (address, DBusServerFlags.AUTHENTICATION_ALLOW_ANONYMOUS, DBus.generate_guid ());
			} catch (GLib.Error listen_error) {
				throw new Error.ADDRESS_IN_USE (listen_error.message);
			}
			server.new_connection.connect (on_connection_opened);
			server.start ();

			loop = new MainLoop ();
			loop.run ();
		}

		private void on_agent_session_opened (AgentSessionId id, AgentSession session) {
			agent_sessions.set (id, session);

			foreach (var entry in clients.entries)
				entry.value.register_agent_session (id, session);
		}

		private void on_agent_session_closed (AgentSessionId id, AgentSession session) {
			foreach (var entry in clients.entries)
				entry.value.unregister_agent_session (id, session);

			agent_sessions.unset (id);
		}

		private bool on_connection_opened (DBusConnection connection) {
			connection.closed.connect (on_connection_closed);

			var client = new Client (connection);
			client.register_host_session (host_session);
			foreach (var entry in agent_sessions.entries)
				client.register_agent_session (entry.key, entry.value);
			clients.set (connection, client);

			return true;
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			bool closed_by_us = (!remote_peer_vanished && error == null);
			if (closed_by_us)
				return;

			Client client;
			clients.unset (connection, out client);
			client.close ();
		}

		private class Client : Object {
			public DBusConnection connection {
				get;
				construct;
			}

			private Gee.HashSet<uint> registrations = new Gee.HashSet<uint> ();
			private Gee.HashMap<AgentSessionId?, uint> agent_registration_by_id = new Gee.HashMap<AgentSessionId?, uint> ();

			public Client (DBusConnection connection) {
				Object (connection: connection);
			}

			public void close () {
				foreach (var registration_id in registrations)
					connection.unregister_object (registration_id);
				registrations.clear ();
				agent_registration_by_id.clear ();
			}

			public void register_host_session (HostSession session) {
				try {
					registrations.add (connection.register_object (ObjectPath.HOST_SESSION, session));
				} catch (IOError e) {
					assert_not_reached ();
				}
			}

			public void register_agent_session (AgentSessionId id, AgentSession session) {
				try {
					var registration_id = connection.register_object (ObjectPath.from_agent_session_id (id), session);
					registrations.add (registration_id);
					agent_registration_by_id.set (id, registration_id);
				} catch (IOError e) {
					assert_not_reached ();
				}
			}

			public void unregister_agent_session (AgentSessionId id, AgentSession session) {
				uint registration_id;
				agent_registration_by_id.unset (id, out registration_id);
				registrations.remove (registration_id);
				connection.unregister_object (registration_id);
			}
		}

		private const string DEFAULT_LISTEN_ADDRESS = "tcp:host=127.0.0.1,port=27042";
		private static bool output_version;
		[CCode (array_length = false, array_null_terminated = true)]
		private static string[] listen_addresses;

		static const OptionEntry[] options = {
			{ "version", 0, 0, OptionArg.NONE, ref output_version, "Output version information and exit", null },
			{ "", 0, 0, OptionArg.STRING_ARRAY, ref listen_addresses, null, "[LISTEN_ADDRESS]" },
			{ null }
		};

		private static int main (string[] args) {
			try {
				var ctx = new OptionContext ();
				ctx.set_help_enabled (true);
				ctx.add_main_entries (options, null);
				ctx.parse (ref args);
				if (output_version) {
					stdout.printf ("%s\n", version_string ());
					return 0;
				}
			} catch (OptionError e) {
				stdout.printf ("%s\n", e.message);
				stdout.printf ("Run '%s --help' to see a full list of available command line options.\n", args[0]);
				return 1;
			}

			var listen_address = DEFAULT_LISTEN_ADDRESS;
			if (listen_addresses.length > 0)
				listen_address = listen_addresses[0];

			var server = new Server ();

			try {
				server.run (listen_address);
			} catch (Error e) {
				printerr ("Unable to start server: %s\n", e.message);
				return 1;
			}

			return 0;
		}
	}
}
