namespace Frida.Server {
	private static Application application;

	private const string DEFAULT_LISTEN_ADDRESS = "127.0.0.1";
	private const uint16 DEFAULT_LISTEN_PORT = 27042;
	private static bool output_version;
	private static string listen_address;

	const OptionEntry[] options = {
		{ "version", 0, 0, OptionArg.NONE, ref output_version, "Output version information and exit", null },
		{ "listen", 'l', 0, OptionArg.STRING, ref listen_address, "Listen on ADDRESS", "ADDRESS" },
		{ null }
	};

	private static int main (string[] args) {
#if !WINDOWS
		Posix.setsid ();
#endif

		Environment.init ();

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
			printerr ("%s\n", e.message);
			printerr ("Run '%s --help' to see a full list of available command line options.\n", args[0]);
			return 1;
		}

		string listen_uri;
		try {
			var raw_address = (listen_address != null) ? listen_address : DEFAULT_LISTEN_ADDRESS;
			var socket_address = NetworkAddress.parse (raw_address, DEFAULT_LISTEN_PORT).enumerate ().next ();
			if (socket_address is InetSocketAddress) {
				var inet_socket_address = socket_address as InetSocketAddress;
				var inet_address = inet_socket_address.get_address ();
				var family = (inet_address.get_family () == SocketFamily.IPV6) ? "ipv6" : "ipv4";
				listen_uri = "tcp:family=%s,host=%s,port=%hu".printf (family, inet_address.to_string (), inet_socket_address.get_port ());
			} else {
				printerr ("Invalid listen address\n");
				return 1;
			}
		} catch (GLib.Error e) {
			printerr ("%s\n", e.message);
			return 1;
		}

		application = new Application ();

#if !WINDOWS
		Posix.signal (Posix.SIGINT, (sig) => {
			application.stop ();
		});
		Posix.signal (Posix.SIGTERM, (sig) => {
			application.stop ();
		});
#endif

		try {
			application.run (listen_uri);
		} catch (Error e) {
			printerr ("Unable to start server: %s\n", e.message);
			return 1;
		}

		return 0;
	}

	namespace Environment {
		public extern void init ();
	}

	public class Application : Object {
		private BaseDBusHostSession host_session;
		private Gee.HashMap<uint, AgentSession> agent_sessions = new Gee.HashMap<uint, AgentSession> ();
		private DBusServer server;
		private Gee.HashMap<DBusConnection, Client> clients = new Gee.HashMap<DBusConnection, Client> ();
		private Gee.HashMap<uint32, DBusMessage> method_calls = new Gee.HashMap<uint32, DBusMessage> ();

		private MainLoop loop;
		private bool stopping;

		construct {
			TemporaryDirectory.always_use ("re.frida.server");

#if WINDOWS
			host_session = new WindowsHostSession ();
#endif
#if DARWIN
			host_session = new DarwinHostSession (new DarwinHelperBackend (), new TemporaryDirectory ());
#endif
#if LINUX
			host_session = new LinuxHostSession ();
#endif
#if QNX
			host_session = new QnxHostSession ();
#endif
			host_session.agent_session_opened.connect (on_agent_session_opened);
			host_session.agent_session_closed.connect (on_agent_session_closed);
		}

		public void run (string listen_uri) throws Error {
			try {
				server = new DBusServer.sync (listen_uri, DBusServerFlags.AUTHENTICATION_ALLOW_ANONYMOUS, DBus.generate_guid ());
			} catch (GLib.Error listen_error) {
				throw new Error.ADDRESS_IN_USE (listen_error.message);
			}
			server.new_connection.connect (on_connection_opened);
			server.start ();

			loop = new MainLoop ();
			loop.run ();
		}

		public void stop () {
			Idle.add (() => {
				perform_stop.begin ();
				return false;
			});
		}

		public async void perform_stop () {
			if (stopping)
				return;
			stopping = true;

			server.new_connection.disconnect (on_connection_opened);

			while (clients.size != 0) {
				foreach (var entry in clients.entries) {
					var connection = entry.key;
					var client = entry.value;
					clients.unset (connection);
					try {
						yield connection.flush ();
					} catch (GLib.Error e) {
					}
					client.close ();
					try {
						yield connection.close ();
					} catch (GLib.Error e) {
					}
					break;
				}
			}

			server.stop ();

			while (agent_sessions.size != 0) {
				foreach (var entry in agent_sessions.entries) {
					var id = entry.key;
					var session = entry.value;
					agent_sessions.unset (id);
					try {
						yield session.close ();
					} catch (GLib.Error e) {
					}
					break;
				}
			}

			yield host_session.close ();

			agent_sessions.clear ();

			Idle.add (() => {
				loop.quit ();
				return false;
			});
		}

		private void on_agent_session_opened (AgentSessionId id, AgentSession session) {
			agent_sessions.set (id.handle, session);

			foreach (var entry in clients.entries)
				entry.value.register_agent_session (id, session);
		}

		private void on_agent_session_closed (AgentSessionId id, AgentSession session) {
			foreach (var entry in clients.entries)
				entry.value.unregister_agent_session (id, session);

			var raw_id = id.handle;
			agent_sessions.unset (raw_id);
		}

		private bool on_connection_opened (DBusConnection connection) {
			connection.closed.connect (on_connection_closed);
			connection.add_filter (on_connection_message);

			var client = new Client (connection);
			client.register_host_session (host_session);
			foreach (var entry in agent_sessions.entries)
				client.register_agent_session (AgentSessionId (entry.key), entry.value);
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

			foreach (var raw_session_id in client.sessions)
				close_session.begin (AgentSessionId (raw_session_id));
		}

		private async void close_session (AgentSessionId id) {
			try {
				var session = yield host_session.obtain_agent_session (id);
				yield session.close ();
			} catch (GLib.Error e) {
			}
		}

		private void on_session_opened (uint session_id, DBusConnection connection) {
			var client = clients[connection];
			if (client != null)
				client.sessions.add (session_id);
		}

		private void on_session_closed (uint session_id, DBusConnection connection) {
			var client = clients[connection];
			if (client != null)
				client.sessions.remove (session_id);
		}

		private GLib.DBusMessage on_connection_message (DBusConnection connection, owned DBusMessage message, bool incoming) {
			DBusMessage result = message;

			var type = message.get_message_type ();
			DBusMessage call = null;
			switch (type) {
				case DBusMessageType.METHOD_CALL:
					method_calls[message.get_serial ()] = message;
					break;
				case DBusMessageType.METHOD_RETURN:
					method_calls.unset (message.get_reply_serial (), out call);
					break;
				case DBusMessageType.ERROR:
					method_calls.unset (message.get_reply_serial (), out call);
					break;
				case DBusMessageType.SIGNAL:
					break;
				default:
					assert_not_reached ();
			}

			if (type == DBusMessageType.SIGNAL || type == DBusMessageType.ERROR)
				return result;

			string path, iface, member;
			if (call == null) {
				path = message.get_path ();
				iface = message.get_interface ();
				member = message.get_member ();
			} else {
				path = call.get_path ();
				iface = call.get_interface ();
				member = call.get_member ();
			}
			if (iface == "re.frida.HostSession8") {
				if (member == "AttachTo" && type == DBusMessageType.METHOD_RETURN) {
					uint32 session_id;
					message.get_body ().get ("((u))", out session_id);
					Idle.add (() => {
						on_session_opened (session_id, connection);
						return false;
					});
				}
			} else if (iface == "re.frida.AgentSession8") {
				uint session_id;
				path.scanf ("/re/frida/AgentSession/%u", out session_id);
				if (member == "Close") {
					if (type != DBusMessageType.METHOD_CALL) {
						Idle.add (() => {
							on_session_closed (session_id, connection);
							return false;
						});
					}
				}
			}

			return result;
		}

		private class Client : Object {
			public DBusConnection connection {
				get;
				construct;
			}

			public Gee.HashSet<uint> sessions {
				get;
				construct;
			}

			private Gee.HashSet<uint> registrations = new Gee.HashSet<uint> ();
			private Gee.HashMap<uint, uint> agent_registration_by_id = new Gee.HashMap<uint, uint> ();

			public Client (DBusConnection connection) {
				Object (connection: connection, sessions: new Gee.HashSet<uint> ());
			}

			public void close () {
				agent_registration_by_id.clear ();

				foreach (var registration_id in registrations)
					connection.unregister_object (registration_id);
				registrations.clear ();
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
					agent_registration_by_id.set (id.handle, registration_id);
				} catch (IOError e) {
					assert_not_reached ();
				}
			}

			public void unregister_agent_session (AgentSessionId id, AgentSession session) {
				uint registration_id;
				agent_registration_by_id.unset (id.handle, out registration_id);
				registrations.remove (registration_id);
				connection.unregister_object (registration_id);
			}
		}
	}
}
