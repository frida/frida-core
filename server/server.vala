namespace Frida.Server {
	private static Application application;

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
			stdout.printf ("%s\n", e.message);
			stdout.printf ("Run '%s --help' to see a full list of available command line options.\n", args[0]);
			return 1;
		}

		var listen_address = DEFAULT_LISTEN_ADDRESS;
		if (listen_addresses.length > 0)
			listen_address = listen_addresses[0];

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
			application.run (listen_address);
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
		private Gee.HashMap<uint, SessionResources> session_resources = new Gee.HashMap<uint, SessionResources> ();
		private Gee.HashMap<uint32, DBusMessage> method_calls = new Gee.HashMap<uint32, DBusMessage> ();

		private MainLoop loop;
		private bool stopping;

		construct {
#if WINDOWS
			host_session = new WindowsHostSession ();
#endif
#if DARWIN
			host_session = new DarwinHostSession ();
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

			agent_sessions.unset (id.handle);
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

			prune_sessions.begin (connection);
		}

		private void on_session_opened (uint session_id, DBusConnection connection) {
			var resources = session_resources[session_id];
			if (resources == null) {
				resources = new SessionResources (session_id);
				session_resources[session_id] = resources;
			}
			resources.connections.add (connection);
		}

		private void on_session_closed (uint session_id, DBusConnection connection) {
			var resources = session_resources[session_id];
			prune_session.begin (resources, connection);
		}

		private void on_script_created (uint script_id, uint session_id, DBusConnection connection) {
			var resources = session_resources[session_id];
			resources.scripts[script_id] = connection;
		}

		private void on_script_destroyed (uint script_id, uint session_id, DBusConnection connection) {
			var resources = session_resources[session_id];
			resources.scripts.unset (script_id);
		}

		private void on_debugger_enabled (uint session_id, DBusConnection connection) {
			var resources = session_resources[session_id];
			resources.debugger = connection;
		}

		private void on_debugger_disabled (uint session_id, DBusConnection connection) {
			var resources = session_resources[session_id];
			resources.debugger = null;
		}

		private async void prune_sessions (DBusConnection connection) {
			foreach (var resources in session_resources.values.to_array ())
				yield prune_session (resources, connection);
		}

		private async void prune_session (SessionResources resources, DBusConnection connection) {
			var session_id = resources.session_id;
			var session = agent_sessions[session_id];
			if (session == null) {
				session_resources.unset (session_id);
				return;
			}

			resources.connections.remove (connection);

			var scripts_to_destroy = new Gee.ArrayList<uint> ();
			var scripts = resources.scripts;
			foreach (var entry in scripts.entries) {
				if (entry.value == connection) {
					scripts_to_destroy.add (entry.key);
				}
			}
			foreach (var id in scripts_to_destroy)
				scripts.unset (id);

			foreach (var id in scripts_to_destroy) {
				try {
					yield session.destroy_script (AgentScriptId (id));
				} catch (GLib.Error e) {
				}
			}

			if (resources.debugger == connection) {
				resources.debugger = null;

				try {
					yield session.disable_debugger ();
				} catch (GLib.Error e) {
				}
			}

			if (resources.connections.is_empty) {
				session_resources.unset (session_id);

				try {
					yield session.close ();
				} catch (GLib.Error e) {
				}
			}
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
			if (iface == "re.frida.HostSession1") {
				if (member == "AttachTo" && type == DBusMessageType.METHOD_RETURN) {
					uint32 session_id;
					message.get_body ().get ("((u))", out session_id);
					Idle.add (() => {
						on_session_opened (session_id, connection);
						return false;
					});
				}
			} else if (iface == "re.frida.AgentSession1") {
				uint session_id;
				path.scanf ("/re/frida/AgentSession1/%u", out session_id);
				if (member == "Close") {
					if (type == DBusMessageType.METHOD_CALL) {
						try {
							result = message.copy ();
						} catch (GLib.Error e) {
							assert_not_reached ();
						}
						result.set_member ("Ping");
					} else {
						Idle.add (() => {
							on_session_closed (session_id, connection);
							return false;
						});
					}
				} else if (member == "CreateScript" && type == DBusMessageType.METHOD_RETURN) {
					uint32 script_id;
					message.get_body ().get ("((u))", out script_id);
					Idle.add (() => {
						on_script_created (script_id, session_id, connection);
						return false;
					});
				} else if (member == "DestroyScript" && type == DBusMessageType.METHOD_RETURN) {
					uint32 script_id;
					call.get_body ().get ("((u))", out script_id);
					Idle.add (() => {
						on_script_destroyed (script_id, session_id, connection);
						return false;
					});
				} else if (member == "EnableDebugger" && type == DBusMessageType.METHOD_RETURN) {
					Idle.add (() => {
						on_debugger_enabled (session_id, connection);
						return false;
					});
				} else if (member == "DisableDebugger" && type == DBusMessageType.METHOD_RETURN) {
					Idle.add (() => {
						on_debugger_disabled (session_id, connection);
						return false;
					});
				}
			}

			return result;
		}

		private class Client : Object {
			public DBusConnection connection {
				get;
				construct;
			}

			private Gee.HashSet<uint> registrations = new Gee.HashSet<uint> ();
			private Gee.HashMap<uint, uint> agent_registration_by_id = new Gee.HashMap<uint, uint> ();

			public Client (DBusConnection connection) {
				Object (connection: connection);
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

		private class SessionResources : Object {
			public uint session_id {
				get;
				construct;
			}

			public Gee.HashSet<DBusConnection> connections {
				get;
				construct;
			}

			public Gee.HashMap<uint, DBusConnection> scripts {
				get;
				construct;
			}

			public DBusConnection? debugger {
				get;
				set;
			}

			public SessionResources (uint session_id) {
				Object (
					session_id: session_id,
					connections: new Gee.HashSet<DBusConnection> (),
					scripts: new Gee.HashMap<uint, DBusConnection> ()
				);
			}
		}
	}
}
