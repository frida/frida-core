namespace Frida.Server {
	private static Application application;

	private const string DEFAULT_LISTEN_ADDRESS = "127.0.0.1";
	private const uint16 DEFAULT_LISTEN_PORT = 27042;
	private const string DEFAULT_DIRECTORY = "re.frida.server";
	private static bool output_version = false;
	private static string listen_address = null;
	private static string directory = null;
#if !WINDOWS
	private static bool daemonize = false;
#endif

	private delegate void ReadyHandler (bool success);

	const OptionEntry[] options = {
		{ "version", 0, 0, OptionArg.NONE, ref output_version, "Output version information and exit", null },
		{ "listen", 'l', 0, OptionArg.STRING, ref listen_address, "Listen on ADDRESS", "ADDRESS" },
		{ "directory", 'd', 0, OptionArg.STRING, ref directory, "Store binaries in DIRECTORY", "DIRECTORY" },
#if !WINDOWS
		{ "daemonize", 'D', 0, OptionArg.NONE, ref daemonize, "Detach and become a daemon", null },
#endif
		{ null }
	};

	private static int main (string[] args) {
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

		ReadyHandler on_ready = null;
#if !WINDOWS
		if (daemonize) {
			var sync_fds = new int[2];

			try {
				Unix.open_pipe (sync_fds, 0);
				Unix.set_fd_nonblocking (sync_fds[0], true);
				Unix.set_fd_nonblocking (sync_fds[1], true);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			var sync_in = new UnixInputStream (sync_fds[0], true);
			var sync_out = new UnixOutputStream (sync_fds[1], true);

			var pid = Posix.fork ();
			if (pid != 0) {
				try {
					var status = new uint8[1];
					sync_in.read (status);
					return status[0];
				} catch (GLib.Error e) {
					return 1;
				}
			}

			sync_in = null;
			on_ready = (success) => {
				if (success) {
					Posix.setsid ();

					var null_in = Posix.open ("/dev/null", Posix.O_RDONLY);
					var null_out = Posix.open ("/dev/null", Posix.O_WRONLY);
					Posix.dup2 (null_in, Posix.STDIN_FILENO);
					Posix.dup2 (null_out, Posix.STDOUT_FILENO);
					Posix.dup2 (null_out, Posix.STDERR_FILENO);
					Posix.close (null_in);
					Posix.close (null_out);
				}

				var status = new uint8[1];
				status[0] = success ? 0 : 1;
				try {
					sync_out.write (status);
				} catch (GLib.Error e) {
				}
				sync_out = null;
			};
		}
#endif

		Environment.configure ();

#if DARWIN
		var worker = new Thread<int> ("frida-server-main-loop", () => {
			var exit_code = run_application (listen_uri, on_ready);

			_stop_run_loop ();

			return exit_code;
		});
		_start_run_loop ();

		var exit_code = worker.join ();

		return exit_code;
#else
		return run_application (listen_uri, on_ready);
#endif
	}

	private static int run_application (string listen_uri, ReadyHandler on_ready) {
		application = new Application ();

#if !WINDOWS
		Posix.signal (Posix.Signal.INT, (sig) => {
			application.stop ();
		});
		Posix.signal (Posix.Signal.TERM, (sig) => {
			application.stop ();
		});
#endif

		try {
			Idle.add (() => {
				if (on_ready != null) {
					on_ready (true);
					on_ready = null;
				}

				return false;
			});

			application.run (listen_uri);
		} catch (Error e) {
			printerr ("Unable to start server: %s\n", e.message);

			if (on_ready != null) {
				on_ready (false);
				on_ready = null;
			}

			return 1;
		}

		application = null;

		return 0;
	}

	namespace Environment {
		public extern void init ();
		public extern void configure ();
	}

#if DARWIN
	public extern void _start_run_loop ();
	public extern void _stop_run_loop ();
#endif

	public class Application : Object {
		private BaseDBusHostSession host_session;
		private Gee.HashMap<AgentSessionId?, AgentSession> agent_sessions =
			new Gee.HashMap<AgentSessionId?, AgentSession> (AgentSessionId.hash, AgentSessionId.equal);
		private DBusServer server;
		private Gee.HashMap<DBusConnection, Client> clients = new Gee.HashMap<DBusConnection, Client> ();

		private MainLoop loop;
		private bool stopping;

		construct {
			TemporaryDirectory.always_use ((directory != null) ? directory : DEFAULT_DIRECTORY);

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
			connection.on_closed.connect (on_connection_closed);

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

			if (client.is_spawn_gating)
				host_session.disable_spawn_gating.begin ();

			foreach (var session_id in client.sessions)
				close_session.begin (session_id);
		}

		private async void close_session (AgentSessionId id) {
			try {
				var session = yield host_session.obtain_agent_session (id);
				yield session.close ();
			} catch (GLib.Error e) {
			}
		}

		private class Client : Object {
			public DBusConnection connection {
				get;
				construct;
			}

			public bool is_spawn_gating {
				get;
				private set;
			}

			public Gee.HashSet<AgentSessionId?> sessions {
				get;
				default = new Gee.HashSet<AgentSessionId?> (AgentSessionId.hash, AgentSessionId.equal);
			}

			private uint filter_id;
			private Gee.HashSet<uint> registrations = new Gee.HashSet<uint> ();
			private Gee.HashMap<AgentSessionId?, uint> agent_registrations =
				new Gee.HashMap<AgentSessionId?, uint> (AgentSessionId.hash, AgentSessionId.equal);
			private Gee.HashMap<uint32, DBusMessage> method_calls = new Gee.HashMap<uint32, DBusMessage> ();

			public Client (DBusConnection connection) {
				Object (connection: connection);
			}

			construct {
				filter_id = connection.add_filter (on_connection_message);
			}

			public void close () {
				agent_registrations.clear ();

				foreach (var registration_id in registrations)
					connection.unregister_object (registration_id);
				registrations.clear ();

				connection.remove_filter (filter_id);
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
					agent_registrations.set (id, registration_id);
				} catch (IOError e) {
					assert_not_reached ();
				}
			}

			public void unregister_agent_session (AgentSessionId id, AgentSession session) {
				uint registration_id;
				agent_registrations.unset (id, out registration_id);
				registrations.remove (registration_id);
				connection.unregister_object (registration_id);
			}

			private void schedule_idle (owned ScheduledFunc func) {
				var client = this;
				Idle.add (() => {
					func ();
					client = null;
					return false;
				});
			}

			private delegate void ScheduledFunc ();

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
				if (iface == "re.frida.HostSession12") {
					if (member == "EnableSpawnGating" && type == DBusMessageType.METHOD_RETURN) {
						schedule_idle (() => {
							is_spawn_gating = true;
						});
					} else if (member == "DisableSpawnGating" && type == DBusMessageType.METHOD_RETURN) {
						schedule_idle (() => {
							is_spawn_gating = false;
						});
					} else if (member == "AttachTo" && type == DBusMessageType.METHOD_RETURN) {
						uint32 raw_id;
						message.get_body ().get ("((u))", out raw_id);
						schedule_idle (() => {
							sessions.add (AgentSessionId (raw_id));
						});
					}
				} else if (iface == "re.frida.AgentSession12") {
					uint raw_id;
					path.scanf ("/re/frida/AgentSession/%u", out raw_id);
					if (member == "Close") {
						if (type != DBusMessageType.METHOD_CALL) {
							schedule_idle (() => {
								sessions.remove (AgentSessionId (raw_id));
							});
						}
					}
				}

				return result;
			}
		}
	}
}
