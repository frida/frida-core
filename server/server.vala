namespace Frida.Server {
	private static Application application;

	private const string DEFAULT_LISTEN_ADDRESS = "127.0.0.1";
	private const uint16 DEFAULT_LISTEN_PORT = 27042;
	private const string DEFAULT_DIRECTORY = "re.frida.server";
	private static bool output_version = false;
	private static string? listen_address = null;
	private static string? directory = null;
#if !WINDOWS
	private static bool daemonize = false;
#endif
	private static bool verbose = false;

	private delegate void ReadyHandler (bool success);

	const OptionEntry[] options = {
		{ "version", 0, 0, OptionArg.NONE, ref output_version, "Output version information and exit", null },
		{ "listen", 'l', 0, OptionArg.STRING, ref listen_address, "Listen on ADDRESS", "ADDRESS" },
		{ "directory", 'd', 0, OptionArg.STRING, ref directory, "Store binaries in DIRECTORY", "DIRECTORY" },
#if !WINDOWS
		{ "daemonize", 'D', 0, OptionArg.NONE, ref daemonize, "Detach and become a daemon", null },
#endif
		{ "verbose", 'v', 0, OptionArg.NONE, ref verbose, "Be verbose", null },
		{ null }
	};

	private static int main (string[] args) {
		Environment.init ();

		try {
			var ctx = new OptionContext ();
			ctx.set_help_enabled (true);
			ctx.add_main_entries (options, null);
			ctx.parse (ref args);
		} catch (OptionError e) {
			printerr ("%s\n", e.message);
			printerr ("Run '%s --help' to see a full list of available command line options.\n", args[0]);
			return 1;
		}

		if (output_version) {
			stdout.printf ("%s\n", version_string ());
			return 0;
		}

		Environment.set_verbose_logging_enabled (verbose);

		SocketConnectable connectable;
		string raw_address = (listen_address != null) ? listen_address : DEFAULT_LISTEN_ADDRESS;
#if !WINDOWS
		if (raw_address.has_prefix ("unix:")) {
			string path = raw_address.substring (5);

			UnixSocketAddressType type = UnixSocketAddress.abstract_names_supported ()
				? UnixSocketAddressType.ABSTRACT
				: UnixSocketAddressType.PATH;

			connectable = new UnixSocketAddress.with_type (path, -1, type);
		} else {
#else
		{
#endif
			try {
				connectable = NetworkAddress.parse (raw_address, DEFAULT_LISTEN_PORT);
			} catch (GLib.Error e) {
				printerr ("%s\n", e.message);
				return 1;
			}
		}

		ReadyHandler? on_ready = null;
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
					return 2;
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
			var exit_code = run_application (connectable, on_ready);

			_stop_run_loop ();

			return exit_code;
		});
		_start_run_loop ();

		var exit_code = worker.join ();

		return exit_code;
#else
		return run_application (connectable, on_ready);
#endif
	}

	private static int run_application (SocketConnectable connectable, ReadyHandler on_ready) {
		application = new Application ();

		Posix.signal (Posix.Signal.INT, (sig) => {
			application.stop ();
		});
		Posix.signal (Posix.Signal.TERM, (sig) => {
			application.stop ();
		});

		if (on_ready != null) {
			application.ready.connect (() => {
				on_ready (true);
				on_ready = null;
			});
		}

		return application.run (connectable);
	}

	namespace Environment {
		public extern void init ();
		public extern void set_verbose_logging_enabled (bool enabled);
		public extern void configure ();
	}

	namespace Tcp {
		public extern void enable_nodelay (Socket socket);
	}

#if DARWIN
	public extern void _start_run_loop ();
	public extern void _stop_run_loop ();
#endif

	public class Application : Object, TransportBroker {
		public signal void ready ();

		private BaseDBusHostSession host_session;
		private Gee.HashMap<AgentSessionId?, AgentSession> agent_sessions =
			new Gee.HashMap<AgentSessionId?, AgentSession> (AgentSessionId.hash, AgentSessionId.equal);

		private SocketService server = new SocketService ();
		private string guid = DBus.generate_guid ();
		private Gee.HashMap<DBusConnection, Client> clients = new Gee.HashMap<DBusConnection, Client> ();

		private SocketService broker_service = new SocketService ();
#if !WINDOWS
		private uint16 broker_port = 0;
#endif
		private Gee.HashMap<string, Transport> transports = new Gee.HashMap<string, Transport> ();

		private Cancellable io_cancellable = new Cancellable ();

		private int exit_code;
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

			server.incoming.connect (on_server_connection);

			broker_service.incoming.connect (on_broker_service_connection);
		}

		public int run (SocketConnectable connectable) {
			Idle.add (() => {
				start.begin (connectable);
				return false;
			});

			exit_code = 0;

			loop = new MainLoop ();
			loop.run ();

			return exit_code;
		}

		private async void start (SocketConnectable connectable) {
			var enumerator = connectable.enumerate ();
			SocketAddress? address;
			try {
				while ((address = yield enumerator.next_async (io_cancellable)) != null) {
					SocketAddress effective_address;
					server.add_address (address, SocketType.STREAM, SocketProtocol.DEFAULT, null,
						out effective_address);
				}
			} catch (GLib.Error e) {
				printerr ("Unable to start: %s\n", e.message);
				exit_code = 3;
				stop ();
				return;
			}

			server.start ();

			Idle.add (() => {
				ready ();
				return false;
			});

			try {
				yield host_session.preload (io_cancellable);
			} catch (Error e) {
				if (verbose)
					printerr ("Unable to preload: %s\n", e.message);
			} catch (IOError e) {
			}
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

			transports.clear ();
			broker_service.stop ();

			server.stop ();

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

			while (agent_sessions.size != 0) {
				foreach (var entry in agent_sessions.entries) {
					var id = entry.key;
					var session = entry.value;
					agent_sessions.unset (id);
					try {
						yield session.close (null);
					} catch (GLib.Error e) {
					}
					break;
				}
			}

			try {
				yield host_session.close (null);
			} catch (IOError e) {
			}

			agent_sessions.clear ();

			io_cancellable.cancel ();

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

		private bool on_server_connection (SocketConnection connection, Object? source_object) {
#if IOS
			/*
			 * We defer the launchd injection until the first connection is established in order
			 * to avoid bootloops on unsupported jailbreaks.
			 */
			((DarwinHostSession) host_session).activate_crash_reporter_integration ();
#endif

			handle_server_connection.begin (connection);
			return true;
		}

		private async void handle_server_connection (SocketConnection socket_connection) throws GLib.Error {
			var socket = socket_connection.socket;
			if (socket.get_family () != UNIX)
				Tcp.enable_nodelay (socket);

			var connection = yield new DBusConnection (socket_connection, guid,
				AUTHENTICATION_SERVER | AUTHENTICATION_ALLOW_ANONYMOUS | DELAY_MESSAGE_PROCESSING,
				null, io_cancellable);
			connection.on_closed.connect (on_connection_closed);

			var client = new Client (connection);
			client.register_host_session (host_session);
			foreach (var entry in agent_sessions.entries)
				client.register_agent_session (entry.key, entry.value);
			client.register_transport_broker (this);
			clients.set (connection, client);

			connection.start_message_processing ();
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			bool closed_by_us = (!remote_peer_vanished && error == null);
			if (closed_by_us)
				return;

			Client client;
			clients.unset (connection, out client);
			client.close ();

			if (client.is_spawn_gating)
				host_session.disable_spawn_gating.begin (io_cancellable);

			foreach (var pid in client.orphans)
				host_session.kill.begin (pid, io_cancellable);

			foreach (var session_id in client.sessions)
				close_session.begin (session_id);
		}

		private async void close_session (AgentSessionId id) {
			try {
				var session = host_session.obtain_agent_session (id);
				yield session.close (io_cancellable);
			} catch (GLib.Error e) {
			}
		}

		private async void open_tcp_transport (AgentSessionId id, Cancellable? cancellable, out uint16 port, out string token)
				throws Error {
#if WINDOWS
			throw new Error.NOT_SUPPORTED ("Not yet supported on Windows");
#else
			if (broker_port == 0) {
				try {
					broker_port = broker_service.add_any_inet_port (null);
				} catch (GLib.Error e) {
					throw new Error.NOT_SUPPORTED ("Unable to listen: %s", e.message);
				}

				broker_service.start ();
			}

			string transport_id = Uuid.string_random ();

			var expiry_source = new TimeoutSource.seconds (20);
			expiry_source.set_callback (() => {
				transports.unset (transport_id);
				return false;
			});
			expiry_source.attach (MainContext.get_thread_default ());

			transports[transport_id] = new Transport (id, expiry_source);

			port = broker_port;
			token = transport_id;
#endif
		}

		private bool on_broker_service_connection (SocketConnection connection, Object? source_object) {
			handle_broker_connection.begin (connection);
			return true;
		}

		private async void handle_broker_connection (SocketConnection connection) throws GLib.Error {
			var socket = connection.socket;
			if (socket.get_family () != UNIX)
				Tcp.enable_nodelay (socket);

			const size_t uuid_length = 36;

			var raw_token = new uint8[uuid_length + 1];
			size_t bytes_read;
			yield connection.input_stream.read_all_async (raw_token[0:uuid_length], Priority.DEFAULT, io_cancellable,
				out bytes_read);
			unowned string token = (string) raw_token;

			Transport transport;
			if (!transports.unset (token, out transport))
				return;

			transport.expiry_source.destroy ();

			AgentSessionId session_id = transport.session_id;

#if !WINDOWS
			AgentSessionProvider provider = host_session.obtain_session_provider (session_id);

			yield provider.migrate (session_id, socket, io_cancellable);
#endif

			if (!agent_sessions.has_key (session_id))
				return;
			var session = agent_sessions[session_id];
			foreach (var client in clients.values)
				client.unregister_agent_session (session_id, session);
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

			public Gee.HashSet<uint> orphans {
				get;
				default = new Gee.HashSet<uint> ();
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

			public void register_transport_broker (TransportBroker transport_broker) {
				try {
					registrations.add (connection.register_object (ObjectPath.TRANSPORT_BROKER, transport_broker));
				} catch (IOError e) {
					assert_not_reached ();
				}
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

			private GLib.DBusMessage on_connection_message (DBusConnection connection, owned DBusMessage message,
					bool incoming) {
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
					} else if (member == "Spawn" && type == DBusMessageType.METHOD_RETURN) {
						uint32 pid;
						message.get_body ().get ("(u)", out pid);
						schedule_idle (() => {
							orphans.add (pid);
						});
					} else if ((member == "Resume" || member == "Kill") && type == DBusMessageType.METHOD_RETURN) {
						uint32 pid;
						call.get_body ().get ("(u)", out pid);
						schedule_idle (() => {
							orphans.remove (pid);
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

		private class Transport {
			public AgentSessionId session_id;
			public Source expiry_source;

			public Transport (AgentSessionId session_id, Source expiry_source) {
				this.session_id = session_id;
				this.expiry_source = expiry_source;
			}
		}
	}
}
