namespace Frida {
	public class SocketHostSessionBackend : Object, HostSessionBackend {
		private SocketHostSessionProvider provider;

		public async void start (Cancellable? cancellable) throws IOError {
			provider = new SocketHostSessionProvider ();
			provider_available (provider);
		}

		public async void stop (Cancellable? cancellable) throws IOError {
			provider_unavailable (provider);
			yield provider.close (cancellable);
			provider = null;
		}
	}

	public class SocketHostSessionProvider : Object, HostSessionProvider {
		public string id {
			get { return "socket"; }
		}

		public string name {
			get { return _name; }
		}
		private string _name = "Local Socket";

		public Image? icon {
			get { return _icon; }
		}
		private Image _icon = new Image (ImageData (16, 16, 16 * 4, "AAAAAAAAAAAAAAAAOjo6Dzo6OhQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOjo6TZCHbvlycnL4Ojo6iTo6OhMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOjo6aa6fdv7878f/+/Te/93d3f9xcXH3Ojo6gTo6Og8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOjo6F4KAfv//5Hn//fHK//r6+v/39/f/9/f3/9LS0v9kZGTzOjo6eDo6OgsAAAAAAAAAAAAAAAAAAAAAAAAAADo6Og6Tk5P/zc3N//z8/P/6+vr/8PDw/+7u7v/p6en/9PT0/8jIyP9XV1f2Ojo6SgAAAAAAAAAAAAAAAAAAAAA6OjoIb29v/8HBwf+5ubn/9/f3/+/v7//p6en/+Pj4/+np6f/o6Oj/4ODg/z09PcsAAAAAAAAAAAAAAAAAAAAAAAAAAjMzM1p8fHz/wsLC/7CwsP/x8fH/8/P0/9zc3f/09PT/+vr6/8vLy/9AQEDFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALS0tV2pqav7BwcH/rq6u/+bm5v/09PT/s7Oz/93d3f/R0dL/VVVVygAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjIyNRWlpa+7+/v/+wsLD/oaGh/4iIiP9NTU7/VVVW/0BAQf89PT61Pj4/BgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABsbG09NTU32urq6/4yMjP9ycnL/Pj4//1BQUf9tbW7/XFxd/z4+P8M+Pj8PAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAExMTTD09PfBzc3P/LCwsvDAwMbVEREX/f3+A/6ioqf9tbW7zPj4/lAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANDQ0vGRkZggAAAAAAAAAAJycnh0NDRP2GhojujIyP4EtLS4k/Pz8YAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjIyRoRUVFq21tbp5TU1ZUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACkpK10AAAAWAAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="));

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.REMOTE; }
		}

		private Gee.Set<HostEntry> hosts = new Gee.HashSet<HostEntry> ();

		private Cancellable io_cancellable = new Cancellable ();

		public async void close (Cancellable? cancellable) throws IOError {
			while (!hosts.is_empty) {
				var iterator = hosts.iterator ();
				iterator.next ();
				HostEntry entry = iterator.get ();

				hosts.remove (entry);

				yield destroy_host_entry (entry, APPLICATION_REQUESTED, cancellable);
			}

			io_cancellable.cancel ();
		}

		public async HostSession create (HostSessionOptions? options, Cancellable? cancellable) throws Error, IOError {
			string? raw_address = null;
			TlsCertificate? certificate = null;
			string? token = null;
			int keepalive_interval = -1;
			if (options != null) {
				var opts = options.map;

				Value? address_val = opts["address"];
				if (address_val != null)
					raw_address = address_val.get_string ();

				Value? cert_val = opts["certificate"];
				if (cert_val != null)
					certificate = (TlsCertificate) cert_val.get_object ();

				Value? token_val = opts["token"];
				if (token_val != null)
					token = token_val.get_string ();

				Value? keepalive_interval_val = opts["keepalive_interval"];
				if (keepalive_interval_val != null)
					keepalive_interval = keepalive_interval_val.get_int ();
			}
			SocketConnectable connectable = parse_control_address (raw_address);

			SocketConnection socket_connection;
			try {
				var client = new SocketClient ();
				socket_connection = yield client.connect_async (connectable, cancellable);
			} catch (GLib.Error e) {
				if (e is IOError.CONNECTION_REFUSED)
					throw new Error.SERVER_NOT_RUNNING ("Unable to connect to remote frida-server");
				else
					throw new Error.SERVER_NOT_RUNNING ("Unable to connect to remote frida-server: %s", e.message);
			}

			Socket socket = socket_connection.socket;
			SocketFamily family = socket.get_family ();

			if (family != UNIX)
				Tcp.enable_nodelay (socket);

			if (keepalive_interval == -1)
				keepalive_interval = (family == UNIX) ? 0 : 30;

			IOStream stream = socket_connection;

			if (certificate != null) {
				try {
					var tc = TlsClientConnection.new (stream, null);
					tc.set_database (null);
					var accept_handler = tc.accept_certificate.connect ((peer_cert, errors) => {
						return peer_cert.verify (null, certificate) == 0;
					});
					try {
						yield tc.handshake_async (Priority.DEFAULT, cancellable);
					} finally {
						tc.disconnect (accept_handler);
					}
					stream = tc;
				} catch (GLib.Error e) {
					throw new Error.TRANSPORT ("%s", e.message);
				}
			}

			DBusConnection connection;
			try {
				connection = yield new DBusConnection (stream, null, DBusConnectionFlags.NONE, null, cancellable);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("%s", e.message);
			}

			if (token != null) {
				AuthenticationService auth_service;
				try {
					auth_service = yield connection.get_proxy (null, ObjectPath.AUTHENTICATION_SERVICE,
						DO_NOT_LOAD_PROPERTIES, cancellable);
				} catch (IOError e) {
					throw new Error.PROTOCOL ("Incompatible frida-server version");
				}

				try {
					yield auth_service.authenticate (token, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
			}

			HostSession host_session;
			try {
				host_session = yield connection.get_proxy (null, ObjectPath.HOST_SESSION, DO_NOT_LOAD_PROPERTIES,
					cancellable);
			} catch (IOError e) {
				throw new Error.PROTOCOL ("Incompatible frida-server version");
			}

			var entry = new HostEntry (connection, host_session, keepalive_interval);
			entry.agent_session_detached.connect (on_agent_session_detached);
			hosts.add (entry);

			connection.on_closed.connect (on_host_connection_closed);

			return host_session;
		}

		public async void destroy (HostSession host_session, Cancellable? cancellable) throws Error, IOError {
			foreach (var entry in hosts) {
				if (entry.host_session == host_session) {
					hosts.remove (entry);
					yield destroy_host_entry (entry, APPLICATION_REQUESTED, cancellable);
					return;
				}
			}
			throw new Error.INVALID_ARGUMENT ("Invalid host session");
		}

		private async void destroy_host_entry (HostEntry entry, SessionDetachReason reason,
				Cancellable? cancellable) throws IOError {
			entry.connection.on_closed.disconnect (on_host_connection_closed);

			yield entry.destroy (reason, cancellable);

			entry.agent_session_detached.disconnect (on_agent_session_detached);

			host_session_detached (entry.host_session);
		}

		private void on_host_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			bool closed_by_us = (!remote_peer_vanished && error == null);
			if (closed_by_us)
				return;

			HostEntry entry_to_remove = null;
			foreach (var entry in hosts) {
				if (entry.connection == connection) {
					entry_to_remove = entry;
					break;
				}
			}
			assert (entry_to_remove != null);

			hosts.remove (entry_to_remove);
			destroy_host_entry.begin (entry_to_remove, CONNECTION_TERMINATED, io_cancellable);
		}

		public async AgentSession link_agent_session (HostSession host_session, AgentSessionId id, AgentMessageSink sink,
				Cancellable? cancellable) throws Error, IOError {
			foreach (var entry in hosts) {
				if (entry.host_session == host_session)
					return yield entry.link_agent_session (id, sink, cancellable);
			}
			throw new Error.INVALID_ARGUMENT ("Invalid host session");
		}

		private void on_agent_session_detached (AgentSessionId id, SessionDetachReason reason, CrashInfo crash) {
			agent_session_detached (id, reason, crash);
		}

		private class HostEntry : Object {
			public signal void agent_session_detached (AgentSessionId id, SessionDetachReason reason, CrashInfo crash);

			public DBusConnection connection {
				get;
				construct;
			}

			public HostSession host_session {
				get;
				construct;
			}

			public uint keepalive_interval {
				get;
				construct;
			}

			private TimeoutSource? keepalive_timer;

			private Gee.HashMap<AgentSessionId?, AgentSessionEntry> agent_sessions =
				new Gee.HashMap<AgentSessionId?, AgentSessionEntry> (AgentSessionId.hash, AgentSessionId.equal);

			private Cancellable io_cancellable = new Cancellable ();

			public HostEntry (DBusConnection connection, HostSession host_session, uint keepalive_interval) {
				Object (
					connection: connection,
					host_session: host_session,
					keepalive_interval: keepalive_interval
				);

				host_session.agent_session_detached.connect (on_agent_session_detached);
			}

			construct {
				if (keepalive_interval != 0) {
					var source = new TimeoutSource.seconds (keepalive_interval);
					source.set_callback (on_keepalive_tick);
					source.attach (MainContext.get_thread_default ());
					keepalive_timer = source;

					on_keepalive_tick ();
				}
			}

			public async void destroy (SessionDetachReason reason, Cancellable? cancellable) throws IOError {
				io_cancellable.cancel ();

				if (keepalive_timer != null) {
					keepalive_timer.destroy ();
					keepalive_timer = null;
				}

				host_session.agent_session_detached.disconnect (on_agent_session_detached);

				var no_crash = CrashInfo.empty ();
				foreach (AgentSessionId id in agent_sessions.keys)
					agent_session_detached (id, reason, no_crash);
				agent_sessions.clear ();

				if (reason != CONNECTION_TERMINATED) {
					try {
						yield connection.close (cancellable);
					} catch (GLib.Error e) {
					}
				}
			}

			public async AgentSession link_agent_session (AgentSessionId id, AgentMessageSink sink,
					Cancellable? cancellable) throws Error, IOError {
				if (agent_sessions.has_key (id))
					throw new Error.INVALID_OPERATION ("Already linked");

				var entry = new AgentSessionEntry (connection);
				agent_sessions[id] = entry;

				AgentSession session = yield connection.get_proxy (null, ObjectPath.for_agent_session (id),
					DO_NOT_LOAD_PROPERTIES, cancellable);

				entry.sink_registration_id = connection.register_object (ObjectPath.for_agent_message_sink (id), sink);

				return session;
			}

			private bool on_keepalive_tick () {
				host_session.ping.begin (keepalive_interval, io_cancellable);
				return true;
			}

			private void on_agent_session_detached (AgentSessionId id, SessionDetachReason reason, CrashInfo crash) {
				agent_sessions.unset (id);
				agent_session_detached (id, reason, crash);
			}
		}

		private class AgentSessionEntry {
			public DBusConnection connection {
				get;
				set;
			}

			public uint sink_registration_id {
				get;
				set;
			}

			public AgentSessionEntry (DBusConnection connection) {
				this.connection = connection;
			}

			~AgentSessionEntry () {
				if (sink_registration_id != 0)
					connection.unregister_object (sink_registration_id);
			}
		}
	}
}
