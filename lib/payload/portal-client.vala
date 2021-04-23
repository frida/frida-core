namespace Frida {
	public class PortalClient : Object, AgentSessionProvider {
		public signal void resume ();
		public signal void kill ();

		public weak ProcessInvader invader {
			get;
			construct;
		}

		public SocketConnectable connectable {
			get;
			construct;
		}

		public TlsCertificate? certificate {
			get;
			construct;
		}

		public string? token {
			get;
			construct;
		}

		public HostApplicationInfo app_info {
			get;
			construct;
		}

		private DBusConnection? connection;
		private Promise<MainContext>? dbus_context_request;
		private SourceFunc? on_connection_event;
		private uint reconnect_timer;
		private Promise<bool> stopped = new Promise<bool> ();
		private Gee.Collection<uint> registrations = new Gee.ArrayList<uint> ();
		private PortalSession? portal_session;
		private Gee.Map<AgentSessionId?, LiveAgentSession> agent_sessions =
			new Gee.HashMap<AgentSessionId?, LiveAgentSession> (AgentSessionId.hash, AgentSessionId.equal);

		private Gee.Collection<Gum.Script> eternalized_scripts = new Gee.ArrayList<Gum.Script> ();

		private Cancellable io_cancellable = new Cancellable ();

		public PortalClient (ProcessInvader invader, SocketConnectable connectable, TlsCertificate? certificate, string? token,
				HostApplicationInfo app_info) {
			Object (
				invader: invader,
				connectable: connectable,
				certificate: certificate,
				token: token,
				app_info: app_info
			);
		}

		public async void start (Cancellable? cancellable = null) throws Error, IOError {
			var promise = new Promise<bool> ();

			maintain_connection.begin (promise);

			yield promise.future.wait_async (cancellable);
		}

		public async void stop (Cancellable? cancellable = null) throws IOError {
			if (reconnect_timer != 0) {
				Source.remove (reconnect_timer);
				reconnect_timer = 0;
			}

			io_cancellable.cancel ();

			if (on_connection_event != null)
				on_connection_event ();

			try {
				yield stopped.future.wait_async (cancellable);
				yield teardown_connection (cancellable);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
		}

		private async void maintain_connection (Promise<bool> start_request) {
			bool waiting = false;
			on_connection_event = () => {
				if (waiting)
					maintain_connection.callback ();
				return false;
			};

			uint reconnect_delay = 0;

			do {
				try {
					yield establish_connection ();

					if (start_request != null) {
						start_request.resolve (true);
						start_request = null;
					}

					reconnect_delay = 0;

					waiting = true;
					yield;
					waiting = false;
				} catch (GLib.Error e) {
					if (start_request != null) {
						GLib.Error start_error = (e is IOError.CANCELLED)
							? e
							: new Error.TRANSPORT ("%s", e.message);
						start_request.reject (start_error);
						start_request = null;
						break;
					}
				}

				if (io_cancellable.is_cancelled ())
					break;

				var source = new TimeoutSource (reconnect_delay + Random.int_range (0, 3000));
				source.set_callback (() => {
					maintain_connection.callback ();
					return false;
				});
				source.attach (MainContext.get_thread_default ());
				waiting = true;
				yield;
				waiting = false;

				reconnect_delay = (reconnect_delay != 0)
					? uint.min (reconnect_delay * 2, 17000)
					: 2000;
			} while (!io_cancellable.is_cancelled ());

			on_connection_event = null;

			stopped.resolve (true);
		}

		private async void establish_connection () throws GLib.Error {
			var client = new SocketClient ();
			SocketConnection socket_connection = yield client.connect_async (connectable, io_cancellable);

			var socket = socket_connection.socket;
			if (socket.get_family () != UNIX)
				Tcp.enable_nodelay (socket);

			IOStream stream = socket_connection;

			if (certificate != null) {
				var tc = TlsClientConnection.new (stream, null);
				tc.set_database (null);
				var accept_handler = tc.accept_certificate.connect ((peer_cert, errors) => {
					return peer_cert.verify (null, certificate) == 0;
				});
				try {
					yield tc.handshake_async (Priority.DEFAULT, io_cancellable);
				} finally {
					tc.disconnect (accept_handler);
				}
				stream = tc;
			}

			connection = yield new DBusConnection (stream, null, DELAY_MESSAGE_PROCESSING, null, io_cancellable);
			connection.on_closed.connect (on_connection_closed);

			dbus_context_request = detect_dbus_context (connection, io_cancellable);

			AgentSessionProvider provider = this;
			registrations.add (connection.register_object (ObjectPath.AGENT_SESSION_PROVIDER, provider));

			connection.start_message_processing ();

			if (token != null) {
				AuthenticationService auth_service = yield connection.get_proxy (null, ObjectPath.AUTHENTICATION_SERVICE,
					DBusProxyFlags.NONE, io_cancellable);
				yield auth_service.authenticate (token, io_cancellable);
			}

			portal_session = yield connection.get_proxy (null, ObjectPath.PORTAL_SESSION, DBusProxyFlags.NONE, io_cancellable);
			portal_session.resume.connect (on_resume);
			portal_session.kill.connect (on_kill);

			SpawnStartState current_state = invader.query_current_spawn_state ();
			SpawnStartState next_state;
			yield portal_session.join (app_info, current_state, io_cancellable, out next_state);

			if (next_state == RUNNING)
				resume ();
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			teardown_connection.begin (null);
		}

		private async void teardown_connection (Cancellable? cancellable) throws IOError {
			if (connection == null)
				return;

			foreach (var session in agent_sessions.values.to_array ()) {
				try {
					yield session.close (cancellable);
				} catch (GLib.Error e) {
					assert (e is IOError.CANCELLED);
					throw (IOError) e;
				}
			}

			foreach (var id in registrations)
				connection.unregister_object (id);
			registrations.clear ();

			connection = null;

			if (on_connection_event != null)
				on_connection_event ();
		}

		private async void open (AgentSessionId id, AgentSessionOptions options, Cancellable? cancellable) throws Error, IOError {
			var opts = SessionOptions._deserialize (options.data);
			if (opts.realm == EMULATED)
				throw new Error.NOT_SUPPORTED ("Emulated realm is not supported by frida-gadget");

			MainContext dbus_context = yield dbus_context_request.future.wait_async (cancellable);

			var session = new LiveAgentSession (invader, id, dbus_context);
			agent_sessions[id] = session;
			session.closed.connect (on_session_closed);
			session.script_eternalized.connect (on_script_eternalized);

			try {
				session.registration_id = connection.register_object (ObjectPath.from_agent_session_id (id),
					(AgentSession) session);
			} catch (IOError io_error) {
				assert_not_reached ();
			}

			// Ensure DBusConnection gets the signal first, as we will unregister the object right after.
			session.migrated.connect (on_session_migrated);

			opened (id);
		}

#if !WINDOWS
		private async void migrate (AgentSessionId id, Socket to_socket, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Session migration is not supported with frida-portal");
		}
#endif

		private async void unload (Cancellable? cancellable) throws Error, IOError {
			throw new Error.INVALID_OPERATION ("Unload is not allowed with frida-portal");
		}

		private void on_resume () {
			resume ();
		}

		private void on_kill () {
			kill ();
		}

		private void on_session_closed (BaseAgentSession base_session) {
			LiveAgentSession session = (LiveAgentSession) base_session;

			closed (session.id);

			unregister_session (session);

			session.migrated.disconnect (on_session_migrated);
			session.script_eternalized.disconnect (on_script_eternalized);
			session.closed.disconnect (on_session_closed);
			agent_sessions.unset (session.id);
		}

		private void on_session_migrated (AgentSession abstract_session) {
			LiveAgentSession session = (LiveAgentSession) abstract_session;

			unregister_session (session);
		}

		private void unregister_session (LiveAgentSession session) {
			var id = session.registration_id;
			if (id != 0) {
				connection.unregister_object (id);
				session.registration_id = 0;
			}
		}

		private void on_script_eternalized (Gum.Script script) {
			eternalized_scripts.add (script);
			eternalized ();
		}

		private class LiveAgentSession : BaseAgentSession {
			public AgentSessionId id {
				get;
				construct;
			}

			public uint registration_id {
				get;
				set;
			}

			public LiveAgentSession (ProcessInvader invader, AgentSessionId id, MainContext dbus_context) {
				Object (
					invader: invader,
					frida_context: MainContext.ref_thread_default (),
					dbus_context: dbus_context,
					id: id
				);
			}
		}
	}
}
