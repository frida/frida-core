namespace Frida {
	public class ControlService : Object {
		public HostSession host_session {
			get;
			construct;
		}

		public EndpointParameters endpoint_params {
			get;
			construct;
		}

		public ControlServiceOptions options {
			get;
			construct;
		}

		private State state = STOPPED;

		private WebService service;
		private Gee.Map<DBusConnection, Peer> peers = new Gee.HashMap<DBusConnection, Peer> ();

		private Gee.Set<ControlChannel> spawn_gaters = new Gee.HashSet<ControlChannel> ();
		private Gee.Map<uint, PendingSpawn> pending_spawn = new Gee.HashMap<uint, PendingSpawn> ();
		private Gee.Map<AgentSessionId?, AgentSessionEntry> sessions =
			new Gee.HashMap<AgentSessionId?, AgentSessionEntry> (AgentSessionId.hash, AgentSessionId.equal);

		private SocketService broker_service = new SocketService ();
#if !WINDOWS
		private uint16 broker_port = 0;
#endif
		private Gee.Map<string, Transport> transports = new Gee.HashMap<string, Transport> ();

		private Cancellable io_cancellable = new Cancellable ();

		private enum State {
			STOPPED,
			STARTING,
			STARTED,
			STOPPING
		}

		public ControlService (EndpointParameters endpoint_params, ControlServiceOptions? options = null) {
			ControlServiceOptions opts = (options != null) ? options : new ControlServiceOptions ();

			HostSession host_session;
#if WINDOWS
			var tempdir = new TemporaryDirectory ();
			host_session = new WindowsHostSession (new WindowsHelperProcess (tempdir), tempdir);
#endif
#if DARWIN
			host_session = new DarwinHostSession (new DarwinHelperBackend (), new TemporaryDirectory (),
				opts.sysroot, opts.report_crashes);
#endif
#if LINUX
			var tempdir = new TemporaryDirectory ();
			host_session = new LinuxHostSession (new LinuxHelperProcess (tempdir), tempdir, opts.report_crashes);
#endif
#if FREEBSD
			host_session = new FreebsdHostSession ();
#endif
#if QNX
			host_session = new QnxHostSession ();
#endif

			Object (
				host_session: host_session,
				endpoint_params: endpoint_params,
				options: opts
			);
		}

		public ControlService.with_host_session (HostSession host_session, EndpointParameters endpoint_params,
				ControlServiceOptions? options = null) {
			Object (
				host_session: host_session,
				endpoint_params: endpoint_params,
				options: (options != null) ? options : new ControlServiceOptions ()
			);
		}

		construct {
			host_session.spawn_added.connect (notify_spawn_added);
			host_session.child_added.connect (notify_child_added);
			host_session.child_removed.connect (notify_child_removed);
			host_session.process_crashed.connect (notify_process_crashed);
			host_session.output.connect (notify_output);
			host_session.agent_session_detached.connect (on_agent_session_detached);
			host_session.uninjected.connect (notify_uninjected);

			service = new WebService (endpoint_params, CONTROL);
			service.incoming.connect (on_server_connection);

			broker_service.incoming.connect (on_broker_service_connection);
		}

		public async void start (Cancellable? cancellable = null) throws Error, IOError {
			if (state != STOPPED)
				throw new Error.INVALID_OPERATION ("Invalid operation");
			state = STARTING;

			try {
				yield service.start (cancellable);

				if (options.enable_preload) {
					var base_host_session = host_session as BaseDBusHostSession;
					if (base_host_session != null)
						base_host_session.preload.begin (io_cancellable);
				}

				state = STARTED;
			} finally {
				if (state != STARTED)
					state = STOPPED;
			}
		}

		public void start_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<StartTask> ().execute (cancellable);
		}

		private class StartTask : ControlServiceTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.start (cancellable);
			}
		}

		public async void stop (Cancellable? cancellable = null) throws Error, IOError {
			if (state != STARTED)
				throw new Error.INVALID_OPERATION ("Invalid operation");
			state = STOPPING;

			broker_service.stop ();
			service.stop ();

			io_cancellable.cancel ();

			transports.clear ();

			foreach (var peer in peers.values.to_array ()) {
				try {
					yield peer.close ();
				} catch (IOError e) {
					assert_not_reached ();
				}
			}
			peers.clear ();

			var base_host_session = host_session as BaseDBusHostSession;
			if (base_host_session != null)
				yield base_host_session.close (cancellable);

			state = STOPPED;
		}

		public void stop_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<StopTask> ().execute (cancellable);
		}

		private class StopTask : ControlServiceTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.stop (cancellable);
			}
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		private abstract class ControlServiceTask<T> : AsyncTask<T> {
			public weak ControlService parent {
				get;
				construct;
			}
		}

		private void on_server_connection (IOStream connection, SocketAddress remote_address) {
#if IOS || TVOS
			/*
			 * We defer the launchd injection until the first connection is established in order
			 * to avoid bootloops on unsupported jailbreaks.
			 */
			var darwin_host_session = host_session as DarwinHostSession;
			if (darwin_host_session != null)
				darwin_host_session.activate_crash_reporter_integration ();
#endif

			handle_server_connection.begin (connection);
		}

		private async void handle_server_connection (IOStream raw_connection) throws GLib.Error {
			var connection = yield new DBusConnection (raw_connection, null, DELAY_MESSAGE_PROCESSING, null, io_cancellable);
			connection.on_closed.connect (on_connection_closed);

			Peer peer;
			AuthenticationService? auth_service = endpoint_params.auth_service;
			if (auth_service != null)
				peer = new AuthenticationChannel (this, connection, auth_service);
			else
				peer = setup_control_channel (connection);
			peers[connection] = peer;

			connection.start_message_processing ();
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			Peer peer;
			if (peers.unset (connection, out peer))
				peer.close.begin (io_cancellable);
		}

		private async void promote_authentication_channel (AuthenticationChannel channel) throws GLib.Error {
			DBusConnection connection = channel.connection;

			peers.unset (connection);
			yield channel.close (io_cancellable);

			peers[connection] = setup_control_channel (connection);
		}

		private void kick_authentication_channel (AuthenticationChannel channel) {
			var source = new IdleSource ();
			source.set_callback (() => {
				channel.connection.close.begin (io_cancellable);
				return false;
			});
			source.attach (MainContext.get_thread_default ());
		}

		private ControlChannel setup_control_channel (DBusConnection connection) {
			return new ControlChannel (this, connection);
		}

		private async void teardown_control_channel (ControlChannel channel) {
			foreach (AgentSessionId id in channel.sessions) {
				AgentSessionEntry entry = sessions[id];

				var base_host_session = host_session as BaseDBusHostSession;
				if (base_host_session != null)
					base_host_session.unlink_agent_session (id);

				AgentSession? session = entry.session;

				if (entry.persist_timeout == 0 || session == null) {
					sessions.unset (id);
					if (session != null)
						session.close.begin (io_cancellable);
				} else {
					entry.detach_controller ();
					session.interrupt.begin (io_cancellable);
				}
			}

			try {
				yield disable_spawn_gating (channel);
			} catch (GLib.Error e) {
			}
		}

		private Gee.Iterator<ControlChannel> all_control_channels () {
			return (Gee.Iterator<ControlChannel>) peers.values.filter (peer => peer is ControlChannel);
		}

		private async void enable_spawn_gating (ControlChannel requester) throws GLib.Error {
			bool is_first = spawn_gaters.is_empty;
			spawn_gaters.add (requester);
			foreach (var spawn in pending_spawn.values)
				spawn.pending_approvers.add (requester);

			if (is_first)
				yield host_session.enable_spawn_gating (io_cancellable);
		}

		private async void disable_spawn_gating (ControlChannel requester) throws GLib.Error {
			if (spawn_gaters.remove (requester)) {
				foreach (uint pid in pending_spawn.keys.to_array ())
					host_session.resume.begin (pid, io_cancellable);
			}

			if (spawn_gaters.is_empty)
				yield host_session.disable_spawn_gating (io_cancellable);
		}

		private HostSpawnInfo[] enumerate_pending_spawn () {
			var result = new HostSpawnInfo[pending_spawn.size];
			var i = 0;
			foreach (var spawn in pending_spawn.values)
				result[i++] = spawn.info;
			return result;
		}

		private async void resume (uint pid, ControlChannel requester) throws GLib.Error {
			PendingSpawn? spawn = pending_spawn[pid];
			if (spawn == null) {
				yield host_session.resume (pid, io_cancellable);
				return;
			}

			var approvers = spawn.pending_approvers;
			approvers.remove (requester);
			if (approvers.is_empty) {
				pending_spawn.unset (pid);

				yield host_session.resume (pid, io_cancellable);

				notify_spawn_removed (spawn.info);
			}
		}

		private async AgentSessionId attach (uint pid, HashTable<string, Variant> options, ControlChannel requester,
				Cancellable? cancellable) throws Error, IOError {
			AgentSessionId id;
			try {
				id = yield host_session.attach (pid, options, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			requester.sessions.add (id);

			var opts = SessionOptions._deserialize (options);

			var entry = new AgentSessionEntry (requester, id, opts.persist_timeout, io_cancellable);
			sessions[id] = entry;
			entry.expired.connect (on_agent_session_expired);

			yield link_session (id, entry, requester, cancellable);

			return id;
		}

		private async void reattach (AgentSessionId id, ControlChannel requester, Cancellable? cancellable) throws Error, IOError {
			AgentSessionEntry? entry = sessions[id];
			if (entry == null || entry.controller != null)
				throw new Error.INVALID_OPERATION ("Invalid session ID");

			requester.sessions.add (id);

			entry.attach_controller (requester);

			yield link_session (id, entry, requester, cancellable);
		}

		private async void link_session (AgentSessionId id, AgentSessionEntry entry, ControlChannel requester,
				Cancellable? cancellable) throws Error, IOError {
			DBusConnection controller_connection = requester.connection;

			AgentMessageSink sink;
			try {
				sink = yield controller_connection.get_proxy (null, ObjectPath.for_agent_message_sink (id),
					DO_NOT_LOAD_PROPERTIES, cancellable);
			} catch (IOError e) {
				throw_dbus_error (e);
			}

			AgentSession session;
			var base_host_session = host_session as BaseDBusHostSession;
			if (base_host_session != null) {
				session = yield base_host_session.link_agent_session (id, sink, cancellable);
			} else {
				DBusConnection internal_connection = ((DBusProxy) host_session).g_connection;

				try {
					session = yield internal_connection.get_proxy (null, ObjectPath.for_agent_session (id),
						DO_NOT_LOAD_PROPERTIES, cancellable);
				} catch (IOError e) {
					throw_dbus_error (e);
				}

				entry.internal_connection = internal_connection;
				try {
					entry.take_internal_registration (
						internal_connection.register_object (ObjectPath.for_agent_message_sink (id), sink));
				} catch (IOError e) {
					assert_not_reached ();
				}
			}

			entry.session = session;
			try {
				entry.take_controller_registration (
					controller_connection.register_object (ObjectPath.for_agent_session (id), session));
			} catch (IOError e) {
				assert_not_reached ();
			}
		}

		private void notify_spawn_added (HostSpawnInfo info) {
			foreach (ControlChannel channel in spawn_gaters)
				channel.spawn_added (info);
		}

		private void notify_spawn_removed (HostSpawnInfo info) {
			foreach (ControlChannel channel in spawn_gaters)
				channel.spawn_removed (info);
		}

		private void notify_child_added (HostChildInfo info) {
			all_control_channels ().foreach (channel => {
				channel.child_added (info);
				return true;
			});
		}

		private void notify_child_removed (HostChildInfo info) {
			all_control_channels ().foreach (channel => {
				channel.child_removed (info);
				return true;
			});
		}

		private void notify_process_crashed (CrashInfo crash) {
			all_control_channels ().foreach (channel => {
				channel.process_crashed (crash);
				return true;
			});
		}

		private void notify_output (uint pid, int fd, uint8[] data) {
			all_control_channels ().foreach (channel => {
				channel.output (pid, fd, data);
				return true;
			});
		}

		private void on_agent_session_detached (AgentSessionId id, SessionDetachReason reason, CrashInfo crash) {
			AgentSessionEntry entry;
			if (sessions.unset (id, out entry)) {
				ControlChannel? controller = entry.controller;
				if (controller != null) {
					controller.sessions.remove (id);
					controller.agent_session_detached (id, reason, crash);
				}
			}
		}

		private void notify_uninjected (InjectorPayloadId id) {
			all_control_channels ().foreach (channel => {
				channel.uninjected (id);
				return true;
			});
		}

		private void on_agent_session_expired (AgentSessionEntry entry) {
			sessions.unset (entry.id);
		}

		private void open_tcp_transport (AgentSessionId id, Cancellable? cancellable, out uint16 port,
				out string token) throws Error {
#if WINDOWS
			throw new Error.NOT_SUPPORTED ("Not yet supported on Windows");
#else
			var base_host_session = host_session as BaseDBusHostSession;
			if (base_host_session == null)
				throw new Error.NOT_SUPPORTED ("Not supported for remote host sessions");
			if (!base_host_session.can_pass_file_descriptors_to_agent_session (id))
				throw new Error.INVALID_ARGUMENT ("Not supported by this particular agent session");

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

#if !WINDOWS
			AgentSessionId session_id = transport.session_id;

			var base_host_session = host_session as BaseDBusHostSession;
			if (base_host_session == null)
				throw new Error.NOT_SUPPORTED ("Not supported for remote host sessions");

			AgentSessionProvider provider = base_host_session.obtain_session_provider (session_id);
			yield provider.migrate (session_id, socket, io_cancellable);
#endif
		}

		private interface Peer : Object {
			public abstract async void close (Cancellable? cancellable = null) throws IOError;
		}

		private class AuthenticationChannel : Object, Peer, AuthenticationService {
			public weak ControlService parent {
				get;
				construct;
			}

			public DBusConnection connection {
				get;
				construct;
			}

			public AuthenticationService service {
				get;
				construct;
			}

			private Gee.Collection<uint> registrations = new Gee.ArrayList<uint> ();

			public AuthenticationChannel (ControlService parent, DBusConnection connection, AuthenticationService service) {
				Object (
					parent: parent,
					connection: connection,
					service: service
				);
			}

			construct {
				try {
					registrations.add (connection.register_object (ObjectPath.AUTHENTICATION_SERVICE,
						(AuthenticationService) this));

					HostSession host_session = new UnauthorizedHostSession ();
					registrations.add (connection.register_object (ObjectPath.HOST_SESSION, host_session));
				} catch (IOError e) {
					assert_not_reached ();
				}
			}

			public async void close (Cancellable? cancellable) throws IOError {
				foreach (var id in registrations)
					connection.unregister_object (id);
				registrations.clear ();
			}

			public async string authenticate (string token, Cancellable? cancellable) throws GLib.Error {
				try {
					string session_info = yield service.authenticate (token, cancellable);
					yield parent.promote_authentication_channel (this);
					return session_info;
				} catch (GLib.Error e) {
					if (e is Error.INVALID_ARGUMENT)
						parent.kick_authentication_channel (this);
					throw e;
				}
			}
		}

		private class ControlChannel : Object, Peer, HostSession, TransportBroker {
			public weak ControlService parent {
				get;
				construct;
			}

			public DBusConnection connection {
				get;
				construct;
			}

			public Gee.Set<AgentSessionId?> sessions {
				get;
				default = new Gee.HashSet<AgentSessionId?> (AgentSessionId.hash, AgentSessionId.equal);
			}

			private Gee.Set<uint> registrations = new Gee.HashSet<uint> ();
			private TimeoutSource? ping_timer;

			public ControlChannel (ControlService parent, DBusConnection connection) {
				Object (parent: parent, connection: connection);
			}

			construct {
				try {
					HostSession session = this;
					registrations.add (connection.register_object (ObjectPath.HOST_SESSION, session));

					AuthenticationService null_auth = new NullAuthenticationService ();
					registrations.add (connection.register_object (Frida.ObjectPath.AUTHENTICATION_SERVICE, null_auth));

					TransportBroker broker = this;
					registrations.add (connection.register_object (Frida.ObjectPath.TRANSPORT_BROKER, broker));
				} catch (IOError e) {
					assert_not_reached ();
				}
			}

			public async void close (Cancellable? cancellable) throws IOError {
				discard_ping_timer ();

				yield parent.teardown_control_channel (this);

				foreach (var id in registrations)
					connection.unregister_object (id);
				registrations.clear ();
			}

			public async void ping (uint interval_seconds, Cancellable? cancellable) throws Error, IOError {
				discard_ping_timer ();

				if (interval_seconds != 0) {
					ping_timer = new TimeoutSource (interval_seconds * 1500);
					ping_timer.set_callback (on_ping_timeout);
					ping_timer.attach (MainContext.get_thread_default ());
				}
			}

			private void discard_ping_timer () {
				if (ping_timer == null)
					return;
				ping_timer.destroy ();
				ping_timer = null;
			}

			private bool on_ping_timeout () {
				connection.close.begin ();
				return false;
			}

			public async HashTable<string, Variant> query_system_parameters (Cancellable? cancellable) throws GLib.Error {
				return yield parent.host_session.query_system_parameters (cancellable);
			}

			public async HostApplicationInfo get_frontmost_application (HashTable<string, Variant> options,
					Cancellable? cancellable) throws GLib.Error {
				return yield parent.host_session.get_frontmost_application (options, cancellable);
			}

			public async HostApplicationInfo[] enumerate_applications (HashTable<string, Variant> options,
					Cancellable? cancellable) throws GLib.Error {
				return yield parent.host_session.enumerate_applications (options, cancellable);
			}

			public async HostProcessInfo[] enumerate_processes (HashTable<string, Variant> options,
					Cancellable? cancellable) throws GLib.Error {
				return yield parent.host_session.enumerate_processes (options, cancellable);
			}

			public async void enable_spawn_gating (Cancellable? cancellable) throws GLib.Error {
				yield parent.enable_spawn_gating (this);
			}

			public async void disable_spawn_gating (Cancellable? cancellable) throws GLib.Error {
				yield parent.disable_spawn_gating (this);
			}

			public async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws GLib.Error {
				return parent.enumerate_pending_spawn ();
			}

			public async HostChildInfo[] enumerate_pending_children (Cancellable? cancellable) throws GLib.Error {
				return yield parent.host_session.enumerate_pending_children (cancellable);
			}

			public async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable) throws GLib.Error {
				return yield parent.host_session.spawn (program, options, cancellable);
			}

			public async void input (uint pid, uint8[] data, Cancellable? cancellable) throws GLib.Error {
				yield parent.host_session.input (pid, data, cancellable);
			}

			public async void resume (uint pid, Cancellable? cancellable) throws GLib.Error {
				yield parent.resume (pid, this);
			}

			public async void kill (uint pid, Cancellable? cancellable) throws GLib.Error {
				yield parent.host_session.kill (pid, cancellable);
			}

			public async AgentSessionId attach (uint pid, HashTable<string, Variant> options,
					Cancellable? cancellable) throws GLib.Error {
				return yield parent.attach (pid, options, this, cancellable);
			}

			public async void reattach (AgentSessionId id, Cancellable? cancellable) throws Error, IOError {
				yield parent.reattach (id, this, cancellable);
			}

			public async InjectorPayloadId inject_library_file (uint pid, string path, string entrypoint, string data,
					Cancellable? cancellable) throws GLib.Error {
				return yield parent.host_session.inject_library_file (pid, path, entrypoint, data, cancellable);
			}

			public async InjectorPayloadId inject_library_blob (uint pid, uint8[] blob, string entrypoint, string data,
					Cancellable? cancellable) throws GLib.Error {
				return yield parent.host_session.inject_library_blob (pid, blob, entrypoint, data, cancellable);
			}

			private async void open_tcp_transport (AgentSessionId id, Cancellable? cancellable, out uint16 port,
					out string token) throws Error {
				parent.open_tcp_transport (id, cancellable, out port, out token);
			}
		}

		private class PendingSpawn {
			public HostSpawnInfo info {
				get;
				private set;
			}

			public Gee.Set<ControlChannel> pending_approvers {
				get;
				default = new Gee.HashSet<ControlChannel> ();
			}

			public PendingSpawn (uint pid, string identifier, Gee.Iterator<ControlChannel> gaters) {
				info = HostSpawnInfo (pid, identifier);
				pending_approvers.add_all_iterator (gaters);
			}
		}

		private class AgentSessionEntry {
			public signal void expired ();

			public ControlChannel? controller {
				get;
				private set;
			}

			public AgentSessionId id {
				get;
				private set;
			}

			public AgentSession? session {
				get;
				set;
			}

			public uint persist_timeout {
				get;
				private set;
			}

			public DBusConnection? internal_connection {
				get;
				set;
			}

			public Cancellable io_cancellable {
				get;
				private set;
			}

			private Gee.Collection<uint> internal_registrations = new Gee.ArrayList<uint> ();
			private Gee.Collection<uint> controller_registrations = new Gee.ArrayList<uint> ();

			private TimeoutSource? expiry_timer;

			public AgentSessionEntry (ControlChannel controller, AgentSessionId id, uint persist_timeout,
					Cancellable io_cancellable) {
				this.controller = controller;
				this.id = id;
				this.persist_timeout = persist_timeout;
				this.io_cancellable = io_cancellable;
			}

			~AgentSessionEntry () {
				stop_expiry_timer ();
				unregister_all ();
			}

			public void detach_controller () {
				unregister_all ();
				controller = null;
				session = null;

				start_expiry_timer ();
			}

			public void attach_controller (ControlChannel c) {
				stop_expiry_timer ();

				assert (controller == null);
				controller = c;
			}

			public void take_internal_registration (uint id) {
				internal_registrations.add (id);
			}

			public void take_controller_registration (uint id) {
				controller_registrations.add (id);
			}

			private void unregister_all () {
				if (controller != null)
					unregister_all_in (controller_registrations, controller.connection);
				if (internal_connection != null)
					unregister_all_in (internal_registrations, internal_connection);
			}

			private void unregister_all_in (Gee.Collection<uint> ids, DBusConnection connection) {
				foreach (uint id in ids)
					connection.unregister_object (id);
				ids.clear ();
			}

			private void start_expiry_timer () {
				if (expiry_timer != null)
					return;
				expiry_timer = new TimeoutSource.seconds (persist_timeout + 1);
				expiry_timer.set_callback (() => {
					expired ();
					return false;
				});
				expiry_timer.attach (MainContext.get_thread_default ());
			}

			private void stop_expiry_timer () {
				if (expiry_timer == null)
					return;
				expiry_timer.destroy ();
				expiry_timer = null;
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

	public class ControlServiceOptions : Object {
		public string? sysroot {
			get;
			set;
		}

		public bool enable_preload {
			get;
			set;
			default = true;
		}

		public bool report_crashes {
			get;
			set;
			default = true;
		}
	}
}
