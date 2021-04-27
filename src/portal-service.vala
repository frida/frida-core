namespace Frida {
	public class PortalService : Object {
		public signal void node_connected (uint connection_id, SocketAddress remote_address);
		public signal void node_joined (uint connection_id, Application application);
		public signal void node_left (uint connection_id, Application application);
		public signal void node_disconnected (uint connection_id, SocketAddress remote_address);

		public signal void controller_connected (uint connection_id, SocketAddress remote_address);
		public signal void controller_disconnected (uint connection_id, SocketAddress remote_address);

		public signal void authenticated (uint connection_id, string session_info);
		public signal void message (uint connection_id, string message, Bytes? data);

		public Device device {
			get {
				return _device;
			}
		}
		private Device _device;

		public EndpointParameters cluster_params {
			get;
			construct;
		}

		public EndpointParameters? control_params {
			get;
			construct;
		}

		private SocketService server = new SocketService ();
		private string guid = DBus.generate_guid ();

		private Gee.Map<uint, ConnectionEntry> connections = new Gee.HashMap<uint, ConnectionEntry> ();
		private uint next_connection_id = 1;

		private Gee.Map<DBusConnection, Peer> peers = new Gee.HashMap<DBusConnection, Peer> ();

		private Gee.Map<uint, ClusterNode> node_by_pid = new Gee.HashMap<uint, ClusterNode> ();
		private Gee.Map<string, ClusterNode> node_by_identifier = new Gee.HashMap<string, ClusterNode> ();

		private Gee.Set<ControlChannel> spawn_gaters = new Gee.HashSet<ControlChannel> ();
		private Gee.Map<uint, PendingSpawn> pending_spawn = new Gee.HashMap<uint, PendingSpawn> ();
		private Gee.Map<AgentSessionId?, AgentSessionEntry> sessions =
			new Gee.HashMap<AgentSessionId?, AgentSessionEntry> (AgentSessionId.hash, AgentSessionId.equal);
		private uint next_agent_session_id = 1;

		private Cancellable io_cancellable;

		public PortalService (EndpointParameters cluster_params, EndpointParameters? control_params = null) {
			Object (cluster_params: cluster_params, control_params: control_params);
		}

		construct {
			_device = new Device (null, "portal", "Portal", HostSessionProviderKind.LOCAL,
				new PortalHostSessionProvider (this));

			server.incoming.connect (on_incoming_connection);
		}

		public override void dispose () {
			if (_device != null) {
				Device d = _device;
				_device = null;
				teardown_device.begin (d);
			}

			base.dispose ();
		}

		private async void teardown_device (Device d) {
			try {
				yield d._do_close (SessionDetachReason.DEVICE_LOST, true, null);
			} catch (IOError e) {
				assert_not_reached ();
			}
		}

		public async void start (Cancellable? cancellable = null) throws Error, IOError {
			io_cancellable = new Cancellable ();

			try {
				yield add_endpoint (parse_cluster_address (cluster_params.address, cluster_params.port),
					cluster_params, cancellable);

				if (control_params != null) {
					yield add_endpoint (parse_control_address (control_params.address, control_params.port),
						control_params, cancellable);
				}
			} catch (GLib.Error e) {
				throw new Error.ADDRESS_IN_USE ("%s", e.message);
			}

			server.start ();
		}

		public void start_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<StartTask> ().execute (cancellable);
		}

		private class StartTask : PortalServiceTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.start (cancellable);
			}
		}

		private async void add_endpoint (SocketConnectable connectable, EndpointParameters parameters,
				Cancellable? cancellable) throws GLib.Error {
			var enumerator = connectable.enumerate ();
			SocketAddress? address;
			while ((address = yield enumerator.next_async (cancellable)) != null) {
				SocketAddress effective_address;
				server.add_address (address, SocketType.STREAM, SocketProtocol.DEFAULT, parameters, out effective_address);
			}
		}

		public async void stop (Cancellable? cancellable = null) throws IOError {
			server.stop ();

			io_cancellable.cancel ();

			foreach (var peer in peers.values.to_array ())
				peer.close ();
			peers.clear ();
		}

		public void stop_sync (Cancellable? cancellable = null) throws IOError {
			try {
				create<StopTask> ().execute (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}
		}

		private class StopTask : PortalServiceTask<void> {
			protected override async void perform_operation () throws IOError {
				yield parent.stop (cancellable);
			}
		}

		public async void post (uint connection_id, string message, Bytes? data = null,
				Cancellable? cancellable = null) throws Error, IOError {
			ConnectionEntry? entry = connections[connection_id];
			if (entry != null)
				entry.post (message, data);
		}

		public void post_sync (uint connection_id, string message, Bytes? data = null,
				Cancellable? cancellable = null) throws Error, IOError {
			var task = create<PostTask> ();
			task.connection_id = connection_id;
			task.message = message;
			task.data = data;
			task.execute (cancellable);
		}

		private class PostTask : PortalServiceTask<void> {
			public uint connection_id;
			public string message;
			public Bytes? data;

			protected override async void perform_operation () throws Error, IOError {
				yield parent.post (connection_id, message, data, cancellable);
			}
		}

		public async void broadcast (string message, Bytes? data = null, Cancellable? cancellable = null) throws Error, IOError {
			var has_data = data != null;
			var data_param = has_data ? data.get_data () : new uint8[0];

			foreach (Peer peer in peers.values) {
				ControlChannel? channel = peer as ControlChannel;
				if (channel != null)
					channel.message (message, has_data, data_param);
			}
		}

		public void broadcast_sync (string message, Bytes? data = null, Cancellable? cancellable = null) throws Error, IOError {
			var task = create<BroadcastTask> ();
			task.message = message;
			task.data = data;
			task.execute (cancellable);
		}

		private class BroadcastTask : PortalServiceTask<void> {
			public string message;
			public Bytes? data;

			protected override async void perform_operation () throws Error, IOError {
				yield parent.broadcast (message, data, cancellable);
			}
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		private abstract class PortalServiceTask<T> : AsyncTask<T> {
			public weak PortalService parent {
				get;
				construct;
			}
		}

		private bool on_incoming_connection (SocketConnection connection, Object? source_object) {
			var parameters = (EndpointParameters) source_object;
			handle_incoming_connection.begin (connection, parameters);
			return true;
		}

		private async void handle_incoming_connection (SocketConnection socket_connection,
				EndpointParameters parameters) throws GLib.Error {
			var socket = socket_connection.socket;
			if (socket.get_family () != UNIX)
				Tcp.enable_nodelay (socket);

			IOStream stream = socket_connection;

			TlsCertificate? certificate = parameters.certificate;
			if (certificate != null) {
				var tc = TlsServerConnection.new (stream, certificate);
				tc.set_database (null);
				tc.set_certificate (certificate);
				yield tc.handshake_async (Priority.DEFAULT, io_cancellable);
				stream = tc;
			}

			var connection = yield new DBusConnection (stream, guid, DELAY_MESSAGE_PROCESSING, null, io_cancellable);
			connection.on_closed.connect (on_connection_closed);

			uint connection_id = register_connection (socket_connection, parameters);

			Peer peer;
			if (parameters.auth_service != null)
				peer = setup_unauthorized_peer (connection_id, connection, parameters);
			else
				peer = yield setup_authorized_peer (connection_id, connection, parameters);
			peers[connection] = peer;
		}

		private uint register_connection (SocketConnection connection, EndpointParameters parameters) throws GLib.Error {
			uint id = next_connection_id++;
			SocketAddress address = connection.get_remote_address ();

			var entry = new ConnectionEntry (address, parameters);
			connections[id] = entry;

			if (parameters == cluster_params)
				node_connected (id, address);
			else
				controller_connected (id, address);

			return id;
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			Peer peer;
			if (peers.unset (connection, out peer)) {
				peer.close ();

				uint id = peer.connection_id;

				ConnectionEntry meta;
				connections.unset (id, out meta);

				if (meta.parameters == cluster_params)
					node_disconnected (id, meta.address);
				else
					controller_disconnected (id, meta.address);
			}
		}

		private Peer setup_unauthorized_peer (uint connection_id, DBusConnection connection, EndpointParameters parameters) {
			var channel = new AuthenticationChannel (this, connection_id, connection, parameters);

			try {
				if (parameters == cluster_params) {
					PortalSession portal_session = new UnauthorizedPortalSession ();
					channel.take_registration (connection.register_object (ObjectPath.PORTAL_SESSION, portal_session));
				} else {
					HostSession host_session = new UnauthorizedHostSession ();
					channel.take_registration (connection.register_object (ObjectPath.HOST_SESSION, host_session));

					BusSession bus_session = new UnauthorizedBusSession ();
					channel.take_registration (connection.register_object (ObjectPath.BUS_SESSION, bus_session));
				}
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			connection.start_message_processing ();

			return channel;
		}

		private async void promote_authentication_channel (AuthenticationChannel channel, string session_info) throws GLib.Error {
			uint connection_id = channel.connection_id;
			DBusConnection connection = channel.connection;

			peers.unset (connection);
			channel.close ();

			peers[connection] = yield setup_authorized_peer (connection_id, connection, channel.parameters);

			authenticated (connection_id, session_info);
		}

		private void kick_authentication_channel (AuthenticationChannel channel) {
			var source = new IdleSource ();
			source.set_callback (() => {
				channel.connection.close.begin (io_cancellable);
				return false;
			});
			source.attach (MainContext.get_thread_default ());
		}

		private async Peer setup_authorized_peer (uint connection_id, DBusConnection connection,
				EndpointParameters parameters) throws GLib.Error {
			Peer peer;
			if (parameters == cluster_params)
				peer = yield setup_cluster_node (connection_id, connection);
			else
				peer = setup_control_channel (connection_id, connection);

			ConnectionEntry? entry = connections[peer.connection_id];
			if (entry == null)
				throw new Error.TRANSPORT ("Peer disconnected");
			entry.peer = peer;

			return peer;
		}

		private ControlChannel setup_control_channel (uint connection_id, DBusConnection connection) {
			var channel = new ControlChannel (this, connection_id, connection);

			connection.start_message_processing ();

			return channel;
		}

		private void teardown_control_channel (ControlChannel channel) {
			foreach (var id in channel.sessions) {
				AgentSessionEntry? entry = sessions[id];
				if (entry == null)
					continue;

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

			disable_spawn_gating (channel);
		}

		private async ClusterNode setup_cluster_node (uint connection_id, DBusConnection connection) throws GLib.Error {
			var node = new ClusterNode (this, connection_id, connection);
			node.session_closed.connect (on_agent_session_closed);

			connection.start_message_processing ();

			node.session_provider = yield connection.get_proxy (null, ObjectPath.AGENT_SESSION_PROVIDER,
				DBusProxyFlags.NONE, io_cancellable);

			return node;
		}

		private void teardown_cluster_node (ClusterNode node) {
			var no_crash = CrashInfo.empty ();
			foreach (var id in node.sessions) {
				AgentSessionEntry? entry = sessions[id];
				if (entry == null)
					continue;

				ControlChannel? c = entry.controller;
				if (c != null)
					c.sessions.remove (id);

				AgentSession? session = entry.session;
				if (entry.persist_timeout == 0 || session == null) {
					sessions.unset (id);
					if (c != null)
						c.agent_session_detached (id, SessionDetachReason.PROCESS_TERMINATED, no_crash);
				} else {
					entry.detach_node_and_controller ();
					if (c != null)
						c.agent_session_detached (id, SessionDetachReason.CONNECTION_TERMINATED, no_crash);
				}
			}

			Application? app = node.application;
			if (app != null) {
				uint pid = app.pid;

				node_left (node.connection_id, app);

				node_by_pid.unset (pid);
				node_by_identifier.unset (app.identifier);

				PendingSpawn spawn;
				if (pending_spawn.unset (pid, out spawn))
					notify_spawn_removed (spawn.info);
			}
		}

		private HostApplicationInfo[] enumerate_applications () {
			Gee.Collection<ClusterNode> nodes = node_by_identifier.values;
			var result = new HostApplicationInfo[nodes.size];
			int i = 0;
			foreach (var node in nodes) {
				Application app = node.application;
				result[i++] = HostApplicationInfo (app.identifier, app.name, app.pid,
					Icon.to_image_data (app.small_icon),
					Icon.to_image_data (app.large_icon));
			}
			return result;
		}

		private HostProcessInfo[] enumerate_processes () {
			Gee.Collection<ClusterNode> nodes = node_by_identifier.values;
			var result = new HostProcessInfo[nodes.size];
			int i = 0;
			foreach (var node in nodes) {
				Application app = node.application;
				result[i++] = HostProcessInfo (app.pid, app.name,
					Icon.to_image_data (app.small_icon),
					Icon.to_image_data (app.large_icon));
			}
			return result;
		}

		private void enable_spawn_gating (ControlChannel requester) {
			spawn_gaters.add (requester);
			foreach (var spawn in pending_spawn.values)
				spawn.pending_approvers.add (requester);
		}

		private void disable_spawn_gating (ControlChannel requester) {
			if (spawn_gaters.remove (requester)) {
				foreach (uint pid in pending_spawn.keys.to_array ())
					resume (pid, requester);
			}
		}

		private HostSpawnInfo[] enumerate_pending_spawn () {
			var result = new HostSpawnInfo[pending_spawn.size];
			var i = 0;
			foreach (var spawn in pending_spawn.values)
				result[i++] = spawn.info;
			return result;
		}

		private void resume (uint pid, ControlChannel requester) {
			PendingSpawn? spawn = pending_spawn[pid];
			if (spawn == null)
				return;

			var approvers = spawn.pending_approvers;
			approvers.remove (requester);
			if (approvers.is_empty) {
				pending_spawn.unset (pid);

				var node = node_by_pid[pid];
				assert (node != null);
				node.resume ();

				notify_spawn_removed (spawn.info);
			}
		}

		private void kill (uint pid) {
			var node = node_by_pid[pid];
			if (node == null)
				return;

			node.kill ();
		}

		private void handle_bus_message (ControlChannel sender, string message, Bytes? data) {
			this.message (sender.connection_id, message, data);
		}

		private async AgentSessionId attach (uint pid, AgentSessionOptions options, ControlChannel requester,
				Cancellable? cancellable) throws Error, IOError {
			var node = node_by_pid[pid];
			if (node == null)
				throw new Error.PROCESS_NOT_FOUND ("Unable to find process with pid %u", pid);

			var id = AgentSessionId (next_agent_session_id++);

			yield node.open_session (id, options, cancellable);

			requester.sessions.add (id);

			var opts = SessionOptions._deserialize (options.data);

			var entry = new AgentSessionEntry (node, requester, id, opts.persist_timeout, io_cancellable);
			sessions[id] = entry;
			entry.expired.connect (on_agent_session_expired);

			yield link_session (id, entry, requester, cancellable);

			return id;
		}

		private async void reattach (AgentSessionId id, ControlChannel requester, Cancellable? cancellable) throws Error, IOError {
			AgentSessionEntry? entry = sessions[id];
			if (entry == null || entry.controller != null)
				throw new Error.INVALID_OPERATION ("Invalid session ID");
			if (entry.node == null)
				throw new Error.INVALID_OPERATION ("Cluster node is temporarily unavailable");

			requester.sessions.add (id);

			entry.attach_controller (requester);

			yield link_session (id, entry, requester, cancellable);
		}

		private async void link_session (AgentSessionId id, AgentSessionEntry entry, ControlChannel requester,
				Cancellable? cancellable) throws Error, IOError {
			DBusConnection node_connection = entry.node.connection;

			AgentSession? session = entry.session;
			if (session == null) {
				try {
					session = yield node_connection.get_proxy (null, ObjectPath.for_agent_session (id),
						DBusProxyFlags.NONE, cancellable);
				} catch (IOError e) {
					throw_dbus_error (e);
				}
				entry.session = session;
			}

			DBusConnection? controller_connection = requester.connection;
			if (controller_connection != null) {
				AgentMessageSink sink;
				try {
					sink = yield controller_connection.get_proxy (null, ObjectPath.for_agent_message_sink (id),
						DBusProxyFlags.NONE, null);
				} catch (IOError e) {
					throw_dbus_error (e);
				}

				try {
					entry.take_controller_registration (
						controller_connection.register_object (ObjectPath.for_agent_session (id), session));
					entry.take_node_registration (
						node_connection.register_object (ObjectPath.for_agent_message_sink (id), sink));
				} catch (IOError e) {
					assert_not_reached ();
				}
			}
		}

		private async void handle_join_request (ClusterNode node, HostApplicationInfo app, SpawnStartState current_state,
				AgentSessionId[] interrupted_sessions, Cancellable? cancellable,
				out SpawnStartState next_state) throws Error, IOError {
			if (node.application != null)
				throw new Error.PROTOCOL ("Already joined");
			if (node.session_provider == null)
				throw new Error.PROTOCOL ("Missing session provider");

			foreach (AgentSessionId id in interrupted_sessions) {
				AgentSessionEntry? entry = sessions[id];
				if (entry == null)
					continue;
				if (entry.node != null)
					throw new Error.PROTOCOL ("Session already claimed");
				entry.attach_node (node);
			}

			uint pid = app.pid;
			while (node_by_pid.has_key (pid))
				pid++;

			string real_identifier = app.identifier;
			string candidate = real_identifier;
			uint serial = 2;
			while (node_by_identifier.has_key (candidate))
				candidate = "%s[%u]".printf (real_identifier, serial++);
			string identifier = candidate;

			node.application = new Application (identifier, app.name, pid,
				Icon.from_image_data (app.small_icon),
				Icon.from_image_data (app.large_icon));

			node_by_pid[pid] = node;
			node_by_identifier[identifier] = node;

			node_joined (node.connection_id, node.application);

			if (current_state == SUSPENDED && !spawn_gaters.is_empty) {
				next_state = SUSPENDED;

				var spawn = new PendingSpawn (pid, identifier, spawn_gaters.iterator ());
				pending_spawn[pid] = spawn;
				notify_spawn_added (spawn.info);
			} else {
				next_state = RUNNING;
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

		private void on_agent_session_expired (AgentSessionEntry entry) {
			sessions.unset (entry.id);
		}

		private void on_agent_session_closed (AgentSessionId id) {
			AgentSessionEntry entry;
			if (sessions.unset (id, out entry)) {
				ControlChannel? controller = entry.controller;
				if (controller != null) {
					controller.agent_session_detached (id, SessionDetachReason.APPLICATION_REQUESTED,
						CrashInfo.empty ());
				}
			}
		}

		private class PortalHostSessionProvider : Object, HostSessionProvider {
			public weak PortalService parent {
				get;
				construct;
			}

			public string id {
				get { return "portal"; }
			}

			public string name {
				get { return _name; }
			}
			private string _name = "Portal";

			public Image? icon {
				get { return _icon; }
			}
			private Image _icon = new Image (ImageData (16, 16, 16 * 4, "AAAAAAAAAAAAAAAAOjo6Dzo6OhQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOjo6TZCHbvlycnL4Ojo6iTo6OhMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOjo6aa6fdv7878f/+/Te/93d3f9xcXH3Ojo6gTo6Og8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOjo6F4KAfv//5Hn//fHK//r6+v/39/f/9/f3/9LS0v9kZGTzOjo6eDo6OgsAAAAAAAAAAAAAAAAAAAAAAAAAADo6Og6Tk5P/zc3N//z8/P/6+vr/8PDw/+7u7v/p6en/9PT0/8jIyP9XV1f2Ojo6SgAAAAAAAAAAAAAAAAAAAAA6OjoIb29v/8HBwf+5ubn/9/f3/+/v7//p6en/+Pj4/+np6f/o6Oj/4ODg/z09PcsAAAAAAAAAAAAAAAAAAAAAAAAAAjMzM1p8fHz/wsLC/7CwsP/x8fH/8/P0/9zc3f/09PT/+vr6/8vLy/9AQEDFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALS0tV2pqav7BwcH/rq6u/+bm5v/09PT/s7Oz/93d3f/R0dL/VVVVygAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjIyNRWlpa+7+/v/+wsLD/oaGh/4iIiP9NTU7/VVVW/0BAQf89PT61Pj4/BgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABsbG09NTU32urq6/4yMjP9ycnL/Pj4//1BQUf9tbW7/XFxd/z4+P8M+Pj8PAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAExMTTD09PfBzc3P/LCwsvDAwMbVEREX/f3+A/6ioqf9tbW7zPj4/lAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANDQ0vGRkZggAAAAAAAAAAJycnh0NDRP2GhojujIyP4EtLS4k/Pz8YAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjIyRoRUVFq21tbp5TU1ZUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACkpK10AAAAWAAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="));

			public HostSessionProviderKind kind {
				get { return HostSessionProviderKind.LOCAL; }
			}

			private ControlChannel? channel;

			public PortalHostSessionProvider (PortalService parent) {
				Object (parent: parent);
			}

			public async HostSession create (HostSessionOptions? options, Cancellable? cancellable) throws Error, IOError {
				if (channel != null)
					throw new Error.INVALID_OPERATION ("Already created");

				channel = new ControlChannel (parent);
				channel.agent_session_detached.connect (on_agent_session_detached);

				return channel;
			}

			public async void destroy (HostSession host_session, Cancellable? cancellable) throws Error, IOError {
				if (host_session != channel)
					throw new Error.INVALID_ARGUMENT ("Invalid host session");

				channel.agent_session_detached.disconnect (on_agent_session_detached);

				HostSession session = channel;

				channel.close ();
				channel = null;

				host_session_detached (session);
			}

			public async AgentSession link_agent_session (HostSession host_session, AgentSessionId id, AgentMessageSink sink,
					Cancellable? cancellable) throws Error, IOError {
				if (host_session != channel)
					throw new Error.INVALID_ARGUMENT ("Invalid host session");

				AgentSessionEntry entry = parent.sessions[id];
				if (entry == null)
					throw new Error.INVALID_ARGUMENT ("Invalid session ID");

				try {
					entry.take_node_registration (
						entry.node.connection.register_object (ObjectPath.for_agent_message_sink (id), sink));
				} catch (IOError e) {
					assert_not_reached ();
				}

				return entry.session;
			}

			private void on_agent_session_detached (AgentSessionId id, SessionDetachReason reason, CrashInfo crash) {
				agent_session_detached (id, reason, crash);
			}
		}

		private class ConnectionEntry {
			public SocketAddress address {
				get;
				private set;
			}

			public EndpointParameters parameters {
				get;
				private set;
			}

			public Peer? peer {
				get;
				set;
			}

			public ConnectionEntry (SocketAddress address, EndpointParameters parameters) {
				this.address = address;
				this.parameters = parameters;
			}

			public void post (string message, Bytes? data) {
				if (peer == null)
					return;

				ControlChannel? channel = peer as ControlChannel;
				if (channel == null)
					return;

				bool has_data = data != null;
				var data_param = has_data ? data.get_data () : new uint8[0];
				channel.message (message, has_data, data_param);
			}
		}

		private interface Peer : Object {
			public abstract uint connection_id {
				get;
				construct;
			}

			public abstract void close ();
		}

		private class AuthenticationChannel : Object, Peer, AuthenticationService {
			public weak PortalService parent {
				get;
				construct;
			}

			public uint connection_id {
				get;
				construct;
			}

			public DBusConnection connection {
				get;
				construct;
			}

			public EndpointParameters parameters {
				get;
				construct;
			}

			private Gee.Collection<uint> registrations = new Gee.ArrayList<uint> ();

			public AuthenticationChannel (PortalService parent, uint connection_id, DBusConnection connection,
					EndpointParameters parameters) {
				Object (
					parent: parent,
					connection_id: connection_id,
					connection: connection,
					parameters: parameters
				);
			}

			construct {
				try {
					registrations.add (connection.register_object (ObjectPath.AUTHENTICATION_SERVICE,
						(AuthenticationService) this));
				} catch (IOError e) {
					assert_not_reached ();
				}
			}

			public void close () {
				foreach (var id in registrations)
					connection.unregister_object (id);
				registrations.clear ();
			}

			public void take_registration (uint id) {
				registrations.add (id);
			}

			public async string authenticate (string token, Cancellable? cancellable) throws GLib.Error {
				try {
					string session_info = yield parameters.auth_service.authenticate (token, cancellable);
					yield parent.promote_authentication_channel (this, session_info);
					return session_info;
				} catch (GLib.Error e) {
					if (e is Error.INVALID_ARGUMENT)
						parent.kick_authentication_channel (this);
					throw e;
				}
			}
		}

		private class ControlChannel : Object, Peer, HostSession, BusSession {
			public weak PortalService parent {
				get;
				construct;
			}

			public uint connection_id {
				get;
				construct;
			}

			public DBusConnection? connection {
				get;
				construct;
			}

			public Gee.Set<AgentSessionId?> sessions {
				get;
				default = new Gee.HashSet<AgentSessionId?> (AgentSessionId.hash, AgentSessionId.equal);
			}

			private Gee.Set<uint> registrations = new Gee.HashSet<uint> ();

			public ControlChannel (PortalService parent, uint connection_id = 0, DBusConnection? connection = null) {
				Object (
					parent: parent,
					connection_id: connection_id,
					connection: connection
				);
			}

			construct {
				if (connection != null) {
					try {
						registrations.add (
							connection.register_object (ObjectPath.HOST_SESSION, (HostSession) this));

						registrations.add (
							connection.register_object (ObjectPath.BUS_SESSION, (BusSession) this));

						AuthenticationService null_auth = new NullAuthenticationService ();
						registrations.add (
							connection.register_object (Frida.ObjectPath.AUTHENTICATION_SERVICE, null_auth));
					} catch (IOError e) {
						assert_not_reached ();
					}
				}
			}

			public void close () {
				parent.teardown_control_channel (this);

				if (connection != null) {
					foreach (var id in registrations)
						connection.unregister_object (id);
					registrations.clear ();
				}
			}

			public async HostApplicationInfo get_frontmost_application (Cancellable? cancellable) throws Error, IOError {
				throw new Error.NOT_SUPPORTED ("Not supported");
			}

			public async HostApplicationInfo[] enumerate_applications (Cancellable? cancellable) throws Error, IOError {
				return parent.enumerate_applications ();
			}

			public async HostProcessInfo[] enumerate_processes (Cancellable? cancellable) throws Error, IOError {
				return parent.enumerate_processes ();
			}

			public async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
				parent.enable_spawn_gating (this);
			}

			public async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
				parent.disable_spawn_gating (this);
			}

			public async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws Error, IOError {
				return parent.enumerate_pending_spawn ();
			}

			public async HostChildInfo[] enumerate_pending_children (Cancellable? cancellable) throws Error, IOError {
				return {};
			}

			public async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError {
				throw new Error.NOT_SUPPORTED ("Not supported");
			}

			public async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError {
				throw new Error.NOT_SUPPORTED ("Not supported");
			}

			public async void resume (uint pid, Cancellable? cancellable) throws Error, IOError {
				parent.resume (pid, this);
			}

			public async void kill (uint pid, Cancellable? cancellable) throws Error, IOError {
				parent.kill (pid);
			}

			public async AgentSessionId attach (uint pid, AgentSessionOptions options,
					Cancellable? cancellable) throws Error, IOError {
				return yield parent.attach (pid, options, this, cancellable);
			}

			public async void reattach (AgentSessionId id, Cancellable? cancellable) throws Error, IOError {
				yield parent.reattach (id, this, cancellable);
			}

			public async InjectorPayloadId inject_library_file (uint pid, string path, string entrypoint, string data,
					Cancellable? cancellable) throws Error, IOError {
				throw new Error.NOT_SUPPORTED ("Not supported");
			}

			public async InjectorPayloadId inject_library_blob (uint pid, uint8[] blob, string entrypoint, string data,
					Cancellable? cancellable) throws Error, IOError {
				throw new Error.NOT_SUPPORTED ("Not supported");
			}

			public async void post (string message, bool has_data, uint8[] data,
					Cancellable? cancellable) throws Error, IOError {
				parent.handle_bus_message (this, message, has_data ? new Bytes (data) : null);
			}
		}

		private class ClusterNode : Object, Peer, PortalSession {
			public signal void session_closed (AgentSessionId id);

			public weak PortalService parent {
				get;
				construct;
			}

			public uint connection_id {
				get;
				construct;
			}

			public Application? application {
				get;
				set;
			}

			public DBusConnection connection {
				get;
				construct;
			}

			public AgentSessionProvider? session_provider {
				get {
					return _session_provider;
				}
				set {
					if (_session_provider != null)
						_session_provider.closed.disconnect (on_session_closed);
					_session_provider = value;
					_session_provider.closed.connect (on_session_closed);
				}
			}
			private AgentSessionProvider? _session_provider;

			public Gee.Set<AgentSessionId?> sessions {
				get;
				default = new Gee.HashSet<AgentSessionId?> (AgentSessionId.hash, AgentSessionId.equal);
			}

			private Gee.Set<uint> registrations = new Gee.HashSet<uint> ();

			public ClusterNode (PortalService parent, uint connection_id, DBusConnection connection) {
				Object (
					parent: parent,
					connection_id: connection_id,
					connection: connection
				);
			}

			construct {
				try {
					PortalSession session = this;
					registrations.add (connection.register_object (ObjectPath.PORTAL_SESSION, session));

					AuthenticationService null_auth = new NullAuthenticationService ();
					registrations.add (connection.register_object (Frida.ObjectPath.AUTHENTICATION_SERVICE, null_auth));
				} catch (IOError e) {
					assert_not_reached ();
				}
			}

			public void close () {
				parent.teardown_cluster_node (this);

				foreach (var id in registrations)
					connection.unregister_object (id);
				registrations.clear ();
			}

			public async void join (HostApplicationInfo app, SpawnStartState current_state,
					AgentSessionId[] interrupted_sessions, Cancellable? cancellable,
					out SpawnStartState next_state) throws Error, IOError {
				yield parent.handle_join_request (this, app, current_state, interrupted_sessions, cancellable,
					out next_state);
			}

			public async void open_session (AgentSessionId id, AgentSessionOptions options,
					Cancellable? cancellable) throws Error, IOError {
				try {
					yield session_provider.open (id, options, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}

				sessions.add (id);
			}

			private void on_session_closed (AgentSessionId id) {
				if (sessions.remove (id))
					session_closed (id);
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

			public ClusterNode? node {
				get;
				private set;
			}

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

			public Cancellable io_cancellable {
				get;
				private set;
			}

			private Gee.Collection<uint> node_registrations = new Gee.ArrayList<uint> ();
			private Gee.Collection<uint> controller_registrations = new Gee.ArrayList<uint> ();

			private TimeoutSource? expiry_timer;

			public AgentSessionEntry (ClusterNode node, ControlChannel controller, AgentSessionId id, uint persist_timeout,
					Cancellable io_cancellable) {
				this.node = node;
				this.controller = controller;
				this.id = id;
				this.persist_timeout = persist_timeout;
				this.io_cancellable = io_cancellable;
			}

			~AgentSessionEntry () {
				stop_expiry_timer ();
				unregister_all ();
			}

			public void detach_node_and_controller () {
				unregister_all ();
				node = null;
				controller = null;

				start_expiry_timer ();
			}

			public void attach_node (ClusterNode n) {
				assert (node == null);
				node = n;
			}

			public void detach_controller () {
				unregister_all ();
				controller = null;

				start_expiry_timer ();
			}

			public void attach_controller (ControlChannel c) {
				stop_expiry_timer ();

				assert (node != null);
				assert (controller == null);
				controller = c;
			}

			public void take_node_registration (uint id) {
				node_registrations.add (id);
			}

			public void take_controller_registration (uint id) {
				controller_registrations.add (id);
			}

			private void unregister_all () {
				if (controller != null)
					unregister_all_in (controller_registrations, controller.connection);
				if (node != null)
					unregister_all_in (node_registrations, node.connection);
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
	}
}
