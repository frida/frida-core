namespace Frida {
	public class PortalService : Object {
		public signal void node_connected (uint connection_id, SocketAddress remote_address);
		public signal void node_joined (uint connection_id, Application application);
		public signal void node_left (uint connection_id, Application application);
		public signal void node_disconnected (uint connection_id, SocketAddress remote_address);

		public signal void controller_connected (uint connection_id, SocketAddress remote_address);
		public signal void controller_disconnected (uint connection_id, SocketAddress remote_address);

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
		private Gee.Map<AgentSessionId?, ControlChannel> sessions =
			new Gee.HashMap<AgentSessionId?, ControlChannel> (AgentSessionId.hash, AgentSessionId.equal);
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

			var connection = yield new DBusConnection (stream, guid,
				AUTHENTICATION_SERVER | AUTHENTICATION_ALLOW_ANONYMOUS | DELAY_MESSAGE_PROCESSING, null, io_cancellable);
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

		private async void promote_authentication_channel (AuthenticationChannel channel) throws GLib.Error {
			DBusConnection connection = channel.connection;

			peers.unset (connection);
			channel.close ();

			peers[connection] = yield setup_authorized_peer (channel.connection_id, connection, channel.parameters);
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
			foreach (var session in channel.sessions.values)
				session.close.begin (io_cancellable);

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
			foreach (var id in node.sessions) {
				ControlChannel c;
				if (sessions.unset (id, out c)) {
					c.unregister_agent_session (id);
					c.agent_session_destroyed (id, SessionDetachReason.PROCESS_TERMINATED);
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

		private async AgentSession attach (uint pid, Realm realm, ControlChannel requester, Cancellable? cancellable,
				out AgentSessionId id) throws Error, IOError {
			var node = node_by_pid[pid];
			if (node == null)
				throw new Error.PROCESS_NOT_FOUND ("Unable to find process with pid %u", pid);

			id = AgentSessionId (next_agent_session_id++);

			var session = yield node.open_session (id, realm, cancellable);
			sessions[id] = requester;

			return session;
		}

		private async void handle_join_request (ClusterNode node, HostApplicationInfo app, SpawnStartState current_state,
				Cancellable? cancellable, out SpawnStartState next_state) throws Error, IOError {
			if (node.application != null)
				throw new Error.PROTOCOL ("Already joined");
			if (node.session_provider == null)
				throw new Error.PROTOCOL ("Missing session provider");

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

		private void on_agent_session_closed (AgentSessionId id) {
			ControlChannel channel;
			if (sessions.unset (id, out channel)) {
				channel.unregister_agent_session (id);

				channel.agent_session_destroyed (id, SessionDetachReason.APPLICATION_REQUESTED);
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
				channel.agent_session_destroyed.connect (on_agent_session_destroyed);
				channel.agent_session_crashed.connect (on_agent_session_crashed);

				return channel;
			}

			public async void destroy (HostSession host_session, Cancellable? cancellable) throws Error, IOError {
				if (host_session != channel)
					throw new Error.INVALID_ARGUMENT ("Invalid host session");

				channel.agent_session_destroyed.disconnect (on_agent_session_destroyed);
				channel.agent_session_crashed.disconnect (on_agent_session_crashed);

				HostSession session = channel;

				channel.close ();
				channel = null;

				host_session_closed (session);
			}

			public async AgentSession obtain_agent_session (HostSession host_session, AgentSessionId id,
					Cancellable? cancellable) throws Error, IOError {
				if (host_session != channel)
					throw new Error.INVALID_ARGUMENT ("Invalid host session");

				var session = channel.sessions[id];
				if (session == null)
					throw new Error.INVALID_ARGUMENT ("Invalid session ID");
				return session;
			}

			public void migrate_agent_session (HostSession host_session, AgentSessionId id, AgentSession new_session) throws Error {
				if (host_session != channel)
					throw new Error.INVALID_ARGUMENT ("Invalid host session");

				if (!channel.sessions.has_key (id))
					throw new Error.INVALID_ARGUMENT ("Invalid session ID");

				channel.unregister_agent_session (id);
				channel.sessions[id] = new_session;
			}

			private void on_agent_session_destroyed (AgentSessionId id, SessionDetachReason reason) {
				agent_session_closed (id, reason, null);
			}

			private void on_agent_session_crashed (AgentSessionId id, CrashInfo crash) {
				agent_session_closed (id, SessionDetachReason.PROCESS_TERMINATED, crash);
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
				get {
					return _peer;
				}
				set {
					_peer = value;
					if (_peer != null)
						deliver_pending_messages ();
				}
			}
			private Peer? _peer;

			private Gee.Queue<BusMessage> pending_messages = new Gee.ArrayQueue<BusMessage> ();

			public ConnectionEntry (SocketAddress address, EndpointParameters parameters) {
				this.address = address;
				this.parameters = parameters;
			}

			public void post (string message, Bytes? data) {
				if (peer != null) {
					ControlChannel? channel = peer as ControlChannel;
					if (channel == null)
						return;
					emit_bus_message (channel, message, data);
				} else {
					pending_messages.offer (new BusMessage (message, data));
				}
			}

			private void deliver_pending_messages () {
				ControlChannel? channel = peer as ControlChannel;
				if (channel == null) {
					pending_messages.clear ();
					return;
				}

				BusMessage? m;
				while ((m = pending_messages.poll ()) != null)
					emit_bus_message (channel, m.message, m.data);
			}

			private void emit_bus_message (ControlChannel channel, string message, Bytes? data) {
				bool has_data = data != null;
				var data_param = has_data ? data.get_data () : new uint8[0];
				channel.message (message, has_data, data_param);
			}

			private class BusMessage {
				public string message {
					get;
					private set;
				}

				public Bytes? data {
					get;
					private set;
				}

				public BusMessage (string message, Bytes? data) {
					this.message = message;
					this.data = data;
				}
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

			public async void authenticate (string token, Cancellable? cancellable) throws GLib.Error {
				try {
					yield parameters.auth_service.authenticate (token, cancellable);
					yield parent.promote_authentication_channel (this);
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

			public Gee.Map<AgentSessionId?, AgentSession> sessions {
				get;
				default = new Gee.HashMap<AgentSessionId?, AgentSession> (AgentSessionId.hash, AgentSessionId.equal);
			}

			private Gee.Set<uint> registrations = new Gee.HashSet<uint> ();
			private Gee.Map<AgentSessionId?, uint> agent_registrations =
				new Gee.HashMap<AgentSessionId?, uint> (AgentSessionId.hash, AgentSessionId.equal);

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

				agent_registrations.clear ();

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

			public async AgentSessionId attach_to (uint pid, Cancellable? cancellable) throws Error, IOError {
				try {
					return yield attach_in_realm (pid, NATIVE, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
			}

			public async AgentSessionId attach_in_realm (uint pid, Realm realm,
					Cancellable? cancellable) throws Error, IOError {
				AgentSessionId id;
				var session = yield parent.attach (pid, realm, this, cancellable, out id);

				register_agent_session (id, session);

				return id;
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

			private void register_agent_session (AgentSessionId id, AgentSession session) {
				try {
					sessions[id] = session;

					if (connection != null) {
						var registration_id = connection.register_object (ObjectPath.from_agent_session_id (id),
							session);
						registrations.add (registration_id);

						agent_registrations.set (id, registration_id);
					}

					monitor_agent_session (this, id, session);
				} catch (IOError e) {
					assert_not_reached ();
				}
			}

			private static void monitor_agent_session (ControlChannel channel, AgentSessionId id, AgentSession session) {
				unowned ControlChannel ch = channel;
				session.migrated.connect (() => {
					if (ch.sessions.has (id, session))
						ch.unregister_agent_session (id);
				});
			}

			public void unregister_agent_session (AgentSessionId id) {
				uint registration_id;
				if (agent_registrations.unset (id, out registration_id)) {
					registrations.remove (registration_id);
					connection.unregister_object (registration_id);
				}

				sessions.unset (id);
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

			public async void join (HostApplicationInfo app, SpawnStartState current_state, Cancellable? cancellable,
					out SpawnStartState next_state) throws Error, IOError {
				yield parent.handle_join_request (this, app, current_state, cancellable, out next_state);
			}

			public async AgentSession open_session (AgentSessionId id, Realm realm,
					Cancellable? cancellable) throws Error, IOError {
				AgentSession session;
				try {
					yield session_provider.open (id, realm, cancellable);

					session = yield connection.get_proxy (null, ObjectPath.from_agent_session_id (id),
						DBusProxyFlags.NONE, cancellable);
				} catch (GLib.Error e) {
					throw new Error.PROTOCOL ("%s", e.message);
				}

				sessions.add (id);

				return session;
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
	}
}
