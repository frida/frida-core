namespace Frida {
	public sealed class BareboneHostSessionBackend : Object, HostSessionBackend {
		private BareboneHostSessionProvider? provider;

		private const uint16 DEFAULT_PORT = 3333;

		public async void start (Cancellable? cancellable) throws IOError {
			SocketConnectable? connectable = null;
			unowned string? address = Environment.get_variable ("FRIDA_BAREBONE_ADDRESS");
			if (address != null) {
				try {
					connectable = NetworkAddress.parse (address, DEFAULT_PORT);
				} catch (GLib.Error e) {
				}
			}
			if (connectable == null)
				connectable = new InetSocketAddress (new InetAddress.loopback (SocketFamily.IPV4), DEFAULT_PORT);

			uint64 heap_base_pa = 0;
			unowned string? heap_base_preference = Environment.get_variable ("FRIDA_BAREBONE_HEAP_BASE");
			if (heap_base_preference != null)
				heap_base_pa = uint64.parse (heap_base_preference, 16);

			provider = new BareboneHostSessionProvider (connectable, heap_base_pa);
			provider_available (provider);
		}

		public async void stop (Cancellable? cancellable) throws IOError {
			provider = null;
		}
	}

	public sealed class BareboneHostSessionProvider : Object, HostSessionProvider {
		public string id {
			get { return "barebone"; }
		}

		public string name {
			get { return "GDB Remote Stub"; }
		}

		public Variant? icon {
			get { return null; }
		}

		public HostSessionProviderKind kind {
			get {
				return HostSessionProviderKind.REMOTE;
			}
		}

		public SocketConnectable connectable {
			get;
			construct;
		}

		public uint64 heap_base_pa {
			get;
			construct;
		}

		private BareboneHostSession? host_session;

		public BareboneHostSessionProvider (SocketConnectable connectable, uint64 heap_base_pa) {
			Object (connectable: connectable, heap_base_pa: heap_base_pa);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			if (host_session != null) {
				yield host_session.close (cancellable);
				host_session = null;
			}
		}

		public async HostSession create (HostSessionOptions? options, Cancellable? cancellable) throws Error, IOError {
			if (host_session != null)
				throw new Error.INVALID_OPERATION ("Already created");

			IOStream stream;
			try {
				var client = new SocketClient ();
				var connection = yield client.connect_async (connectable, cancellable);

				Tcp.enable_nodelay (connection.socket);

				stream = connection;
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("The specified GDB remote stub cannot be reached: %s", e.message);
			}

			var gdb = yield GDB.Client.open (stream, cancellable);

			Barebone.Machine machine;
			switch (gdb.arch) {
				case IA32:
					machine = new Barebone.IA32Machine (gdb);
					break;
				case X64:
					machine = new Barebone.X64Machine (gdb);
					break;
				case ARM:
					machine = new Barebone.ArmMachine (gdb);
					break;
				case ARM64:
					machine = new Barebone.Arm64Machine (gdb);
					break;
				default:
					machine = new Barebone.UnknownMachine (gdb);
					break;
			}

			var page_size = yield machine.query_page_size (cancellable);

			// TODO: Locate and use kernel's allocator when possible.
			Barebone.Allocator allocator = new Barebone.SimpleAllocator (machine, page_size, heap_base_pa);

			var interceptor = new Barebone.Interceptor (machine, allocator);

			var services = new Barebone.Services (machine, allocator, interceptor);

			host_session = new BareboneHostSession (services);
			host_session.agent_session_detached.connect (on_agent_session_detached);

			return host_session;
		}

		public async void destroy (HostSession session, Cancellable? cancellable) throws Error, IOError {
			if (session != host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");

			yield host_session.close (cancellable);
			host_session.agent_session_detached.disconnect (on_agent_session_detached);
			host_session = null;
		}

		public async AgentSession link_agent_session (HostSession host_session, AgentSessionId id, AgentMessageSink sink,
				Cancellable? cancellable) throws Error, IOError {
			if (host_session != this.host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");

			return yield this.host_session.link_agent_session (id, sink, cancellable);
		}

		public void unlink_agent_session (HostSession host_session, AgentSessionId id) {
			if (host_session != this.host_session)
				return;

			this.host_session.unlink_agent_session (id);
		}

		public async IOStream link_channel (HostSession host_session, ChannelId id, Cancellable? cancellable)
				throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Channels are not supported by this backend");
		}

		public void unlink_channel (HostSession host_session, ChannelId id) {
		}

		public async ServiceSession link_service_session (HostSession host_session, ServiceSessionId id, Cancellable? cancellable)
				throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Services are not supported by this backend");
		}

		public void unlink_service_session (HostSession host_session, ServiceSessionId id) {
		}

		private void on_agent_session_detached (AgentSessionId id, SessionDetachReason reason, CrashInfo crash) {
			agent_session_detached (id, reason, crash);
		}
	}

	public sealed class BareboneHostSession : Object, HostSession {
		public Barebone.Services services {
			get;
			construct;
		}

		private Gee.Map<AgentSessionId?, BareboneAgentSession> agent_sessions =
			new Gee.HashMap<AgentSessionId?, BareboneAgentSession> (AgentSessionId.hash, AgentSessionId.equal);

		public BareboneHostSession (Barebone.Services services) {
			Object (services: services);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			foreach (BareboneAgentSession session in agent_sessions.values.to_array ()) {
				try {
					yield session.close (cancellable);
				} catch (GLib.Error e) {
					assert (e is IOError.CANCELLED);
					throw (IOError) e;
				}
			}
		}

		public async void ping (uint interval_seconds, Cancellable? cancellable) throws Error, IOError {
			throw new Error.INVALID_OPERATION ("Only meant to be implemented by services");
		}

		public async HashTable<string, Variant> query_system_parameters (Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async HostApplicationInfo get_frontmost_application (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async HostApplicationInfo[] enumerate_applications (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async HostProcessInfo[] enumerate_processes (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async HostChildInfo[] enumerate_pending_children (Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async void resume (uint pid, Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async void kill (uint pid, Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async AgentSessionId attach (uint pid, HashTable<string, Variant> options, Cancellable? cancellable)
				throws Error, IOError {
			if (pid != 0)
				throw_not_supported ();

			var opts = SessionOptions._deserialize (options);
			if (opts.realm == EMULATED)
				throw new Error.NOT_SUPPORTED ("Emulated realm is not supported on barebone targets");

			var session_id = AgentSessionId.generate ();

			MainContext dbus_context = yield get_dbus_context ();

			var session = new BareboneAgentSession (session_id, opts.persist_timeout, dbus_context, services);
			agent_sessions[session_id] = session;
			session.closed.connect (on_agent_session_closed);

			return session_id;
		}

		public async void reattach (AgentSessionId id, Cancellable? cancellable) throws Error, IOError {
			throw new Error.INVALID_OPERATION ("Only meant to be implemented by services");
		}

		public async AgentSession link_agent_session (AgentSessionId id, AgentMessageSink sink,
				Cancellable? cancellable) throws Error, IOError {
			BareboneAgentSession? session = agent_sessions[id];
			if (session == null)
				throw new Error.INVALID_ARGUMENT ("Invalid session ID");

			session.message_sink = sink;

			return session;
		}

		public void unlink_agent_session (AgentSessionId id) {
			BareboneAgentSession? session = agent_sessions[id];
			if (session == null)
				return;

			session.message_sink = null;
		}

		public async InjectorPayloadId inject_library_file (uint pid, string path, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async InjectorPayloadId inject_library_blob (uint pid, uint8[] blob, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async ChannelId open_channel (string address, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Channels are not supported by this backend");
		}

		public async ServiceSessionId open_service (string address, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Services are not supported by this backend");
		}

		private void on_agent_session_closed (BareboneAgentSession session) {
			AgentSessionId id = session.id;

			session.closed.disconnect (on_agent_session_closed);
			agent_sessions.unset (id);

			SessionDetachReason reason = APPLICATION_REQUESTED;
			var no_crash = CrashInfo.empty ();
			agent_session_detached (id, reason, no_crash);
		}
	}

	private sealed class BareboneAgentSession : Object, AgentSession {
		public signal void closed ();

		public AgentSessionId id {
			get;
			construct;
		}

		public uint persist_timeout {
			get;
			construct;
		}

		public AgentMessageSink? message_sink {
			get { return transmitter.message_sink; }
			set { transmitter.message_sink = value; }
		}

		public MainContext frida_context {
			get;
			construct;
		}

		public MainContext dbus_context {
			get;
			construct;
		}

		public Barebone.Services services {
			get;
			construct;
		}

		public Barebone.Allocator allocator {
			get;
			construct;
		}

		private Promise<bool>? close_request;

		private Gee.Map<AgentScriptId?, BareboneScript> scripts =
			new Gee.HashMap<AgentScriptId?, BareboneScript> (AgentScriptId.hash, AgentScriptId.equal);
		private uint next_script_id = 1;

		private AgentMessageTransmitter transmitter;

		public BareboneAgentSession (AgentSessionId id, uint persist_timeout, MainContext dbus_context,
				Barebone.Services services) {
			Object (
				id: id,
				persist_timeout: persist_timeout,
				frida_context: MainContext.ref_thread_default (),
				dbus_context: dbus_context,
				services: services
			);
		}

		construct {
			assert (frida_context != null);
			assert (dbus_context != null);

			transmitter = new AgentMessageTransmitter (this, persist_timeout, frida_context, dbus_context);
			transmitter.closed.connect (on_transmitter_closed);
			transmitter.new_candidates.connect (on_transmitter_new_candidates);
			transmitter.candidate_gathering_done.connect (on_transmitter_candidate_gathering_done);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			while (close_request != null) {
				try {
					yield close_request.future.wait_async (cancellable);
					return;
				} catch (GLib.Error e) {
					assert (e is IOError.CANCELLED);
					cancellable.set_error_if_cancelled ();
				}
			}
			close_request = new Promise<bool> ();

			yield transmitter.close (cancellable);

			close_request.resolve (true);
		}

		public async void interrupt (Cancellable? cancellable) throws Error, IOError {
			transmitter.interrupt ();
		}

		public async void resume (uint rx_batch_id, Cancellable? cancellable, out uint tx_batch_id) throws Error, IOError {
			transmitter.resume (rx_batch_id, out tx_batch_id);
		}

		public async void enable_child_gating (Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async void disable_child_gating (Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async AgentScriptId create_script (string source, HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			check_open ();

			var opts = ScriptOptions._deserialize (options);
			if (opts.runtime == V8)
				throw new Error.INVALID_ARGUMENT ("The V8 runtime is not supported by the barebone backend");

			var id = AgentScriptId (next_script_id++);

			var script = BareboneScript.create (id, source, services);
			scripts[id] = script;
			script.message.connect (on_message_from_script);

			return id;
		}

		public async AgentScriptId create_script_from_bytes (uint8[] bytes, HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async uint8[] compile_script (string source, HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async uint8[] snapshot_script (string embed_script, HashTable<string, Variant> options, Cancellable? cancellable)
				throws Error, IOError {
			throw_not_supported ();
		}

		public async void destroy_script (AgentScriptId script_id, Cancellable? cancellable) throws Error, IOError {
			check_open ();

			BareboneScript script = get_script (script_id);
			yield script.destroy (cancellable);
			script.message.disconnect (on_message_from_script);

			scripts.unset (script_id);
		}

		public async void load_script (AgentScriptId script_id, Cancellable? cancellable) throws Error, IOError {
			check_open ();
			var script = get_script (script_id);
			yield script.load (cancellable);
		}

		public async void eternalize_script (AgentScriptId script_id, Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		private BareboneScript get_script (AgentScriptId script_id) throws Error {
			var script = scripts[script_id];
			if (script == null)
				throw new Error.INVALID_ARGUMENT ("Invalid script ID");
			return script;
		}

		public async void enable_debugger (AgentScriptId script_id, Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async void disable_debugger (AgentScriptId script_id, Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async void post_messages (AgentMessage[] messages, uint batch_id,
				Cancellable? cancellable) throws Error, IOError {
			transmitter.check_okay_to_receive ();

			foreach (var m in messages) {
				switch (m.kind) {
					case SCRIPT: {
						BareboneScript? script = scripts[m.script_id];
						if (script != null)
							script.post (m.text, m.has_data ? new Bytes (m.data) : null);
						break;
					}
					case DEBUGGER:
						break;
				}
			}

			transmitter.notify_rx_batch_id (batch_id);
		}

		public async PortalMembershipId join_portal (string address, HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async void leave_portal (PortalMembershipId membership_id, Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async void offer_peer_connection (string offer_sdp, HashTable<string, Variant> peer_options,
				Cancellable? cancellable, out string answer_sdp) throws Error, IOError {
			yield transmitter.offer_peer_connection (offer_sdp, peer_options, cancellable, out answer_sdp);
		}

		public async void add_candidates (string[] candidate_sdps, Cancellable? cancellable) throws Error, IOError {
			transmitter.add_candidates (candidate_sdps);
		}

		public async void notify_candidate_gathering_done (Cancellable? cancellable) throws Error, IOError {
			transmitter.notify_candidate_gathering_done ();
		}

		public async void begin_migration (Cancellable? cancellable) throws Error, IOError {
			transmitter.begin_migration ();
		}

		public async void commit_migration (Cancellable? cancellable) throws Error, IOError {
			transmitter.commit_migration ();
		}

		private void check_open () throws Error {
			if (close_request != null)
				throw new Error.INVALID_OPERATION ("Session is closing");
		}

		private void on_message_from_script (BareboneScript script, string json, Bytes? data) {
			transmitter.post_message_from_script (script.id, json, data);
		}

		private void on_transmitter_closed () {
			transmitter.closed.disconnect (on_transmitter_closed);
			transmitter.new_candidates.disconnect (on_transmitter_new_candidates);
			transmitter.candidate_gathering_done.disconnect (on_transmitter_candidate_gathering_done);

			closed ();
		}

		private void on_transmitter_new_candidates (string[] candidate_sdps) {
			new_candidates (candidate_sdps);
		}

		private void on_transmitter_candidate_gathering_done () {
			candidate_gathering_done ();
		}
	}

	namespace Barebone {
		public sealed class Services : Object {
			public Machine machine {
				get;
				construct;
			}

			public Allocator allocator {
				get;
				construct;
			}

			public Interceptor interceptor {
				get;
				construct;
			}

			public Services (Machine machine, Allocator allocator, Interceptor interceptor) {
				Object (
					machine: machine,
					allocator: allocator,
					interceptor: interceptor
				);
			}
		}
	}

	[NoReturn]
	private static void throw_not_supported () throws Error {
		throw new Error.NOT_SUPPORTED ("Not yet supported");
	}
}
