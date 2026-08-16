namespace Frida {
	public sealed class BareboneHostSessionBackend : Object, HostSessionBackend {
		private BareboneHostSessionProvider? provider;

		public async void start (Cancellable? cancellable) throws IOError {
			provider = new BareboneHostSessionProvider ();
			provider_available (provider);
		}

		public async void stop (Cancellable? cancellable) throws IOError {
			provider = null;
		}
	}

	public sealed class BareboneHostSessionProvider : Object, HostSessionProvider {
		public string id {
			get {
				return "barebone";
			}
		}

		public string name {
			get {
				return "GDB Remote Stub";
			}
		}

		public Variant? icon {
			get {
				return _icon;
			}
		}

		public HostSessionProviderKind kind {
			get {
				return HostSessionProviderKind.REMOTE;
			}
		}

		private static Variant _icon;
		private BareboneHostSession? host_session;

		static construct {
			_icon = make_provider_icon (Frida.Data.Icons.get_barebone_png_blob ().data);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			if (host_session != null) {
				yield host_session.close (cancellable);
				host_session = null;
			}
		}

		public async HostSession create (HostSessionHub hub, HostSessionOptions? options, Cancellable? cancellable)
				throws Error, IOError {
			if (host_session != null)
				throw new Error.INVALID_OPERATION ("Already created");

			Barebone.Config? config = null;
			if (options != null) {
				Value? val = options.map["config"];
				if (val != null) {
					config = (Barebone.Config) val.get_object ();
					config.check ();
				}
			}

			unowned string? config_path = Environment.get_variable ("FRIDA_BAREBONE_CONFIG");
			if (config == null && config_path != null) {
				try {
					var config_data = yield FS.read_all_text (File.new_for_path (config_path), cancellable);
					var cfg = (Barebone.Config) Json.gobject_from_data (typeof (Barebone.Config), config_data);
					cfg.check ();
					config = cfg;
				} catch (GLib.Error e) {
					throw new Error.INVALID_ARGUMENT ("Unable to load %s: %s", config_path, e.message);
				}
			}

			if (config == null)
				config = new Barebone.Config ();

			Barebone.AgentConfig? resident_agent = config.agent;
			if (resident_agent != null && (resident_agent.transport is Barebone.DeviceTransportConfig
					|| resident_agent.transport is Barebone.SocketTransportConfig)) {
				host_session = yield attach_to_resident_agent (resident_agent.transport, cancellable);
				host_session.agent_session_detached.connect (on_agent_session_detached);

				return host_session;
			}

			SocketConnectable connectable;
			try {
				Barebone.ConnectionConfig c = config.connection;
				connectable = NetworkAddress.parse (c.host, c.port);
			} catch (GLib.Error e) {
				throw new Error.INVALID_ARGUMENT ("Unable to load %s: %s", config_path, e.message);
			}

			IOStream stream;
			try {
				var client = new SocketClient ();
				var connection = yield client.connect_async (connectable, cancellable);

				Tcp.enable_nodelay (connection.socket);

				stream = connection;
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("The specified GDB remote stub cannot be reached: %s", e.message);
			}

			GDB.Client gdb;
			if (config.connection.flavor == Barebone.StubFlavor.VZ)
				gdb = yield Barebone.VzStubClient.open (stream, cancellable);
			else
				gdb = yield GDB.Client.open (stream, cancellable);

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

			// Read the daemon's guest-RAM map only once the stub has halted the VM: reading the
			// high-VA backing while the vCPUs run blocks mach_vm_read. The map is dynamic (the daemon
			// reclaims idle RAM), so VzPhysicalMemory re-reads it on demand as the agent maps pages.
#if DARWIN
			if (config.connection.flavor == VZ && machine is Barebone.Arm64Machine)
				((Barebone.Arm64Machine) machine).physical_memory = Barebone.VzPhysicalMemory.open (config.connection.pid);
#endif

			size_t page_size;
			try {
				page_size = yield machine.query_page_size (cancellable);
			} catch (Error e) {
				page_size = 0;
			}

			// Resolve the kernel's runtime layout before building the allocator: on a scattered
			// SPTM kernel collection the config-supplied addresses are static and must be translated.
			Barebone.KernelRelocation? relocation = null;
			uint64 kernel_base = 0;
			Barebone.ImageConfig? image = config.image;
			if (image != null) {
				if (image.base != null) {
					kernel_base = image.base.address;
				} else {
					var payload = yield Barebone.Img4.parse_file (File.new_for_path (image.file), cancellable);
					uint64? summaries = image.symbols["gLoadedKextSummaries"];
					relocation = yield Barebone.KernelRelocation.compute (machine, payload.data,
						summaries ?? 0, cancellable);
					kernel_base = relocation.reference_base;
				}
			}

			Gee.List<Barebone.ModuleInfo> kernel_modules = new Gee.ArrayList<Barebone.ModuleInfo> ();
			Gee.List<Barebone.SymbolInfo> kernel_symbols = new Gee.ArrayList<Barebone.SymbolInfo> ();
			if (config.kernel == WIN9X) {
				var win9x_layout = yield Barebone.collect_win9x_layout (machine, cancellable);
				kernel_modules = win9x_layout.modules;
				kernel_symbols = win9x_layout.symbols;
			}

			Barebone.Allocator allocator;
			Barebone.AllocatorConfig? ac = config.allocator;
			if (ac == null)
				ac = infer_allocator_config (config.kernel, kernel_symbols);
			if (ac == null) {
				allocator = new Barebone.NullAllocator (page_size);
			} else if (ac is Barebone.PhysicalAllocatorConfig) {
				allocator = new Barebone.PhysicalAllocator (machine, page_size,
					(Barebone.PhysicalAllocatorConfig) ac);
			} else if (ac is Barebone.TargetFunctionsAllocatorConfig) {
				var tfa = (Barebone.TargetFunctionsAllocatorConfig) ac;
				if (relocation != null) {
					tfa.alloc_function = new Barebone.NonNullMemoryAddress ("allocator.alloc_function",
						relocation.translate (tfa.alloc_function.address));
					tfa.free_function = new Barebone.NonNullMemoryAddress ("allocator.free_function",
						relocation.translate (tfa.free_function.address));
				}
				allocator = new Barebone.TargetFunctionsAllocator (machine, page_size, tfa);
			} else {
				assert_not_reached ();
			}

			Barebone.AgentConnection? agent_connection = null;
			Barebone.AgentConfig? agent_config = config.agent;
			if (agent_config != null) {
				agent_connection = yield Barebone.AgentConnection.open (agent_config, config.image, config.kernel,
					relocation, kernel_base, machine, allocator, kernel_modules, kernel_symbols,
					cancellable);
			}

			var interceptor = new Barebone.Interceptor (machine, allocator);

			var services = new Barebone.Services (machine, allocator, interceptor);

			host_session = new BareboneHostSession (agent_connection, services);
			host_session.agent_session_detached.connect (on_agent_session_detached);

			return host_session;
		}

		private async BareboneHostSession attach_to_resident_agent (Barebone.TransportConfig transport,
				Cancellable? cancellable) throws Error, IOError {
#if WINDOWS
			throw new Error.NOT_SUPPORTED ("Resident agents are not available on this OS");
#else
			IOStream stream;
			if (transport is Barebone.SocketTransportConfig) {
				string path = ((Barebone.SocketTransportConfig) transport).path;
				var client = new SocketClient ();
				try {
					stream = yield client.connect_async (new UnixSocketAddress (path), cancellable);
				} catch (GLib.Error e) {
					throw new Error.TRANSPORT ("Unable to connect to %s: %s", path, e.message);
				}
			} else {
				string path = ((Barebone.DeviceTransportConfig) transport).path;
				int fd = Posix.open (path, Posix.O_RDWR);
				if (fd == -1)
					throw new Error.TRANSPORT ("Unable to open %s: %s", path, Posix.strerror (Posix.errno));
				stream = new SimpleIOStream (new UnixInputStream (fd, true), new UnixOutputStream (fd, false));
			}

			var connection = yield Barebone.AgentConnection.open_resident (stream, cancellable);

			return new BareboneHostSession (connection, null);
#endif
		}

		private static Barebone.AllocatorConfig? infer_allocator_config (Barebone.KernelKind kind,
				Gee.List<Barebone.SymbolInfo> kernel_symbols) {
			if (kind != WIN9X)
				return null;

			Barebone.SymbolInfo? alloc = null;
			Barebone.SymbolInfo? free = null;
			foreach (var s in kernel_symbols) {
				if (s.name == "_HeapAllocate")
					alloc = s;
				else if (s.name == "_HeapFree")
					free = s;
			}
			if (alloc == null || free == null)
				return null;

			return new Barebone.TargetFunctionsAllocatorConfig () {
				alloc_function = new Barebone.NonNullMemoryAddress ("allocator.alloc_function", alloc.offset),
				free_function = new Barebone.NonNullMemoryAddress ("allocator.free_function", free.offset),
			};
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
		public Barebone.AgentConnection? connection {
			get;
			construct;
		}

		/** Absent for a resident agent: every service here is built on a debugger stub. */
		public Barebone.Services? services {
			get;
			construct;
		}

		private Gee.Map<AgentSessionId?, BareboneAgentSession> agent_sessions =
			new Gee.HashMap<AgentSessionId?, BareboneAgentSession> (AgentSessionId.hash, AgentSessionId.equal);

		public BareboneHostSession (Barebone.AgentConnection? connection, Barebone.Services? services) {
			Object (connection: connection, services: services);
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
			if (connection == null)
				throw_not_supported ();
			return yield connection.enumerate_processes (ProcessQueryOptions._deserialize (options).scope,
				cancellable);
		}

		public async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async void enable_spawn_gating_with_options (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
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
			if (pid != 0) {
				if (connection == null)
					throw_not_supported ();

				// The agent reports the process that it started in. A different value shows that the copy
				// went to the incorrect process.
				uint64 entry = yield connection.place_user_agent (cancellable);
				uint reached = yield connection.inject_into_process (pid, entry, cancellable);
				if (reached != pid)
					throw new Error.NOT_SUPPORTED ("Agent landed in process %u, not %u", reached, pid);
			}

			var opts = SessionOptions._deserialize (options);
			if (opts.realm == EMULATED)
				throw new Error.NOT_SUPPORTED ("Emulated realm is not supported on Barebone targets");

			var session_id = AgentSessionId.generate ();

			MainContext dbus_context = yield get_dbus_context ();

			BareboneAgentSession session;
			if (connection != null) {
				session = new RemoteBareboneAgentSession (connection, pid, session_id, opts.persist_timeout,
					dbus_context);
			} else {
				if (services == null)
					throw new Error.NOT_SUPPORTED ("Barebone target has neither an agent nor a debugger stub");
				session = new LocalBareboneAgentSession (services, session_id, opts.persist_timeout, dbus_context);
			}
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

	private sealed class LocalBareboneAgentSession : BareboneAgentSession {
		public Barebone.Services services {
			get;
			construct;
		}

		private Gee.Map<AgentScriptId?, BareboneScript> scripts =
			new Gee.HashMap<AgentScriptId?, BareboneScript> (AgentScriptId.hash, AgentScriptId.equal);
		private uint next_script_id = 1;

		public LocalBareboneAgentSession (Barebone.Services services, AgentSessionId id, uint persist_timeout,
				MainContext dbus_context) {
			Object (
				services: services,
				id: id,
				persist_timeout: persist_timeout,
				frida_context: MainContext.ref_thread_default (),
				dbus_context: dbus_context
			);
		}

		public override async AgentScriptId create_script (string source, HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			check_open ();

			var opts = ScriptOptions._deserialize (options);
			if (opts.runtime == V8)
				throw new Error.INVALID_ARGUMENT ("The V8 runtime is not supported by the Barebone backend");

			var id = AgentScriptId (next_script_id++);

			var script = BareboneScript.create (id, source, services);
			scripts[id] = script;
			script.message.connect (on_message_from_script);

			return id;
		}

		public override async void destroy_script (AgentScriptId script_id, Cancellable? cancellable) throws Error, IOError {
			check_open ();

			BareboneScript script = get_script (script_id);
			yield script.destroy (cancellable);
			script.message.disconnect (on_message_from_script);

			scripts.unset (script_id);
		}

		public override async void load_script (AgentScriptId script_id, Cancellable? cancellable) throws Error, IOError {
			check_open ();
			var script = get_script (script_id);
			yield script.load (cancellable);
		}

		public override async void post_messages (AgentMessage[] messages, uint batch_id, Cancellable? cancellable)
				throws Error, IOError {
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

		private void on_message_from_script (BareboneScript script, string json, Bytes? data) {
			transmitter.post_message_from_script (script.id, json, data);
		}

		private BareboneScript get_script (AgentScriptId script_id) throws Error {
			var script = scripts[script_id];
			if (script == null)
				throw new Error.INVALID_ARGUMENT ("Invalid script ID");
			return script;
		}
	}

	private sealed class RemoteBareboneAgentSession : BareboneAgentSession {
		public Barebone.AgentConnection connection {
			get;
			construct;
		}

		// Zero selects the kernel, which is the only target that runs scripts without a copy.
		public uint pid {
			get;
			construct;
		}

		public RemoteBareboneAgentSession (Barebone.AgentConnection connection, uint pid, AgentSessionId id,
				uint persist_timeout, MainContext dbus_context) {
			Object (
				connection: connection,
				pid: pid,
				id: id,
				persist_timeout: persist_timeout,
				frida_context: MainContext.ref_thread_default (),
				dbus_context: dbus_context
			);
		}

		construct {
			connection.script_message.connect (on_message_from_script);
		}

		public override async AgentScriptId create_script (string source, HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			check_open ();

			var opts = ScriptOptions._deserialize (options);
			if (opts.runtime == V8)
				throw new Error.INVALID_ARGUMENT ("The V8 runtime is not supported by the Barebone backend");

			return yield connection.create_script (source, pid, cancellable);
		}

		public override async void destroy_script (AgentScriptId script_id, Cancellable? cancellable) throws Error, IOError {
			check_open ();

			yield connection.destroy_script (script_id, pid, cancellable);
		}

		public override async void load_script (AgentScriptId script_id, Cancellable? cancellable) throws Error, IOError {
			check_open ();

			yield connection.load_script (script_id, pid, cancellable);
		}

		public override async void post_messages (AgentMessage[] messages, uint batch_id, Cancellable? cancellable)
				throws Error, IOError {
			transmitter.check_okay_to_receive ();

			foreach (var m in messages) {
				switch (m.kind) {
					case SCRIPT:
						yield connection.post_script_message (m.script_id, m.text,
							m.has_data ? new Bytes (m.data) : null, pid, cancellable);
						break;
					case DEBUGGER:
						break;
				}
			}

			transmitter.notify_rx_batch_id (batch_id);
		}

		private void on_message_from_script (AgentScriptId id, string json, Bytes? data) {
			transmitter.post_message_from_script (id, json, data);
		}
	}

	private abstract class BareboneAgentSession : Object, AgentSession {
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
			get {
				return transmitter.message_sink;
			}
			set {
				transmitter.message_sink = value;
			}
		}

		public MainContext frida_context {
			get;
			construct;
		}

		public MainContext dbus_context {
			get;
			construct;
		}

		private Promise<bool>? close_request;

		protected AgentMessageTransmitter transmitter;

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

		public abstract async AgentScriptId create_script (string source, HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError;

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

		public abstract async void destroy_script (AgentScriptId script_id, Cancellable? cancellable) throws Error, IOError;

		public abstract async void load_script (AgentScriptId script_id, Cancellable? cancellable) throws Error, IOError;

		public async void interrupt_script (AgentScriptId script_id, Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async void terminate_script (AgentScriptId script_id, Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async void eternalize_script (AgentScriptId script_id, Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async void enable_debugger (AgentScriptId script_id, Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async void disable_debugger (AgentScriptId script_id, Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public abstract async void post_messages (AgentMessage[] messages, uint batch_id, Cancellable? cancellable)
			throws Error, IOError;

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

		protected void check_open () throws Error {
			if (close_request != null)
				throw new Error.INVALID_OPERATION ("Session is closing");
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
