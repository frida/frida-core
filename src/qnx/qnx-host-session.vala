namespace Frida {
	public class QnxHostSessionBackend : Object, HostSessionBackend {
		private QnxHostSessionProvider local_provider;

		public async void start (Cancellable? cancellable) throws IOError {
			assert (local_provider == null);
			local_provider = new QnxHostSessionProvider ();
			provider_available (local_provider);
		}

		public async void stop (Cancellable? cancellable) throws IOError {
			assert (local_provider != null);
			provider_unavailable (local_provider);
			yield local_provider.close (cancellable);
			local_provider = null;
		}
	}

	public class QnxHostSessionProvider : Object, HostSessionProvider {
		public string id {
			get { return "local"; }
		}

		public string name {
			get { return "Local System"; }
		}

		public Variant? icon {
			get { return null; }
		}

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.LOCAL; }
		}

		private QnxHostSession host_session;

		public async void close (Cancellable? cancellable) throws IOError {
			if (host_session == null)
				return;
			host_session.agent_session_detached.disconnect (on_agent_session_detached);
			yield host_session.close (cancellable);
			host_session = null;
		}

		public async HostSession create (HostSessionOptions? options, Cancellable? cancellable) throws Error, IOError {
			if (host_session != null)
				throw new Error.INVALID_OPERATION ("Already created");

			host_session = new QnxHostSession ();
			host_session.agent_session_detached.connect (on_agent_session_detached);

			return host_session;
		}

		public async void destroy (HostSession session, Cancellable? cancellable) throws Error, IOError {
			if (session != host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");

			host_session.agent_session_detached.disconnect (on_agent_session_detached);

			yield host_session.close (cancellable);
			host_session = null;
		}

		public async AgentSession link_agent_session (HostSession host_session, AgentSessionId id, AgentMessageSink sink,
				Cancellable? cancellable) throws Error, IOError {
			if (host_session != this.host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");

			return yield this.host_session.link_agent_session (id, sink, cancellable);
		}

		private void on_agent_session_detached (AgentSessionId id, SessionDetachReason reason, CrashInfo crash) {
			agent_session_detached (id, reason, crash);
		}
	}

	public class QnxHostSession : BaseDBusHostSession {
		private AgentContainer system_session_container;

		private AgentDescriptor agent_desc;

		private ApplicationEnumerator application_enumerator = new ApplicationEnumerator ();
		private ProcessEnumerator process_enumerator = new ProcessEnumerator ();

		construct {
			injector = new Qinjector ();
			injector.uninjected.connect (on_uninjected);

			var blob = Frida.Data.Agent.get_frida_agent_so_blob ();
			agent_desc = new AgentDescriptor (blob.name, new MemoryInputStream.from_data (blob.data, null));
		}

		public override async void close (Cancellable? cancellable) throws IOError {
			yield base.close (cancellable);

			var qinjector = injector as Qinjector;

			yield wait_for_uninject (injector, cancellable, () => {
				return qinjector.any_still_injected ();
			});

			injector.uninjected.disconnect (on_uninjected);
			yield injector.close (cancellable);

			if (system_session_container != null) {
				yield system_session_container.destroy (cancellable);
				system_session_container = null;
			}
		}

		protected override async AgentSessionProvider create_system_session_provider (Cancellable? cancellable,
				out DBusConnection connection) throws Error, IOError {
			var qinjector = injector as Qinjector;

			PipeTransport.set_temp_directory (qinjector.temp_directory);

			var agent_filename = qinjector.resource_store.ensure_copy_of (agent_desc);
			system_session_container = yield AgentContainer.create (agent_filename, cancellable);

			connection = system_session_container.connection;

			return system_session_container;
		}

		public override async HostApplicationInfo get_frontmost_application (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			return System.get_frontmost_application (FrontmostQueryOptions._deserialize (options));
		}

		public override async HostApplicationInfo[] enumerate_applications (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			return yield application_enumerator.enumerate_applications (ApplicationQueryOptions._deserialize (options));
		}

		public override async HostProcessInfo[] enumerate_processes (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			return yield process_enumerator.enumerate_processes (ProcessQueryOptions._deserialize (options));
		}

		public override async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		public override async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		public override async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		public override async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable)
				throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		protected override bool process_is_alive (uint pid) {
			return Posix.kill ((Posix.pid_t) pid, 0) == 0 || Posix.errno == Posix.EPERM;
		}

		public override async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		protected override async void perform_resume (uint pid, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		public override async void kill (uint pid, Cancellable? cancellable) throws Error, IOError {
			System.kill (pid);
		}

		protected override async Future<IOStream> perform_attach_to (uint pid, Cancellable? cancellable, out Object? transport)
				throws Error, IOError {
			var qinjector = injector as Qinjector;

			PipeTransport.set_temp_directory (qinjector.temp_directory);

			var t = new PipeTransport ();

			var stream_request = Pipe.open (t.local_address, cancellable);

			var id = yield qinjector.inject_library_resource (pid, agent_desc, "frida_agent_main", t.remote_address,
				cancellable);
			injectee_by_pid[pid] = id;

			transport = t;

			return stream_request;
		}
	}
}
