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

		public Image? icon {
			get { return null; }
		}

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.LOCAL; }
		}

		private QnxHostSession host_session;

		public async void close (Cancellable? cancellable) throws IOError {
			if (host_session == null)
				return;
			host_session.agent_session_closed.disconnect (on_agent_session_closed);
			yield host_session.close (cancellable);
			host_session = null;
		}

		public async HostSession create (string? location, Cancellable? cancellable) throws Error, IOError {
			assert (location == null);
			if (host_session != null)
				throw new Error.INVALID_ARGUMENT ("Invalid location: already created");
			host_session = new QnxHostSession ();
			host_session.agent_session_closed.connect (on_agent_session_closed);
			return host_session;
		}

		public async void destroy (HostSession session, Cancellable? cancellable) throws Error, IOError {
			if (session != host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");
			host_session.agent_session_closed.disconnect (on_agent_session_closed);
			yield host_session.close (cancellable);
			host_session = null;
		}

		public async AgentSession obtain_agent_session (HostSession host_session, AgentSessionId agent_session_id,
				Cancellable? cancellable) throws Error, IOError {
			if (host_session != this.host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");
			return this.host_session.obtain_agent_session (agent_session_id);
		}

		private void on_agent_session_closed (AgentSessionId id, AgentSession session, SessionDetachReason reason,
				CrashInfo? crash) {
			agent_session_closed (id, reason, crash);
		}
	}

	public class QnxHostSession : BaseDBusHostSession {
		private AgentContainer system_session_container;

		private AgentDescriptor agent_desc;

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

		public override async HostApplicationInfo get_frontmost_application (Cancellable? cancellable) throws Error, IOError {
			return System.get_frontmost_application ();
		}

		public override async HostApplicationInfo[] enumerate_applications (Cancellable? cancellable) throws Error, IOError {
			return System.enumerate_applications ();
		}

		public override async HostProcessInfo[] enumerate_processes (Cancellable? cancellable) throws Error, IOError {
			return System.enumerate_processes ();
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

			yield wait_for_uninject (injector, cancellable, () => {
				return injectee_by_pid.has_key (pid);
			});

			var id = yield qinjector.inject_library_resource (pid, agent_desc, "frida_agent_main", t.remote_address,
				cancellable);
			injectee_by_pid[pid] = id;

			transport = t;

			return stream_request;
		}

		private void on_uninjected (uint id) {
			foreach (var entry in injectee_by_pid.entries) {
				if (entry.value == id) {
					injectee_by_pid.unset (entry.key);
					return;
				}
			}

			uninjected (InjectorPayloadId (id));
		}
	}
}
