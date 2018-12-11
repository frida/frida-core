namespace Frida {
	public class QnxHostSessionBackend : Object, HostSessionBackend {
		private QnxHostSessionProvider local_provider;

		public async void start () {
			assert (local_provider == null);
			local_provider = new QnxHostSessionProvider ();
			provider_available (local_provider);
		}

		public async void stop () {
			assert (local_provider != null);
			provider_unavailable (local_provider);
			yield local_provider.close ();
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

		public async void close () {
			if (host_session != null) {
				host_session.agent_session_closed.disconnect (on_agent_session_closed);
				yield host_session.close ();
				host_session = null;
			}
		}

		public async HostSession create (string? location = null) throws Error {
			assert (location == null);
			if (host_session != null)
				throw new Error.INVALID_ARGUMENT ("Invalid location: already created");
			host_session = new QnxHostSession ();
			host_session.agent_session_closed.connect (on_agent_session_closed);
			return host_session;
		}

		public async void destroy (HostSession session) throws Error {
			if (session != host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");
			host_session.agent_session_closed.disconnect (on_agent_session_closed);
			yield host_session.close ();
			host_session = null;
		}

		public async AgentSession obtain_agent_session (HostSession host_session, AgentSessionId agent_session_id) throws Error {
			if (host_session != this.host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");
			return yield this.host_session.obtain_agent_session (agent_session_id);
		}

		private void on_agent_session_closed (AgentSessionId id, AgentSession session, SessionDetachReason reason, string? crash_report) {
			agent_session_closed (id, reason, crash_report);
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

		public override async void close () {
			yield base.close ();

			var qinjector = injector as Qinjector;

			var uninjected_handler = injector.uninjected.connect ((id) => close.callback ());
			while (qinjector.any_still_injected ())
				yield;
			injector.disconnect (uninjected_handler);

			injector.uninjected.disconnect (on_uninjected);
			injector = null;

			if (system_session_container != null) {
				yield system_session_container.destroy ();
				system_session_container = null;
			}
		}

		protected override async AgentSessionProvider create_system_session_provider (out DBusConnection connection) throws Error {
			var qinjector = injector as Qinjector;

			PipeTransport.set_temp_directory (qinjector.temp_directory);

			var agent_filename = qinjector.resource_store.ensure_copy_of (agent_desc);
			system_session_container = yield AgentContainer.create (agent_filename);

			connection = system_session_container.connection;

			return system_session_container;
		}

		public override async HostApplicationInfo get_frontmost_application () throws Error {
			return System.get_frontmost_application ();
		}

		public override async HostApplicationInfo[] enumerate_applications () throws Error {
			return System.enumerate_applications ();
		}

		public override async Frida.HostProcessInfo[] enumerate_processes () throws Error {
			return System.enumerate_processes ();
		}

		public override async void enable_spawn_gating () throws Error {
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		public override async void disable_spawn_gating () throws Error {
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		public override async HostSpawnInfo[] enumerate_pending_spawn () throws Error {
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		public override async uint spawn (string program, HostSpawnOptions options) throws Error {
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		protected override bool process_is_alive (uint pid) {
			return Posix.kill ((Posix.pid_t) pid, 0) == 0 || Posix.errno == Posix.EPERM;
		}

		public override async void input (uint pid, uint8[] data) throws Error {
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		protected override async void perform_resume (uint pid) throws Error {
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		public override async void kill (uint pid) throws Error {
			System.kill (pid);
		}

		protected override async Gee.Promise<IOStream> perform_attach_to (uint pid, out Object? transport) throws Error {
			var qinjector = injector as Qinjector;

			PipeTransport.set_temp_directory (qinjector.temp_directory);

			PipeTransport t;
			try {
				t = new PipeTransport ();
			} catch (IOError e) {
				throw new Error.NOT_SUPPORTED (e.message);
			}

			var stream_request = Pipe.open (t.local_address);

			var uninjected_handler = injector.uninjected.connect ((id) => perform_attach_to.callback ());
			while (injectee_by_pid.has_key (pid))
				yield;
			injector.disconnect (uninjected_handler);

			var id = yield qinjector.inject_library_resource (pid, agent_desc, "frida_agent_main", t.remote_address);
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
