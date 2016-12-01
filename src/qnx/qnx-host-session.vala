#if QNX
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

		public ImageData? icon {
			get { return null; }
		}

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.LOCAL_SYSTEM; }
		}

		private QnxHostSession host_session;

		public async void close () {
			if (host_session != null)
				yield host_session.close ();
			host_session = null;
		}

		public async HostSession create (string? location = null) throws Error {
			assert (location == null);
			if (host_session != null)
				throw new Error.INVALID_ARGUMENT ("Invalid location: already created");
			host_session = new QnxHostSession ();
			host_session.agent_session_closed.connect ((id) => this.agent_session_closed (id));
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

		private void on_agent_session_closed (AgentSessionId id, AgentSession session) {
			agent_session_closed (id);
		}
	}

	public class QnxHostSession : BaseDBusHostSession {
		private AgentContainer system_session_container;

		public Gee.HashMap<uint, void *> instance_by_pid = new Gee.HashMap<uint, void *> ();
		private Gee.HashMap<uint, uint> injectee_by_pid = new Gee.HashMap<uint, uint> ();

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

		public override async HostSpawnInfo[] enumerate_pending_spawns () throws Error {
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		public override async uint spawn (string path, string[] argv, string[] envp) throws Error {
			return _do_spawn (path, argv, envp);
		}

		public override async void input (uint pid, uint8[] data) throws Error {
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		public override async void resume (uint pid) throws Error {
			void * instance;
			bool instance_found = instance_by_pid.unset (pid, out instance);
			if (!instance_found)
				throw new Error.NOT_SUPPORTED ("no such pid");
			_resume_instance (instance);
			_free_instance (instance);
		}

		public override async void kill (uint pid) throws Error {
			void * instance;
			bool instance_found = instance_by_pid.unset (pid, out instance);
			if (instance_found)
				_free_instance (instance);
			System.kill (pid);
		}

		protected override async IOStream perform_attach_to (uint pid, out Object? transport) throws Error {
			var qinjector = injector as Qinjector;

			PipeTransport.set_temp_directory (qinjector.temp_directory);

			PipeTransport t;
			Pipe stream;
			try {
				t = new PipeTransport ();
				stream = new Pipe (t.local_address);
			} catch (IOError stream_error) {
				throw new Error.NOT_SUPPORTED (stream_error.message);
			}

			var uninjected_handler = injector.uninjected.connect ((id) => perform_attach_to.callback ());
			while (injectee_by_pid.has_key (pid))
				yield;
			injector.disconnect (uninjected_handler);

			var id = yield qinjector.inject_library_resource (pid, agent_desc, "frida_agent_main", t.remote_address);
			injectee_by_pid[pid] = id;

			transport = t;

			return stream;
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

		public extern uint _do_spawn (string path, string[] argv, string[] envp) throws Error;
		public extern void _resume_instance (void * instance);
		public extern void _free_instance (void * instance);
	}
}
#endif
