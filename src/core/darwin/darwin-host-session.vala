namespace Zed {
	public class DarwinHostSessionBackend : Object, HostSessionBackend {
		private DarwinHostSessionProvider local_provider;

		public async void start () {
			assert (local_provider == null);
			local_provider = new DarwinHostSessionProvider ();
			provider_available (local_provider);
		}

		public async void stop () {
			assert (local_provider != null);
			provider_unavailable (local_provider);
			yield local_provider.close ();
			local_provider = null;
		}
	}

	public class DarwinHostSessionProvider : Object, HostSessionProvider {
		public string name {
			get { return "Local System"; }
		}

		public ImageData? icon {
			get { return null; }
		}

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.LOCAL_SYSTEM; }
		}

		private DarwinHostSession host_session;

		public async void close () {
			if (host_session != null)
				yield host_session.close ();
			host_session = null;
		}

		public async HostSession create () throws IOError {
			if (host_session != null)
				throw new IOError.FAILED ("may only create one HostSession");
			host_session = new DarwinHostSession ();
			host_session.agent_session_closed.connect ((id, error) => this.agent_session_closed (id, error));
			return host_session;
		}

		public async AgentSession obtain_agent_session (AgentSessionId id) throws IOError {
			if (host_session == null)
				throw new IOError.FAILED ("no such id");
			return yield host_session.obtain_agent_session (id);
		}
	}

	public class DarwinHostSession : BaseDBusHostSession, HostSession {
		private MainContext main_context;
		public void * context;
		public Gee.HashMap<uint, void *> instance_by_pid = new Gee.HashMap<uint, void *> ();

		private Fruitjector injector = new Fruitjector ();
		private AgentDescriptor agent_desc;

		construct {
			main_context = MainContext.get_thread_default ();
			_create_context ();

			var blob = Zed.Data.Agent.get_libzed_agent_dylib_blob ();
			agent_desc = new AgentDescriptor (blob.name, new MemoryInputStream.from_data (blob.data, null));
		}

		public override async void close () {
			yield base.close ();

			while (injector.any_still_injected ()) {
				injector.uninjected.connect ((id) => close.callback ());
				yield;
			}

			injector = null;
		}

		public async Zed.HostProcessInfo[] enumerate_processes () throws IOError {
			return System.enumerate_processes ();
		}

		public async uint spawn (string path, string[] argv, string[] envp) throws IOError {
			return _do_spawn (path, argv, envp);
		}

		public async void resume (uint pid) throws IOError {
			_do_resume (pid);
		}

		public async Zed.AgentSessionId attach_to (uint pid) throws IOError {
			var session = allocate_session ();
			yield injector.inject (pid, agent_desc, session.listen_address);
			return session.id;
		}

		public void _on_instance_dead (uint pid) {
			var source = new IdleSource ();
			source.set_callback (() => {
				void * instance;
				bool instance_id_found = instance_by_pid.unset (pid, out instance);
				assert (instance_id_found);
				_free_instance (instance);
				return false;
			});
			source.attach (main_context);
		}

		public extern void _create_context ();
		public extern void _destroy_context ();
		public extern void _free_instance (void * instance);
		public extern uint _do_spawn (string path, string[] argv, string[] envp) throws IOError;
		public extern void _do_resume (uint pid) throws IOError;
	}
}
