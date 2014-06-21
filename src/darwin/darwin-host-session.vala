#if DARWIN
namespace Frida {
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
			get { return _icon; }
		}
		private ImageData? _icon;

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.LOCAL_SYSTEM; }
		}

		private DarwinHostSession host_session;

		construct {
			_icon = _extract_icon ();
		}

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

		public static extern ImageData? _extract_icon ();
	}

	public class DarwinHostSession : BaseDBusHostSession, HostSession {
		public signal void child_dead (uint pid);
		public signal void child_ready (uint pid);

		private MainContext main_context;
		public void * context;
		public Gee.HashMap<uint, void *> instance_by_pid = new Gee.HashMap<uint, void *> ();

		private Fruitjector injector = new Fruitjector ();
		private AgentDescriptor agent_desc;

		construct {
			main_context = MainContext.get_thread_default ();
			_create_context ();

			var blob = Frida.Data.Agent.get_libfrida_agent_dylib_blob ();
			agent_desc = new AgentDescriptor (blob.name, new MemoryInputStream.from_data (blob.data, null));
		}

		public override async void close () {
			yield base.close ();

			while (injector.any_still_injected ()) {
				injector.uninjected.connect ((id) => close.callback ());
				yield;
			}

			yield injector.close ();
			injector = null;
		}

		public async Frida.HostProcessInfo[] enumerate_processes () throws IOError {
			return System.enumerate_processes ();
		}

		public async uint spawn (string path, string[] argv, string[] envp) throws IOError {
			string error = null;

			uint child_pid = _do_spawn (path, argv, envp);
			var death_handler = child_dead.connect ((pid) => {
				if (pid == child_pid) {
					error = "child died prematurely";
					spawn.callback ();
				}
			});
			var ready_handler = child_ready.connect ((pid) => {
				if (pid == child_pid) {
					spawn.callback ();
				}
			});
			yield;
			disconnect (death_handler);
			disconnect (ready_handler);

			if (error != null)
				throw new IOError.FAILED (error);

			return child_pid;
		}

		public async void resume (uint pid) throws IOError {
			void * instance;
			bool instance_found = instance_by_pid.unset (pid, out instance);
			if (!instance_found)
				throw new IOError.FAILED ("no such pid");
			_resume_instance (instance);
			_free_instance (instance);
		}

		public async void kill (uint pid) throws IOError {
			System.kill (pid);
		}

		public async Frida.AgentSessionId attach_to (uint pid) throws IOError {
			string local_address, remote_address;
			yield injector.make_pipe_endpoints (pid, out local_address, out remote_address);
			var stream = new Pipe (local_address);
			yield injector.inject (pid, agent_desc, remote_address);
			return yield allocate_session (null, stream);
		}

		public void _on_instance_dead (uint pid) {
			var source = new IdleSource ();
			source.set_callback (() => {
				void * instance;
				bool instance_found = instance_by_pid.unset (pid, out instance);
				assert (instance_found);
				_free_instance (instance);
				child_dead (pid);
				return false;
			});
			source.attach (main_context);
		}

		public void _on_instance_ready (uint pid) {
			var source = new IdleSource ();
			source.set_callback (() => {
				child_ready (pid);
				return false;
			});
			source.attach (main_context);
		}

		public extern void _create_context ();
		public extern void _destroy_context ();
		public extern uint _do_spawn (string path, string[] argv, string[] envp) throws IOError;
		public extern void _resume_instance (void * instance);
		public extern void _free_instance (void * instance);
	}
}
#endif
