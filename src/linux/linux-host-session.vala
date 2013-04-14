#if LINUX
namespace Frida {
	public class LinuxHostSessionBackend : Object, HostSessionBackend {
		private LinuxHostSessionProvider local_provider;

		public async void start () {
			assert (local_provider == null);
			local_provider = new LinuxHostSessionProvider ();
			provider_available (local_provider);
		}

		public async void stop () {
			assert (local_provider != null);
			provider_unavailable (local_provider);
			yield local_provider.close ();
			local_provider = null;
		}
	}

	public class LinuxHostSessionProvider : Object, HostSessionProvider {
		public string name {
			get { return "Local System"; }
		}

		public ImageData? icon {
			get { return null; }
		}

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.LOCAL_SYSTEM; }
		}

		private LinuxHostSession host_session;

		public async void close () {
			if (host_session != null)
				yield host_session.close ();
			host_session = null;
		}

		public async HostSession create () throws IOError {
			if (host_session != null)
				throw new IOError.FAILED ("may only create one HostSession");
			host_session = new LinuxHostSession ();
			host_session.agent_session_closed.connect ((id, error) => this.agent_session_closed (id, error));
			return host_session;
		}

		public async AgentSession obtain_agent_session (AgentSessionId id) throws IOError {
			if (host_session == null)
				throw new IOError.FAILED ("no such id");
			return yield host_session.obtain_agent_session (id);
		}
	}

	public class LinuxHostSession : BaseDBusHostSession, HostSession {
		private Linjector injector = new Linjector ();
		private AgentDescriptor agent_desc;

		construct {
			var blob = Frida.Data.Agent.get_libfrida_agent_so_blob ();
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

		public async Frida.HostProcessInfo[] enumerate_processes () throws IOError {
			return System.enumerate_processes ();
		}

		public async uint spawn (string path, string[] argv, string[] envp) throws IOError {
			throw new IOError.FAILED ("not yet implemented in the Linux backend");
		}

		public async void resume (uint pid) throws IOError {
			throw new IOError.FAILED ("not yet implemented in the Linux backend");
		}

		public async void kill (uint pid) throws IOError {
			System.kill (pid);
		}

		public async Frida.AgentSessionId attach_to (uint pid) throws IOError {
			var transport = new PipeTransport ();
			var stream = new Pipe (transport.local_address);
			yield injector.inject (pid, agent_desc, transport.remote_address);
			return yield allocate_session (transport, stream);
		}
	}
}
#endif
