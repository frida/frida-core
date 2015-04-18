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

	public class LinuxHostSession : BaseDBusHostSession {
		private HelperProcess helper;
		private Linjector injector;
		private AgentDescriptor agent_desc;

		construct {
			helper = new HelperProcess ();
			injector = new Linjector.with_helper (helper);

			var blob32 = Frida.Data.Agent.get_frida_agent_32_so_blob ();
			var blob64 = Frida.Data.Agent.get_frida_agent_64_so_blob ();
			agent_desc = new AgentDescriptor ("frida-agent-%u.so",
				new MemoryInputStream.from_data (blob32.data, null),
				new MemoryInputStream.from_data (blob64.data, null));
		}

		public override async void close () {
			yield base.close ();

			var uninjected_handler = injector.uninjected.connect ((id) => close.callback ());
			while (injector.any_still_injected ())
				yield;
			injector.disconnect (uninjected_handler);
			yield injector.close ();
			injector = null;

			yield helper.close ();
			helper = null;
		}

		public override async Frida.HostProcessInfo[] enumerate_processes () throws IOError {
			return System.enumerate_processes ();
		}

		public override async uint spawn (string path, string[] argv, string[] envp) throws IOError {
			return yield helper.spawn (path, argv, envp);
		}

		public override async void resume (uint pid) throws IOError {
			yield helper.resume (pid);
		}

		public override async void kill (uint pid) throws IOError {
			yield helper.kill (pid);
		}

		protected override async IOStream perform_attach_to (uint pid, out Object? transport) throws IOError {
			PipeTransport.set_temp_directory (helper.tempdir.path);
			var pipe_transport = new PipeTransport ();
			var stream = new Pipe (pipe_transport.local_address);
			yield injector.inject (pid, agent_desc, pipe_transport.remote_address);
			transport = pipe_transport;
			return stream;
		}
	}
}
#endif
