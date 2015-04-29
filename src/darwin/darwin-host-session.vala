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

		public async HostSession create (string? location = null) throws Error {
			assert (location == null);
			if (host_session != null)
				throw new Error.INVALID_ARGUMENT ("Invalid location: already created");
			host_session = new DarwinHostSession ();
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

		private void on_agent_session_closed (AgentSessionId id, AgentSession session) {
			agent_session_closed (id);
		}

		public static extern ImageData? _extract_icon ();
	}

	public class DarwinHostSession : BaseDBusHostSession {
		private HelperProcess helper;
		private Fruitjector injector;
		private AgentDescriptor agent_desc;

		construct {
			helper = new HelperProcess ();
			injector = new Fruitjector.with_helper (helper);

			var blob = Frida.Data.Agent.get_frida_agent_dylib_blob ();
			agent_desc = new AgentDescriptor (blob.name, new MemoryInputStream.from_data (blob.data, null));
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

		public override async Frida.HostProcessInfo[] enumerate_processes () throws Error {
			return System.enumerate_processes ();
		}

		public override async uint spawn (string path, string[] argv, string[] envp) throws Error {
			return yield helper.spawn (path, argv, envp);
		}

		public override async void resume (uint pid) throws Error {
			yield helper.resume (pid);
		}

		public override async void kill (uint pid) throws Error {
			System.kill (pid);
		}

		protected override async IOStream perform_attach_to (uint pid, out Object? transport) throws Error {
			string local_address, remote_address;
			yield injector.make_pipe_endpoints (pid, out local_address, out remote_address);
			Pipe stream;
			try {
				stream = new Pipe (local_address);
			} catch (IOError stream_error) {
				throw new Error.NOT_SUPPORTED (stream_error.message);
			}
			yield injector.inject (pid, agent_desc, remote_address);
			transport = null;
			return stream;
		}
	}
}
#endif
