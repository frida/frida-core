#if WINDOWS
namespace Frida {
	public class WindowsHostSessionBackend : Object, HostSessionBackend {
		private WindowsHostSessionProvider local_provider;

		public async void start () {
			assert (local_provider == null);
			local_provider = new WindowsHostSessionProvider ();
			provider_available (local_provider);
		}

		public async void stop () {
			assert (local_provider != null);
			provider_unavailable (local_provider);
			yield local_provider.close ();
			local_provider = null;
		}
	}

	public class WindowsHostSessionProvider : Object, HostSessionProvider {
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

		private WindowsHostSession host_session;

		construct {
			try {
				_icon = _extract_icon ();
			} catch (IOError e) {
			}
		}

		public async void close () {
			if (host_session != null)
				yield host_session.close ();
			host_session = null;
		}

		public async HostSession create () throws IOError {
			if (host_session != null)
				throw new IOError.FAILED ("may only create one HostSession");
			host_session = new WindowsHostSession ();
			host_session.agent_session_closed.connect ((id, error) => this.agent_session_closed (id, error));
			return host_session;
		}

		public async AgentSession obtain_agent_session (AgentSessionId id) throws IOError {
			if (host_session == null)
				throw new IOError.FAILED ("no such id");
			return yield host_session.obtain_agent_session (id);
		}

		public static extern ImageData? _extract_icon () throws IOError;
	}

	public class WindowsHostSession : BaseDBusHostSession, HostSession {
		private ProcessEnumerator process_enumerator = new ProcessEnumerator ();

		private Winjector winjector = new Winjector ();
		private AgentDescriptor agent_desc;

		construct {
			var blob32 = Frida.Data.Agent.get_frida_agent_32_dll_blob ();
			var blob64 = Frida.Data.Agent.get_frida_agent_64_dll_blob ();
			agent_desc = new AgentDescriptor ("frida-agent-%u.dll",
				new MemoryInputStream.from_data (blob32.data, null),
				new MemoryInputStream.from_data (blob64.data, null));
		}

		public override async void close () {
			yield base.close ();

			/* HACK: give processes 100 ms to unload DLLs */
			var source = new TimeoutSource (100);
			source.set_callback (() => {
				close.callback ();
				return false;
			});
			source.attach (MainContext.get_thread_default ());
			yield;

			agent_desc = null;

			yield winjector.close ();
			winjector = null;
		}

		public async HostProcessInfo[] enumerate_processes () throws IOError {
			var processes = yield process_enumerator.enumerate_processes ();
			return processes;
		}

		public async uint spawn (string path, string[] argv, string[] envp) throws IOError {
			throw new IOError.FAILED ("not yet implemented in the Windows backend");
		}

		public async void resume (uint pid) throws IOError {
			throw new IOError.FAILED ("not yet implemented in the Windows backend");
		}

		public async void kill (uint pid) throws IOError {
			throw new IOError.FAILED ("not yet implemented in the Windows backend");
		}

		public async AgentSessionId attach_to (uint pid) throws IOError {
			var transport = new PipeTransport ();
			var stream = new Pipe (transport.local_address);
			yield winjector.inject (pid, agent_desc, transport.remote_address, null);
			return yield allocate_session (transport, stream);
		}
	}
}
#endif
