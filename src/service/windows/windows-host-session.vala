namespace Zed.Service {
	public class WindowsHostSessionBackend : Object, HostSessionBackend {
		public Winjector winjector {
			get;
			private set;
		}

		private WindowsHostSessionProvider local_provider;

		public async void start () {
			assert (winjector == null);
			winjector = new Winjector ();

			assert (local_provider == null);
			local_provider = new WindowsHostSessionProvider ();

			var source = new IdleSource ();
			source.set_callback (() => {
				provider_available (local_provider);
				return false;
			});
			source.attach (MainContext.get_thread_default ());
		}

		public async void stop () {
			assert (local_provider != null);
			//yield local_provider.stop ();
			local_provider = null;

			// HACK: give processes 50 ms to unload DLLs
			var source = new TimeoutSource (50);
			source.set_callback (() => {
				stop.callback ();
				return false;
			});
			source.attach (MainContext.get_thread_default ());
			yield;

			yield winjector.close ();
		}
	}

	public class WindowsHostSessionProvider : Object, HostSessionProvider {
		public string name {
			get { return "Local System"; }
		}

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.LOCAL_SYSTEM; }
		}

		public async HostSession create () throws IOError {
			return new WindowsHostSession ();
		}

		public async AgentSession obtain_agent_session (AgentSessionId id) throws IOError {
			throw new IOError.FAILED ("not yet implemented bla %u", id.handle);
		}
	}

	public class WindowsHostSession : Object, HostSession {
		private WindowsProcessBackend process_backend = new WindowsProcessBackend ();

		public async HostProcessInfo[] enumerate_processes () throws IOError {
			var processes = yield process_backend.enumerate_processes ();
			return processes;
		}

		public async AgentSessionId attach_to (uint pid) throws IOError {
			return AgentSessionId (pid);
		}
	}

	public class WindowsProcessBackend {
		private MainContext current_main_context;
		private Gee.ArrayList<EnumerateRequest> pending_requests = new Gee.ArrayList<EnumerateRequest> ();

		public async HostProcessInfo[] enumerate_processes () {
			bool is_first_request = pending_requests.is_empty;

			var request = new EnumerateRequest (() => enumerate_processes.callback ());
			if (is_first_request) {
				current_main_context = MainContext.get_thread_default ();

				try {
					Thread.create (enumerate_processes_worker, false);
				} catch (ThreadError e) {
					error (e.message);
				}
			}
			pending_requests.add (request);
			yield;

			return request.result;
		}

		public static extern HostProcessInfo[] enumerate_processes_sync ();

		private void * enumerate_processes_worker () {
			var processes = enumerate_processes_sync ();

			var source = new IdleSource ();
			source.set_callback (() => {
				current_main_context = null;
				var requests = pending_requests;
				pending_requests = new Gee.ArrayList<EnumerateRequest> ();

				foreach (var request in requests)
					request.complete (processes);

				return false;
			});
			source.attach (current_main_context);

			return null;
		}

		private class EnumerateRequest {
			public delegate void CompletionHandler ();
			private CompletionHandler handler;

			public HostProcessInfo[] result {
				get;
				private set;
			}

			public EnumerateRequest (CompletionHandler handler) {
				this.handler = handler;
			}

			public void complete (HostProcessInfo[] processes) {
				this.result = processes;
				handler ();
			}
		}
	}
}

