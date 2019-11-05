namespace Frida {
	public class AgentContainer : Object, AgentSessionProvider {
		public DBusConnection connection {
			get;
			private set;
		}

		private Module module;
		[CCode (has_target = false)]
		private delegate void AgentMainFunc (string data, Gum.MemoryRange? mapped_range, Gum.ThreadId parent_thread_id);
		private AgentMainFunc main_impl;
		private PipeTransport transport;
		private Thread<bool> thread;
		private AgentSessionProvider provider;

		public static async AgentContainer create (string agent_filename, Cancellable? cancellable) throws Error, IOError {
			var container = new AgentContainer ();

			container.module = Module.open (agent_filename, 0);
			assert (container.module != null);

			void * main_func_symbol;
			var main_func_found = container.module.symbol ("frida_agent_main", out main_func_symbol);
			assert (main_func_found);
			container.main_impl = (AgentMainFunc) main_func_symbol;

			var transport = new PipeTransport ();
			container.transport = transport;

			var stream_request = Pipe.open (transport.local_address, cancellable);

			container.start_worker_thread ();

			DBusConnection connection;
			AgentSessionProvider provider;
			try {
				var stream = yield stream_request.wait_async (cancellable);

				connection = yield new DBusConnection (stream, ServerGuid.HOST_SESSION_SERVICE,
					AUTHENTICATION_SERVER | AUTHENTICATION_ALLOW_ANONYMOUS, null, cancellable);

				provider = yield connection.get_proxy (null, ObjectPath.AGENT_SESSION_PROVIDER, DBusProxyFlags.NONE,
					cancellable);
				provider.opened.connect (container.on_session_opened);
				provider.closed.connect (container.on_session_closed);
			} catch (GLib.Error e) {
				throw new Error.PERMISSION_DENIED ("%s", e.message);
			}

			container.connection = connection;
			container.provider = provider;

			return container;
		}

		public async void destroy (Cancellable? cancellable) throws IOError {
			provider.opened.disconnect (on_session_opened);
			provider.closed.disconnect (on_session_closed);
			provider = null;

			try {
				yield connection.close (cancellable);
			} catch (GLib.Error connection_error) {
			}
			connection = null;

			stop_worker_thread ();

			transport = null;

			module = null;
		}

		private void start_worker_thread () {
			thread = new Thread<bool> ("frida-agent-container", run);
		}

		private void stop_worker_thread () {
			Thread<bool> t = thread;
			t.join ();
			thread = null;
		}

		private bool run () {
			main_impl (transport.remote_address, null, 0);
			return true;
		}

		public async void open (AgentSessionId id, Cancellable? cancellable) throws GLib.Error {
			yield provider.open (id, cancellable);
		}

#if !WINDOWS
		private async void migrate (AgentSessionId id, Socket to_socket, Cancellable? cancellable) throws GLib.Error {
			yield provider.migrate (id, to_socket, cancellable);
		}
#endif

		public async void unload (Cancellable? cancellable) throws GLib.Error {
			yield provider.unload (cancellable);
		}

		private void on_session_opened (AgentSessionId id) {
			opened (id);
		}

		private void on_session_closed (AgentSessionId id) {
			closed (id);
		}
	}
}
