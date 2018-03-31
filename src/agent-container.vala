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

		public static async AgentContainer create (string agent_filename) throws Error {
			var container = new AgentContainer ();

			container.module = Module.open (agent_filename, 0);
			assert (container.module != null);

			void * main_func_symbol;
			var main_func_found = container.module.symbol ("frida_agent_main", out main_func_symbol);
			assert (main_func_found);
			container.main_impl = (AgentMainFunc) main_func_symbol;

			PipeTransport transport;
			try {
				transport = new PipeTransport ();
			} catch (IOError transport_error) {
				assert_not_reached ();
			}
			container.transport = transport;

			container.start_worker_thread ();

			DBusConnection connection;
			AgentSessionProvider provider;
			try {
				var stream = yield Pipe.open (transport.local_address).future.wait_async ();
				connection = yield new DBusConnection (stream, null, DBusConnectionFlags.NONE);
				provider = yield connection.get_proxy (null, ObjectPath.AGENT_SESSION_PROVIDER);
				provider.opened.connect (container.on_session_opened);
				provider.closed.connect (container.on_session_closed);
			} catch (GLib.Error dbus_error) {
				assert_not_reached ();
			}

			container.connection = connection;
			container.provider = provider;

			return container;
		}

		public async void destroy () {
			provider.opened.disconnect (on_session_opened);
			provider.closed.disconnect (on_session_closed);
			provider = null;

			try {
				yield connection.close ();
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

		public async void open (AgentSessionId id) throws GLib.Error {
			yield provider.open (id);
		}

		public async void unload () throws GLib.Error {
			yield provider.unload ();
		}

		private void on_session_opened (AgentSessionId id) {
			opened (id);
		}

		private void on_session_closed (AgentSessionId id) {
			closed (id);
		}
	}
}
