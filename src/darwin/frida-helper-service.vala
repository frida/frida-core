#if DARWIN
namespace Frida {
	public int main (string[] args) {
		Posix.setsid ();

		Gum.init ();

		var parent_address = args[1];
		var worker = new Thread<int> ("frida-helper-main-loop", () => {
			var service = new DarwinHelperService (parent_address);

			var exit_code = service.run ();
			_stop_run_loop ();

			return exit_code;
		});
		_start_run_loop ();
		var exit_code = worker.join ();

		return exit_code;
	}

	public extern void _start_run_loop ();
	public extern void _stop_run_loop ();

	public class DarwinHelperService : Object, DarwinRemoteHelper {
		public string parent_address {
			get;
			construct;
		}

		private MainLoop loop = new MainLoop ();
		private int run_result = 0;
		private Gee.Promise<bool> shutdown_request;

		private DBusConnection connection;
		private uint helper_registration_id = 0;
		private uint system_session_registration_id = 0;
		private Gee.HashMap<uint, uint> system_sessions = new Gee.HashMap<uint, uint> ();
		private Gee.HashMap<PipeProxy, uint> pipe_proxies = new Gee.HashMap<PipeProxy, uint> ();
		private uint last_pipe_proxy_id = 1;

		private DarwinHelperBackend backend = new DarwinHelperBackend ();
		private AgentSessionProvider system_session_provider;
		private DBusConnection system_session_connection;

		public DarwinHelperService (string parent_address) {
			Object (parent_address: parent_address);
		}

		construct {
			backend.idle.connect (on_backend_idle);
			backend.output.connect (on_backend_output);
			backend.uninjected.connect (on_backend_uninjected);
		}

		public int run () {
			Idle.add (() => {
				start.begin ();
				return false;
			});

			loop.run ();

			return run_result;
		}

		private async void shutdown () {
			if (shutdown_request != null) {
				try {
					yield shutdown_request.future.wait_async ();
				} catch (Gee.FutureError e) {
					assert_not_reached ();
				}
				return;
			}
			shutdown_request = new Gee.Promise<bool> ();

			if (connection != null) {
				foreach (var registration_id in system_sessions.values)
					connection.unregister_object (registration_id);
				system_sessions.clear ();

				foreach (var registration_id in pipe_proxies.values)
					connection.unregister_object (registration_id);
				pipe_proxies.clear ();

				system_session_connection = null;
				if (system_session_provider != null) {
					system_session_provider.opened.disconnect (on_system_session_opened);
					system_session_provider.closed.disconnect (on_system_session_closed);

					assert (system_session_registration_id != 0);
					connection.unregister_object (system_session_registration_id);
				}

				if (helper_registration_id != 0)
					connection.unregister_object (helper_registration_id);

				connection.closed.disconnect (on_connection_closed);
				try {
					yield connection.close ();
				} catch (GLib.Error connection_error) {
				}
				connection = null;
			}

			yield backend.close ();
			backend.idle.disconnect (on_backend_idle);
			backend.output.disconnect (on_backend_output);
			backend.uninjected.disconnect (on_backend_uninjected);
			backend = null;

			shutdown_request.set_value (true);

			Idle.add (() => {
				loop.quit ();
				return false;
			});
		}

		private async void start () {
			try {
				connection = yield DBusConnection.new_for_address (parent_address, DBusConnectionFlags.AUTHENTICATION_CLIENT | DBusConnectionFlags.DELAY_MESSAGE_PROCESSING);
				connection.closed.connect (on_connection_closed);

				DarwinRemoteHelper helper = this;
				helper_registration_id = connection.register_object (Frida.ObjectPath.HELPER, helper);

				connection.start_message_processing ();
			} catch (GLib.Error e) {
				printerr ("Unable to start: %s\n", e.message);
				run_result = 1;
				shutdown.begin ();
			}
		}

		public async void stop () throws Error {
			Timeout.add (20, () => {
				shutdown.begin ();
				return false;
			});
		}

		private void on_backend_idle () {
			if (connection.is_closed ())
				shutdown.begin ();
		}

		private void on_connection_closed (bool remote_peer_vanished, GLib.Error? error) {
			if (backend.is_idle)
				shutdown.begin ();
		}

		public async string create_system_session_provider (string agent_filename) throws Error {
			assert (system_session_provider == null);

			DBusConnection connection;
			var provider = yield backend.create_system_session_provider (agent_filename, out connection);

			try {
				system_session_registration_id = connection.register_object (Frida.ObjectPath.SYSTEM_SESSION_PROVIDER, provider);
			} catch (IOError e) {
				assert_not_reached ();
			}

			system_session_provider = provider;
			system_session_connection = connection;
			provider.opened.connect (on_system_session_opened);
			provider.closed.connect (on_system_session_closed);

			return Frida.ObjectPath.SYSTEM_SESSION_PROVIDER;
		}

		private void on_system_session_opened (AgentSessionId id) {
			try {
				var session_path = ObjectPath.from_agent_session_id (id);
				AgentSession session = system_session_connection.get_proxy_sync (null, session_path);
				var session_registration = connection.register_object (session_path, session);
				system_sessions[id.handle] = session_registration;
			} catch (GLib.Error e) {
			}
		}

		private void on_system_session_closed (AgentSessionId id) {
			uint session_registration;
			var found = system_sessions.unset (id.handle, out session_registration);
			assert (found);
			connection.unregister_object (session_registration);
		}

		public async uint spawn (string path, string[] argv, string[] envp) throws Error {
			return yield backend.spawn (path, argv, envp);
		}

		public async void launch (string identifier, string url) throws Error {
			yield backend.launch (identifier, url);
		}

		public async void input (uint pid, uint8[] data) throws Error {
			yield backend.input (pid, data);
		}

		public async void resume (uint pid) throws Error {
			yield backend.resume (pid);
		}

		public async void kill_process (uint pid) throws Error {
			yield backend.kill_process (pid);
		}

		public async void kill_application (string identifier) throws Error {
			yield backend.kill_application (identifier);
		}

		public async uint inject_library_file (uint pid, string path, string entrypoint, string data) throws Error {
			return yield backend.inject_library_file (pid, path, entrypoint, data);
		}

		public async uint inject_library_blob (uint pid, string name, MappedLibraryBlob blob, string entrypoint, string data) throws Error {
			return yield backend.inject_library_blob (pid, name, blob, entrypoint, data);
		}

		public async PipeEndpoints make_pipe_endpoints (uint local_pid, uint remote_pid) throws Error {
			var local_task = backend.borrow_task_for_local_pid (local_pid);
			var remote_task = backend.borrow_task_for_remote_pid (remote_pid);

			var endpoints = DarwinHelperBackend.make_pipe_endpoints (local_task, remote_pid, remote_task);

			bool need_proxy = local_task == 0;
			if (need_proxy) {
				Pipe pipe;

				try {
					pipe = new Pipe (endpoints.local_address);
				} catch (IOError e) {
					assert_not_reached ();
				}
				var proxy = new PipeProxy (pipe);

				var id = last_pipe_proxy_id++;
				var proxy_object_path = Frida.ObjectPath.from_tunneled_stream_id (id);
				TunneledStream ts = proxy;

				uint registration_id;
				try {
					registration_id = connection.register_object (proxy_object_path, ts);
					pipe_proxies[proxy] = registration_id;
				} catch (IOError e) {
					assert_not_reached ();
				}

				proxy.closed.connect (() => {
					connection.unregister_object (registration_id);
					pipe_proxies.unset (proxy);
				});

				return PipeEndpoints (proxy_object_path, endpoints.remote_address);
			}

			return endpoints;
		}

		private void on_backend_output (uint pid, int fd, uint8[] data) {
			output (pid, fd, data);
		}

		private void on_backend_uninjected (uint id) {
			uninjected (id);
		}
	}

	private class PipeProxy : Object, TunneledStream {
		public signal void closed ();

		public Pipe pipe {
			get;
			construct;
		}
		private InputStream input;
		private OutputStream output;

		public PipeProxy (Pipe pipe) {
			Object (pipe: pipe);
		}

		construct {
			input = pipe.input_stream;
			output = pipe.output_stream;
		}

		public async void close () throws GLib.Error {
			try {
				yield pipe.close_async ();
			} catch (GLib.Error e) {
			}
			closed ();
		}

		public async uint8[] read () throws GLib.Error {
			try {
				var buf = new uint8[4096];
				var n = yield input.read_async (buf);
				return buf[0:n];
			} catch (GLib.Error e) {
				close.begin ();
				throw e;
			}
		}

		public async void write (uint8[] data) throws GLib.Error {
			try {
				var data_copy = data; /* FIXME: workaround for Vala compiler bug */
				yield output.write_all_async (data_copy, Priority.DEFAULT, null, null);
			} catch (GLib.Error e) {
				close.begin ();
				throw e;
			}
		}
	}
}
#endif
