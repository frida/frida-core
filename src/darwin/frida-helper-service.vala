namespace Frida {
	public int main (string[] args) {
		Posix.setsid ();

		Gum.init ();

		var parent_service_name = args[1];
		var worker = new Thread<int> ("frida-helper-main-loop", () => {
			var service = new DarwinHelperService (parent_service_name);

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
		public string parent_service_name {
			get;
			construct;
		}

		private MainLoop loop = new MainLoop ();
		private int run_result = 0;
		private Gee.Promise<bool> shutdown_request;

		private DBusConnection connection;
		private uint helper_registration_id = 0;
		private TaskPort parent_task;

		private DarwinHelperBackend backend = new DarwinHelperBackend ();

		public DarwinHelperService (string parent_service_name) {
			Object (parent_service_name: parent_service_name);
		}

		construct {
			backend.idle.connect (on_backend_idle);
			backend.output.connect (on_backend_output);
			backend.spawned.connect (on_backend_spawned);
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
				if (helper_registration_id != 0)
					connection.unregister_object (helper_registration_id);

				connection.on_closed.disconnect (on_connection_closed);
				try {
					yield connection.close ();
				} catch (GLib.Error connection_error) {
				}
				connection = null;
			}

			yield backend.close ();
			backend.idle.disconnect (on_backend_idle);
			backend.output.disconnect (on_backend_output);
			backend.spawned.disconnect (on_backend_spawned);
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
				IOStream stream;
				var handshake_port = new HandshakePort.remote (parent_service_name);

				yield handshake_port.exchange (0, out parent_task, out stream);

				connection = yield new DBusConnection (stream, null, DBusConnectionFlags.DELAY_MESSAGE_PROCESSING);
				connection.on_closed.connect (on_connection_closed);

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

		public async void enable_spawn_gating () throws Error {
			yield backend.enable_spawn_gating ();
		}

		public async void disable_spawn_gating () throws Error {
			yield backend.disable_spawn_gating ();
		}

		public async HostSpawnInfo[] enumerate_pending_spawns () throws Error {
			return yield backend.enumerate_pending_spawns ();
		}

		public async uint spawn (string path, string[] argv, bool has_envp, string[] envp) throws Error {
			return yield backend.spawn (path, argv, has_envp, envp);
		}

		public async void launch (string identifier, string url) throws Error {
			yield backend.launch (identifier, (url != "") ? url : null);
		}

		public async void input (uint pid, uint8[] data) throws Error {
			yield backend.input (pid, data);
		}

		public async void wait_until_suspended (uint pid) throws Error {
			yield backend.wait_until_suspended (pid);
		}

		public async void cancel_pending_waits (uint pid) throws Error {
			yield backend.cancel_pending_waits (pid);
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

		public async uint demonitor_and_clone_injectee_state (uint id) throws Error {
			return yield backend.demonitor_and_clone_injectee_state (id);
		}

		public async void recreate_injectee_thread (uint pid, uint id) throws Error {
			yield backend.recreate_injectee_thread (pid, id);
		}

		public async PipeEndpoints make_pipe_endpoints (uint remote_pid) throws Error {
			var remote_task = backend.borrow_task_for_remote_pid (remote_pid);

			return DarwinHelperBackend.make_pipe_endpoints (parent_task.mach_port, remote_pid, remote_task);
		}

		private void on_backend_output (uint pid, int fd, uint8[] data) {
			output (pid, fd, data);
		}

		private void on_backend_spawned (HostSpawnInfo info) {
			spawned (info);
		}

		private void on_backend_uninjected (uint id) {
			uninjected (id);
		}
	}
}
