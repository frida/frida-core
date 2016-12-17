#if DARWIN
namespace Frida {
	public int main (string[] args) {
		Posix.setsid ();

		Gum.init ();

		var parent_address = args[1];
		var worker = new Thread<int> ("frida-helper-main-loop", () => {
			var service = new HelperService (parent_address);

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

	public class HelperService : Object, Helper {
		public signal void child_dead (uint pid);
		public signal void child_ready (uint pid);

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
		private AgentContainer system_session_container;
		private Gee.HashMap<uint, uint> system_sessions = new Gee.HashMap<uint, uint> ();
		private Gee.HashMap<uint, OutputStream> stdin_streams = new Gee.HashMap<uint, OutputStream> ();
		private Gee.HashMap<uint, uint> local_task_by_pid = new Gee.HashMap<uint, uint> ();
		private Gee.HashMap<uint, uint> remote_task_by_pid = new Gee.HashMap<uint, uint> ();
		private Gee.HashMap<uint, uint> expiry_timer_by_pid = new Gee.HashMap<uint, uint> ();
		private Gee.HashMap<PipeProxy, uint> pipe_proxies = new Gee.HashMap<PipeProxy, uint> ();
		private uint last_pipe_proxy_id = 1;

		/* these should be private, but must be accessible to glue code */
		public void * context;
		public Gee.HashMap<uint, void *> spawn_instance_by_pid = new Gee.HashMap<uint, void *> ();
		public Gee.HashMap<uint, void *> inject_instance_by_id = new Gee.HashMap<uint, void *> ();
		public uint last_id = 1;

		public HelperService (string parent_address) {
			Object (parent_address: parent_address);
			_create_context ();
		}

		~HelperService () {
			foreach (var instance in spawn_instance_by_pid.values)
				_free_spawn_instance (instance);
			foreach (var instance in inject_instance_by_id.values)
				_free_inject_instance (instance);
			_destroy_context ();
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

				if (system_session_container != null) {
					system_session_container.opened.disconnect (on_system_session_opened);
					system_session_container.closed.disconnect (on_system_session_closed);

					assert (system_session_registration_id != 0);
					connection.unregister_object (system_session_registration_id);

					yield system_session_container.destroy ();
					system_session_container = null;
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

			loop.quit ();

			shutdown_request.set_value (true);
		}

		private async void start () {
			try {
				connection = yield DBusConnection.new_for_address (parent_address, DBusConnectionFlags.AUTHENTICATION_CLIENT | DBusConnectionFlags.DELAY_MESSAGE_PROCESSING);
				connection.closed.connect (on_connection_closed);

				Helper helper = this;
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

		public async string create_system_session_provider (string agent_filename) throws GLib.Error {
			assert (system_session_container == null);

			system_session_container = yield AgentContainer.create (agent_filename);
			AgentSessionProvider provider = system_session_container;
			system_session_registration_id = connection.register_object (Frida.ObjectPath.SYSTEM_SESSION_PROVIDER, provider);

			provider.opened.connect (on_system_session_opened);
			provider.closed.connect (on_system_session_closed);

			return Frida.ObjectPath.SYSTEM_SESSION_PROVIDER;
		}

		private void on_system_session_opened (AgentSessionId id) {
			try {
				var session_path = ObjectPath.from_agent_session_id (id);
				AgentSession session = system_session_container.connection.get_proxy_sync (null, session_path);
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
			StdioPipes pipes;
			var child_pid = _do_spawn (path, argv, envp, out pipes);

			ChildWatch.add ((Pid) child_pid, on_child_dead);

			stdin_streams[child_pid] = new UnixOutputStream (pipes.input, false);
			process_next_output_from.begin (new UnixInputStream (pipes.output, false), child_pid, 1, pipes);
			process_next_output_from.begin (new UnixInputStream (pipes.error, false), child_pid, 2, pipes);

			string error = null;
			var death_handler = child_dead.connect ((pid) => {
				if (pid == child_pid) {
					error = "Unexpected error while spawning child process '%s' (child process crashed)".printf (path);
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
				throw new Error.NOT_SUPPORTED (error);

			return child_pid;
		}

		private void on_child_dead (Pid pid, int status) {
			var child_pid = (uint) pid;

			stdin_streams.unset (child_pid);

			void * instance;
			if (spawn_instance_by_pid.unset (pid, out instance))
				_free_spawn_instance (instance);

			child_dead (pid);
		}

		private async void process_next_output_from (InputStream stream, uint pid, int fd, Object resource) {
			try {
				var buf = new uint8[4096];
				var n = yield stream.read_async (buf);

				var data = buf[0:n];
				output (pid, fd, data);

				if (n > 0)
					process_next_output_from.begin (stream, pid, fd, resource);
			} catch (GLib.Error e) {
				output (pid, fd, new uint8[0]);
			}
		}

		public async void launch (string identifier, string url) throws Error {
			_do_launch (identifier, (url.length > 0) ? url : null);
		}

		public async void input (uint pid, uint8[] data) throws GLib.Error {
			var stream = stdin_streams[pid];
			if (stream == null)
				throw new Error.INVALID_ARGUMENT ("Invalid pid");
			var data_copy = data; /* FIXME: workaround for Vala compiler bug */
			yield stream.write_all_async (data_copy, Priority.DEFAULT, null, null);
		}

		public async void resume (uint pid) throws Error {
			void * instance;
			bool instance_found = spawn_instance_by_pid.unset (pid, out instance);
			if (!instance_found)
				throw new Error.INVALID_ARGUMENT ("Invalid pid");
			_resume_spawn_instance (instance);
			_free_spawn_instance (instance);
		}

		public async void kill_process (uint pid) throws Error {
			_do_kill_process (pid);
		}

		public async void kill_application (string identifier) throws Error {
			_do_kill_application (identifier);
		}

		public async uint inject_library_file (uint pid, string path, string entrypoint, string data) throws Error {
			var task = steal_task_for_remote_pid (pid);

			return _do_inject (pid, task, path, entrypoint, data);
		}

		public async PipeEndpoints make_pipe_endpoints (uint local_pid, uint remote_pid) throws GLib.Error {
			var local_task = borrow_task_for_local_pid (local_pid);
			var remote_task = borrow_task_for_remote_pid (remote_pid);

			bool need_proxy;
			var endpoints = _do_make_pipe_endpoints (local_task, remote_pid, remote_task, out need_proxy);
			if (need_proxy) {
				var pipe = new Pipe (endpoints.local_address);
				var proxy = new PipeProxy (pipe);

				var id = last_pipe_proxy_id++;
				var proxy_object_path = Frida.ObjectPath.from_tunneled_stream_id (id);
				TunneledStream ts = proxy;
				var registration_id = connection.register_object (proxy_object_path, ts);
				pipe_proxies[proxy] = registration_id;
				proxy.closed.connect (() => {
					connection.unregister_object (registration_id);
					pipe_proxies.unset (proxy);
				});

				return PipeEndpoints (proxy_object_path, endpoints.remote_address);
			}
			return endpoints;
		}

		private uint borrow_task_for_local_pid (uint pid) throws Error {
			if (local_task_by_pid.has_key (pid))
				return local_task_by_pid[pid];

			uint task;
			try {
				task = _task_for_pid (pid);
			} catch (Error e) {
				task = 0;
			}
			local_task_by_pid[pid] = task;

			return task;
		}

		private uint borrow_task_for_remote_pid (uint pid) throws Error {
			uint task = remote_task_by_pid[pid];
			if (task != 0) {
				schedule_task_expiry_for_remote_pid (pid);
				return task;
			}

			task = _task_for_pid (pid);
			remote_task_by_pid[pid] = task;
			schedule_task_expiry_for_remote_pid (pid);

			return task;
		}

		private uint steal_task_for_remote_pid (uint pid) throws Error {
			uint task;
			if (remote_task_by_pid.unset (pid, out task)) {
				cancel_task_expiry_for_remote_pid (pid);
				return task;
			}

			return _task_for_pid (pid);
		}

		private void schedule_task_expiry_for_remote_pid (uint pid) {
			uint previous_timer;
			if (expiry_timer_by_pid.unset (pid, out previous_timer))
				Source.remove (previous_timer);

			expiry_timer_by_pid[pid] = Timeout.add (500, () => {
				uint task;
				var removed = remote_task_by_pid.unset (pid, out task);
				assert (removed);

				_deallocate_port (task);

				return false;
			});
		}

		private void cancel_task_expiry_for_remote_pid (uint pid) {
			uint timer;
			var found = expiry_timer_by_pid.unset (pid, out timer);
			assert (found);

			Source.remove (timer);
		}

		private void on_connection_closed (bool remote_peer_vanished, GLib.Error? error) {
			shutdown.begin ();
		}

		public void _on_spawn_instance_ready (uint pid) {
			Idle.add (() => {
				child_ready (pid);
				return false;
			});
		}

		public void _on_mach_thread_dead (uint id, void * posix_thread) {
			Idle.add (() => {
				var instance = inject_instance_by_id[id];
				assert (instance != null);

				if (posix_thread != null)
					_join_inject_instance_posix_thread (instance, posix_thread);
				else
					destroy_inject_instance (id);

				return false;
			});
		}

		public void _on_posix_thread_dead (uint id) {
			Idle.add (() => {
				destroy_inject_instance (id);
				return false;
			});
		}

		private void destroy_inject_instance (uint id) {
			void * instance;
			bool instance_id_found = inject_instance_by_id.unset (id, out instance);
			assert (instance_id_found);

			var is_resident = _is_instance_resident (instance);

			_free_inject_instance (instance);

			if (!is_resident)
				uninjected (id);
		}

		public extern void _create_context ();
		public extern void _destroy_context ();

		public extern uint _do_spawn (string path, string[] argv, string[] envp, out StdioPipes pipes) throws Error;
		public extern void _do_launch (string identifier, string? url) throws Error;
		public extern void _do_kill_process (uint pid);
		public extern void _do_kill_application (string identifier);
		public extern void _resume_spawn_instance (void * instance);
		public extern void _free_spawn_instance (void * instance);

		public extern uint _do_inject (uint pid, uint task, string path, string entrypoint, string data) throws Error;
		public extern void _join_inject_instance_posix_thread (void * instance, void * posix_thread);
		public extern bool _is_instance_resident (void * instance);
		public extern void _free_inject_instance (void * instance);

		public static extern PipeEndpoints _do_make_pipe_endpoints (uint local_task, uint remote_pid, uint remote_task, out bool need_proxy) throws Error;

		public extern uint _task_for_pid (uint pid) throws Error;
		public extern void _deallocate_port (uint port);
	}

	public class StdioPipes : Object {
		public int input {
			get;
			construct;
		}

		public int output {
			get;
			construct;
		}

		public int error {
			get;
			construct;
		}

		public StdioPipes (int input, int output, int error) {
			Object (input: input, output: output, error: error);
		}

		construct {
			try {
				Unix.set_fd_nonblocking (input, true);
				Unix.set_fd_nonblocking (output, true);
				Unix.set_fd_nonblocking (error, true);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
		}

		~StdioPipes () {
			Posix.close (input);
			Posix.close (output);
			Posix.close (error);
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
