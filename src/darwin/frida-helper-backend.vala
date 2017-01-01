#if DARWIN
namespace Frida {
	public class DarwinHelperBackend : Object, DarwinHelper {
		public signal void idle ();
		public signal void child_dead (uint pid);
		public signal void spawn_instance_ready (uint pid);

		public uint pid {
			get {
				return Posix.getpid ();
			}
		}

		public bool is_idle {
			get {
				return inject_instance_by_id.is_empty;
			}
		}

		private Gee.HashMap<uint, OutputStream> stdin_streams = new Gee.HashMap<uint, OutputStream> ();
		private Gee.HashMap<uint, uint> remote_task_by_pid = new Gee.HashMap<uint, uint> ();
		private Gee.HashMap<uint, uint> expiry_timer_by_pid = new Gee.HashMap<uint, uint> ();

		/* these should be private, but must be accessible to glue code */
		public void * context;
		public Gee.HashMap<uint, void *> spawn_instance_by_pid = new Gee.HashMap<uint, void *> ();
		public Gee.HashMap<uint, void *> inject_instance_by_id = new Gee.HashMap<uint, void *> ();
		public uint last_id = 1;

		public DarwinHelperBackend () {
			Object ();

			_create_context ();
		}

		~DarwinHelperBackend () {
			foreach (var instance in spawn_instance_by_pid.values)
				_free_spawn_instance (instance);
			foreach (var instance in inject_instance_by_id.values)
				_free_inject_instance (instance);
			_destroy_context ();
		}

		public async void close () {
		}

		public async void preload () throws Error {
		}

		public async uint spawn (string path, string[] argv, string[] envp) throws Error {
			StdioPipes pipes;
			var child_pid = _spawn (path, argv, envp, out pipes);

			ChildWatch.add ((Pid) child_pid, on_child_dead);

			stdin_streams[child_pid] = new UnixOutputStream (pipes.input, false);
			process_next_output_from.begin (new UnixInputStream (pipes.output, false), child_pid, 1, pipes);
			process_next_output_from.begin (new UnixInputStream (pipes.error, false), child_pid, 2, pipes);

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

		public async void launch (string identifier, string? url) throws Error {
			_launch (identifier, url);
		}

		public async void input (uint pid, uint8[] data) throws Error {
			var stream = stdin_streams[pid];
			if (stream == null)
				throw new Error.INVALID_ARGUMENT ("Invalid pid");
			var data_copy = data; /* FIXME: workaround for Vala compiler bug */
			try {
				yield stream.write_all_async (data_copy, Priority.DEFAULT, null, null);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT (e.message);
			}
		}

		public async void resume (uint pid) throws Error {
			void * instance;
			if (spawn_instance_by_pid.unset (pid, out instance)) {
				_resume_spawn_instance (instance);
				_free_spawn_instance (instance);
			} else {
				_resume_process (pid, steal_task_for_remote_pid (pid));
			}
		}

		public async void kill_process (uint pid) throws Error {
			_kill_process (pid);
		}

		public async void kill_application (string identifier) throws Error {
			_kill_application (identifier);
		}

		public async uint inject_library_file (uint pid, string path, string entrypoint, string data) throws Error {
			return yield _inject (pid, path, null, entrypoint, data);
		}

		public async uint inject_library_blob (uint pid, string name, MappedLibraryBlob blob, string entrypoint, string data) throws Error {
			return yield _inject (pid, name, blob, entrypoint, data);
		}

		private async uint _inject (uint pid, string path_or_name, MappedLibraryBlob? blob, string entrypoint, string data) throws Error {
			var task = steal_task_for_remote_pid (pid);

			var spawn_instance = spawn_instance_by_pid[pid];
			if (spawn_instance == null)
				spawn_instance = _create_spawn_instance_if_suspended (pid, task);
			if (spawn_instance != null) {
				_prepare_spawn_instance_for_injection (spawn_instance, task);

				bool timed_out = false;
				var ready_handler = spawn_instance_ready.connect ((ready_pid) => {
					if (ready_pid == pid)
						_inject.callback ();
				});
				var timeout = Timeout.add (10000, () => {
					timed_out = true;
					_inject.callback ();
					return false;
				});

				yield;

				if (!timed_out)
					Source.remove (timeout);
				disconnect (ready_handler);

				if (timed_out)
					throw new Error.TIMED_OUT ("Unexpectedly timed out while initializing suspended process");
			}

			return _inject_into_task (pid, task, path_or_name, blob, entrypoint, data);
		}

		public async IOStream make_pipe_stream (uint remote_pid, out string remote_address) throws Error {
			var remote_task = borrow_task_for_remote_pid (remote_pid);

			var endpoints = make_pipe_endpoints (0, remote_pid, remote_task);

			remote_address = endpoints.remote_address;

			try {
				return new Pipe (endpoints.local_address);
			} catch (IOError e) {
				throw new Error.TRANSPORT (e.message);
			}
		}

		public async MappedLibraryBlob? try_mmap (Bytes blob) throws Error {
			if (!is_mmap_available ())
				return null;

			return mmap (0, blob);
		}

		public uint borrow_task_for_remote_pid (uint pid) throws Error {
			uint task = remote_task_by_pid[pid];
			if (task != 0) {
				schedule_task_expiry_for_remote_pid (pid);
				return task;
			}

			task = task_for_pid (pid);
			remote_task_by_pid[pid] = task;
			schedule_task_expiry_for_remote_pid (pid);

			return task;
		}

		public uint steal_task_for_remote_pid (uint pid) throws Error {
			uint task;
			if (remote_task_by_pid.unset (pid, out task)) {
				cancel_task_expiry_for_remote_pid (pid);
				return task;
			}

			return task_for_pid (pid);
		}

		private void schedule_task_expiry_for_remote_pid (uint pid) {
			uint previous_timer;
			if (expiry_timer_by_pid.unset (pid, out previous_timer))
				Source.remove (previous_timer);

			expiry_timer_by_pid[pid] = Timeout.add (2000, () => {
				var removed = expiry_timer_by_pid.unset (pid);
				assert (removed);

				uint task;
				removed = remote_task_by_pid.unset (pid, out task);
				assert (removed);

				deallocate_port (task);

				return false;
			});
		}

		private void cancel_task_expiry_for_remote_pid (uint pid) {
			uint timer;
			var found = expiry_timer_by_pid.unset (pid, out timer);
			assert (found);

			Source.remove (timer);
		}

		public void _on_spawn_instance_ready (uint pid) {
			Idle.add (() => {
				spawn_instance_ready (pid);
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

			if (inject_instance_by_id.is_empty)
				idle ();
		}

		public static extern PipeEndpoints make_pipe_endpoints (uint local_task, uint remote_pid, uint remote_task) throws Error;

		public static extern uint task_for_pid (uint pid) throws Error;
		public static extern void deallocate_port (uint port);

		public static extern bool is_mmap_available ();
		public static extern MappedLibraryBlob mmap (uint task, Bytes blob) throws Error;

		protected extern void _create_context ();
		protected extern void _destroy_context ();

		protected extern uint _spawn (string path, string[] argv, string[] envp, out StdioPipes pipes) throws Error;
		protected extern void _launch (string identifier, string? url) throws Error;
		protected extern void _resume_process (uint pid, uint task) throws Error;
		protected extern void _kill_process (uint pid);
		protected extern void _kill_application (string identifier);
		protected extern void * _create_spawn_instance_if_suspended (uint pid, uint task) throws Error;
		protected extern void _prepare_spawn_instance_for_injection (void * instance, uint task) throws Error;
		protected extern void _resume_spawn_instance (void * instance);
		protected extern void _free_spawn_instance (void * instance);

		protected extern uint _inject_into_task (uint pid, uint task, string path_or_name, MappedLibraryBlob? blob, string entrypoint, string data) throws Error;
		protected extern void _join_inject_instance_posix_thread (void * instance, void * posix_thread);
		protected extern bool _is_instance_resident (void * instance);
		protected extern void _free_inject_instance (void * instance);
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
}
#endif
