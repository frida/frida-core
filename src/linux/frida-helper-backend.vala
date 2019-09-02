namespace Frida {
	public class LinuxHelperBackend : Object, LinuxHelper {
		public signal void idle ();

		public bool is_idle {
			get {
				return inject_instances.is_empty;
			}
		}

		public Gee.HashMap<uint, void *> spawn_instances = new Gee.HashMap<uint, void *> ();
		private Gee.HashMap<uint, uint> watch_sources = new Gee.HashMap<uint, uint> ();
		private Gee.HashMap<uint, OutputStream> stdin_streams = new Gee.HashMap<uint, OutputStream> ();

		public Gee.HashMap<uint, void *> exec_instances = new Gee.HashMap<uint, void *> ();
		private Gee.HashMap<uint, uint> exec_waiters = new Gee.HashMap<uint, uint> ();
		private uint next_waiter_id = 1;

		public Gee.HashMap<uint, void *> inject_instances = new Gee.HashMap<uint, void *> ();
		private Gee.HashMap<uint, RemoteThreadSession> inject_sessions = new Gee.HashMap<uint, RemoteThreadSession> ();
		private Gee.HashMap<uint, uint> inject_expiry_by_id = new Gee.HashMap<uint, uint> ();

		public uint next_id = 0;

		private Cancellable io_cancellable = new Cancellable ();

		~LinuxHelperBackend () {
			foreach (var instance in spawn_instances.values)
				_free_spawn_instance (instance);
			foreach (var instance in exec_instances.values)
				_free_exec_instance (instance);
			foreach (var instance in inject_instances.values)
				_free_inject_instance (instance, RESIDENT);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			io_cancellable.cancel ();
		}

		public async uint spawn (string path, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError {
			if (!FileUtils.test (path, EXISTS))
				throw new Error.EXECUTABLE_NOT_FOUND ("Unable to find executable at '%s'", path);

			StdioPipes? pipes;
			var child_pid = _do_spawn (path, options, out pipes);

			monitor_child (child_pid);

			if (pipes != null) {
				stdin_streams[child_pid] = new UnixOutputStream (pipes.input, false);
				process_next_output_from.begin (new UnixInputStream (pipes.output, false), child_pid, 1, pipes);
				process_next_output_from.begin (new UnixInputStream (pipes.error, false), child_pid, 2, pipes);
			}

			return child_pid;
		}

		private void monitor_child (uint pid) {
			watch_sources[pid] = ChildWatch.add ((Pid) pid, on_child_dead);
		}

		private void demonitor_child (uint pid) {
			uint watch_id;
			if (watch_sources.unset (pid, out watch_id))
				Source.remove (watch_id);
		}

		private void on_child_dead (Pid pid, int status) {
			watch_sources.unset (pid);

			stdin_streams.unset (pid);

			void * instance;
			if (spawn_instances.unset (pid, out instance))
				_free_spawn_instance (instance);
		}

		private async void process_next_output_from (InputStream stream, uint pid, int fd, Object resource) {
			try {
				var buf = new uint8[4096];
				var n = yield stream.read_async (buf, Priority.DEFAULT, io_cancellable);

				var data = buf[0:n];
				output (pid, fd, data);

				if (n > 0)
					process_next_output_from.begin (stream, pid, fd, resource);
			} catch (GLib.Error e) {
				if (!(e is IOError.CANCELLED))
					output (pid, fd, new uint8[0]);
			}
		}

		public async void prepare_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			bool is_child = spawn_instances.has_key (pid);
			if (is_child)
				demonitor_child (pid);

			try {
				_do_prepare_exec_transition (pid);
			} catch (Error e) {
				if (is_child)
					monitor_child (pid);
				throw e;
			}

			_notify_exec_pending (pid, true);
		}

		public async void await_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			var instance = exec_instances[pid];
			if (instance == null)
				throw new Error.INVALID_ARGUMENT ("Invalid PID");

			if (!_try_transition_exec_instance (instance)) {
				uint id = next_waiter_id++;
				Error? pending_error = null;

				exec_waiters[pid] = id;

				Timeout.add (50, () => {
					var cancelled = !exec_waiters.has (pid, id);
					if (cancelled) {
						await_exec_transition.callback ();
						return false;
					}

					try {
						if (_try_transition_exec_instance (instance)) {
							await_exec_transition.callback ();
							return false;
						}
					} catch (Error e) {
						pending_error = e;
						await_exec_transition.callback ();
						return false;
					}

					return true;
				});

				yield;

				var cancelled = !exec_waiters.has (pid, id);
				if (cancelled)
					throw new Error.INVALID_OPERATION ("Cancelled");
				exec_waiters.unset (pid);

				if (pending_error != null) {
					exec_instances.unset (pid);

					_resume_exec_instance (instance);
					_free_exec_instance (instance);

					_notify_exec_pending (pid, false);

					throw pending_error;
				}
			}

			if (spawn_instances.has_key (pid))
				monitor_child (pid);
		}

		public async void cancel_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			void * instance;
			if (!exec_instances.unset (pid, out instance))
				throw new Error.INVALID_ARGUMENT ("Invalid PID");

			exec_waiters.unset (pid);

			_suspend_exec_instance (instance);
			_resume_exec_instance (instance);
			_free_exec_instance (instance);

			if (spawn_instances.has_key (pid))
				monitor_child (pid);
			_notify_exec_pending (pid, false);
		}

		public async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError {
			var stream = stdin_streams[pid];
			if (stream == null)
				throw new Error.INVALID_ARGUMENT ("Invalid PID");
			try {
				yield stream.write_all_async (data, Priority.DEFAULT, null, null);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("%s", e.message);
			}
		}

		public async void resume (uint pid, Cancellable? cancellable) throws Error, IOError {
			void * instance;
			bool instance_found;

			instance_found = spawn_instances.unset (pid, out instance);
			if (instance_found) {
				_resume_spawn_instance (instance);
				_free_spawn_instance (instance);
				return;
			}

			if (exec_waiters.has_key (pid))
				throw new Error.INVALID_OPERATION ("Invalid operation");

			instance_found = exec_instances.unset (pid, out instance);
			if (instance_found) {
				_resume_exec_instance (instance);
				_free_exec_instance (instance);
				return;
			}

			throw new Error.INVALID_ARGUMENT ("Invalid PID");
		}

		public async void kill (uint pid, Cancellable? cancellable) throws Error, IOError {
			Posix.kill ((Posix.pid_t) pid, Posix.Signal.KILL);
		}

		public async uint inject_library_file (uint pid, string path, string entrypoint, string data, string temp_path,
				Cancellable? cancellable) throws Error, IOError {
			var id = _do_inject (pid, path, entrypoint, data, temp_path);

			yield establish_session (id, pid);

			return id;
		}

		public async uint demonitor_and_clone_injectee_state (uint id, Cancellable? cancellable) throws Error, IOError {
			var instance = inject_instances[id];
			if (instance == null)
				throw new Error.INVALID_ARGUMENT ("Invalid ID");

			RemoteThreadSession session;
			if (inject_sessions.unset (id, out session)) {
				session.ended.disconnect (on_remote_thread_session_ended);
				yield session.cancel ();
			}

			var clone_id = _demonitor_and_clone_injectee_state (instance);

			schedule_inject_expiry_for_id (id);
			schedule_inject_expiry_for_id (clone_id);

			return clone_id;
		}

		public async void recreate_injectee_thread (uint pid, uint id, Cancellable? cancellable) throws Error, IOError {
			var instance = inject_instances[id];
			if (instance == null)
				throw new Error.INVALID_ARGUMENT ("Invalid ID");

			cancel_inject_expiry_for_id (id);

			_recreate_injectee_thread (instance, pid);

			yield establish_session (id, pid);
		}

		private async void establish_session (uint id, uint pid) throws Error {
			var fifo = _get_fifo_for_inject_instance (inject_instances[id]);

			var session = new RemoteThreadSession (id, pid, fifo);
			try {
				yield session.establish ();
			} catch (Error e) {
				_destroy_inject_instance (id, IMMEDIATE);
				throw e;
			}

			inject_sessions[id] = session;
			session.ended.connect (on_remote_thread_session_ended);
		}

		private void on_remote_thread_session_ended (RemoteThreadSession session, UnloadPolicy unload_policy) {
			var id = session.id;

			session.ended.disconnect (on_remote_thread_session_ended);
			inject_sessions.unset (id);

			Timeout.add (50, () => {
				_destroy_inject_instance (id, unload_policy);
				return false;
			});
		}

		protected void _destroy_inject_instance (uint id, UnloadPolicy unload_policy) {
			void * instance;
			bool found = inject_instances.unset (id, out instance);
			assert (found);

			_free_inject_instance (instance, unload_policy);

			uninjected (id);

			if (inject_instances.is_empty)
				idle ();
		}

		private void schedule_inject_expiry_for_id (uint id) {
			uint previous_timer;
			if (inject_expiry_by_id.unset (id, out previous_timer))
				Source.remove (previous_timer);

			inject_expiry_by_id[id] = Timeout.add_seconds (20, () => {
				var removed = inject_expiry_by_id.unset (id);
				assert (removed);

				_destroy_inject_instance (id, IMMEDIATE);

				return false;
			});
		}

		private void cancel_inject_expiry_for_id (uint id) {
			uint timer;
			var found = inject_expiry_by_id.unset (id, out timer);
			assert (found);

			Source.remove (timer);
		}

		protected extern uint _do_spawn (string path, HostSpawnOptions options, out StdioPipes? pipes) throws Error;
		protected extern void _resume_spawn_instance (void * instance);
		protected extern void _free_spawn_instance (void * instance);

		protected extern void _do_prepare_exec_transition (uint pid) throws Error;
		protected extern void _notify_exec_pending (uint pid, bool pending);
		protected extern bool _try_transition_exec_instance (void * instance) throws Error;
		protected extern void _suspend_exec_instance (void * instance);
		protected extern void _resume_exec_instance (void * instance);
		protected extern void _free_exec_instance (void * instance);

		protected extern uint _do_inject (uint pid, string path, string entrypoint, string data, string temp_path) throws Error;
		protected extern uint _demonitor_and_clone_injectee_state (void * instance);
		protected extern void _recreate_injectee_thread (void * instance, uint pid) throws Error;
		protected extern InputStream _get_fifo_for_inject_instance (void * instance);
		protected extern void _free_inject_instance (void * instance, UnloadPolicy unload_policy);
	}

	private class RemoteThreadSession : Object {
		public signal void ended (UnloadPolicy unload_policy);

		public uint id {
			get;
			construct;
		}

		public uint pid {
			get;
			construct;
		}

		public InputStream input {
			get;
			construct;
		}

		private Promise<bool> cancel_request = new Promise<bool> ();
		private Cancellable cancellable = new Cancellable ();

		public RemoteThreadSession (uint id, uint pid, InputStream input) {
			Object (id: id, pid: pid, input: input);
		}

		public async void establish () throws Error {
			var timeout = Timeout.add_seconds (2, () => {
				cancellable.cancel ();
				return false;
			});

			ssize_t size = 0;
			var byte_buf = new uint8[1];
			try {
				size = yield input.read_async (byte_buf, Priority.DEFAULT, cancellable);
			} catch (IOError e) {
				if (e is IOError.CANCELLED) {
					throw new Error.PROCESS_NOT_RESPONDING (
						"Unexpectedly timed out while waiting for FIFO to establish");
				} else {
					Source.remove (timeout);

					throw new Error.PROCESS_NOT_RESPONDING ("%s", e.message);
				}
			}

			Source.remove (timeout);

			if (size == 1 && byte_buf[0] != ProgressMessageType.HELLO)
				throw new Error.PROTOCOL ("Unexpected message received");

			if (size == 0) {
				cancel_request.resolve (true);

				Idle.add (() => {
					ended (IMMEDIATE);
					return false;
				});
			} else {
				monitor.begin ();
			}
		}

		public async void cancel () {
			cancellable.cancel ();

			try {
				yield cancel_request.future.wait_async (null);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
		}

		private async void monitor () {
			try {
				var unload_policy = UnloadPolicy.IMMEDIATE;

				var byte_buf = new uint8[1];
				var size = yield input.read_async (byte_buf, Priority.DEFAULT, cancellable);
				if (size == 1) {
					unload_policy = (UnloadPolicy) byte_buf[0];

					var tid_buf = new uint8[4];
					yield input.read_all_async (tid_buf, Priority.DEFAULT, cancellable, null);
					var tid = *((uint *) tid_buf);

					yield input.read_async (byte_buf, Priority.DEFAULT, cancellable);

					var thread_path = "/proc/%u/task/%u".printf (pid, tid);
					while (FileUtils.test (thread_path, EXISTS)) {
						Timeout.add (50, monitor.callback);
						yield;
					}
				}

				ended (unload_policy);
			} catch (GLib.Error e) {
				if (!(e is IOError.CANCELLED))
					ended (IMMEDIATE);
			}

			cancel_request.resolve (true);
		}
	}

	protected enum ProgressMessageType {
		HELLO = 0xff
	}

	protected class StdioPipes : Object {
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
