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

		protected delegate void LaunchCompletionHandler (Error? error);

		private Gee.HashMap<uint, OutputStream> stdin_streams = new Gee.HashMap<uint, OutputStream> ();
		private Gee.HashMap<uint, uint> remote_task_by_pid = new Gee.HashMap<uint, uint> ();
		private Gee.HashMap<uint, uint> expiry_timer_by_pid = new Gee.HashMap<uint, uint> ();

		/* these should be private, but must be accessible to glue code */
		public void * context;
		public Gee.HashMap<uint, void *> spawn_instance_by_pid = new Gee.HashMap<uint, void *> ();
		public Gee.HashMap<uint, void *> inject_instance_by_id = new Gee.HashMap<uint, void *> ();
		private Gee.HashMap<void *, uint> inject_cleaner_by_instance = new Gee.HashMap<void *, uint> ();
		private Gee.HashMap<uint, uint> inject_expiry_by_id = new Gee.HashMap<uint, uint> ();
		public uint next_id = 1;

		private PolicySoftener policy_softener;
		private KernelAgent kernel_agent;

		construct {
			_create_context ();

			kernel_agent = KernelAgent.try_open ();
			if (kernel_agent != null)
				kernel_agent.spawned.connect (on_kernel_agent_spawned);

#if IOS
			if (ElectraPolicySoftener.is_available ())
				policy_softener = new ElectraPolicySoftener ();
			else
#endif
				policy_softener = new NullPolicySoftener ();
		}

		~DarwinHelperBackend () {
			foreach (var instance in spawn_instance_by_pid.values)
				_free_spawn_instance (instance);
			foreach (var instance in inject_instance_by_id.values)
				_free_inject_instance (instance);
			_destroy_context ();
		}

		public async void close () {
			foreach (var entry in inject_cleaner_by_instance.entries) {
				_free_inject_instance (entry.key);
				Source.remove (entry.value);
			}
			inject_cleaner_by_instance.clear ();

			foreach (var id in expiry_timer_by_pid.values)
				Source.remove (id);
			expiry_timer_by_pid.clear ();

			foreach (var task in remote_task_by_pid.values)
				deallocate_port (task);
			remote_task_by_pid.clear ();

			if (kernel_agent != null) {
				kernel_agent.spawned.disconnect (on_kernel_agent_spawned);
				kernel_agent.close ();
				kernel_agent = null;
			}
		}

		public async void preload () throws Error {
		}

		public async void enable_spawn_gating () throws Error {
			if (kernel_agent == null)
				throw new Error.NOT_SUPPORTED ("Kernel driver not loaded");
			kernel_agent.enable_spawn_gating ();
		}

		public async void disable_spawn_gating () throws Error {
			if (kernel_agent == null)
				throw new Error.NOT_SUPPORTED ("Kernel driver not loaded");
			kernel_agent.disable_spawn_gating ();
		}

		public async HostSpawnInfo[] enumerate_pending_spawns () throws Error {
			if (kernel_agent == null)
				throw new Error.NOT_SUPPORTED ("Kernel driver not loaded");
			return kernel_agent.enumerate_pending_spawns ();
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
			Error pending_error = null;

			_launch (identifier, url, (error) => {
				Idle.add (() => {
					pending_error = error;
					launch.callback ();
					return false;
				});
			});

			yield;

			if (pending_error != null)
				throw pending_error;
		}

		public async void input (uint pid, uint8[] data) throws Error {
			var stream = stdin_streams[pid];
			if (stream == null)
				throw new Error.INVALID_ARGUMENT ("Invalid pid");
			try {
				yield stream.write_all_async (data, Priority.DEFAULT, null, null);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT (e.message);
			}
		}

		public async void wait_until_suspended (uint pid) throws Error {
			var timer = new Timer ();

			do {
				var task = borrow_task_for_remote_pid (pid);

				try {
					if (_is_suspended (task))
						return;
				} catch (Error e) {
					if (e is Error.PROCESS_NOT_FOUND) {
						deallocate_port (steal_task_for_remote_pid (pid));
					} else {
						throw e;
					}
				}

				var delay_source = new TimeoutSource (20);
				delay_source.set_callback (() => {
					wait_until_suspended.callback ();
					return false;
				});
				delay_source.attach (MainContext.get_thread_default ());
				yield;
			} while (timer.elapsed () < 2);

			throw new Error.TIMED_OUT ("Unexpectedly timed out while waiting for process to suspend");
		}

		public async void resume (uint pid) throws Error {
			if (kernel_agent != null && kernel_agent.try_resume (pid))
				return;

			void * instance;
			if (spawn_instance_by_pid.unset (pid, out instance)) {
				_resume_spawn_instance (instance);
				_free_spawn_instance (instance);
			} else {
				_resume_process (borrow_task_for_remote_pid (pid));
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
			yield policy_softener.soften (pid);

			var task = borrow_task_for_remote_pid (pid);

			var spawn_instance = spawn_instance_by_pid[pid];
			if (spawn_instance == null && _is_suspended (task))
				spawn_instance = _create_spawn_instance (pid);
			if (spawn_instance != null) {
				_prepare_spawn_instance_for_injection (spawn_instance, task);

				if (kernel_agent == null || !kernel_agent.try_resume (pid))
					_resume_process_fast (task);

				bool timed_out = false;
				var ready_handler = spawn_instance_ready.connect ((ready_pid) => {
					if (ready_pid == pid)
						_inject.callback ();
				});
				var timeout_source = new TimeoutSource.seconds (10);
				timeout_source.set_callback (() => {
					timed_out = true;
					_inject.callback ();
					return false;
				});
				timeout_source.attach (MainContext.get_thread_default ());

				yield;

				timeout_source.destroy ();
				disconnect (ready_handler);

				if (timed_out)
					throw new Error.TIMED_OUT ("Unexpectedly timed out while initializing suspended process");
			}

			return _inject_into_task (pid, task, path_or_name, blob, entrypoint, data);
		}

		public async uint demonitor_and_clone_injectee_state (uint id) throws Error {
			var instance = inject_instance_by_id[id];
			if (instance == null)
				throw new Error.INVALID_ARGUMENT ("Invalid ID");

			var clone_id = _demonitor_and_clone_injectee_state (instance);

			schedule_inject_expiry_for_id (id);
			schedule_inject_expiry_for_id (clone_id);

			return clone_id;
		}

		public async void recreate_injectee_thread (uint pid, uint id) throws Error {
			var instance = inject_instance_by_id[id];
			if (instance == null)
				throw new Error.INVALID_ARGUMENT ("Invalid ID");

			var task = borrow_task_for_remote_pid (pid);

			cancel_inject_expiry_for_id (id);

			_recreate_injectee_thread (instance, pid, task);
		}

		public async Gee.Promise<IOStream> open_pipe_stream (uint remote_pid, out string remote_address) throws Error {
			yield policy_softener.soften (remote_pid);

			var remote_task = borrow_task_for_remote_pid (remote_pid);

			var endpoints = make_pipe_endpoints (0, remote_pid, remote_task);

			remote_address = endpoints.remote_address;

			return Pipe.open (endpoints.local_address);
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

			var expiry_source = new TimeoutSource.seconds (2);
			expiry_source.set_callback (() => {
				var removed = expiry_timer_by_pid.unset (pid);
				assert (removed);

				uint task;
				removed = remote_task_by_pid.unset (pid, out task);
				assert (removed);

				deallocate_port (task);

				return false;
			});
			expiry_timer_by_pid[pid] = expiry_source.attach (MainContext.get_thread_default ());
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
					_destroy_inject_instance (id);

				return false;
			});
		}

		public void _on_posix_thread_dead (uint id) {
			Idle.add (() => {
				_destroy_inject_instance (id);
				return false;
			});
		}

		protected void _destroy_inject_instance (uint id) {
			void * instance;
			bool instance_id_found = inject_instance_by_id.unset (id, out instance);
			assert (instance_id_found);

			var is_resident = _is_instance_resident (instance);

			schedule_inject_instance_cleanup (instance);

			if (!is_resident)
				uninjected (id);

			if (inject_instance_by_id.is_empty)
				idle ();
		}

		private void schedule_inject_instance_cleanup (void * instance) {
			var cleanup_source = new TimeoutSource (50);
			cleanup_source.set_callback (() => {
				_free_inject_instance (instance);

				var removed = inject_cleaner_by_instance.unset (instance);
				assert (removed);

				return false;
			});
			inject_cleaner_by_instance[instance] = cleanup_source.attach (MainContext.get_thread_default ());
		}

		private void schedule_inject_expiry_for_id (uint id) {
			uint previous_timer;
			if (inject_expiry_by_id.unset (id, out previous_timer))
				Source.remove (previous_timer);

			var expiry_source = new TimeoutSource.seconds (20);
			expiry_source.set_callback (() => {
				var removed = inject_expiry_by_id.unset (id);
				assert (removed);

				_destroy_inject_instance (id);

				return false;
			});
			inject_expiry_by_id[id] = expiry_source.attach (MainContext.get_thread_default ());
		}

		private void cancel_inject_expiry_for_id (uint id) {
			uint timer;
			var found = inject_expiry_by_id.unset (id, out timer);
			assert (found);

			Source.remove (timer);
		}

		public uint task_for_pid (uint pid) throws Error {
			if (kernel_agent != null)
				return kernel_agent.task_for_pid (pid);

			return task_for_pid_fallback (pid);
		}

		private void on_kernel_agent_spawned (HostSpawnInfo info) {
			spawned (info);
		}

		public static extern PipeEndpoints make_pipe_endpoints (uint local_task, uint remote_pid, uint remote_task) throws Error;

		public static extern uint task_for_pid_fallback (uint pid) throws Error;
		public static extern void deallocate_port (uint port);

		public static extern bool is_mmap_available ();
		public static extern MappedLibraryBlob mmap (uint task, Bytes blob) throws Error;

		protected extern void _create_context ();
		protected extern void _destroy_context ();

		protected extern uint _spawn (string path, string[] argv, string[] envp, out StdioPipes pipes) throws Error;
		protected extern void _launch (string identifier, string? url, LaunchCompletionHandler on_complete);
		protected extern bool _is_suspended (uint task) throws Error;
		protected extern void _resume_process (uint task) throws Error;
		protected extern void _resume_process_fast (uint task) throws Error;
		protected extern void _kill_process (uint pid);
		protected extern void _kill_application (string identifier);
		protected extern void * _create_spawn_instance (uint pid);
		protected extern void _prepare_spawn_instance_for_injection (void * instance, uint task) throws Error;
		protected extern void _resume_spawn_instance (void * instance);
		protected extern void _free_spawn_instance (void * instance);

		protected extern uint _inject_into_task (uint pid, uint task, string path_or_name, MappedLibraryBlob? blob, string entrypoint, string data) throws Error;
		protected extern uint _demonitor_and_clone_injectee_state (void * instance);
		protected extern void _recreate_injectee_thread (void * instance, uint pid, uint task) throws Error;
		protected extern void _join_inject_instance_posix_thread (void * instance, void * posix_thread);
		protected extern bool _is_instance_resident (void * instance);
		protected extern void _free_inject_instance (void * instance);
	}

	public class KernelAgent : Object {
		public signal void spawned (HostSpawnInfo info);

		public int fd {
			get;
			construct;
		}

		private bool spawn_gating_enabled = false;
		private Gee.HashMap<uint, HostSpawnInfo?> pending_spawn_by_pid = new Gee.HashMap<uint, HostSpawnInfo?> ();

		private DataInputStream input;
		private Cancellable input_cancellable = new Cancellable ();

		private const ulong IOCTL_ENABLE_SPAWN_GATING  = 0x20005201U;
		private const ulong IOCTL_DISABLE_SPAWN_GATING = 0x20005202U;
		private const ulong IOCTL_RESUME               = 0x80045203U;
		private const ulong IOCTL_TASK_FOR_PID         = 0xc0085204U;

		public static KernelAgent? try_open () {
			var fd = Posix.open ("/dev/frida", Posix.O_RDONLY);
			if (fd == -1)
				return null;

			return new KernelAgent (fd);
		}

		private KernelAgent (int fd) {
			Object (fd: fd);
		}

		construct {
			var fd = this.fd;

			try {
				Unix.set_fd_nonblocking (fd, true);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			input = new DataInputStream (new UnixInputStream (fd, true));

			process_incoming_messages.begin ();
		}

		public void close () {
			input_cancellable.cancel ();
		}

		public void enable_spawn_gating () throws Error {
			var status = ioctl (fd, IOCTL_ENABLE_SPAWN_GATING);
			if (status != 0)
				throw new Error.INVALID_OPERATION ("%s", strerror (Posix.errno));
			spawn_gating_enabled = true;
		}

		public void disable_spawn_gating () throws Error {
			var status = ioctl (fd, IOCTL_DISABLE_SPAWN_GATING);
			if (status != 0)
				throw new Error.INVALID_OPERATION ("%s", strerror (Posix.errno));
			spawn_gating_enabled = false;
		}

		public HostSpawnInfo[] enumerate_pending_spawns () {
			var result = new HostSpawnInfo[pending_spawn_by_pid.size];
			var index = 0;
			foreach (var spawn in pending_spawn_by_pid.values)
				result[index++] = spawn;
			return result;
		}

		public bool try_resume (uint pid) throws Error {
			HostSpawnInfo? info;
			if (!pending_spawn_by_pid.unset (pid, out info))
				return false;

			var status = ioctl (fd, IOCTL_RESUME, ref pid);
			if (status != 0)
				throw new Error.INVALID_OPERATION ("%s", strerror (Posix.errno));

			return true;
		}

		public uint task_for_pid (uint pid) throws Error {
			uint val = pid;
			var status = ioctl (fd, IOCTL_TASK_FOR_PID, ref val);
			if (status != 0) {
				var error = Posix.errno;
				if (error == Posix.ESRCH)
					throw new Error.PROCESS_NOT_FOUND ("Unable to find process with pid %u", pid);
				else
					throw new Error.INVALID_OPERATION ("%s", strerror (error));
			}
			return val;
		}

		private async void process_incoming_messages () {
			try {
				while (true) {
					var line = yield input.read_line_async (Priority.DEFAULT, input_cancellable);
					if (line == null)
						break;

					var tokens = line.split (":");

					var state = tokens[2];
					if (state != "suspended" || !spawn_gating_enabled)
						continue;

					var pid = int.parse (tokens[0]);
					var executable_path = tokens[1];

					var info = HostSpawnInfo (pid, executable_path);
					pending_spawn_by_pid[pid] = info;
					spawned (info);
				}
			} catch (IOError e) {
			}
		}

		[CCode (cheader_filename = "sys/ioctl.h", cname = "ioctl", sentinel = "")]
		private static extern int ioctl (int fildes, ulong request, ...);
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
