namespace Frida {
	public sealed class Binjector : Object, Injector {
		public signal void output (uint pid, int fd, uint8[] data);

		public string temp_directory {
			owned get {
				return resource_store.tempdir.path;
			}
		}

		public ResourceStore resource_store {
			get {
				if (_resource_store == null) {
					try {
						_resource_store = new ResourceStore ();
					} catch (Error e) {
						assert_not_reached ();
					}
				}
				return _resource_store;
			}
		}
		private ResourceStore _resource_store;

		private Gee.HashMap<uint, uint> pid_by_id = new Gee.HashMap<uint, uint> ();
		private Gee.HashMap<uint, TemporaryFile> blob_file_by_id = new Gee.HashMap<uint, TemporaryFile> ();
		private uint next_injectee_id = 1;
		private uint next_blob_id = 1;

		private Gee.HashMap<uint, SpawnInstance> spawn_instances = new Gee.HashMap<uint, SpawnInstance> ();
		private Gee.HashMap<uint, uint> watch_sources = new Gee.HashMap<uint, uint> ();
		private Gee.HashMap<uint, OutputStream> stdin_streams = new Gee.HashMap<uint, OutputStream> ();

		private Gee.HashMap<uint, InjectInstance> inject_instances = new Gee.HashMap<uint, InjectInstance> ();
		private Gee.HashMap<uint, RemoteThreadSession> inject_sessions = new Gee.HashMap<uint, RemoteThreadSession> ();
		private Gee.HashMap<uint, uint> inject_expiry_by_id = new Gee.HashMap<uint, uint> ();

		private Cancellable io_cancellable = new Cancellable ();

		public async void close (Cancellable? cancellable) throws IOError {
			io_cancellable.cancel ();

			_resource_store = null;
		}

		public async uint spawn (string path, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError {
			bool is_program = path.has_prefix ("/");
			if (is_program && !FileUtils.test (path, EXISTS))
				throw new Error.EXECUTABLE_NOT_FOUND ("Unable to find executable at '%s'", path);

			StdioPipes? pipes;
			uint child_pid = is_program
				? spawn_program (path, options, out pipes)
				: spawn_app (path, options, out pipes);

			monitor_child (child_pid);

			if (pipes != null) {
				stdin_streams[child_pid] = pipes.input;
				process_next_output_from.begin (pipes.output, child_pid, 1, pipes);
				process_next_output_from.begin (pipes.error, child_pid, 2, pipes);
			}

			return child_pid;
		}

		private void monitor_child (uint pid) {
			watch_sources[pid] = ChildWatch.add ((Pid) pid, on_child_dead);
		}

		private void on_child_dead (Pid pid, int status) {
			watch_sources.unset (pid);

			stdin_streams.unset (pid);

			spawn_instances.unset (pid);
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
			throw new Error.NOT_SUPPORTED ("Exec transitions are not yet supported on this OS");
		}

		public async void await_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Exec transitions are not yet supported on this OS");
		}

		public async void cancel_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Exec transitions are not yet supported on this OS");
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
			SpawnInstance instance;
			if (!spawn_instances.unset (pid, out instance))
				throw new Error.INVALID_ARGUMENT ("Invalid PID");

			instance.resume ();
		}

		public async uint inject_library_file (uint pid, string path, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			uint id = next_injectee_id++;
			inject_instances[id] = inject (pid, path, data, id);

			pid_by_id[id] = pid;

			yield establish_session (id, pid);

			return id;
		}

		public async uint inject_library_blob (uint pid, Bytes blob, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			var name = "blob%u.so".printf (next_blob_id++);
			var file = new TemporaryFile.from_stream (name, new MemoryInputStream.from_bytes (blob), resource_store.tempdir);
			var path = file.path;
			FileUtils.chmod (path, 0755);

			var id = yield inject_library_file (pid, path, entrypoint, data, cancellable);

			blob_file_by_id[id] = file;

			return id;
		}

		public async uint inject_library_resource (uint pid, AgentDescriptor descriptor, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			return yield inject_library_file (pid, resource_store.ensure_copy_of (descriptor), entrypoint, data, cancellable);
		}

		public async void demonitor (uint id, Cancellable? cancellable) throws Error, IOError {
			if (!inject_instances.has_key (id))
				throw new Error.INVALID_ARGUMENT ("Invalid ID");

			yield end_session (id);

			schedule_inject_expiry_for_id (id);
		}

		public async uint demonitor_and_clone_state (uint id, Cancellable? cancellable) throws Error, IOError {
			if (!inject_instances.has_key (id))
				throw new Error.INVALID_ARGUMENT ("Invalid ID");

			yield end_session (id);

			uint clone_id = next_injectee_id++;

			schedule_inject_expiry_for_id (id);
			schedule_inject_expiry_for_id (clone_id);

			return clone_id;
		}

		public async void recreate_thread (uint pid, uint id, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Forked children are not yet supported on this OS");
		}

		public IOStream request_control_channel (uint id) throws Error {
			var instance = inject_instances[id];
			if (instance == null)
				throw new Error.INVALID_ARGUMENT ("Invalid ID");

			return instance.take_control_channel ();
		}

		private async void establish_session (uint id, uint pid) throws Error {
			var session = new RemoteThreadSession (id, pid, inject_instances[id].open_fifo ());
			try {
				yield session.establish ();
			} catch (Error e) {
				destroy_inject_instance (id, IMMEDIATE);
				throw e;
			}

			inject_sessions[id] = session;
			session.ended.connect (on_remote_thread_session_ended);
		}

		private async void end_session (uint id) {
			RemoteThreadSession session;
			if (!inject_sessions.unset (id, out session))
				return;

			session.ended.disconnect (on_remote_thread_session_ended);
			yield session.cancel ();
		}

		private void on_remote_thread_session_ended (RemoteThreadSession session, UnloadPolicy unload_policy) {
			var id = session.id;

			session.ended.disconnect (on_remote_thread_session_ended);
			inject_sessions.unset (id);

			Timeout.add (50, () => {
				destroy_inject_instance (id, unload_policy);
				return false;
			});
		}

		private void destroy_inject_instance (uint id, UnloadPolicy unload_policy) {
			bool found = inject_instances.unset (id);
			assert (found);

			on_uninjected (id);
		}

		private void schedule_inject_expiry_for_id (uint id) {
			uint previous_timer;
			if (inject_expiry_by_id.unset (id, out previous_timer))
				Source.remove (previous_timer);

			inject_expiry_by_id[id] = Timeout.add_seconds (20, () => {
				var removed = inject_expiry_by_id.unset (id);
				assert (removed);

				destroy_inject_instance (id, IMMEDIATE);

				return false;
			});
		}

		public bool any_still_injected () {
			return !pid_by_id.is_empty;
		}

		public bool is_still_injected (uint id) {
			return pid_by_id.has_key (id);
		}

		private void on_uninjected (uint id) {
			pid_by_id.unset (id);
			blob_file_by_id.unset (id);

			uninjected (id);
		}

		private uint spawn_program (string path, HostSpawnOptions options, out StdioPipes? pipes) throws Error {
			var image = new ElfImage.from_file (path);

			string[] argv = options.compute_argv (path);

			FileDescriptor? in_fd, out_fd, err_fd;
			pipes = make_stdio_pipes (options.stdio, true, out in_fd, null, out out_fd, null, out err_fd, null);

			var process = new RemoteProcess (spawn_signed_host (argv));
			try {
				process.run_to_main ();

				var credentials = process.save_credentials ();
				process.raise_credentials ();
				try {
					if (in_fd != null)
						process.adopt_stdio (in_fd, out_fd, err_fd);

					load_program (process, image, Path.get_basename (argv[0]));
				} finally {
					process.restore_credentials (credentials);
				}
			} catch (Error e) {
				process.kill ();
				throw e;
			}

			uint pid = process.pid;
			spawn_instances[pid] = new SpawnInstance (pid);

			return pid;
		}

		private uint spawn_app (string identifier, HostSpawnOptions options, out StdioPipes? pipes) throws Error {
			pipes = null;

			string[] argv = options.compute_argv (identifier);

			var process = new RemoteProcess (AppLauncher.launch (identifier, argv));
			try {
				Gum.Address entry = Prospero.kernel_dynlib_entry_addr ((int) process.pid, MAIN_MODULE_HANDLE);
				if (entry == 0) {
					throw new Error.NOT_SUPPORTED ("Unable to locate the entrypoint of '%s'",
						identifier);
				}

				process.run_to (entry + SPAWN_MAIN_OFFSET);
			} catch (Error e) {
				process.kill ();
				throw e;
			}

			uint pid = process.pid;
			spawn_instances[pid] = new SpawnInstance (pid);

			return pid;
		}

		private void load_program (RemoteProcess process, ElfImage image, string name) throws Error {
			var mapping = process.map_image (image);

			Gum.Address args = process.make_payload_args ();

			var regs = process.get_regs ();

			regs.r_rsp -= (int64) sizeof (uint64);
			process.write_u64 ((Gum.Address) regs.r_rsp, (uint64) regs.r_rip);

			regs.r_rip = (int64) (mapping.load_bias + image.entrypoint);
			regs.r_rdi = (int64) args;

			process.set_regs (regs);

			process.set_name (name);
		}

		private InjectInstance inject (uint pid, string path, string data, uint id) throws Error {
			var image = new ElfImage.from_file (path);

			FileDescriptor fifo, fifo_peer, ctrl, ctrl_peer;
			make_socketpair (out fifo, out fifo_peer);
			make_socketpair (out ctrl, out ctrl_peer);

			var instance = new InjectInstance (id, pid, (owned) fifo, (owned) ctrl);

			bool already_attached;
			Ptrace.attach (pid, out already_attached);

			var process = new RemoteProcess (pid);

			var credentials = process.save_credentials ();
			process.raise_credentials ();
			try {
				int remote_fifo = process.dup_fd (fifo_peer.handle);
				int remote_ctrl = process.dup_fd (ctrl_peer.handle);

				var mapping = process.map_image (image);

				seed_agent_args (process, image, mapping, data, remote_fifo, remote_ctrl);

				instance.agent_thread = start_agent_thread (process, image, mapping);
			} catch (Error e) {
				process.restore_credentials (credentials);
				if (!already_attached)
					Ptrace.detach (pid);
				throw e;
			}
			process.restore_credentials (credentials);

			if (already_attached) {
				process.hold_other_threads (instance.agent_thread);

				var spawned = spawn_instances[pid];
				if (spawned != null)
					spawned.stopped = false;
			} else {
				Ptrace.detach (pid);
			}

			return instance;
		}

		private void seed_agent_args (RemoteProcess process, ElfImage image, MappedImage mapping,
				string data, int remote_fifo, int remote_ctrl) throws Error {
			Gum.Address args_location = image.find_export (Prospero.AGENT_ARGS_SYMBOL);
			if (args_location == 0)
				throw new Error.NOT_SUPPORTED ("Agent is missing %s", Prospero.AGENT_ARGS_SYMBOL);

			size_t parameters_size = data.length + 1;
			Gum.Address parameters = process.mmap ((size_t) round_page (parameters_size), Posix.PROT_READ | Posix.PROT_WRITE);
			process.write (parameters, data.data[0:parameters_size]);

			var args = Prospero.AgentArgs ();
			args.agent_parameters = parameters;
			args.fifo_fd = remote_fifo;
			args.agent_ctrlfd = remote_ctrl;
			args.mapped_range = mapping.range;

			var raw_args = new uint8[sizeof (Prospero.AgentArgs)];
			Memory.copy (raw_args, &args, raw_args.length);

			process.write (mapping.load_bias + args_location, raw_args);
		}

		private int start_agent_thread (RemoteProcess process, ElfImage image, MappedImage mapping) throws Error {
			Gum.Address create_impl = process.resolve ("scePthreadCreate");
			if (create_impl == 0)
				throw new Error.NOT_SUPPORTED ("Unable to resolve scePthreadCreate");

			Gum.Address storage = process.mmap (PAGE_SIZE, Posix.PROT_READ | Posix.PROT_WRITE);
			Gum.Address name = storage + sizeof (void *);
			process.write (name, AGENT_THREAD_NAME.data[0:AGENT_THREAD_NAME.length + 1]);

			Gum.Address payload_args = process.make_payload_args ();

			int[] before = process.list_threads ();

			uint64 retval = process.call (create_impl, new Gum.Address[] {
				storage,
				0,
				mapping.load_bias + image.entrypoint,
				payload_args,
				name,
			});
			if (retval != 0)
				throw new Error.NOT_SUPPORTED ("Unable to start agent thread: 0x%" + uint64.FORMAT_MODIFIER + "x", retval);

			foreach (int tid in process.list_threads ()) {
				if (!(tid in before))
					return tid;
			}

			return 0;
		}

		public sealed class ResourceStore {
			public TemporaryDirectory tempdir {
				get;
				private set;
			}

			private Gee.HashMap<string, TemporaryFile> agents = new Gee.HashMap<string, TemporaryFile> ();

			public ResourceStore () throws Error {
				tempdir = new TemporaryDirectory ();
				FileUtils.chmod (tempdir.path, 0755);
			}

			~ResourceStore () {
				foreach (var tempfile in agents.values)
					tempfile.destroy ();
				tempdir.destroy ();
			}

			public string ensure_copy_of (AgentDescriptor desc) throws Error {
				var temp_agent = agents[desc.name];
				if (temp_agent == null) {
					temp_agent = new TemporaryFile.from_stream (desc.name, desc.sofile, tempdir);
					FileUtils.chmod (temp_agent.path, 0755);
					agents[desc.name] = temp_agent;
				}
				return temp_agent.path;
			}
		}
	}

	public sealed class AgentDescriptor : Object {
		public string name {
			get;
			construct;
		}

		public InputStream sofile {
			get {
				reset_stream (_sofile);
				return _sofile;
			}

			construct {
				_sofile = value;
			}
		}
		private InputStream _sofile;

		public AgentDescriptor (string name, InputStream sofile) {
			Object (name: name, sofile: sofile);

			assert (sofile is Seekable);
		}

		private void reset_stream (InputStream stream) {
			try {
				((Seekable) stream).seek (0, SeekType.SET);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
		}
	}

	private sealed class SpawnInstance : Object {
		public bool stopped {
			get;
			set;
			default = true;
		}

		private uint pid;

		public SpawnInstance (uint pid) {
			this.pid = pid;
		}

		public void resume () {
			if (!stopped) {
				Posix.kill ((Posix.pid_t) pid, Posix.Signal.STOP);
				Posix.waitpid ((Posix.pid_t) pid, null, 0);
			}

			Ptrace.detach (pid);
		}
	}

	private sealed class InjectInstance : Object {
		public uint id;
		public uint pid;
		public int agent_thread;

		private FileDescriptor fifo;
		private FileDescriptor ctrl;

		public InjectInstance (uint id, uint pid, owned FileDescriptor fifo, owned FileDescriptor ctrl) {
			this.id = id;
			this.pid = pid;
			this.fifo = (owned) fifo;
			this.ctrl = (owned) ctrl;
		}

		public InputStream open_fifo () {
			return new UnixInputStream (fifo.handle, false);
		}

		public IOStream take_control_channel () throws Error {
			try {
				var socket = new Socket.from_fd (ctrl.steal ());

				return SocketConnection.factory_create_connection (socket);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("%s", e.message);
			}
		}
	}

	private sealed class RemoteThreadSession : Object {
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

					while (process_has_thread (pid, tid)) {
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

	private sealed class AppLauncher : Object {
		private string identifier;
		private string[] argv;

		public static uint launch (string identifier, string[] argv) throws Error {
			uint launcher = find_process_by_name (APP_LAUNCHER_NAME);
			if (launcher == 0)
				throw new Error.NOT_SUPPORTED ("Unable to find %s", APP_LAUNCHER_NAME);

			int queue = FreeBSD.kqueue ();
			try {
				var change = FreeBSD.KEvent ();
				change.ident = launcher;
				change.filter = PROC;
				change.flags = FreeBSD.EventFlags.ADD | FreeBSD.EventFlags.ENABLE | FreeBSD.EventFlags.CLEAR;
				change.fflags = FreeBSD.ProcEvent.FORK | FreeBSD.ProcEvent.EXEC | FreeBSD.ProcEvent.TRACK;
				if (FreeBSD.kevent (queue, &change, 1, null, 0, null) == -1)
					throw new Error.NOT_SUPPORTED ("Unable to launch '%s'", identifier);

				var request = new AppLauncher (identifier, argv);
				new Thread<void> ("frida-app-launch", request.run);

				var event = FreeBSD.KEvent ();
				var timeout = Posix.timespec ();
				timeout.tv_sec = APP_LAUNCH_TIMEOUT;
				if (FreeBSD.kevent (queue, null, 0, &event, 1, timeout) != 1)
					throw new Error.NOT_SUPPORTED ("Unable to launch '%s'", identifier);

				if ((event.fflags & FreeBSD.ProcEvent.CHILD) == 0)
					throw new Error.NOT_SUPPORTED ("Unable to launch '%s'", identifier);

				uint pid = (uint) event.ident;

				try {
					hold_at_entry (pid);
				} catch (Error e) {
					Ptrace.run (KILL, pid, null, 0);
					Ptrace.detach (pid);
					throw e;
				}

				return pid;
			} finally {
				Posix.close (queue);
			}
		}

		private AppLauncher (string identifier, string[] argv) {
			this.identifier = identifier;
			this.argv = argv;
		}

		private void run () {
			var ctx = Prospero.AppLaunchContext ();

			Prospero.sceUserServiceInitialize (null);
			Prospero.sceUserServiceGetForegroundUser (out ctx.user_id);

			Prospero.sceSystemServiceLaunchApp (identifier, argv, ref ctx);
		}

		private static void hold_at_entry (uint pid) throws Error {
			if (Ptrace.run (ATTACH, pid, null, 0) != 0 || Posix.waitpid ((Posix.pid_t) pid, null, 0) != (Posix.pid_t) pid)
				throw new Error.NOT_SUPPORTED ("Unable to hold the app while it starts: %s", strerror (Posix.errno));

			if (Ptrace.run (LWP_EVENTS, pid, null, 1) != 0)
				throw new Error.NOT_SUPPORTED ("Unable to hold the app while it starts: %s", strerror (Posix.errno));

			if (Ptrace.run (CONTINUE, pid, (void *) 1, Posix.Signal.CONT) != 0)
				throw new Error.NOT_SUPPORTED ("Unable to hold the app while it starts: %s", strerror (Posix.errno));

			await_exec (pid);

			if (Ptrace.run (LWP_EVENTS, pid, null, 0) != 0)
				throw new Error.NOT_SUPPORTED ("Unable to hold the app while it starts: %s", strerror (Posix.errno));
		}

		private static void await_exec (uint pid) throws Error {
			var info = FreeBSD.PtraceLwpInfo ();

			while ((info.pl_flags & FreeBSD.PtraceLwpFlags.EXEC) == 0) {
				if (Posix.waitpid ((Posix.pid_t) pid, null, 0) != (Posix.pid_t) pid)
					throw new Error.NOT_SUPPORTED ("Unable to observe the app's exec");

				if (Ptrace.run (LWPINFO, pid, &info, (int) sizeof (FreeBSD.PtraceLwpInfo)) != 0)
					throw new Error.NOT_SUPPORTED ("Unable to observe the app's exec");
			}
		}

		private static uint find_process_by_name (string name) {
			uint result = 0;

			var options = new ProcessQueryOptions ();
			options.scope = MINIMAL;

			foreach (var process in System.enumerate_processes (options)) {
				if (process.name == name) {
					result = process.pid;
					break;
				}
			}

			return result;
		}
	}

	private sealed class RemoteProcess : Object {
		public uint pid {
			get;
			private set;
		}

		public RemoteProcess (uint pid) {
			this.pid = pid;
		}

		public void kill () {
			Ptrace.run (KILL, pid, null, 0);
			Ptrace.detach (pid);
		}

		public void run_to_main () throws Error {
			if (syscall (SYS_DYNLIB_RELOCATE, {}) != 0)
				throw new Error.NOT_SUPPORTED ("Unable to bring host process to main");

			set_heap_size (UNLIMITED_HEAP);

			Gum.Address entry = Prospero.kernel_dynlib_entry_addr ((int) pid, MAIN_MODULE_HANDLE);
			if (entry == 0)
				throw new Error.NOT_SUPPORTED ("Unable to bring host process to main");

			run_to (entry + SPAWN_MAIN_OFFSET);
		}

		public void run_to (Gum.Address address) throws Error {
			if (Prospero.kernel_mprotect ((int) pid, address, PAGE_SIZE,
					Posix.PROT_READ | Posix.PROT_WRITE | Posix.PROT_EXEC) != 0) {
				throw new Error.NOT_SUPPORTED ("Unable to run to 0x%" + uint64.FORMAT_MODIFIER + "x: %s", address,
					strerror (Posix.errno));
			}

			var original = new uint8[1];
			read (address, original);

			write (address, new uint8[] { BREAKPOINT_INSN });

			if (Ptrace.run (CONTINUE, pid, (void *) 1, Posix.Signal.CONT) != 0 ||
					Posix.waitpid ((Posix.pid_t) pid, null, 0) != (Posix.pid_t) pid) {
				throw new Error.NOT_SUPPORTED ("Unable to run to 0x%" + uint64.FORMAT_MODIFIER + "x: %s", address,
					strerror (Posix.errno));
			}

			write (address, original);

			var regs = get_regs ();
			regs.r_rip = (int64) address;
			set_regs (regs);
		}

		public void adopt_stdio (FileDescriptor in_fd, FileDescriptor out_fd, FileDescriptor err_fd) throws Error {
			FileDescriptor[] sources = { in_fd, out_fd, err_fd };

			for (int i = 0; i != sources.length; i++) {
				int remote_fd = dup_fd (sources[i].handle);

				dup2 (remote_fd, i);

				syscall (FreeBSD.Syscall.CLOSE, { remote_fd });
			}
		}

		public MappedImage map_image (ElfImage image) throws Error {
			Gum.Address lowest = image.lowest;
			size_t size = (size_t) (image.highest - lowest);

			Gum.Address base_address = mmap (size, Posix.PROT_READ | Posix.PROT_WRITE);
			Gum.Address load_bias = base_address - lowest;

			write (base_address, image.materialize (load_bias));

			image.enumerate_code_segments (segment => {
				try {
					protect_code (load_bias + segment.vm_address, (size_t) round_page (segment.vm_size));
				} catch (Error e) {
				}
				return true;
			});

			return new MappedImage (base_address, size, load_bias);
		}

		public Gum.Address make_payload_args () throws Error {
			Gum.Address page = mmap (PAGE_SIZE, Posix.PROT_READ | Posix.PROT_WRITE);

			int master_sock = (int) syscall (FreeBSD.Syscall.SOCKET,
				{ Posix.AF_INET6, Posix.SOCK_DGRAM, Posix.IPProto.UDP });
			int victim_sock = (int) syscall (FreeBSD.Syscall.SOCKET,
				{ Posix.AF_INET6, Posix.SOCK_DGRAM, Posix.IPProto.UDP });
			if (master_sock < 0 || victim_sock < 0)
				throw new Error.NOT_SUPPORTED ("Unable to hand kernel access to the agent: socket failed");

			var pktoptions = new uint32[6];
			pktoptions[0] = 20;
			pktoptions[1] = Posix.IPProto.IPV6;
			pktoptions[2] = FreeBSD.IPV6_TCLASS;
			write (page, ((uint8[]) pktoptions)[0:24]);

			if (syscall (FreeBSD.Syscall.SETSOCKOPT,
					{ master_sock, Posix.IPProto.IPV6, IPV6_2292PKTOPTIONS, page, 24 }) != 0) {
				throw new Error.NOT_SUPPORTED (
					"Unable to hand kernel access to the agent: setsockopt(master) failed");
			}

			write (page, new uint8[20]);

			if (syscall (FreeBSD.Syscall.SETSOCKOPT,
					{ victim_sock, Posix.IPProto.IPV6, FreeBSD.IPV6_PKTINFO, page, 20 }) != 0) {
				throw new Error.NOT_SUPPORTED (
					"Unable to hand kernel access to the agent: setsockopt(victim) failed");
			}

			if (Prospero.kernel_overlap_sockets ((int) pid, master_sock, victim_sock) != 0) {
				throw new Error.NOT_SUPPORTED (
					"Unable to hand kernel access to the agent: kernel_overlap_sockets failed");
			}

			Gum.Address pipe_impl = resolve ("pipe");
			if (pipe_impl == 0)
				throw new Error.NOT_SUPPORTED ("Unable to hand kernel access to the agent: resolve(pipe) failed");

			if ((int) call (pipe_impl, { page }) != 0)
				throw new Error.NOT_SUPPORTED ("Unable to hand kernel access to the agent: pipe failed");

			int pipe_read = read_i32 (page);
			int pipe_write = read_i32 (page + 4);

			Gum.Address getpid_impl = resolve ("getpid");
			if (getpid_impl == 0)
				throw new Error.NOT_SUPPORTED ("Unable to hand kernel access to the agent: resolve(getpid) failed");

			Gum.Address kpipe = Prospero.kernel_get_proc_file ((int) pid, pipe_read);
			if (kpipe == 0) {
				throw new Error.NOT_SUPPORTED (
					"Unable to hand kernel access to the agent: kernel_get_proc_file failed");
			}

			Gum.Address rwpipe = page + ARGS_RWPIPE_OFFSET;
			Gum.Address rwpair = page + ARGS_RWPAIR_OFFSET;
			Gum.Address payloadout = page + ARGS_PAYLOADOUT_OFFSET;

			var slots = new uint64[6];
			slots[0] = getpid_impl;
			slots[1] = rwpipe;
			slots[2] = rwpair;
			slots[3] = kpipe;
			slots[4] = Prospero.KERNEL_ADDRESS_DATA_BASE;
			slots[5] = payloadout;
			write (page, (uint8[]) slots);

			var pipe_fds = new int32[] { pipe_read, pipe_write };
			write (rwpipe, (uint8[]) pipe_fds);

			var sock_fds = new int32[] { master_sock, victim_sock };
			write (rwpair, (uint8[]) sock_fds);

			return page;
		}

		public Gum.Address mmap (size_t size, int prot) throws Error {
			Gum.Address result = (Gum.Address) syscall (FreeBSD.Syscall.MMAP,
				{ 0, size, prot, Posix.MAP_PRIVATE | FreeBSD.MAP_ANONYMOUS, uint64.MAX, 0 });
			if (result == 0 || result == MAP_FAILED)
				throw new Error.NOT_SUPPORTED ("Unable to allocate %zu bytes in target process", size);

			return result;
		}

		public void protect_code (Gum.Address address, size_t size) throws Error {
			if (Prospero.kernel_mprotect ((int) pid, address, size,
					Posix.PROT_READ | Posix.PROT_WRITE | Posix.PROT_EXEC) != 0) {
				throw new Error.NOT_SUPPORTED ("Unable to make agent code executable");
			}
		}

		public void set_name (string name) throws Error {
			Gum.Address buffer = mmap (PAGE_SIZE, Posix.PROT_READ | Posix.PROT_WRITE);

			write (buffer, name.data[0:name.length + 1]);

			syscall (FreeBSD.Syscall.THR_SET_NAME, { uint64.MAX, buffer });
			syscall (FreeBSD.Syscall.MUNMAP, { buffer, PAGE_SIZE });
		}

		public void set_heap_size (ssize_t size) throws Error {
			Gum.Address query_impl = resolve ("sceKernelGetProcParam");
			if (query_impl == 0)
				throw new Error.NOT_SUPPORTED ("Unable to reach the libc parameters");

			Gum.Address proc_param = call (query_impl, {});
			if (proc_param == 0)
				throw new Error.NOT_SUPPORTED ("Unable to reach the libc parameters");

			Gum.Address libc_param = read_u64 (proc_param + PROC_PARAM_LIBC_OFFSET);
			Gum.Address heap_size_slot = read_u64 (libc_param + LIBC_PARAM_HEAP_SIZE_OFFSET);

			write_u64 (heap_size_slot, (uint64) size);

			write_u64 (libc_param + LIBC_PARAM_EXTENDED_OFFSET, read_u64 (libc_param + LIBC_PARAM_NEED_OFFSET));
		}

		public void hold_other_threads (int keep) throws Error {
			int[] threads = list_threads ();
			if (threads.length == 0)
				throw new Error.NOT_SUPPORTED ("Unable to hold the spawned program: %s", strerror (Posix.errno));

			foreach (int tid in threads) {
				if (tid == keep)
					continue;

				if (Ptrace.run (SUSPEND, tid, null, 0) != 0) {
					throw new Error.NOT_SUPPORTED ("Unable to hold the spawned program: %s",
						strerror (Posix.errno));
				}
			}

			if (Ptrace.run (CONTINUE, pid, (void *) 1, 0) != 0)
				throw new Error.NOT_SUPPORTED ("Unable to hold the spawned program: %s", strerror (Posix.errno));
		}

		public int[] list_threads () {
			var threads = new int[MAX_THREADS];

			long n = Ptrace.run (GETLWPLIST, pid, threads, threads.length);
			if (n <= 0)
				return new int[0];

			return threads[0:n];
		}

		public int dup_fd (int fd) throws Error {
			int result = (int) syscall (SYS_RDUP, { Posix.getpid (), fd });
			if (result < 0)
				throw new Error.NOT_SUPPORTED ("Unable to hand the agent its end of the channel");

			return result;
		}

		public void dup2 (int old_fd, int new_fd) throws Error {
			if (syscall (FreeBSD.Syscall.DUP2, { old_fd, new_fd }) < 0)
				throw new Error.NOT_SUPPORTED ("Unable to set up stdio in target process");
		}

		public Gum.Address resolve (string name) {
			var nid = new char[12];
			Prospero.nid_encode (name, nid);

			Gum.Address result = Prospero.kernel_dynlib_resolve ((int) pid, LIB_EXECUTABLE, nid);
			if (result != 0)
				return result;

			return Prospero.kernel_dynlib_resolve ((int) pid, LIB_KERNEL, nid);
		}

		public uint64 call (Gum.Address func, Gum.Address[] args) throws Error {
			var saved_regs = get_regs ();

			var regs = saved_regs;
			regs.r_rip = (int64) func;
			regs.r_rsp -= (int64) RED_ZONE_SIZE;
			regs.r_rsp -= regs.r_rsp % (int64) STACK_ALIGNMENT;

			for (int i = 0; i != args.length; i++) {
				switch (i) {
					case 0: regs.r_rdi = (int64) args[i]; break;
					case 1: regs.r_rsi = (int64) args[i]; break;
					case 2: regs.r_rdx = (int64) args[i]; break;
					case 3: regs.r_rcx = (int64) args[i]; break;
					case 4: regs.r_r8 = (int64) args[i]; break;
					case 5: regs.r_r9 = (int64) args[i]; break;
				}
			}

			regs.r_rsp -= (int64) sizeof (uint64);
			write_u64 ((Gum.Address) regs.r_rsp, DUMMY_RETURN_ADDRESS);

			set_regs (regs);

			if (!Ptrace.resume_until_stopped (pid, Posix.Signal.SEGV))
				throw new Error.NOT_SUPPORTED ("Target process did not return from remote call");

			regs = get_regs ();
			uint64 retval = (uint64) regs.r_rax;

			set_regs (saved_regs);

			return retval;
		}

		public long syscall (long number, Gum.Address[] args) {
			Gum.Address insn = resolve ("getpid");
			if (insn == 0)
				return -1;
			insn += SYSCALL_INSN_OFFSET;

			var saved_regs = FreeBSD.Regs ();
			var regs = FreeBSD.Regs ();
			if (Ptrace.run (GETREGS, pid, &saved_regs, 0) != 0)
				return -1;
			regs = saved_regs;

			regs.r_rip = (int64) insn;
			regs.r_rax = number;

			for (int i = 0; i != args.length; i++) {
				switch (i) {
					case 0: regs.r_rdi = (int64) args[i]; break;
					case 1: regs.r_rsi = (int64) args[i]; break;
					case 2: regs.r_rdx = (int64) args[i]; break;
					case 3: regs.r_r10 = (int64) args[i]; break;
					case 4: regs.r_r8 = (int64) args[i]; break;
					case 5: regs.r_r9 = (int64) args[i]; break;
				}
			}

			if (Ptrace.run (SETREGS, pid, &regs, 0) != 0)
				return -1;

			do {
				if (Ptrace.run (STEP, pid, (void *) 1, 0) != 0)
					return -1;
				if (Posix.waitpid ((Posix.pid_t) pid, null, 0) != (Posix.pid_t) pid)
					return -1;
				if (Ptrace.run (GETREGS, pid, &regs, 0) != 0)
					return -1;
			} while (regs.r_rsp <= saved_regs.r_rsp);

			if (Ptrace.run (SETREGS, pid, &saved_regs, 0) != 0)
				return -1;

			return (long) regs.r_rax;
		}

		public ProcessCredentials save_credentials () {
			var credentials = ProcessCredentials ();
			credentials.rootdir = Prospero.kernel_get_proc_rootdir ((int) pid);
			credentials.jaildir = Prospero.kernel_get_proc_jaildir ((int) pid);
			credentials.uid = Prospero.kernel_get_ucred_uid ((int) pid);
			credentials.caps = new uint8[CAPS_SIZE];
			Prospero.kernel_get_ucred_caps ((int) pid, credentials.caps);

			return credentials;
		}

		public void raise_credentials () {
			var all_caps = new uint8[CAPS_SIZE];
			Memory.set (all_caps, 0xff, all_caps.length);

			Prospero.kernel_set_proc_rootdir ((int) pid, Prospero.kernel_get_root_vnode ());
			Prospero.kernel_set_proc_jaildir ((int) pid, 0);
			Prospero.kernel_set_ucred_uid ((int) pid, 0);
			Prospero.kernel_set_ucred_caps ((int) pid, all_caps);
		}

		public void restore_credentials (ProcessCredentials credentials) {
			Prospero.kernel_set_proc_rootdir ((int) pid, credentials.rootdir);
			Prospero.kernel_set_proc_jaildir ((int) pid, credentials.jaildir);
			Prospero.kernel_set_ucred_uid ((int) pid, credentials.uid);
			Prospero.kernel_set_ucred_caps ((int) pid, credentials.caps);
		}

		public FreeBSD.Regs get_regs () throws Error {
			var regs = FreeBSD.Regs ();

			if (Ptrace.run (GETREGS, pid, &regs, 0) != 0)
				throw new Error.NOT_SUPPORTED ("Unable to drive target process: %s", strerror (Posix.errno));

			return regs;
		}

		public void set_regs (FreeBSD.Regs regs) throws Error {
			if (Ptrace.run (SETREGS, pid, &regs, 0) != 0)
				throw new Error.NOT_SUPPORTED ("Unable to drive target process: %s", strerror (Posix.errno));
		}

		public void read (Gum.Address address, uint8[] buffer) throws Error {
			var desc = FreeBSD.PtraceIoDesc ();
			desc.piod_op = READ_D;
			desc.piod_offs = (void *) address;
			desc.piod_addr = buffer;
			desc.piod_len = buffer.length;

			if (Ptrace.run (IO, pid, &desc, 0) != 0) {
				throw new Error.NOT_SUPPORTED ("Unable to read from target process: %s",
					strerror (Posix.errno));
			}
		}

		public void write (Gum.Address address, uint8[] data) throws Error {
			var desc = FreeBSD.PtraceIoDesc ();
			desc.piod_op = WRITE_D;
			desc.piod_offs = (void *) address;
			desc.piod_addr = data;
			desc.piod_len = data.length;

			if (Ptrace.run (IO, pid, &desc, 0) != 0)
				throw new Error.NOT_SUPPORTED ("Unable to write to target process: %s", strerror (Posix.errno));
		}

		public int read_i32 (Gum.Address address) throws Error {
			var buffer = new uint8[4];
			read (address, buffer);

			return *((int32 *) buffer);
		}

		public uint64 read_u64 (Gum.Address address) throws Error {
			var buffer = new uint8[8];
			read (address, buffer);

			return *((uint64 *) buffer);
		}

		public void write_u64 (Gum.Address address, uint64 val) throws Error {
			var buffer = new uint8[8];
			*((uint64 *) buffer) = val;

			write (address, buffer);
		}
	}

	private sealed class MappedImage {
		public Gum.MemoryRange range;
		public Gum.Address load_bias;

		public MappedImage (Gum.Address base_address, size_t size, Gum.Address load_bias) {
			range = { base_address, size };
			this.load_bias = load_bias;
		}
	}

	private sealed class ElfImage : Object {
		public Gum.Address entrypoint {
			get {
				return module.entrypoint;
			}
		}

		public Gum.Address lowest {
			get;
			private set;
		}

		public Gum.Address highest {
			get;
			private set;
		}

		private Gum.ElfModule module;

		public ElfImage.from_file (string path) throws Error {
			try {
				module = new Gum.ElfModule.from_file (path);
			} catch (Gum.Error e) {
				throw new Error.NOT_SUPPORTED ("Unable to read agent: %s", e.message);
			}

			Gum.Address low = uint64.MAX, high = 0;
			module.enumerate_segments (segment => {
				low = uint64.min (low, trunc_page (segment.vm_address));
				high = uint64.max (high, round_page (segment.vm_address + segment.vm_size));
				return true;
			});
			lowest = low;
			highest = high;
		}

		public uint8[] materialize (Gum.Address load_bias) {
			var mirror = new uint8[highest - lowest];

			unowned uint8[] file_data = module.get_file_data ();

			module.enumerate_segments (segment => {
				Memory.copy ((uint8 *) mirror + segment.vm_address - lowest,
					(uint8 *) file_data + segment.file_offset, (size_t) segment.file_size);
				return true;
			});

			module.enumerate_relocations (relocation => {
				if (relocation.type != R_X86_64_RELATIVE)
					return true;

				Gum.Address offset = module.translate_to_offline (relocation.address) - lowest;
				*((Gum.Address *) ((uint8 *) mirror + offset)) = load_bias + relocation.addend;

				return true;
			});

			return mirror;
		}

		public void enumerate_code_segments (Gum.FoundElfSegmentFunc func) {
			module.enumerate_segments (segment => {
				if ((segment.protection & Gum.PageProtection.EXECUTE) == 0)
					return true;

				return func (segment);
			});
		}

		public Gum.Address find_export (string name) {
			Gum.Address result = 0;

			module.enumerate_dynamic_symbols (symbol => {
				if (symbol.name != name)
					return true;

				result = module.translate_to_offline (symbol.address);
				return false;
			});

			return result;
		}
	}

	private struct ProcessCredentials {
		public Gum.Address rootdir;
		public Gum.Address jaildir;
		public uint uid;
		public uint8[] caps;
	}

	namespace Ptrace {
		private void attach (uint pid, out bool already_attached) throws Error {
			if (run (ATTACH, pid, null, 0) == 0) {
				already_attached = false;

				if (Posix.waitpid ((Posix.pid_t) pid, null, 0) != (Posix.pid_t) pid)
					throw_attach_failure (pid);

				return;
			}

			var regs = FreeBSD.Regs ();
			if (run (GETREGS, pid, &regs, 0) != 0)
				throw_attach_failure (pid);

			already_attached = true;
		}

		private void detach (uint pid) {
			run (DETACH, pid, null, 0);
		}

		private bool resume_until_stopped (uint pid, Posix.Signal signal) {
			if (run (CONTINUE, pid, (void *) 1, 0) != 0)
				return false;

			int status;
			if (Posix.waitpid ((Posix.pid_t) pid, out status, 0) != (Posix.pid_t) pid)
				return false;

			return is_stopped (status) && parse_stop_signal (status) == signal;
		}

		private long run (FreeBSD.PtraceRequest request, uint pid, void * address, long data) {
			Posix.pid_t self = Posix.getpid ();

			uint64 saved_authid = Prospero.kernel_get_ucred_authid (self);
			var saved_caps = new uint8[CAPS_SIZE];
			Prospero.kernel_get_ucred_caps (self, saved_caps);

			var all_caps = new uint8[CAPS_SIZE];
			Memory.set (all_caps, 0xff, all_caps.length);
			Prospero.kernel_set_ucred_authid (self, DEBUGGER_AUTHID);
			Prospero.kernel_set_ucred_caps (self, all_caps);

			long result = FreeBSD.syscall (PTRACE, request, (int) pid, address, data);

			Prospero.kernel_set_ucred_authid (self, saved_authid);
			Prospero.kernel_set_ucred_caps (self, saved_caps);

			return result;
		}

		private void throw_attach_failure (uint pid) throws Error {
			throw new Error.PERMISSION_DENIED ("Unable to attach to process with pid %u: %s", pid,
				strerror (Posix.errno));
		}
	}

	private void make_socketpair (out FileDescriptor local, out FileDescriptor peer) throws Error {
		var fds = new int[2];

		if (Posix.socketpair (Posix.AF_UNIX, Posix.SOCK_STREAM, 0, fds) != 0)
			throw new Error.NOT_SUPPORTED ("Unable to allocate socketpair: %s", strerror (Posix.errno));

		local = new FileDescriptor (fds[0]);
		peer = new FileDescriptor (fds[1]);
	}

	private uint spawn_signed_host (string[] argv) throws Error {
		int queue = FreeBSD.kqueue ();
		var stack = new uint8[PAGE_SIZE];

		int pid = FreeBSD.rfork_thread (FreeBSD.RforkFlags.PROC | FreeBSD.RforkFlags.CFDG | FreeBSD.RforkFlags.MEM,
			(uint8 *) stack + PAGE_SIZE - 8, exec_signed_host, argv);
		try {
			if (pid == -1)
				throw_signed_host_failure ();

			var event = FreeBSD.KEvent ();
			event.ident = pid;
			event.filter = PROC;
			event.flags = FreeBSD.EventFlags.ADD;
			event.fflags = FreeBSD.ProcEvent.EXEC;
			if (FreeBSD.kevent (queue, &event, 1, &event, 1, null) == -1) {
				Posix.kill (pid, Posix.Signal.KILL);
				throw_signed_host_failure ();
			}

			if (Posix.waitpid (pid, null, 0) != pid) {
				Posix.kill (pid, Posix.Signal.KILL);
				throw_signed_host_failure ();
			}
		} finally {
			Posix.close (queue);
		}

		return pid;
	}

	private int exec_signed_host (void * user_data) {
		unowned string[] argv = (string[]) user_data;

		FreeBSD.syscall (SYS_BUDGET_SET, 0);

		Posix.open ("/dev/deci_stdin", Posix.O_RDONLY);
		Posix.open ("/dev/deci_stdout", Posix.O_WRONLY);
		Posix.open ("/dev/deci_stderr", Posix.O_WRONLY);

		FreeBSD.syscall (PTRACE, FreeBSD.PtraceRequest.TRACE_ME, 0, null, 0);

		FreeBSD.execve (SIGNED_HOST_PATH, argv, null);

		Posix._exit (1);

		return 1;
	}

	private void throw_signed_host_failure () throws Error {
		throw new Error.NOT_SUPPORTED ("Unable to spawn the signed host: %s", strerror (Posix.errno));
	}

	private Gum.Address round_page (Gum.Address address) {
		return trunc_page (address + PAGE_SIZE - 1);
	}

	private Gum.Address trunc_page (Gum.Address address) {
		return address & ~((Gum.Address) PAGE_SIZE - 1);
	}

	private bool process_has_thread (uint pid, long tid) {
		return FreeBSD.syscall (THR_KILL2, (int) pid, tid, 0) == 0;
	}

	[CCode (cname = "WIFSTOPPED", cheader_filename = "sys/wait.h")]
	private extern bool is_stopped (int status);

	[CCode (cname = "WSTOPSIG", cheader_filename = "sys/wait.h")]
	private extern Posix.Signal parse_stop_signal (int status);

	private enum ProgressMessageType {
		HELLO = 0xff
	}

	private const size_t PAGE_SIZE = 0x4000;
	private const size_t STACK_ALIGNMENT = 16;
	private const size_t RED_ZONE_SIZE = 128;
	private const size_t CAPS_SIZE = 16;
	private const int MAX_THREADS = 32;
	private const uint64 DUMMY_RETURN_ADDRESS = 0x320;
	private const uint64 MAP_FAILED = uint64.MAX;
	private const uint8 BREAKPOINT_INSN = 0xcc;
	private const uint32 R_X86_64_RELATIVE = 8;

	private const uint64 DEBUGGER_AUTHID = 0x4800000000010003;
	private const uint64 SYSCALL_INSN_OFFSET = 0xa;
	private const uint32 LIB_EXECUTABLE = 0x1;
	private const uint32 LIB_KERNEL = 0x2001;
	private const uint32 MAIN_MODULE_HANDLE = 0;
	private const int IPV6_2292PKTOPTIONS = 25;
	private const string AGENT_THREAD_NAME = "frida-agent";
	private const string SIGNED_HOST_PATH = "/system/vsh/app/NPXS40112/eboot.bin";
	private const string APP_LAUNCHER_NAME = "SceSysCore.elf";
	private const int APP_LAUNCH_TIMEOUT = 15;
	private const uint64 SPAWN_MAIN_OFFSET = 58;
	private const ssize_t UNLIMITED_HEAP = -1;

	private const long SYS_RDUP = 0x25b;
	private const long SYS_BUDGET_SET = 0x23b;
	private const long SYS_DYNLIB_RELOCATE = 599;

	private const uint64 PROC_PARAM_LIBC_OFFSET = 56;
	private const uint64 LIBC_PARAM_HEAP_SIZE_OFFSET = 16;
	private const uint64 LIBC_PARAM_EXTENDED_OFFSET = 32;
	private const uint64 LIBC_PARAM_NEED_OFFSET = 72;

	private const uint64 ARGS_RWPIPE_OFFSET = 0x100;
	private const uint64 ARGS_RWPAIR_OFFSET = 0x200;
	private const uint64 ARGS_PAYLOADOUT_OFFSET = 0x300;
}
