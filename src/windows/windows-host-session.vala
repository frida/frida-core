namespace Frida {
	public class WindowsHostSessionBackend : Object, HostSessionBackend {
		private WindowsHostSessionProvider local_provider;

		public async void start (Cancellable? cancellable) throws IOError {
			assert (local_provider == null);
			local_provider = new WindowsHostSessionProvider ();
			provider_available (local_provider);
		}

		public async void stop (Cancellable? cancellable) throws IOError {
			assert (local_provider != null);
			provider_unavailable (local_provider);
			yield local_provider.close (cancellable);
			local_provider = null;
		}
	}

	public class WindowsHostSessionProvider : Object, HostSessionProvider {
		public string id {
			get { return "local"; }
		}

		public string name {
			get { return "Local System"; }
		}

		public Image? icon {
			get { return _icon; }
		}
		private Image? _icon;

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.LOCAL; }
		}

		private WindowsHostSession host_session;

		construct {
			_icon = Image.from_data (_try_extract_icon ());
		}

		public async void close (Cancellable? cancellable) throws IOError {
			if (host_session == null)
				return;
			host_session.agent_session_closed.disconnect (on_agent_session_closed);
			yield host_session.close (cancellable);
			host_session = null;
		}

		public async HostSession create (string? location, Cancellable? cancellable) throws Error, IOError {
			assert (location == null);
			if (host_session != null)
				throw new Error.INVALID_ARGUMENT ("Invalid location: already created");
			host_session = new WindowsHostSession ();
			host_session.agent_session_closed.connect (on_agent_session_closed);
			return host_session;
		}

		public async void destroy (HostSession session, Cancellable? cancellable) throws Error, IOError {
			if (session != host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");
			host_session.agent_session_closed.disconnect (on_agent_session_closed);
			yield host_session.close (cancellable);
			host_session = null;
		}

		public async AgentSession obtain_agent_session (HostSession host_session, AgentSessionId agent_session_id,
				Cancellable? cancellable) throws Error, IOError {
			if (host_session != this.host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");
			return this.host_session.obtain_agent_session (agent_session_id);
		}

		private void on_agent_session_closed (AgentSessionId id, AgentSession session, SessionDetachReason reason,
				CrashInfo? crash) {
			agent_session_closed (id, reason, crash);
		}

		public extern static ImageData? _try_extract_icon ();
	}

	public class WindowsHostSession : BaseDBusHostSession {
		private AgentContainer system_session_container;

		private AgentDescriptor agent_desc;

		private ApplicationEnumerator application_enumerator = new ApplicationEnumerator ();
		private ProcessEnumerator process_enumerator = new ProcessEnumerator ();

		private Gee.HashMap<uint, ChildProcess> process_by_pid = new Gee.HashMap<uint, ChildProcess> ();

		construct {
			injector = new Winjector ();
			injector.uninjected.connect (on_uninjected);

			var blob32 = Frida.Data.Agent.get_frida_agent_32_dll_blob ();
			var blob64 = Frida.Data.Agent.get_frida_agent_64_dll_blob ();
			var dbghelp32 = Frida.Data.Agent.get_dbghelp_32_dll_blob ();
			var dbghelp64 = Frida.Data.Agent.get_dbghelp_64_dll_blob ();
			var symsrv32 = Frida.Data.Agent.get_symsrv_32_dll_blob ();
			var symsrv64 = Frida.Data.Agent.get_symsrv_64_dll_blob ();

			agent_desc = new AgentDescriptor.with_resources ("%u\\frida-agent.dll",
				new MemoryInputStream.from_data (blob32.data, null),
				new MemoryInputStream.from_data (blob64.data, null),
				new AgentResource[] {
					new AgentResource ("32\\dbghelp.dll", new MemoryInputStream.from_data (dbghelp32.data, null)),
					new AgentResource ("32\\symsrv.dll", new MemoryInputStream.from_data (symsrv32.data, null)),
					new AgentResource ("64\\dbghelp.dll", new MemoryInputStream.from_data (dbghelp64.data, null)),
					new AgentResource ("64\\symsrv.dll", new MemoryInputStream.from_data (symsrv64.data, null))
				}
			);
		}

		public override async void close (Cancellable? cancellable) throws IOError {
			yield base.close (cancellable);

			var winjector = injector as Winjector;

			yield wait_for_uninject (injector, cancellable, () => {
				return winjector.any_still_injected ();
			});

			injector.uninjected.disconnect (on_uninjected);
			yield injector.close (cancellable);

			if (system_session_container != null) {
				yield system_session_container.destroy (cancellable);
				system_session_container = null;
			}

			foreach (var process in process_by_pid.values)
				process.close ();
			process_by_pid.clear ();
		}

		protected override async AgentSessionProvider create_system_session_provider (Cancellable? cancellable,
				out DBusConnection connection) throws Error, IOError {
			var winjector = injector as Winjector;
			var path_template = winjector.get_normal_resource_store ().ensure_copy_of (agent_desc);
			var agent_path = path_template.printf (sizeof (void *) == 8 ? 64 : 32);

			system_session_container = yield AgentContainer.create (agent_path, cancellable);

			connection = system_session_container.connection;

			return system_session_container;
		}

		public override async HostApplicationInfo get_frontmost_application (Cancellable? cancellable) throws Error, IOError {
			return System.get_frontmost_application ();
		}

		public override async HostApplicationInfo[] enumerate_applications (Cancellable? cancellable) throws Error, IOError {
			return yield application_enumerator.enumerate_applications ();
		}

		public override async HostProcessInfo[] enumerate_processes (Cancellable? cancellable) throws Error, IOError {
			return yield process_enumerator.enumerate_processes ();
		}

		public override async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		public override async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		public override async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		public override async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable)
				throws Error, IOError {
			var path = program;

			if (!FileUtils.test (path, EXISTS))
				throw new Error.EXECUTABLE_NOT_FOUND ("Unable to find executable at '%s'", path);

			var process = _spawn (path, options);

			var pid = process.pid;
			process_by_pid[pid] = process;

			var pipes = process.pipes;
			if (pipes != null) {
				process_next_output_from.begin (pipes.output, pid, 1, pipes);
				process_next_output_from.begin (pipes.error, pid, 2, pipes);
			}

			return pid;
		}

		public void _on_child_dead (ChildProcess process, int status) {
			process_by_pid.unset (process.pid);
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

		protected override bool process_is_alive (uint pid) {
			return _process_is_alive (pid);
		}

		public override async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError {
			var process = process_by_pid[pid];
			if (process == null)
				throw new Error.INVALID_ARGUMENT ("Invalid PID");
			try {
				yield process.pipes.input.write_all_async (data, Priority.DEFAULT, cancellable, null);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("%s", e.message);
			}
		}

		protected override async void perform_resume (uint pid, Cancellable? cancellable) throws Error, IOError {
			var process = process_by_pid[pid];
			if (process == null)
				throw new Error.INVALID_ARGUMENT ("Invalid PID");
			process.resume ();
		}

		public override async void kill (uint pid, Cancellable? cancellable) throws Error, IOError {
			System.kill (pid);
		}

		protected override async Future<IOStream> perform_attach_to (uint pid, Cancellable? cancellable, out Object? transport)
				throws Error, IOError {
			var t = new PipeTransport ();

			var stream_request = Pipe.open (t.local_address, cancellable);

			yield wait_for_uninject (injector, cancellable, () => {
				return injectee_by_pid.has_key (pid);
			});

			var winjector = injector as Winjector;
			var id = yield winjector.inject_library_resource (pid, agent_desc, "frida_agent_main", t.remote_address,
				cancellable);
			injectee_by_pid[pid] = id;

			transport = t;

			return stream_request;
		}

		private void on_uninjected (uint id) {
			foreach (var entry in injectee_by_pid.entries) {
				if (entry.value == id) {
					injectee_by_pid.unset (entry.key);
					return;
				}
			}

			uninjected (InjectorPayloadId (id));
		}

		public extern ChildProcess _spawn (string path, HostSpawnOptions options) throws Error;
		public extern static bool _process_is_alive (uint pid);
	}

	public class ChildProcess : Object {
		public unowned Object parent {
			get;
			construct;
		}

		public uint pid {
			get;
			construct;
		}

		public void * handle {
			get;
			construct;
		}

		public void * main_thread {
			get;
			construct;
		}

		public StdioPipes? pipes {
			get;
			construct;
		}

		public Source? watch {
			get;
			set;
		}

		protected bool closed = false;
		protected bool resumed = false;

		public ChildProcess (Object parent, uint pid, void * handle, void * main_thread, StdioPipes? pipes) {
			Object (parent: parent, pid: pid, handle: handle, main_thread: main_thread, pipes: pipes);
		}

		~ChildProcess () {
			close ();
		}

		public extern void close ();

		public extern void resume () throws Error;
	}

	public class StdioPipes : Object {
		public OutputStream input {
			get;
			construct;
		}

		public InputStream output {
			get;
			construct;
		}

		public InputStream error {
			get;
			construct;
		}

		public StdioPipes (OutputStream input, InputStream output, InputStream error) {
			Object (input: input, output: output, error: error);
		}
	}
}
