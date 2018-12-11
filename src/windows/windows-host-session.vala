namespace Frida {
	public class WindowsHostSessionBackend : Object, HostSessionBackend {
		private WindowsHostSessionProvider local_provider;

		public async void start () {
			assert (local_provider == null);
			local_provider = new WindowsHostSessionProvider ();
			provider_available (local_provider);
		}

		public async void stop () {
			assert (local_provider != null);
			provider_unavailable (local_provider);
			yield local_provider.close ();
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

		public async void close () {
			if (host_session != null) {
				host_session.agent_session_closed.disconnect (on_agent_session_closed);
				yield host_session.close ();
				host_session = null;
			}
		}

		public async HostSession create (string? location = null) throws Error {
			assert (location == null);
			if (host_session != null)
				throw new Error.INVALID_ARGUMENT ("Invalid location: already created");
			host_session = new WindowsHostSession ();
			host_session.agent_session_closed.connect (on_agent_session_closed);
			return host_session;
		}

		public async void destroy (HostSession session) throws Error {
			if (session != host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");
			host_session.agent_session_closed.disconnect (on_agent_session_closed);
			yield host_session.close ();
			host_session = null;
		}

		public async AgentSession obtain_agent_session (HostSession host_session, AgentSessionId agent_session_id) throws Error {
			if (host_session != this.host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");
			return yield this.host_session.obtain_agent_session (agent_session_id);
		}

		private void on_agent_session_closed (AgentSessionId id, AgentSession session, SessionDetachReason reason, string? crash_report) {
			agent_session_closed (id, reason, crash_report);
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
			agent_desc = new AgentDescriptor.with_resources ("frida-agent-%u.dll",
				new MemoryInputStream.from_data (blob32.data, null),
				new MemoryInputStream.from_data (blob64.data, null),
				new AgentResource[] {
					new AgentResource ("dbghelp-32.dll", new MemoryInputStream.from_data (dbghelp32.data, null)),
					new AgentResource ("dbghelp-64.dll", new MemoryInputStream.from_data (dbghelp64.data, null))
				}
			);
		}

		public override async void close () {
			yield base.close ();

			var winjector = injector as Winjector;

			var uninjected_handler = injector.uninjected.connect ((id) => close.callback ());
			while (winjector.any_still_injected ())
				yield;
			injector.disconnect (uninjected_handler);

			agent_desc = null;

			injector.uninjected.disconnect (on_uninjected);
			yield winjector.close ();
			injector = null;

			if (system_session_container != null) {
				yield system_session_container.destroy ();
				system_session_container = null;
			}

			foreach (var process in process_by_pid.values)
				process.close ();
			process_by_pid.clear ();
		}

		protected override async AgentSessionProvider create_system_session_provider (out DBusConnection connection) throws Error {
			var winjector = injector as Winjector;
			var path_template = winjector.normal_resource_store.ensure_copy_of (agent_desc);
			var agent_path = path_template.printf (sizeof (void *) == 8 ? 64 : 32);

			system_session_container = yield AgentContainer.create (agent_path);

			connection = system_session_container.connection;

			return system_session_container;
		}

		public override async HostApplicationInfo get_frontmost_application () throws Error {
			return System.get_frontmost_application ();
		}

		public override async HostApplicationInfo[] enumerate_applications () throws Error {
			return yield application_enumerator.enumerate_applications ();
		}

		public override async HostProcessInfo[] enumerate_processes () throws Error {
			return yield process_enumerator.enumerate_processes ();
		}

		public override async void enable_spawn_gating () throws Error {
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		public override async void disable_spawn_gating () throws Error {
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		public override async HostSpawnInfo[] enumerate_pending_spawn () throws Error {
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		public override async uint spawn (string program, HostSpawnOptions options) throws Error {
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
				var n = yield stream.read_async (buf);

				var data = buf[0:n];
				output (pid, fd, data);

				if (n > 0)
					process_next_output_from.begin (stream, pid, fd, resource);
			} catch (GLib.Error e) {
				output (pid, fd, new uint8[0]);
			}
		}

		protected override bool process_is_alive (uint pid) {
			return _process_is_alive (pid);
		}

		public override async void input (uint pid, uint8[] data) throws Error {
			var process = process_by_pid[pid];
			if (process == null)
				throw new Error.INVALID_ARGUMENT ("Invalid PID");
			try {
				yield process.pipes.input.write_all_async (data, Priority.DEFAULT, null, null);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT (e.message);
			}
		}

		protected override async void perform_resume (uint pid) throws Error {
			var process = process_by_pid[pid];
			if (process == null)
				throw new Error.INVALID_ARGUMENT ("Invalid PID");
			process.resume ();
		}

		public override async void kill (uint pid) throws Error {
			System.kill (pid);
		}

		protected override async Gee.Promise<IOStream> perform_attach_to (uint pid, out Object? transport) throws Error {
			PipeTransport t;
			try {
				t = new PipeTransport ();
			} catch (IOError e) {
				throw new Error.NOT_SUPPORTED (e.message);
			}

			var stream_request = Pipe.open (t.local_address);

			var uninjected_handler = injector.uninjected.connect ((id) => perform_attach_to.callback ());
			while (injectee_by_pid.has_key (pid))
				yield;
			injector.disconnect (uninjected_handler);

			var winjector = injector as Winjector;
			var id = yield winjector.inject_library_resource (pid, agent_desc, "frida_agent_main", t.remote_address);
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
