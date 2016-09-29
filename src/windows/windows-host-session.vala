#if WINDOWS
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

		public ImageData? icon {
			get { return _icon; }
		}
		private ImageData? _icon;

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.LOCAL_SYSTEM; }
		}

		private WindowsHostSession host_session;

		construct {
			try {
				_icon = _extract_icon ();
			} catch (Error e) {
			}
		}

		public async void close () {
			if (host_session != null)
				yield host_session.close ();
			host_session = null;
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

		private void on_agent_session_closed (AgentSessionId id, AgentSession session) {
			agent_session_closed (id);
		}

		public static extern ImageData? _extract_icon () throws Error;
	}

	public class WindowsHostSession : BaseDBusHostSession {
		private AgentContainer system_session_container = null;

		private Gee.HashMap<uint, ChildProcess> processes = new Gee.HashMap<uint, ChildProcess> ();

		private Winjector winjector = new Winjector ();
		private AgentDescriptor agent_desc;

		private ApplicationEnumerator application_enumerator = new ApplicationEnumerator ();
		private ProcessEnumerator process_enumerator = new ProcessEnumerator ();

		construct {
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

			/* HACK: give processes 100 ms to unload DLLs */
			var source = new TimeoutSource (100);
			source.set_callback (() => {
				close.callback ();
				return false;
			});
			source.attach (MainContext.get_thread_default ());
			yield;

			agent_desc = null;

			yield winjector.close ();
			winjector = null;

			if (system_session_container != null) {
				yield system_session_container.destroy ();
				system_session_container = null;
			}

			foreach (var process in processes.values)
				process.close ();
			processes.clear ();
		}

		protected override async AgentSessionProvider create_system_session_provider (out DBusConnection connection) throws Error {
			var path_template = winjector.normal_resource_store.ensure_copy_of (agent_desc);
			var agent_filename = path_template.printf (sizeof (void *) == 8 ? 64 : 32);
			system_session_container = yield AgentContainer.create (agent_filename);
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

		public override async HostSpawnInfo[] enumerate_pending_spawns () throws Error {
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		public override async uint spawn (string path, string[] argv, string[] envp) throws Error {
			var process = _do_spawn (path, argv, envp);

			var pid = process.pid;
			processes[pid] = process;

			var pipes = process.pipes;
			process_next_output_from.begin (pipes.output, pid, 1, pipes);
			process_next_output_from.begin (pipes.error, pid, 2, pipes);

			return pid;
		}

		public void _on_child_dead (ChildProcess process, int status) {
			processes.unset (process.pid);
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
				output (pid, fd, new uint8[0] {});
			}
		}

		public override async void input (uint pid, uint8[] data) throws Error {
			var process = processes[pid];
			if (process == null)
				throw new Error.INVALID_ARGUMENT ("Invalid pid");
			var data_copy = data; /* FIXME: workaround for Vala compiler bug */
			try {
				yield process.pipes.input.write_all_async (data_copy, Priority.DEFAULT, null, null);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT (e.message);
			}
		}

		public override async void resume (uint pid) throws Error {
			var process = processes[pid];
			if (process == null)
				throw new Error.INVALID_ARGUMENT ("Invalid pid");
			process.resume ();
		}

		public override async void kill (uint pid) throws Error {
			System.kill (pid);
		}

		protected override async IOStream perform_attach_to (uint pid, out Object? transport) throws Error {
			PipeTransport t;
			Pipe stream;
			try {
				t = new PipeTransport ();
				stream = new Pipe (t.local_address);
			} catch (IOError stream_error) {
				throw new Error.NOT_SUPPORTED (stream_error.message);
			}
			yield winjector.inject (pid, agent_desc, t.remote_address);
			transport = t;
			return stream;
		}

		public extern ChildProcess _do_spawn (string path, string[] argv, string[] envp) throws Error;
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

		public StdioPipes pipes {
			get;
			construct;
		}

		public Source? watch {
			get;
			set;
		}

		protected bool closed = false;
		protected bool resumed = false;

		public ChildProcess (Object parent, uint pid, void * handle, void * main_thread, StdioPipes pipes) {
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
#endif
