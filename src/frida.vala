namespace Frida {
	public class DeviceManager : Object {
		public signal void changed ();

		public MainContext main_context {
			get;
			private set;
		}

		private bool is_closed = false;

		private Gee.ArrayList<Device> devices = new Gee.ArrayList<Device> ();
		private uint last_device_id = 1;

#if !LINUX
		private Frida.FruityHostSessionBackend fruity;
#endif

		public DeviceManager (MainContext main_context) {
			this.main_context = main_context;
		}

		public override void dispose () {
			close ();
			base.dispose ();
		}

		public void close () {
			try {
				(create<CloseTask> () as CloseTask).start_and_wait_for_completion ();
			} catch (Error e) {
				assert_not_reached ();
			}
		}

		public Gee.List<Device> enumerate_devices () throws Error {
			return (create<EnumerateTask> () as EnumerateTask).start_and_wait_for_completion ();
		}

		private Object create<T> () {
			return Object.new (typeof (T), main_context: main_context, parent: this);
		}

		private class CloseTask : ManagerTask<void> {
			protected override void validate_operation () throws Error {
			}

			protected override async void perform_operation () throws Error {
				if (parent.is_closed)
					return;
				parent.is_closed = true;

				yield parent._do_close ();
			}
		}

		private async void _do_close () {
			foreach (var device in devices.to_array ())
				yield device._do_close (true);
			devices = null;
		}

		public void _release_device (Device device) {
			var device_did_exist = devices.remove (device);
			assert (device_did_exist);
		}

		private class EnumerateTask : ManagerTask<Gee.List<Device>> {
			protected override async Gee.List<Device> perform_operation () throws Error {
				yield parent.ensure_devices ();
				return parent.devices.slice (0, parent.devices.size);
			}
		}

		private async void ensure_devices () throws IOError {
			if (devices.size > 0)
				return;

			var local = new LocalDevice (this, last_device_id++);
			devices.add (local);

#if !LINUX
			fruity = new Frida.FruityHostSessionBackend ();
			fruity.provider_available.connect ((provider) => {
				var device = new RemoteDevice (this, last_device_id++, provider.name, provider.kind, provider);
				devices.add (device);
				changed ();
			});
			fruity.provider_unavailable.connect ((provider) => {
				foreach (var device in devices) {
					if (device.provider == provider) {
						device._do_close (false);
						break;
					}
				}
				changed ();
			});
			yield fruity.start ();
#endif
		}

		private abstract class ManagerTask<T> : AsyncTask<T> {
			public weak DeviceManager parent {
				get;
				construct;
			}

			protected override void validate_operation () throws Error {
				if (parent.is_closed)
					throw new IOError.FAILED ("invalid operation (manager is closed)");
			}
		}
	}

	public abstract class Device : Object {
		public signal void closed ();

		public uint id {
			get;
			private set;
		}

		public string name {
			get;
			private set;
		}

		public string kind {
			get;
			private set;
		}

		public Frida.HostSessionProvider provider {
			get;
			protected set;
		}

		public MainContext main_context {
			get;
			private set;
		}

		private weak DeviceManager manager;
		private bool is_closed = false;

		protected Frida.HostSession host_session;
		private Gee.HashMap<uint, Session> session_by_pid = new Gee.HashMap<uint, Session> ();
		private Gee.HashMap<uint, Session> session_by_handle = new Gee.HashMap<uint, Session> ();

		public Device (DeviceManager manager, uint id, string name, Frida.HostSessionProviderKind kind) {
			this.manager = manager;
			this.id = id;
			this.name = name;
			switch (kind) {
				case Frida.HostSessionProviderKind.LOCAL_SYSTEM:
					this.kind = "local";
					break;
				case Frida.HostSessionProviderKind.LOCAL_TETHER:
					this.kind = "tether";
					break;
				case Frida.HostSessionProviderKind.REMOTE_SYSTEM:
					this.kind = "remote";
					break;
			}
			this.main_context = manager.main_context;
		}

		public Gee.List<Frida.HostProcessInfo?> enumerate_processes () throws Error {
			return (create<EnumerateTask> () as EnumerateTask).start_and_wait_for_completion ();
		}

		public uint spawn (string path, string[] argv, string[] envp) throws Error {
			var task = create<SpawnTask> () as SpawnTask;
			task.path = path;
			task.argv = argv;
			task.envp = envp;
			return task.start_and_wait_for_completion ();
		}

		public void resume (uint pid) throws Error {
			var task = create<ResumeTask> () as ResumeTask;
			task.pid = pid;
			task.start_and_wait_for_completion ();
		}

		public Session attach (uint pid) throws Error {
			var task = create<AttachTask> () as AttachTask;
			task.pid = pid;
			return task.start_and_wait_for_completion ();
		}

		private Object create<T> () {
			return Object.new (typeof (T), main_context: main_context, parent: this);
		}

		public async void _do_close (bool may_block) {
			if (is_closed)
				return;
			is_closed = true;

			foreach (var session in session_by_pid.values.to_array ())
				yield session._do_close (may_block);
			session_by_pid.clear ();
			session_by_handle.clear ();

			yield release_host_session ();

			manager._release_device (this);
			manager = null;

			closed ();
		}

		public void _release_session (Session session) {
			var session_did_exist = session_by_pid.unset (session.pid);
			assert (session_did_exist);

			uint handle = 0;
			foreach (var entry in session_by_handle.entries) {
				if (entry.value == session) {
					handle = entry.key;
					break;
				}
			}
			assert (handle != 0);
			session_by_handle.unset (handle);

			if (!is_closed) {
				var source = new IdleSource ();
				source.set_callback (() => {
					if (!is_closed && session_by_pid.is_empty)
						release_host_session ();
					return false;
				});
				source.attach (main_context);
			}
		}

		private class EnumerateTask : DeviceTask<Gee.List<Frida.HostProcessInfo?>> {
			protected override async Gee.List<Frida.HostProcessInfo?> perform_operation () throws Error {
				yield parent.ensure_host_session ();
				var processes = yield parent.host_session.enumerate_processes ();
				var result = new Gee.ArrayList<Frida.HostProcessInfo?> ();
				foreach (var process in processes) {
					result.add(process);
				}
				return result;
			}
		}

		private class SpawnTask : DeviceTask<uint> {
			public string path;
			public string[] argv;
			public string[] envp;

			protected override async uint perform_operation () throws Error {
				yield parent.ensure_host_session ();
				return yield parent.host_session.spawn (path, argv, envp);
			}
		}

		private class ResumeTask : DeviceTask<void> {
			public uint pid;

			protected override async void perform_operation () throws Error {
				yield parent.ensure_host_session ();
				yield parent.host_session.resume (pid);
			}
		}

		private class AttachTask : DeviceTask<Session> {
			public uint pid;

			protected override async Session perform_operation () throws Error {
				var session = parent.session_by_pid[pid];
				if (session == null) {
					yield parent.ensure_host_session ();

					var agent_session_id = yield parent.host_session.attach_to (pid);
					var agent_session = yield parent.provider.obtain_agent_session (agent_session_id);
					session = new Session (parent, pid, agent_session);
					parent.session_by_pid[pid] = session;
					parent.session_by_handle[agent_session_id.handle] = session;
				}

				return session;
			}
		}

		private abstract class DeviceTask<T> : AsyncTask<T> {
			public weak Device parent {
				get;
				construct;
			}

			protected override void validate_operation () throws Error {
				if (parent.is_closed)
					throw new IOError.FAILED ("invalid operation (device is closed)");
			}
		}

		protected abstract async void ensure_host_session () throws IOError;
		protected abstract async void release_host_session ();

		protected void on_agent_session_closed (Frida.AgentSessionId id, Error? error) {
			var session = session_by_handle[id.handle];
			if (session != null)
				session._do_close (false);
		}
	}

	private class LocalDevice : Device {
#if !WINDOWS
		private Server server;
		private Frida.TcpHostSessionProvider local_provider;
#else
		private Frida.WindowsHostSessionProvider local_provider;
#endif

		public LocalDevice (DeviceManager manager, uint id) throws IOError {
			base (manager, id, "Local System", Frida.HostSessionProviderKind.LOCAL_SYSTEM);
		}

		protected override async void ensure_host_session () throws IOError {
			if (host_session == null) {
#if !WINDOWS
				var s = new Server ();
				var p = new Frida.TcpHostSessionProvider.for_address (s.address);
#else
				var p = new Frida.WindowsHostSessionProvider ();
#endif
				var hs = yield p.create ();

#if !WINDOWS
				server = s;
#endif
				local_provider = p;
				provider = p;
				host_session = hs;

				provider.agent_session_closed.connect (on_agent_session_closed);
			}
		}

		protected override async void release_host_session () {
			if (host_session != null) {
				provider.agent_session_closed.disconnect (on_agent_session_closed);

				yield local_provider.close ();

				host_session = null;
				provider = null;
				local_provider = null;

#if !WINDOWS
				server.destroy ();
				server = null;
#endif
			}
		}

#if !WINDOWS
		private class Server {
			private TemporaryFile executable;

			public string address {
				get;
				private set;
			}

			private const string SERVER_ADDRESS_TEMPLATE = "tcp:host=127.0.0.1,port=%u";

			public Server () throws IOError {
				var blob = PyFrida.Data.get_frida_server_blob ();
				executable = new TemporaryFile.from_stream ("server", new MemoryInputStream.from_data (blob.data, null));
				try {
					executable.file.set_attribute_uint32 (FILE_ATTRIBUTE_UNIX_MODE, 0755, FileQueryInfoFlags.NONE);
				} catch (Error e) {
					throw new IOError.FAILED (e.message);
				}

				address = SERVER_ADDRESS_TEMPLATE.printf (get_available_port ());

				try {
					string[] argv = new string[] { executable.file.get_path (), address };
					Pid child_pid;
					Process.spawn_async (null, argv, null, 0, null, out child_pid);
				} catch (SpawnError e) {
					executable.destroy ();
					throw new IOError.FAILED (e.message);
				}
			}

			public void destroy () {
				executable.destroy ();
			}

			private uint get_available_port () {
				uint port = 27042;

				bool found_available = false;
				var loopback = new InetAddress.loopback (SocketFamily.IPV4);
				var address_in_use = new IOError.ADDRESS_IN_USE ("");
				while (!found_available) {
					try {
						var socket = new Socket (SocketFamily.IPV4, SocketType.STREAM, SocketProtocol.TCP);
						socket.bind (new InetSocketAddress (loopback, (uint16) port), false);
						socket.close ();
						found_available = true;
					} catch (Error e) {
						if (e.code == address_in_use.code)
							port--;
						else
							found_available = true;
					}
				}

				return port;
			}
		}

		private class TemporaryFile {
			public File file {
				get;
				private set;
			}

			public TemporaryFile.from_stream (string name, InputStream istream) throws IOError {
				this.file = File.new_for_path (Path.build_filename (Environment.get_tmp_dir (), "cloud-spy-%p-%u-%s".printf (this, Random.next_int (), name)));

				try {
					var ostream = file.create (FileCreateFlags.NONE, null);

					var buf_size = 128 * 1024;
					var buf = new uint8[buf_size];

					while (true) {
						var bytes_read = istream.read (buf);
						if (bytes_read == 0)
							break;
						buf.resize ((int) bytes_read);

						size_t bytes_written;
						ostream.write_all (buf, out bytes_written);
					}

					ostream.close (null);
				} catch (Error e) {
					throw new IOError.FAILED (e.message);
				}
			}

			~TemporaryFile () {
				destroy ();
			}

			public void destroy () {
				try {
					file.delete (null);
				} catch (Error e) {
				}
			}
		}
#endif
	}

	private class RemoteDevice : Device {
		public RemoteDevice (DeviceManager manager, uint id, string name, Frida.HostSessionProviderKind kind, Frida.HostSessionProvider provider) {
			base (manager, id, name, kind);
			this.provider = provider;
			provider.agent_session_closed.connect (on_agent_session_closed);
		}

		~RemoteDevice () {
			provider.agent_session_closed.disconnect (on_agent_session_closed);
		}

		protected override async void ensure_host_session () throws IOError {
			if (host_session == null) {
				host_session = yield provider.create ();
			}
		}

		protected override async void release_host_session () {
		}
	}

	public class Session : Object {
		public signal void closed ();

		public uint pid {
			get;
			private set;
		}

		public Frida.AgentSession internal_session {
			get;
			private set;
		}

		public MainContext main_context {
			get;
			private set;
		}

		private weak Device device;
		private bool is_closed = false;

		private Gee.HashMap<uint, Script> script_by_id = new Gee.HashMap<uint, Script> ();

		public Session (Device device, uint pid, Frida.AgentSession agent_session) {
			this.device = device;
			this.pid = pid;
			this.internal_session = agent_session;
			this.main_context = device.main_context;

			internal_session.message_from_script.connect (on_message_from_script);
		}

		public void close () {
			try {
				(create<CloseTask> () as CloseTask).start_and_wait_for_completion ();
			} catch (Error e) {
				assert_not_reached ();
			}
		}

		public Script create_script (string source) throws Error {
			var task = create<CreateScriptTask> () as CreateScriptTask;
			task.source = source;
			return task.start_and_wait_for_completion ();
		}

		private void on_message_from_script (Frida.AgentScriptId sid, string message, uint8[] data) {
			var script = script_by_id[sid.handle];
			if (script != null)
				script.message (message, data);
		}

		public void _release_script (Frida.AgentScriptId sid) {
			var script_did_exist = script_by_id.unset (sid.handle);
			assert (script_did_exist);
		}

		private Object create<T> () {
			return Object.new (typeof (T), main_context: main_context, parent: this);
		}

		private class CloseTask : SessionTask<void> {
			protected override void validate_operation () throws Error {
			}

			protected override async void perform_operation () throws Error {
				yield parent._do_close (true);
			}
		}

		public async void _do_close (bool may_block) {
			if (is_closed)
				return;
			is_closed = true;

			foreach (var script in script_by_id.values.to_array ())
				yield script._do_unload (may_block);

			if (may_block) {
				try {
					yield internal_session.close ();
				} catch (IOError ignored_error) {
				}
			}
			internal_session.message_from_script.disconnect (on_message_from_script);
			internal_session = null;

			device._release_session (this);
			device = null;

			closed ();
		}

		private class CreateScriptTask : SessionTask<Script> {
			public string source;

			protected override async Script perform_operation () throws Error {
				var sid = yield parent.internal_session.create_script (source);
				var script = new Script (parent, sid);
				parent.script_by_id[sid.handle] = script;
				return script;
			}
		}

		private abstract class SessionTask<T> : AsyncTask<T> {
			public weak Session parent {
				get;
				construct;
			}

			protected override void validate_operation () throws Error {
				if (parent.is_closed)
					throw new IOError.FAILED ("invalid operation (session is closed)");
			}
		}
	}

	public class Script : Object {
		public signal void message (string message, uint8[] data);

		public MainContext main_context {
			get;
			private set;
		}

		private weak Session session;
		private Frida.AgentScriptId script_id;

		public Script (Session session, Frida.AgentScriptId script_id) {
			this.session = session;
			this.script_id = script_id;
			this.main_context = session.main_context;
		}

		public void load () throws Error {
			(create<LoadTask> () as LoadTask).start_and_wait_for_completion ();
		}

		public void unload () throws Error {
			(create<UnloadTask> () as UnloadTask).start_and_wait_for_completion ();
		}

		public void post_message (string message) throws Error {
			var task = create<PostMessageTask> () as PostMessageTask;
			task.message = message;
			task.start_and_wait_for_completion ();
		}

		private Object create<T> () {
			return Object.new (typeof (T), main_context: main_context, parent: this);
		}

		private class LoadTask : ScriptTask<void> {
			protected override async void perform_operation () throws Error {
				yield parent.session.internal_session.load_script (parent.script_id);
			}
		}

		private class UnloadTask : ScriptTask<void> {
			protected override async void perform_operation () throws Error {
				yield parent._do_unload (true);
			}
		}

		public async void _do_unload (bool may_block) {
			var s = session;
			session = null;

			var sid = script_id;

			s._release_script (sid);

			if (may_block) {
				try {
					yield s.internal_session.destroy_script (sid);
				} catch (IOError ignored_error) {
				}
			}
		}

		private class PostMessageTask : ScriptTask<void> {
			public string message;

			protected override async void perform_operation () throws Error {
				yield parent.session.internal_session.post_message_to_script (parent.script_id, message);
			}
		}

		private abstract class ScriptTask<T> : AsyncTask<T> {
			public weak Script parent {
				get;
				construct;
			}

			protected override void validate_operation () throws Error {
				if (parent.session == null)
					throw new IOError.FAILED ("invalid operation (script is destroyed)");
			}
		}
	}

	private abstract class AsyncTask<T> : Object {
		public MainContext main_context {
			get;
			construct;
		}

		private MainLoop loop;
		private bool completed;
		private Mutex mutex = new Mutex ();
		private Cond cond = new Cond ();

		private T result;
		private Error error;

		public T start_and_wait_for_completion () throws Error {
			if (main_context.is_owner ())
				loop = new MainLoop (main_context);

			var source = new IdleSource ();
			source.set_callback (() => {
				do_perform_operation ();
				return false;
			});
			source.attach (main_context);

			if (loop != null) {
				loop.run ();
			} else {
				mutex.lock ();
				while (!completed)
					cond.wait (mutex);
				mutex.unlock ();
			}

			if (error != null)
				throw error;

			return result;
		}

		private async void do_perform_operation () {
			try {
				validate_operation ();
				result = yield perform_operation ();
			} catch (Error e) {
				error = new IOError.FAILED (e.message);
			}

			if (loop != null) {
				loop.quit ();
			} else {
				mutex.lock ();
				completed = true;
				cond.signal ();
				mutex.unlock ();
			}
		}

		protected abstract void validate_operation () throws Error;
		protected abstract async T perform_operation () throws Error;
	}
}
