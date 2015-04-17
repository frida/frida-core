namespace Frida {
	public extern void init ();
	public extern void shutdown ();
	public extern void deinit ();
	public extern unowned MainContext get_main_context ();

	public extern void unref (void * obj);

	public extern void version (out uint major, out uint minor, out uint micro, out uint nano);
	public extern unowned string version_string ();

	public class DeviceManager : Object {
		public signal void added (Device device);
		public signal void removed (Device device);
		public signal void changed ();

		public MainContext main_context {
			get;
			private set;
		}

		private Gee.Promise<bool> ensure_request;
		private Gee.Promise<bool> close_request;

		private HostSessionService service = null;
		private Gee.ArrayList<Device> devices = new Gee.ArrayList<Device> ();
		private uint last_device_id = 1;

		public DeviceManager () {
			this.main_context = get_main_context ();
		}

		public async void close () {
			yield _do_close ();
		}

		public void close_sync () {
			try {
				(create<CloseTask> () as CloseTask).start_and_wait_for_completion ();
			} catch (Error e) {
				assert_not_reached ();
			}
		}

		private class CloseTask : ManagerTask<void> {
			protected override async void perform_operation () throws Error {
				yield parent.close ();
			}
		}

		public async DeviceList enumerate_devices () throws Error {
			check_open ();
			yield ensure_service ();
			return new DeviceList (devices.slice (0, devices.size));
		}

		public DeviceList enumerate_devices_sync () throws Error {
			return (create<EnumerateTask> () as EnumerateTask).start_and_wait_for_completion ();
		}

		private class EnumerateTask : ManagerTask<DeviceList> {
			protected override async DeviceList perform_operation () throws Error {
				return yield parent.enumerate_devices ();
			}
		}

		public void _release_device (Device device) {
			var device_did_exist = devices.remove (device);
			assert (device_did_exist);
		}

		private async void ensure_service () throws IOError {
			if (ensure_request != null) {
				try {
					yield ensure_request.future.wait_async ();
				} catch (Gee.FutureError e) {
					assert_not_reached ();
				}
				return;
			}
			ensure_request = new Gee.Promise<bool> ();

			bool started = false;
			service = new HostSessionService.with_default_backends ();
			service.provider_available.connect ((provider) => {
				var device = new Device (this, last_device_id++, provider.name, provider.kind, provider);
				devices.add (device);
				if (started) {
					added (device);
					changed ();
				}
			});
			service.provider_unavailable.connect ((provider) => {
				foreach (var device in devices) {
					if (device.provider == provider) {
						if (started)
							removed (device);
						device._do_close.begin (false);
						break;
					}
				}
				if (started)
					changed ();
			});
			yield service.start ();
			started = true;

			ensure_request.set_value (true);
		}

		private void check_open () throws Error {
			if (close_request != null)
				throw new IOError.FAILED ("invalid operation (device manager is closed)");
		}

		private async void _do_close () {
			if (close_request != null) {
				try {
					yield close_request.future.wait_async ();
				} catch (Gee.FutureError e) {
					assert_not_reached ();
				}
				return;
			}
			close_request = new Gee.Promise<bool> ();

			if (ensure_request != null) {
				try {
					yield ensure_service ();
				} catch (IOError io_error) {
					assert_not_reached ();
				}
			}

			if (service != null) {
				foreach (var device in devices.to_array ())
					yield device._do_close (true);
				devices.clear ();

				yield service.stop ();
				service = null;
			}

			close_request.set_value (true);
		}

		private Object create<T> () {
			return Object.new (typeof (T), main_context: main_context, parent: this);
		}

		private abstract class ManagerTask<T> : AsyncTask<T> {
			public weak DeviceManager parent {
				get;
				construct;
			}
		}
	}

	public class DeviceList : Object {
		private Gee.List<Device> items;

		public DeviceList (Gee.List<Device> items) {
			this.items = items;
		}

		public int size () {
			return items.size;
		}

		public new Device get (int index) {
			return items.get (index);
		}
	}

	public class Device : Object {
		public signal void lost ();

		public uint id {
			get;
			private set;
		}

		public string name {
			get;
			private set;
		}

		public Icon? icon {
			get;
			private set;
		}

		public DeviceType dtype {
			get;
			private set;
		}

		public HostSessionProvider provider {
			get;
			private set;
		}

		public MainContext main_context {
			get;
			private set;
		}

		private weak DeviceManager manager;
		private Gee.Promise<bool> close_request;

		protected HostSession host_session;
		private Gee.HashMap<uint, Session> session_by_pid = new Gee.HashMap<uint, Session> ();
		private Gee.HashMap<uint, Session> session_by_handle = new Gee.HashMap<uint, Session> ();

		public Device (DeviceManager manager, uint id, string name, HostSessionProviderKind kind, HostSessionProvider provider) {
			this.manager = manager;
			this.id = id;
			this.name = name;
			this.icon = icon_from_image_data (provider.icon);
			switch (kind) {
				case HostSessionProviderKind.LOCAL_SYSTEM:
					this.dtype = DeviceType.LOCAL;
					break;
				case HostSessionProviderKind.LOCAL_TETHER:
					this.dtype = DeviceType.TETHER;
					break;
				case HostSessionProviderKind.REMOTE_SYSTEM:
					this.dtype = DeviceType.REMOTE;
					break;
			}
			this.provider = provider;
			this.main_context = manager.main_context;

			provider.agent_session_closed.connect (on_agent_session_closed);
		}

		public bool is_lost () {
			return close_request != null;
		}

		public async ProcessList enumerate_processes () throws Error {
			check_open ();
			yield ensure_host_session ();
			var processes = yield host_session.enumerate_processes ();
			var result = new Gee.ArrayList<Process> ();
			foreach (var p in processes) {
				result.add (new Process (p.pid, p.name, icon_from_image_data (p.small_icon), icon_from_image_data (p.large_icon)));
			}
			return new ProcessList (result);
		}

		private Icon? icon_from_image_data (ImageData? img) {
			if (img == null || img.width == 0)
				return null;
			return new Icon (img.width, img.height, img.rowstride, Base64.decode (img.pixels));
		}

		public ProcessList enumerate_processes_sync () throws Error {
			return (create<EnumerateTask> () as EnumerateTask).start_and_wait_for_completion ();
		}

		private class EnumerateTask : DeviceTask<ProcessList> {
			protected override async ProcessList perform_operation () throws Error {
				return yield parent.enumerate_processes ();
			}
		}

		public async uint spawn (string path, string[] argv, string[] envp) throws Error {
			check_open ();
			yield ensure_host_session ();
			return yield host_session.spawn (path, argv, envp);
		}

		public uint spawn_sync (string path, string[] argv, string[] envp) throws Error {
			var task = create<SpawnTask> () as SpawnTask;
			task.path = path;
			task.argv = argv;
			task.envp = envp;
			return task.start_and_wait_for_completion ();
		}

		private class SpawnTask : DeviceTask<uint> {
			public string path;
			public string[] argv;
			public string[] envp;

			protected override async uint perform_operation () throws Error {
				return yield parent.spawn (path, argv, envp);
			}
		}

		public async void resume (uint pid) throws Error {
			check_open ();
			yield ensure_host_session ();
			yield host_session.resume (pid);
		}

		public void resume_sync (uint pid) throws Error {
			var task = create<ResumeTask> () as ResumeTask;
			task.pid = pid;
			task.start_and_wait_for_completion ();
		}

		private class ResumeTask : DeviceTask<void> {
			public uint pid;

			protected override async void perform_operation () throws Error {
				yield parent.resume (pid);
			}
		}

		public async void kill (uint pid) throws Error {
			check_open ();
			yield ensure_host_session ();
			yield host_session.kill (pid);
		}

		public void kill_sync (uint pid) throws Error {
			var task = create<KillTask> () as KillTask;
			task.pid = pid;
			task.start_and_wait_for_completion ();
		}

		private class KillTask : DeviceTask<void> {
			public uint pid;

			protected override async void perform_operation () throws Error {
				yield parent.kill (pid);
			}
		}

		public async Session attach (uint pid) throws Error {
			check_open ();
			var session = session_by_pid[pid];
			if (session == null) {
				yield ensure_host_session ();

				var agent_session_id = yield host_session.attach_to (pid);
				var agent_session = yield provider.obtain_agent_session (agent_session_id);
				session = new Session (this, pid, agent_session);
				session_by_pid[pid] = session;
				session_by_handle[agent_session_id.handle] = session;
			}
			return session;
		}

		public Session attach_sync (uint pid) throws Error {
			var task = create<AttachTask> () as AttachTask;
			task.pid = pid;
			return task.start_and_wait_for_completion ();
		}

		private class AttachTask : DeviceTask<Session> {
			public uint pid;

			protected override async Session perform_operation () throws Error {
				return yield parent.attach (pid);
			}
		}

		private void check_open () throws Error {
			if (close_request != null)
				throw new IOError.FAILED ("invalid operation (device is gone)");
		}

		public async void _do_close (bool may_block) {
			if (close_request != null) {
				try {
					yield close_request.future.wait_async ();
				} catch (Gee.FutureError e) {
					assert_not_reached ();
				}
				return;
			}
			close_request = new Gee.Promise<bool> ();

			provider.agent_session_closed.disconnect (on_agent_session_closed);

			foreach (var session in session_by_pid.values.to_array ()) {
				yield session._do_close (may_block);
			}
			session_by_pid.clear ();
			session_by_handle.clear ();

			host_session = null;

			manager._release_device (this);
			manager = null;

			lost ();

			close_request.set_value (true);
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
		}

		private async void ensure_host_session () throws IOError {
			if (host_session == null) {
				host_session = yield provider.create ();
			}
		}

		private void on_agent_session_closed (AgentSessionId id, Error? error) {
			var session = session_by_handle[id.handle];
			if (session != null)
				session._do_close.begin (false);
		}

		private Object create<T> () {
			return Object.new (typeof (T), main_context: main_context, parent: this);
		}

		private abstract class DeviceTask<T> : AsyncTask<T> {
			public weak Device parent {
				get;
				construct;
			}
		}
	}

	public enum DeviceType {
		LOCAL,
		TETHER,
		REMOTE
	}

	public class ProcessList : Object {
		private Gee.List<Process> items;

		public ProcessList (Gee.List<Process> items) {
			this.items = items;
		}

		public int size () {
			return items.size;
		}

		public new Process get (int index) {
			return items.get (index);
		}
	}

	public class Process : Object {
		public uint pid {
			get;
			private set;
		}

		public string name {
			get;
			private set;
		}

		public Icon? small_icon {
			get;
			private set;
		}

		public Icon? large_icon {
			get;
			private set;
		}

		public Process (uint pid, string name, Icon? small_icon, Icon? large_icon) {
			this.pid = pid;
			this.name = name;
			this.small_icon = small_icon;
			this.large_icon = large_icon;
		}
	}

	public class Icon : Object {
		public int width {
			get;
			private set;
		}

		public int height {
			get;
			private set;
		}

		public int rowstride {
			get;
			private set;
		}

		public uint8[] pixels {
			get;
			private set;
		}

		public Icon (int width, int height, int rowstride, uint8[] pixels) {
			this.width = width;
			this.height = height;
			this.rowstride = rowstride;
			this.pixels = pixels;
		}
	}

	public class Session : Object {
		public signal void detached ();

		public uint pid {
			get;
			private set;
		}

		public AgentSession session {
			get;
			private set;
		}

		public MainContext main_context {
			get;
			private set;
		}

		private const uint16 DEFAULT_DEBUG_PORT = 5858;

		private weak Device device;
		private Gee.Promise<bool> close_request;

		private Gee.HashMap<uint, Script> script_by_id = new Gee.HashMap<uint, Script> ();

		private Debugger debugger;

		public Session (Device device, uint pid, AgentSession agent_session) {
			this.device = device;
			this.pid = pid;
			this.session = agent_session;
			this.main_context = device.main_context;

			session.message_from_script.connect (on_message_from_script);
		}

		public bool is_detached () {
			return close_request != null;
		}

		public async void detach () {
			yield _do_close (true);
		}

		public void detach_sync () {
			try {
				(create<DetachTask> () as DetachTask).start_and_wait_for_completion ();
			} catch (Error e) {
				assert_not_reached ();
			}
		}

		private class DetachTask : ProcessTask<void> {
			protected override async void perform_operation () throws Error {
				yield parent.detach ();
			}
		}

		public async Script create_script (string? name, string source) throws Error {
			check_open ();
			var sid = yield session.create_script ((name == null) ? "" : name, source);
			var script = new Script (this, sid);
			script_by_id[sid.handle] = script;
			return script;
		}

		public Script create_script_sync (string? name, string source) throws Error {
			var task = create<CreateScriptTask> () as CreateScriptTask;
			task.name = name;
			task.source = source;
			return task.start_and_wait_for_completion ();
		}

		private class CreateScriptTask : ProcessTask<Script> {
			public string? name;
			public string source;

			protected override async Script perform_operation () throws Error {
				return yield parent.create_script (name, source);
			}
		}

		public async void enable_debugger (uint16 port = 0) throws Error {
			check_open ();

			if (debugger != null)
				throw new IOError.FAILED ("already enabled");

			debugger = new Debugger ((port != 0) ? port : DEFAULT_DEBUG_PORT, session);
			var enabled = false;
			try {
				yield debugger.enable ();
				enabled = true;
			} finally {
				if (!enabled)
					debugger = null;
			}
		}

		public void enable_debugger_sync (uint16 port = 0) throws Error {
			var task = create<EnableScriptDebuggerTask> () as EnableScriptDebuggerTask;
			task.port = port;
			task.start_and_wait_for_completion ();
		}

		private class EnableScriptDebuggerTask : ProcessTask<void> {
			public uint16 port;

			protected override async void perform_operation () throws Error {
				yield parent.enable_debugger (port);
			}
		}

		public async void disable_debugger () throws Error {
			check_open ();

			if (debugger == null)
				return;

			debugger.disable ();
			debugger = null;
		}

		public void disable_debugger_sync () throws Error {
			(create<DisableScriptDebuggerTask> () as DisableScriptDebuggerTask).start_and_wait_for_completion ();
		}

		private class DisableScriptDebuggerTask : ProcessTask<void> {
			protected override async void perform_operation () throws Error {
				yield parent.disable_debugger ();
			}
		}

		private void on_message_from_script (AgentScriptId sid, string message, uint8[] data) {
			var script = script_by_id[sid.handle];
			if (script != null)
				script.message (message, data);
		}

		public void _release_script (AgentScriptId sid) {
			var script_did_exist = script_by_id.unset (sid.handle);
			assert (script_did_exist);
		}

		private void check_open () throws Error {
			if (close_request != null)
				throw new IOError.FAILED ("invalid operation (detached from session)");
		}

		public async void _do_close (bool may_block) {
			if (close_request != null) {
				try {
					yield close_request.future.wait_async ();
				} catch (Gee.FutureError e) {
					assert_not_reached ();
				}
				return;
			}
			close_request = new Gee.Promise<bool> ();

			if (debugger != null) {
				debugger.disable ();
				debugger = null;
			}

			foreach (var script in script_by_id.values.to_array ())
				yield script._do_close (may_block);

			if (may_block) {
				try {
					yield session.close ();
				} catch (IOError ignored_error) {
				}
			}
			session.message_from_script.disconnect (on_message_from_script);
			session = null;

			device._release_session (this);
			device = null;

			detached ();
			close_request.set_value (true);
		}

		private Object create<T> () {
			return Object.new (typeof (T), main_context: main_context, parent: this);
		}

		private abstract class ProcessTask<T> : AsyncTask<T> {
			public weak Session parent {
				get;
				construct;
			}
		}
	}

	public class Script : Object {
		public signal void destroyed ();
		public signal void message (string message, uint8[] data);

		public MainContext main_context {
			get;
			private set;
		}

		private weak Session session;
		private AgentScriptId script_id;

		public Script (Session session, AgentScriptId script_id) {
			this.session = session;
			this.script_id = script_id;
			this.main_context = session.main_context;
		}

		public bool is_destroyed () {
			return session == null;
		}

		public async void load () throws Error {
			check_open ();
			yield session.session.load_script (script_id);
		}

		public void load_sync () throws Error {
			(create<LoadTask> () as LoadTask).start_and_wait_for_completion ();
		}

		private class LoadTask : ScriptTask<void> {
			protected override async void perform_operation () throws Error {
				yield parent.load ();
			}
		}

		public async void unload () throws Error {
			check_open ();
			yield _do_close (true);
		}

		public void unload_sync () throws Error {
			(create<UnloadTask> () as UnloadTask).start_and_wait_for_completion ();
		}

		private class UnloadTask : ScriptTask<void> {
			protected override async void perform_operation () throws Error {
				yield parent.unload ();
			}
		}

		public async void post_message (string message) throws Error {
			check_open ();
			yield session.session.post_message_to_script (script_id, message);
		}

		public void post_message_sync (string message) throws Error {
			var task = create<PostMessageTask> () as PostMessageTask;
			task.message = message;
			task.start_and_wait_for_completion ();
		}

		private class PostMessageTask : ScriptTask<void> {
			public string message;

			protected override async void perform_operation () throws Error {
				yield parent.post_message (message);
			}
		}

		private void check_open () throws Error {
			if (session == null)
				throw new IOError.FAILED ("invalid operation (script is destroyed)");
		}

		public async void _do_close (bool may_block) {
			if (session == null) {
				return;
			}
			var p = session;
			session = null;

			var sid = script_id;

			p._release_script (sid);

			if (may_block) {
				try {
					yield p.session.destroy_script (sid);
				} catch (IOError ignored_error) {
				}
			}

			destroyed ();
		}

		private Object create<T> () {
			return Object.new (typeof (T), main_context: main_context, parent: this);
		}

		private abstract class ScriptTask<T> : AsyncTask<T> {
			public weak Script parent {
				get;
				construct;
			}
		}
	}

	private class Debugger : Object {
		private uint16 port;
		private AgentSession session;

		private SocketService service;
		private Gee.HashSet<DebugSession> sessions = new Gee.HashSet<DebugSession> ();

		public Debugger (uint16 port, AgentSession session) {
			this.port = port;
			this.session = session;
		}

		public async void enable () throws IOError {
			if (service != null)
				throw new IOError.FAILED ("already enabled");
			service = new SocketService ();
			try {
				service.add_inet_port (port, null);
			} catch (Error e) {
				service = null;
				throw new IOError.FAILED (e.message);
			}
			service.incoming.connect (on_incoming_connection);
			service.start ();
			bool enabled = false;
			try {
				yield session.enable_debugger ();
				enabled = true;
			} finally {
				if (!enabled) {
					service.stop ();
					service = null;
				}
			}
		}

		public void disable () {
			if (service == null)
				return;
			if (session != null) {
				session.disable_debugger.begin ();
				session = null;
			}
			service.stop ();
		}

		private bool on_incoming_connection (SocketConnection connection, Object? source_object) {
			var session = new DebugSession (session, connection);
			session.ended.connect (on_session_ended);
			sessions.add (session);
			session.open ();
			return true;
		}

		private void on_session_ended (DebugSession session) {
			sessions.remove (session);
			session.close ();
		}

		private class DebugSession : Object {
			public signal void ended (DebugSession session);

			private const size_t CHUNK_SIZE = 512;
			private const size_t MAX_MESSAGE_SIZE = 2048;

			private weak AgentSession agent_session;

			private IOStream stream;
			private InputStream input;
			private OutputStream output;

			private char * buffer;
			private size_t length;
			private size_t capacity;

			private Queue<string> outgoing = new Queue<string> ();

			public DebugSession (AgentSession agent_session, IOStream stream) {
				this.agent_session = agent_session;

				this.stream = stream;
				this.input = stream.get_input_stream ();
				this.output = stream.get_output_stream ();

				agent_session.message_from_debugger.connect (on_message_from_debugger);
			}

			~DebugSession () {
				free (buffer);

				close ();
			}

			public void open () {
				var headers = new string[] {
					"Type", "connect",
					"V8-Version", "4.3.62", // FIXME
					"Protocol-Version", "1",
					"Embedding-Host", "Frida v4.0.0" // FIXME
				};
				var body = "";
				send (headers, body);

				process_incoming_messages.begin ();
			}

			public void close () {
				agent_session.message_from_debugger.disconnect (on_message_from_debugger);

				if (stream != null) {
					stream.close_async.begin ();
					stream = null;
				}
			}

			private void on_message_from_debugger (string message) {
				send (new string[] {}, message);
			}

			private void send (string[] headers, string content) {
				assert (headers.length % 2 == 0);

				var message = new StringBuilder ("");
				for (var i = 0; i != headers.length; i += 2) {
					var key = headers[i];
					var val = headers[i + 1];
					message.append_printf ("%s: %s\r\n", key, val);
				}
				message.append_printf ("Content-Length: %ld\r\n\r\n%s", content.length, content);

				var write_now = outgoing.is_empty ();
				outgoing.push_tail (message.str);
				if (write_now)
					process_outgoing_messages.begin ();
			}

			private async void process_incoming_messages () {
				try {
					while (true) {
						var message = yield read_message ();
						yield agent_session.post_message_to_debugger (message);
					}
				} catch (IOError e) {
					ended (this);
				}
			}

			private async void process_outgoing_messages () {
				try {
					do {
						var m = outgoing.peek_head ();
						unowned uint8[] buf = (uint8[]) m;
						yield output.write_all_async (buf[0:m.length], Priority.DEFAULT, null, null);
						outgoing.pop_head ();
					} while (!outgoing.is_empty ());
				} catch (Error e) {
				}
			}

			private async string read_message () throws IOError {
				long message_length = 0;
				long header_length = 0;
				long content_length = 0;

				while (true) {
					if (length > 0) {
						unowned string message = (string) buffer;

						if (message_length == 0) {
							int header_end = message.index_of ("\r\n\r\n");
							if (header_end != -1) {
								header_length = header_end + 4;
								var headers = message[0:header_end];
								parse_headers (headers, out content_length);
								message_length = header_length + content_length;
							}
						}

						if (message_length != 0 && length >= message_length) {
							var content = message[header_length:message_length];
							consume_buffer (message_length);
							return content;
						}
					}

					yield fill_buffer ();
				}
			}

			private async void fill_buffer () throws IOError {
				var available = capacity - length;
				if (available < CHUNK_SIZE) {
					capacity = size_t.min (capacity + (CHUNK_SIZE - available), MAX_MESSAGE_SIZE);
					buffer = realloc (buffer, capacity + 1);

					available = capacity - length;
				}

				if (available == 0)
					throw new IOError.FAILED ("maximum message size exceeded");

				buffer[length + available] = 0;
				unowned uint8[] buf = (uint8[]) buffer;
				ssize_t n = yield input.read_async (buf[length:length + available]);
				if (n == 0)
					throw new IOError.CLOSED ("connection closed");
				length += n;
			}

			private void consume_buffer (long n) {
				length -= n;
				if (length > 0) {
					Memory.move (buffer, buffer + n, length);
					buffer[length] = 0;
				}
			}

			private void parse_headers (string headers, out long content_length) throws IOError {
				var lines = headers.split ("\r\n");
				foreach (var line in lines) {
					var tokens = line.split (": ", 2);
					if (tokens.length != 2)
						throw new IOError.FAILED ("malformed header");
					var key = tokens[0];
					var val = tokens[1];
					if (key == "Content-Length") {
						uint64 l;
						if (uint64.try_parse (val, out l)) {
							content_length = (long) l;
							return;
						}
					}
				}

				throw new IOError.FAILED ("missing content length");
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
		private Mutex mutex;
		private Cond cond;

		private T result;
		private Error error;

		public T start_and_wait_for_completion () throws Error {
			if (main_context.is_owner ())
				loop = new MainLoop (main_context);

			var source = new IdleSource ();
			source.set_callback (() => {
				do_perform_operation.begin ();
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

		protected abstract async T perform_operation () throws Error;
	}
}
