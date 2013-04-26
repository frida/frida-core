namespace Frida {
	public extern void init ();
	public extern void shutdown ();
	public extern void deinit ();
	public extern unowned MainContext get_main_context ();

	public class DeviceManager : Object {
		public signal void changed ();

		public MainContext main_context {
			get;
			private set;
		}

		private bool is_closed = false;

		private HostSessionService service = null;
		private Gee.ArrayList<Device> devices = new Gee.ArrayList<Device> ();
		private uint last_device_id = 1;

		public DeviceManager () {
			this.main_context = get_main_context ();
		}

		public override void dispose () {
			close_sync ();
			base.dispose ();
		}

		public async void close () {
			if (is_closed)
				return;
			is_closed = true;

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
			protected override void validate_operation () throws Error {
			}

			protected override async void perform_operation () throws Error {
				yield parent.close ();
			}
		}

		public async DeviceList enumerate_devices () throws Error {
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
			if (service != null)
				return;

			service = new HostSessionService.with_default_backends ();
			service.provider_available.connect ((provider) => {
				var device = new Device (this, last_device_id++, provider.name, provider.kind, provider);
				devices.add (device);
				changed ();
			});
			service.provider_unavailable.connect ((provider) => {
				foreach (var device in devices) {
					if (device.provider == provider) {
						device._do_close (false);
						break;
					}
				}
				changed ();
			});
			yield service.start ();
		}

		private async void _do_close () {
			if (service == null)
				return;

			foreach (var device in devices.to_array ())
				yield device._do_close (true);
			devices.clear ();

			yield service.stop ();
			service = null;
		}

		private Object create<T> () {
			return Object.new (typeof (T), main_context: main_context, parent: this);
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
		private bool is_closed = false;

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

		public async ProcessList enumerate_processes () throws Error {
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

		public async Session attach (uint pid) throws Error {
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

		public async void _do_close (bool may_block) {
			if (is_closed)
				return;
			is_closed = true;

			provider.agent_session_closed.disconnect (on_agent_session_closed);

			foreach (var session in session_by_pid.values.to_array ())
				yield session._do_close (may_block);
			session_by_pid.clear ();
			session_by_handle.clear ();

			host_session = null;

			manager._release_device (this);
			manager = null;

			lost ();
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
				session._do_close (false);
		}

		private Object create<T> () {
			return Object.new (typeof (T), main_context: main_context, parent: this);
		}

		private abstract class DeviceTask<T> : AsyncTask<T> {
			public weak Device parent {
				get;
				construct;
			}

			protected override void validate_operation () throws Error {
				if (parent.is_closed)
					throw new IOError.FAILED ("invalid operation (device is gone)");
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

		private weak Device device;
		private bool is_closed = false;

		private Gee.HashMap<uint, Script> script_by_id = new Gee.HashMap<uint, Script> ();

		public Session (Device device, uint pid, AgentSession agent_session) {
			this.device = device;
			this.pid = pid;
			this.session = agent_session;
			this.main_context = device.main_context;

			session.message_from_script.connect (on_message_from_script);
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
			protected override void validate_operation () throws Error {
			}

			protected override async void perform_operation () throws Error {
				yield parent.detach ();
			}
		}

		public async Script create_script (string source) throws Error {
			var sid = yield session.create_script (source);
			var script = new Script (this, sid);
			script_by_id[sid.handle] = script;
			return script;
		}

		public Script create_script_sync (string source) throws Error {
			var task = create<CreateScriptTask> () as CreateScriptTask;
			task.source = source;
			return task.start_and_wait_for_completion ();
		}

		private class CreateScriptTask : ProcessTask<Script> {
			public string source;

			protected override async Script perform_operation () throws Error {
				return yield parent.create_script (source);
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

		public async void _do_close (bool may_block) {
			if (is_closed)
				return;
			is_closed = true;

			foreach (var script in script_by_id.values.to_array ())
				yield script._do_unload (may_block);

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
		}

		private Object create<T> () {
			return Object.new (typeof (T), main_context: main_context, parent: this);
		}

		private abstract class ProcessTask<T> : AsyncTask<T> {
			public weak Session parent {
				get;
				construct;
			}

			protected override void validate_operation () throws Error {
				if (parent.is_closed)
					throw new IOError.FAILED ("invalid operation (detached from session)");
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
		private AgentScriptId script_id;

		public Script (Session session, AgentScriptId script_id) {
			this.session = session;
			this.script_id = script_id;
			this.main_context = session.main_context;
		}

		public async void load () throws Error {
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
			yield _do_unload (true);
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

		public async void _do_unload (bool may_block) {
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
		}

		private Object create<T> () {
			return Object.new (typeof (T), main_context: main_context, parent: this);
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
