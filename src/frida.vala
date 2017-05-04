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

		public delegate bool Predicate (Device device);

		private Gee.Promise<bool> ensure_request;
		private Gee.Promise<bool> close_request;

		private HostSessionService service = null;
		private Gee.ArrayList<Device> devices = new Gee.ArrayList<Device> ();

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

		public async Device get_device_by_id (string id, int timeout = 0, Cancellable? cancellable = null) throws Error {
			return check_device (yield find_device_by_id (id, timeout, cancellable));
		}

		public Device get_device_by_id_sync (string id, int timeout = 0, Cancellable? cancellable = null) throws Error {
			return check_device (find_device_by_id_sync (id, timeout, cancellable));
		}

		public async Device get_device_by_type (DeviceType type, int timeout = 0, Cancellable? cancellable = null) throws Error {
			return check_device (yield find_device_by_type (type, timeout, cancellable));
		}

		public Device get_device_by_type_sync (DeviceType type, int timeout = 0, Cancellable? cancellable = null) throws Error {
			return check_device (find_device_by_type_sync (type, timeout, cancellable));
		}

		public async Device get_device (Predicate predicate, int timeout = 0, Cancellable? cancellable = null) throws Error {
			return check_device (yield find_device (predicate, timeout, cancellable));
		}

		public Device get_device_sync (Predicate predicate, int timeout = 0, Cancellable? cancellable = null) throws Error {
			return check_device (find_device_sync (predicate, timeout, cancellable));
		}

		private Device check_device (Device? device) throws Error {
			if (device == null)
				throw new Error.INVALID_ARGUMENT ("Device not found");
			return device;
		}

		public async Device? find_device_by_id (string id, int timeout = 0, Cancellable? cancellable = null) throws Error {
			return yield find_device ((device) => { return device.id == id; }, timeout, cancellable);
		}

		public Device? find_device_by_id_sync (string id, int timeout = 0, Cancellable? cancellable = null) throws Error {
			return find_device_sync ((device) => { return device.id == id; }, timeout, cancellable);
		}

		public async Device? find_device_by_type (DeviceType type, int timeout = 0, Cancellable? cancellable = null) throws Error {
			return yield find_device ((device) => { return device.dtype == type; }, timeout, cancellable);
		}

		public Device? find_device_by_type_sync (DeviceType type, int timeout = 0, Cancellable? cancellable = null) throws Error {
			return find_device_sync ((device) => { return device.dtype == type; }, timeout, cancellable);
		}

		public async Device? find_device (Predicate predicate, int timeout = 0, Cancellable? cancellable = null) throws Error {
			check_open ();
			yield ensure_service ();

			Marshal.throw_if_cancelled (cancellable);

			foreach (var device in devices) {
				if (predicate (device))
					return device;
			}

			if (timeout == 0)
				return null;

			Device added_device = null;
			var added_handler = added.connect ((device) => {
				if (predicate (device)) {
					added_device = device;
					find_device.callback ();
				}
			});

			Source timeout_source = null;
			if (timeout > 0) {
				timeout_source = new TimeoutSource (timeout);
				timeout_source.set_callback (() => {
					find_device.callback ();
					return false;
				});
				timeout_source.attach (MainContext.get_thread_default ());
			}

			CancellableSource cancellable_source = null;
			if (cancellable != null) {
				cancellable_source = cancellable.source_new ();
				cancellable_source.set_callback (() => {
					find_device.callback ();
					return false;
				});
				cancellable_source.attach (MainContext.get_thread_default ());
			}

			yield;

			if (cancellable_source != null)
				cancellable_source.destroy ();

			if (timeout_source != null)
				timeout_source.destroy ();

			disconnect (added_handler);

			Marshal.throw_if_cancelled (cancellable);

			return added_device;
		}

		public Device? find_device_sync (Predicate predicate, int timeout = 0, Cancellable? cancellable = null) throws Error {
			var task = create<FindDeviceTask> () as FindDeviceTask;
			task.predicate = (device) => {
				return predicate (device);
			};
			task.timeout = timeout;
			task.cancellable = cancellable;
			return task.start_and_wait_for_completion ();
		}

		private class FindDeviceTask : ManagerTask<Device?> {
			public Predicate predicate;
			public int timeout;
			public Cancellable? cancellable;

			protected override async Device? perform_operation () throws Error {
				return yield parent.find_device (predicate, timeout, cancellable);
			}
		}

		public async DeviceList enumerate_devices () throws Error {
			check_open ();
			yield ensure_service ();
			return new DeviceList (devices.slice (0, devices.size));
		}

		public DeviceList enumerate_devices_sync () throws Error {
			return (create<EnumerateDevicesTask> () as EnumerateDevicesTask).start_and_wait_for_completion ();
		}

		private class EnumerateDevicesTask : ManagerTask<DeviceList> {
			protected override async DeviceList perform_operation () throws Error {
				return yield parent.enumerate_devices ();
			}
		}

		public async Device add_remote_device (string host) throws Error {
			check_open ();

			yield ensure_service ();

			var id = "tcp@" + host;

			foreach (var device in devices) {
				if (device.id == id)
					throw new Error.INVALID_ARGUMENT ("Device already exists");
			}

			HostSessionProvider tcp_provider = null;
			foreach (var device in devices) {
				var p = device.provider;
				if (p is TcpHostSessionProvider) {
					tcp_provider = p;
					break;
				}
			}
			if (tcp_provider == null)
				throw new Error.NOT_SUPPORTED ("TCP backend not available");

			var device = new Device (this, id, host, HostSessionProviderKind.REMOTE_SYSTEM, tcp_provider, host);
			devices.add (device);
			added (device);
			changed ();

			return device;
		}

		public Device add_remote_device_sync (string host) throws Error {
			var task = create<AddRemoteDeviceTask> () as AddRemoteDeviceTask;
			task.host = host;
			return task.start_and_wait_for_completion ();
		}

		private class AddRemoteDeviceTask : ManagerTask<Device> {
			public string host;

			protected override async Device perform_operation () throws Error {
				return yield parent.add_remote_device (host);
			}
		}

		public async void remove_remote_device (string host) throws Error {
			check_open ();

			yield ensure_service ();

			var id = "tcp@" + host;

			foreach (var device in devices) {
				if (device.id == id) {
					yield device._do_close (SessionDetachReason.APPLICATION_REQUESTED, true);
					removed (device);
					changed ();
					return;
				}
			}

			throw new Error.INVALID_ARGUMENT ("Device not found");
		}

		public void remove_remote_device_sync (string host) throws Error {
			var task = create<RemoveRemoteDeviceTask> () as RemoveRemoteDeviceTask;
			task.host = host;
			task.start_and_wait_for_completion ();
		}

		private class RemoveRemoteDeviceTask : ManagerTask<void> {
			public string host;

			protected override async void perform_operation () throws Error {
				yield parent.remove_remote_device (host);
			}
		}

		public void _release_device (Device device) {
			var device_did_exist = devices.remove (device);
			assert (device_did_exist);
		}

		private async void ensure_service () throws Error {
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
				var device = new Device (this, provider.id, provider.name, provider.kind, provider);
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
						device._do_close.begin (SessionDetachReason.DEVICE_LOST, false);
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
				throw new Error.INVALID_OPERATION ("Device manager is closed");
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
				} catch (Error ensure_error) {
					assert_not_reached ();
				}
			}

			if (service != null) {
				foreach (var device in devices.to_array ())
					yield device._do_close (SessionDetachReason.APPLICATION_REQUESTED, true);
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
		public signal void spawned (Spawn spawn);
		public signal void output (uint pid, int fd, Bytes data);
		public signal void uninjected (uint id);
		public signal void lost ();

		public string id {
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

		public delegate bool ProcessPredicate (Process process);

		private weak DeviceManager manager;
		private string? location;
		private Gee.Promise<bool> ensure_request;
		private Gee.Promise<bool> close_request;

		protected HostSession host_session;
		private Gee.HashMap<uint, Session> session_by_handle = new Gee.HashMap<uint, Session> ();
		private Gee.HashSet<Gee.Promise<Session>> pending_attach_requests = new Gee.HashSet<Gee.Promise<Session>> ();
		private Gee.HashMap<uint, Gee.Promise<bool>> pending_detach_requests = new Gee.HashMap<uint, Gee.Promise<bool>> ();

		public Device (DeviceManager manager, string id, string name, HostSessionProviderKind kind, HostSessionProvider provider, string? location = null) {
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
			this.location = location;
			this.main_context = manager.main_context;

			provider.host_session_closed.connect (on_host_session_closed);
			provider.agent_session_closed.connect (on_agent_session_closed);
		}

		public bool is_lost () {
			return close_request != null;
		}

		public async Application? get_frontmost_application () throws Error {
			check_open ();

			HostApplicationInfo app;
			try {
				yield ensure_host_session ();
				app = yield host_session.get_frontmost_application ();
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}

			if (app.pid == 0)
				return null;
			return new Application (app.identifier, app.name, app.pid, icon_from_image_data (app.small_icon), icon_from_image_data (app.large_icon));
		}

		public Application? get_frontmost_application_sync () throws Error {
			return (create<GetFrontmostApplicationTask> () as GetFrontmostApplicationTask).start_and_wait_for_completion ();
		}

		private class GetFrontmostApplicationTask : DeviceTask<Application?> {
			protected override async Application? perform_operation () throws Error {
				return yield parent.get_frontmost_application ();
			}
		}

		public async ApplicationList enumerate_applications () throws Error {
			check_open ();

			HostApplicationInfo[] applications;
			try {
				yield ensure_host_session ();
				applications = yield host_session.enumerate_applications ();
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}

			var result = new Gee.ArrayList<Application> ();
			foreach (var p in applications) {
				result.add (new Application (p.identifier, p.name, p.pid, icon_from_image_data (p.small_icon), icon_from_image_data (p.large_icon)));
			}
			return new ApplicationList (result);
		}

		public ApplicationList enumerate_applications_sync () throws Error {
			return (create<EnumerateApplicationsTask> () as EnumerateApplicationsTask).start_and_wait_for_completion ();
		}

		private class EnumerateApplicationsTask : DeviceTask<ApplicationList> {
			protected override async ApplicationList perform_operation () throws Error {
				return yield parent.enumerate_applications ();
			}
		}

		public async Process get_process_by_pid (uint pid) throws Error {
			return check_process (yield find_process_by_pid (pid));
		}

		public Process get_process_by_pid_sync (uint pid) throws Error {
			return check_process (find_process_by_pid_sync (pid));
		}

		public async Process get_process_by_name (string name, int timeout = 0, Cancellable? cancellable = null) throws Error {
			return check_process (yield find_process_by_name (name, timeout, cancellable));
		}

		public Process get_process_by_name_sync (string name, int timeout = 0, Cancellable? cancellable = null) throws Error {
			return check_process (find_process_by_name_sync (name, timeout, cancellable));
		}

		public async Process get_process (ProcessPredicate predicate, int timeout = 0, Cancellable? cancellable = null) throws Error {
			return check_process (yield find_process (predicate, timeout, cancellable));
		}

		public Process get_process_sync (ProcessPredicate predicate, int timeout = 0, Cancellable? cancellable = null) throws Error {
			return check_process (find_process_sync (predicate, timeout, cancellable));
		}

		private Process check_process (Process? process) throws Error {
			if (process == null)
				throw new Error.INVALID_ARGUMENT ("Process not found");
			return process;
		}

		public async Process? find_process_by_pid (uint pid) throws Error {
			return yield find_process ((process) => { return process.pid == pid; });
		}

		public Process? find_process_by_pid_sync (uint pid) throws Error {
			return find_process_sync ((process) => { return process.pid == pid; });
		}

		public async Process? find_process_by_name (string name, int timeout = 0, Cancellable? cancellable = null) throws Error {
			var folded_name = name.casefold ();
			return yield find_process ((process) => { return process.name.casefold () == folded_name; }, timeout, cancellable);
		}

		public Process? find_process_by_name_sync (string name, int timeout = 0, Cancellable? cancellable = null) throws Error {
			var folded_name = name.casefold ();
			return find_process_sync ((process) => { return process.name.casefold () == folded_name; }, timeout, cancellable);
		}

		public async Process? find_process (ProcessPredicate predicate, int timeout = 0, Cancellable? cancellable = null) throws Error {
			Process process = null;
			bool done = false;
			bool waiting = false;

			Source timeout_source = null;
			if (timeout > 0) {
				timeout_source = new TimeoutSource (timeout);
				timeout_source.set_callback (() => {
					done = true;
					if (waiting)
						find_process.callback ();
					return false;
				});
				timeout_source.attach (MainContext.get_thread_default ());
			}

			CancellableSource cancellable_source = null;
			if (cancellable != null) {
				cancellable_source = cancellable.source_new ();
				cancellable_source.set_callback (() => {
					done = true;
					if (waiting)
						find_process.callback ();
					return false;
				});
				cancellable_source.attach (MainContext.get_thread_default ());
			}

			while (!done) {
				var processes = yield enumerate_processes ();

				var num_processes = processes.size ();
				for (var i = 0; i != num_processes; i++) {
					var p = processes.get (i);
					if (predicate (p)) {
						process = p;
						break;
					}
				}

				if (process != null || done || timeout == 0)
					break;

				var poll_again_source = new TimeoutSource (500);
				poll_again_source.set_callback (() => {
					find_process.callback ();
					return false;
				});
				poll_again_source.attach (MainContext.get_thread_default ());

				waiting = true;
				yield;
				waiting = false;

				poll_again_source.destroy ();
			}

			if (cancellable_source != null)
				cancellable_source.destroy ();

			if (timeout_source != null)
				timeout_source.destroy ();

			Marshal.throw_if_cancelled (cancellable);

			return process;
		}

		public Process? find_process_sync (ProcessPredicate predicate, int timeout = 0, Cancellable? cancellable = null) throws Error {
			var task = create<FindProcessTask> () as FindProcessTask;
			task.predicate = (process) => {
				return predicate (process);
			};
			task.timeout = timeout;
			task.cancellable = cancellable;
			return task.start_and_wait_for_completion ();
		}

		private class FindProcessTask : DeviceTask<Process?> {
			public ProcessPredicate predicate;
			public int timeout;
			public Cancellable? cancellable;

			protected override async Process? perform_operation () throws Error {
				return yield parent.find_process (predicate, timeout, cancellable);
			}
		}

		public async ProcessList enumerate_processes () throws Error {
			check_open ();

			HostProcessInfo[] processes;
			try {
				yield ensure_host_session ();
				processes = yield host_session.enumerate_processes ();
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}

			var result = new Gee.ArrayList<Process> ();
			foreach (var p in processes) {
				result.add (new Process (p.pid, p.name, icon_from_image_data (p.small_icon), icon_from_image_data (p.large_icon)));
			}
			return new ProcessList (result);
		}

		public ProcessList enumerate_processes_sync () throws Error {
			return (create<EnumerateProcessesTask> () as EnumerateProcessesTask).start_and_wait_for_completion ();
		}

		private class EnumerateProcessesTask : DeviceTask<ProcessList> {
			protected override async ProcessList perform_operation () throws Error {
				return yield parent.enumerate_processes ();
			}
		}

		private Icon? icon_from_image_data (ImageData? img) {
			if (img == null || img.width == 0)
				return null;
			return new Icon (img.width, img.height, img.rowstride, new Bytes.take (Base64.decode (img.pixels)));
		}

		public async void enable_spawn_gating () throws Error {
			check_open ();

			try {
				yield ensure_host_session ();
				yield host_session.enable_spawn_gating ();
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public void enable_spawn_gating_sync () throws Error {
			(create<EnableSpawnGatingTask> () as EnableSpawnGatingTask).start_and_wait_for_completion ();
		}

		private class EnableSpawnGatingTask : DeviceTask<void> {
			protected override async void perform_operation () throws Error {
				yield parent.enable_spawn_gating ();
			}
		}

		public async void disable_spawn_gating () throws Error {
			check_open ();

			try {
				yield ensure_host_session ();
				yield host_session.disable_spawn_gating ();
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public void disable_spawn_gating_sync () throws Error {
			(create<DisableSpawnGatingTask> () as DisableSpawnGatingTask).start_and_wait_for_completion ();
		}

		private class DisableSpawnGatingTask : DeviceTask<void> {
			protected override async void perform_operation () throws Error {
				yield parent.disable_spawn_gating ();
			}
		}

		public async SpawnList enumerate_pending_spawns () throws Error {
			check_open ();

			HostSpawnInfo[] pending_spawns;
			try {
				yield ensure_host_session ();
				pending_spawns = yield host_session.enumerate_pending_spawns ();
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}

			var result = new Gee.ArrayList<Spawn> ();
			foreach (var p in pending_spawns)
				result.add (spawn_from_info (p));
			return new SpawnList (result);
		}

		public SpawnList enumerate_pending_spawns_sync () throws Error {
			return (create<EnumeratePendingSpawnsTask> () as EnumeratePendingSpawnsTask).start_and_wait_for_completion ();
		}

		private class EnumeratePendingSpawnsTask : DeviceTask<SpawnList> {
			protected override async SpawnList perform_operation () throws Error {
				return yield parent.enumerate_pending_spawns ();
			}
		}

		private Spawn spawn_from_info (HostSpawnInfo info) {
			var identifier = info.identifier;
			return new Spawn (info.pid, (identifier.length > 0) ? identifier : null);
		}

		public async uint spawn (string path, string[] argv, string[] envp) throws Error {
			check_open ();

			uint pid;
			try {
				/* FIXME: workaround for Vala compiler bug: */
				var argv_copy = argv;
				var envp_copy = envp;
				yield ensure_host_session ();
				pid = yield host_session.spawn (path, argv_copy, envp_copy);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}

			return pid;
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

		public async void input (uint pid, Bytes data) throws Error {
			check_open ();

			try {
				yield ensure_host_session ();
				yield host_session.input (pid, data.get_data ());
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public void input_sync (uint pid, Bytes data) throws Error {
			var task = create<InputTask> () as InputTask;
			task.pid = pid;
			task.data = data;
			task.start_and_wait_for_completion ();
		}

		private class InputTask : DeviceTask<void> {
			public uint pid;
			public Bytes data;

			protected override async void perform_operation () throws Error {
				yield parent.input (pid, data);
			}
		}

		public async void resume (uint pid) throws Error {
			check_open ();

			try {
				yield ensure_host_session ();
				yield host_session.resume (pid);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
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

			try {
				yield ensure_host_session ();
				yield host_session.kill (pid);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
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

			var attach_request = new Gee.Promise<Session> ();
			pending_attach_requests.add (attach_request);

			Session session;
			try {
				yield ensure_host_session ();

				var agent_session_id = yield host_session.attach_to (pid);
				var agent_session = yield provider.obtain_agent_session (host_session, agent_session_id);
				session = new Session (this, pid, agent_session);
				session_by_handle[agent_session_id.handle] = session;

				attach_request.set_value (session);
				pending_attach_requests.remove (attach_request);
			} catch (GLib.Error raw_attach_error) {
				var attach_error = Marshal.from_dbus (raw_attach_error);

				attach_request.set_exception (attach_error);
				pending_attach_requests.remove (attach_request);

				throw attach_error;
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

		public async uint inject_library_file (uint pid, string path, string entrypoint, string data) throws Error {
			check_open ();

			try {
				yield ensure_host_session ();

				var id = yield host_session.inject_library_file (pid, path, entrypoint, data);

				return id.handle;
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public uint inject_library_file_sync (uint pid, string path, string entrypoint, string data) throws Error {
			var task = create<InjectLibraryFileTask> () as InjectLibraryFileTask;
			task.pid = pid;
			task.path = path;
			task.entrypoint = entrypoint;
			task.data = data;
			return task.start_and_wait_for_completion ();
		}

		private class InjectLibraryFileTask : DeviceTask<uint> {
			public uint pid;
			public string path;
			public string entrypoint;
			public string data;

			protected override async uint perform_operation () throws Error {
				return yield parent.inject_library_file (pid, path, entrypoint, data);
			}
		}

		public async uint inject_library_blob (uint pid, Bytes blob, string entrypoint, string data) throws Error {
			check_open ();

			try {
				yield ensure_host_session ();

				var id = yield host_session.inject_library_blob (pid, blob.get_data (), entrypoint, data);

				return id.handle;
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public uint inject_library_blob_sync (uint pid, Bytes blob, string entrypoint, string data) throws Error {
			var task = create<InjectLibraryBlobTask> () as InjectLibraryBlobTask;
			task.pid = pid;
			task.blob = blob;
			task.entrypoint = entrypoint;
			task.data = data;
			return task.start_and_wait_for_completion ();
		}

		private class InjectLibraryBlobTask : DeviceTask<uint> {
			public uint pid;
			public Bytes blob;
			public string entrypoint;
			public string data;

			protected override async uint perform_operation () throws Error {
				return yield parent.inject_library_blob (pid, blob, entrypoint, data);
			}
		}

		private void check_open () throws Error {
			if (close_request != null)
				throw new Error.INVALID_OPERATION ("Device is gone");
		}

		public async void _do_close (SessionDetachReason reason, bool may_block) {
			if (close_request != null) {
				try {
					yield close_request.future.wait_async ();
				} catch (Gee.FutureError e) {
					assert_not_reached ();
				}
				return;
			}
			close_request = new Gee.Promise<bool> ();

			while (!pending_detach_requests.is_empty) {
				var iterator = pending_detach_requests.entries.iterator ();
				iterator.next ();
				var entry = iterator.get ();
				var handle = entry.key;
				var detach_request = entry.value;
				detach_request.set_value (true);
				pending_detach_requests.unset (handle);
			}

			while (!pending_attach_requests.is_empty) {
				var iterator = pending_attach_requests.iterator ();
				iterator.next ();
				var attach_request = iterator.get ();
				try {
					yield attach_request.future.wait_async ();
				} catch (Gee.FutureError e) {
				}
			}

			if (ensure_request != null) {
				try {
					yield ensure_host_session ();
				} catch (Error ensure_error) {
				}
			}

			foreach (var session in session_by_handle.values.to_array ()) {
				yield session._do_close (reason, may_block);
			}
			session_by_handle.clear ();

			provider.host_session_closed.disconnect (on_host_session_closed);
			provider.agent_session_closed.disconnect (on_agent_session_closed);

			if (host_session != null) {
				host_session.spawned.disconnect (on_spawned);
				host_session.output.disconnect (on_output);
				host_session.uninjected.disconnect (on_uninjected);
				if (may_block) {
					try {
						yield provider.destroy (host_session);
					} catch (Error e) {
					}
				}
				host_session = null;
			}

			manager._release_device (this);
			manager = null;

			lost ();

			close_request.set_value (true);
		}

		public async void _release_session (Session session, bool may_block) {
			bool session_exists = false;
			uint handle = 0;
			foreach (var entry in session_by_handle.entries) {
				if (entry.value == session) {
					session_exists = true;
					handle = entry.key;
					break;
				}
			}
			assert (session_exists);
			session_by_handle.unset (handle);

			if (may_block) {
				var detach_request = new Gee.Promise<bool> ();

				pending_detach_requests[handle] = detach_request;

				try {
					yield detach_request.future.wait_async ();
				} catch (Gee.FutureError e) {
					assert_not_reached ();
				}
			}
		}

		private async void ensure_host_session () throws Error {
			if (ensure_request != null) {
				var future = ensure_request.future;
				try {
					yield future.wait_async ();
				} catch (Gee.FutureError e) {
					throw (Error) future.exception;
				}
				return;
			}
			ensure_request = new Gee.Promise<bool> ();

			try {
				host_session = yield provider.create (location);
				host_session.spawned.connect (on_spawned);
				host_session.output.connect (on_output);
				host_session.uninjected.connect (on_uninjected);
				ensure_request.set_value (true);
			} catch (Error e) {
				ensure_request.set_exception (e);
				ensure_request = null;
				throw e;
			}
		}

		private void on_spawned (HostSpawnInfo info) {
			spawned (spawn_from_info (info));
		}

		private void on_output (uint pid, int fd, uint8[] data) {
			output (pid, fd, new Bytes (data));
		}

		private void on_uninjected (InjectorPayloadId id) {
			uninjected (id.handle);
		}

		private void on_host_session_closed (HostSession session) {
			if (session != host_session)
				return;

			host_session.spawned.disconnect (on_spawned);
			host_session.output.disconnect (on_output);
			host_session.uninjected.disconnect (on_uninjected);
			host_session = null;

			ensure_request = null;
		}

		private void on_agent_session_closed (AgentSessionId id, SessionDetachReason reason) {
			var handle = id.handle;

			var session = session_by_handle[handle];
			if (session != null)
				session._do_close.begin (reason, false);

			Gee.Promise<bool> detach_request;
			if (pending_detach_requests.unset (handle, out detach_request))
				detach_request.set_value (true);
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

	public class ApplicationList : Object {
		private Gee.List<Application> items;

		public ApplicationList (Gee.List<Application> items) {
			this.items = items;
		}

		public int size () {
			return items.size;
		}

		public new Application get (int index) {
			return items.get (index);
		}
	}

	public class Application : Object {
		public string identifier {
			get;
			private set;
		}

		public string name {
			get;
			private set;
		}

		public uint pid {
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

		public Application (string identifier, string name, uint pid, Icon? small_icon, Icon? large_icon) {
			this.identifier = identifier;
			this.name = name;
			this.pid = pid;
			this.small_icon = small_icon;
			this.large_icon = large_icon;
		}
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

	public class SpawnList : Object {
		private Gee.List<Spawn> items;

		public SpawnList (Gee.List<Spawn> items) {
			this.items = items;
		}

		public int size () {
			return items.size;
		}

		public new Spawn get (int index) {
			return items.get (index);
		}
	}

	public class Spawn : Object {
		public uint pid {
			get;
			private set;
		}

		public string? identifier {
			get;
			private set;
		}

		public Spawn (uint pid, string? identifier) {
			this.pid = pid;
			this.identifier = identifier;
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

		public Bytes pixels {
			get;
			private set;
		}

		public Icon (int width, int height, int rowstride, Bytes pixels) {
			this.width = width;
			this.height = height;
			this.rowstride = rowstride;
			this.pixels = pixels;
		}
	}

	public class Session : Object {
		public signal void detached (SessionDetachReason reason);

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
			yield _do_close (SessionDetachReason.APPLICATION_REQUESTED, true);
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

			AgentScriptId sid;
			try {
				sid = yield session.create_script ((name == null) ? "" : name, source);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}

			check_open ();

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

		public async Script create_script_from_bytes (Bytes bytes) throws Error {
			check_open ();

			AgentScriptId sid;
			try {
				sid = yield session.create_script_from_bytes (bytes.get_data ());
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}

			check_open ();

			var script = new Script (this, sid);
			script_by_id[sid.handle] = script;

			return script;
		}

		public Script create_script_from_bytes_sync (Bytes bytes) throws Error {
			var task = create<CreateScriptFromBytesTask> () as CreateScriptFromBytesTask;
			task.bytes = bytes;
			return task.start_and_wait_for_completion ();
		}

		private class CreateScriptFromBytesTask : ProcessTask<Script> {
			public Bytes bytes;

			protected override async Script perform_operation () throws Error {
				return yield parent.create_script_from_bytes (bytes);
			}
		}

		public async Bytes compile_script (string? name, string source) throws Error {
			check_open ();

			uint8[] data;
			try {
				data = yield session.compile_script ((name == null) ? "" : name, source);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}

			return new Bytes (data);
		}

		public Bytes compile_script_sync (string? name, string source) throws Error {
			var task = create<CompileScriptTask> () as CompileScriptTask;
			task.name = name;
			task.source = source;
			return task.start_and_wait_for_completion ();
		}

		private class CompileScriptTask : ProcessTask<Bytes> {
			public string? name;
			public string source;

			protected override async Bytes perform_operation () throws Error {
				return yield parent.compile_script (name, source);
			}
		}

		public async void enable_debugger (uint16 port = 0) throws Error {
			check_open ();

			if (debugger != null)
				throw new Error.INVALID_OPERATION ("Debugger is already enabled");

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

		public async void enable_jit () throws Error {
			check_open ();

			try {
				yield session.enable_jit ();
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public void enable_jit_sync () throws Error {
			(create<EnableJitTask> () as EnableJitTask).start_and_wait_for_completion ();
		}

		private class EnableJitTask : ProcessTask<void> {
			protected override async void perform_operation () throws Error {
				yield parent.enable_jit ();
			}
		}

		private void on_message_from_script (AgentScriptId sid, string message, bool has_data, uint8[] data) {
			var script = script_by_id[sid.handle];
			if (script != null)
				script.message (message, has_data ? new Bytes (data) : null);
		}

		public void _release_script (AgentScriptId sid) {
			var script_did_exist = script_by_id.unset (sid.handle);
			assert (script_did_exist);
		}

		private void check_open () throws Error {
			if (close_request != null)
				throw new Error.INVALID_OPERATION ("Session is detached");
		}

		public async void _do_close (SessionDetachReason reason, bool may_block) {
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

			if (may_block)
				session.close.begin ();
			session.message_from_script.disconnect (on_message_from_script);
			session = null;

			yield device._release_session (this, may_block);
			device = null;

			detached (reason);
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
		public signal void message (string message, Bytes? data);

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

			try {
				yield session.session.load_script (script_id);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
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

		public async void post (string message, Bytes? data = null) throws Error {
			check_open ();

			var has_data = data != null;
			var data_param = has_data ? data.get_data () : new uint8[0];

			try {
				yield session.session.post_to_script (script_id, message, has_data, data_param);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public void post_sync (string message, Bytes? data = null) throws Error {
			var task = create<PostTask> () as PostTask;
			task.message = message;
			task.data = data;
			task.start_and_wait_for_completion ();
		}

		private class PostTask : ScriptTask<void> {
			public string message;
			public Bytes? data;

			protected override async void perform_operation () throws Error {
				yield parent.post (message, data);
			}
		}

		private void check_open () throws Error {
			if (session == null)
				throw new Error.INVALID_OPERATION ("Script is destroyed");
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
				} catch (GLib.Error ignored_error) {
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

	public interface Injector : Object {
		public signal void uninjected (uint id);

		public static Injector new () {
#if WINDOWS
			return new Winjector ();
#endif
#if DARWIN
			var tempdir = new TemporaryDirectory ();
			var helper = new DarwinHelperProcess (tempdir);
			return new Fruitjector (helper, true, tempdir);
#endif
#if LINUX
			return new Linjector ();
#endif
#if QNX
			return new Qinjector ();
#endif
		}

		public static Injector new_inprocess () {
#if WINDOWS
			return new Winjector ();
#endif
#if DARWIN
			var tempdir = new TemporaryDirectory ();
			var helper = new DarwinHelperBackend ();
			return new Fruitjector (helper, true, tempdir);
#endif
#if LINUX
			return new Linjector ();
#endif
#if QNX
			return new Qinjector ();
#endif
		}

		public abstract async void close ();

		public void close_sync () {
			try {
				(create<CloseTask> () as CloseTask).start_and_wait_for_completion ();
			} catch (Error e) {
				assert_not_reached ();
			}
		}

		private class CloseTask : InjectorTask<void> {
			protected override async void perform_operation () throws Error {
				yield parent.close ();
			}
		}

		public abstract async uint inject_library_file (uint pid, string path, string entrypoint, string data) throws Error;

		public uint inject_library_file_sync (uint pid, string path, string entrypoint, string data) throws Error {
			var task = create<InjectLibraryFileTask> () as InjectLibraryFileTask;
			task.pid = pid;
			task.path = path;
			task.entrypoint = entrypoint;
			task.data = data;
			return task.start_and_wait_for_completion ();
		}

		private class InjectLibraryFileTask : InjectorTask<uint> {
			public uint pid;
			public string path;
			public string entrypoint;
			public string data;

			protected override async uint perform_operation () throws Error {
				return yield parent.inject_library_file (pid, path, entrypoint, data);
			}
		}

		public abstract async uint inject_library_blob (uint pid, Bytes blob, string entrypoint, string data) throws Error;

		public uint inject_library_blob_sync (uint pid, Bytes blob, string entrypoint, string data) throws Error {
			var task = create<InjectLibraryBlobTask> () as InjectLibraryBlobTask;
			task.pid = pid;
			task.blob = blob;
			task.entrypoint = entrypoint;
			task.data = data;
			return task.start_and_wait_for_completion ();
		}

		private class InjectLibraryBlobTask : InjectorTask<uint> {
			public uint pid;
			public Bytes blob;
			public string entrypoint;
			public string data;

			protected override async uint perform_operation () throws Error {
				return yield parent.inject_library_blob (pid, blob, entrypoint, data);
			}
		}

		private Object create<T> () {
			return Object.new (typeof (T), main_context: get_main_context (), parent: this);
		}

		private abstract class InjectorTask<T> : AsyncTask<T> {
			public weak Injector parent {
				get;
				construct;
			}
		}
	}

	public class FileMonitor : Object {
		public signal void change (string file_path, string? other_file_path, FileMonitorEvent event);

		public string path {
			get;
			construct;
		}

		public MainContext main_context {
			get;
			construct;
		}

		private GLib.FileMonitor monitor;

		public FileMonitor (string path) {
			Object (path: path, main_context: get_main_context ());
		}

		~FileMonitor () {
			clear ();
		}

		public async void enable (Cancellable? cancellable = null) throws Error {
			if (monitor != null)
				throw new Error.INVALID_OPERATION ("Already enabled");

			var file = File.parse_name (path);

			try {
				monitor = file.monitor (FileMonitorFlags.NONE, cancellable);
			} catch (GLib.Error e) {
				throw new Error.INVALID_OPERATION (e.message);
			}

			monitor.changed.connect (on_changed);
		}

		public void enable_sync (Cancellable? cancellable = null) throws Error {
			var task = create<EnableTask> () as EnableTask;
			task.cancellable = cancellable;
			task.start_and_wait_for_completion ();
		}

		private class EnableTask : FileMonitorTask<void> {
			public Cancellable? cancellable;

			protected override async void perform_operation () throws Error {
				yield parent.enable (cancellable);
			}
		}

		public async void disable () throws Error {
			if (monitor == null)
				throw new Error.INVALID_OPERATION ("Already disabled");

			clear ();
		}

		private void clear () {
			if (monitor == null)
				return;

			monitor.changed.disconnect (on_changed);
			monitor.cancel ();
			monitor = null;
		}

		public void disable_sync () throws Error {
			(create<DisableTask> () as DisableTask).start_and_wait_for_completion ();
		}

		private class DisableTask : FileMonitorTask<void> {
			protected override async void perform_operation () throws Error {
				yield parent.disable ();
			}
		}

		private void on_changed (File file, File? other_file, FileMonitorEvent event) {
			change (file.get_parse_name (), (other_file != null) ? other_file.get_parse_name () : null, event);
		}

		private Object create<T> () {
			return Object.new (typeof (T), main_context: main_context, parent: this);
		}

		private abstract class FileMonitorTask<T> : AsyncTask<T> {
			public weak FileMonitor parent {
				get;
				construct;
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
		private Error? error;

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
				error = e;
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

	private Mutex gc_mutex;
	private uint gc_generation = 0;
	private bool gc_scheduled = false;

	public void on_pending_garbage (void * data) {
		gc_mutex.lock ();
		gc_generation++;
		bool already_scheduled = gc_scheduled;
		gc_scheduled = true;
		gc_mutex.unlock ();

		if (already_scheduled)
			return;

		Timeout.add (50, () => {
			gc_mutex.lock ();
			uint generation = gc_generation;
			gc_mutex.unlock ();

			bool collected_everything = garbage_collect ();

			gc_mutex.lock ();
			bool same_generation = generation == gc_generation;
			bool repeat = !collected_everything || !same_generation;
			if (!repeat)
				gc_scheduled = false;
			gc_mutex.unlock ();

			return repeat;
		});
	}

	[CCode (cname = "g_thread_garbage_collect")]
	private extern bool garbage_collect ();
}
