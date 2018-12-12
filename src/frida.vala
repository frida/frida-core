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
			construct;
		}

		public delegate bool Predicate (Device device);

		private Gee.Promise<bool> ensure_request;
		private Gee.Promise<bool> close_request;

		private HostSessionService service = null;
		private Gee.ArrayList<Device> devices = new Gee.ArrayList<Device> ();

		public DeviceManager () {
			Object (main_context: get_main_context ());
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

			var device = new Device (this, id, host, HostSessionProviderKind.REMOTE, tcp_provider, host);
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

			service = new HostSessionService.with_default_backends ();
			service.provider_available.connect (on_provider_available);
			service.provider_unavailable.connect (on_provider_unavailable);
			yield service.start ();

			ensure_request.set_value (true);
		}

		private void on_provider_available (HostSessionProvider provider) {
			var device = new Device (this, provider.id, provider.name, provider.kind, provider);
			devices.add (device);

			var started = ensure_request.future.ready;
			if (started) {
				added (device);
				changed ();
			}
		}

		private void on_provider_unavailable (HostSessionProvider provider) {
			var started = ensure_request.future.ready;

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
				service.provider_available.disconnect (on_provider_available);
				service.provider_unavailable.disconnect (on_provider_unavailable);
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
		public signal void spawn_added (Spawn spawn);
		public signal void spawn_removed (Spawn spawn);
		public signal void child_added (Child child);
		public signal void child_removed (Child child);
		public signal void output (uint pid, int fd, Bytes data);
		public signal void uninjected (uint id);
		public signal void lost ();

		public string id {
			get;
			construct;
		}

		public string name {
			get;
			construct;
		}

		public Icon? icon {
			get;
			construct;
		}

		public DeviceType dtype {
			get;
			construct;
		}

		public HostSessionProvider provider {
			get;
			construct;
		}

		public weak DeviceManager manager {
			get;
			construct;
		}

		public MainContext main_context {
			get;
			construct;
		}

		public delegate bool ProcessPredicate (Process process);

		private string? location;
		private Gee.Promise<bool> ensure_request;
		private Gee.Promise<bool> close_request;

		protected HostSession host_session;
		private Gee.HashMap<AgentSessionId?, Session> agent_sessions =
			new Gee.HashMap<AgentSessionId?, Session> (AgentSessionId.hash, AgentSessionId.equal);
		private Gee.HashSet<Gee.Promise<Session>> pending_attach_requests = new Gee.HashSet<Gee.Promise<Session>> ();
		private Gee.HashMap<AgentSessionId?, Gee.Promise<bool>> pending_detach_requests =
			new Gee.HashMap<AgentSessionId?, Gee.Promise<bool>> (AgentSessionId.hash, AgentSessionId.equal);

		public Device (DeviceManager manager, string id, string name, HostSessionProviderKind kind, HostSessionProvider provider, string? location = null) {
			DeviceType dtype;
			switch (kind) {
				case HostSessionProviderKind.LOCAL:
					dtype = DeviceType.LOCAL;
					break;
				case HostSessionProviderKind.REMOTE:
					dtype = DeviceType.REMOTE;
					break;
				case HostSessionProviderKind.USB:
					dtype = DeviceType.USB;
					break;
				default:
					assert_not_reached ();
			}

			Object (
				id: id,
				name: name,
				icon: icon_from_image (provider.icon),
				dtype: dtype,
				provider: provider,
				manager: manager,
				main_context: manager.main_context
			);

			this.location = location;
		}

		construct {
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
			var task = create<FindSessionTask> () as FindSessionTask;
			task.predicate = (process) => {
				return predicate (process);
			};
			task.timeout = timeout;
			task.cancellable = cancellable;
			return task.start_and_wait_for_completion ();
		}

		private class FindSessionTask : DeviceTask<Process?> {
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

		private static Icon? icon_from_image (Image? image) {
			if (image == null)
				return null;
			return icon_from_image_data (image.data);
		}

		private static Icon? icon_from_image_data (ImageData image) {
			if (image.width == 0)
				return null;
			return new Icon (image.width, image.height, image.rowstride, new Bytes.take (Base64.decode (image.pixels)));
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

		public async SpawnList enumerate_pending_spawn () throws Error {
			check_open ();

			HostSpawnInfo[] pending_spawn;
			try {
				yield ensure_host_session ();
				pending_spawn = yield host_session.enumerate_pending_spawn ();
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}

			var result = new Gee.ArrayList<Spawn> ();
			foreach (var p in pending_spawn)
				result.add (spawn_from_info (p));
			return new SpawnList (result);
		}

		public SpawnList enumerate_pending_spawn_sync () throws Error {
			return (create<EnumeratePendingSpawnTask> () as EnumeratePendingSpawnTask).start_and_wait_for_completion ();
		}

		private class EnumeratePendingSpawnTask : DeviceTask<SpawnList> {
			protected override async SpawnList perform_operation () throws Error {
				return yield parent.enumerate_pending_spawn ();
			}
		}

		private Spawn spawn_from_info (HostSpawnInfo info) {
			var identifier = info.identifier;
			return new Spawn (info.pid, (identifier.length > 0) ? identifier : null);
		}

		public async ChildList enumerate_pending_children () throws Error {
			check_open ();

			HostChildInfo[] pending_children;
			try {
				yield ensure_host_session ();
				pending_children = yield host_session.enumerate_pending_children ();
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}

			var result = new Gee.ArrayList<Child> ();
			foreach (var p in pending_children)
				result.add (child_from_info (p));
			return new ChildList (result);
		}

		public ChildList enumerate_pending_children_sync () throws Error {
			return (create<EnumeratePendingChildrenTask> () as EnumeratePendingChildrenTask).start_and_wait_for_completion ();
		}

		private class EnumeratePendingChildrenTask : DeviceTask<ChildList> {
			protected override async ChildList perform_operation () throws Error {
				return yield parent.enumerate_pending_children ();
			}
		}

		private Child child_from_info (HostChildInfo info) {
			var identifier = info.identifier;
			var path = info.path;
			return new Child (
				info.pid,
				info.parent_pid,
				info.origin,
				(identifier.length > 0) ? identifier : null,
				(path.length > 0) ? path : null,
				info.has_argv ? info.argv : null,
				info.has_envp ? info.envp : null
			);
		}

		public async uint spawn (string program, SpawnOptions? options = null) throws Error {
			check_open ();

			var raw_options = HostSpawnOptions ();
			if (options != null) {
				var argv = options.argv;
				if (argv != null) {
					raw_options.has_argv = true;
					raw_options.argv = argv;
				}

				var envp = options.envp;
				if (envp != null) {
					raw_options.has_envp = true;
					raw_options.envp = envp;
				}

				var env = options.env;
				if (env != null) {
					raw_options.has_env = true;
					raw_options.env = env;
				}

				var cwd = options.cwd;
				if (cwd != null)
					raw_options.cwd = cwd;

				raw_options.stdio = options.stdio;

				raw_options.aux = options.get_aux_bytes ().get_data ();
			}

			uint pid;
			try {
				yield ensure_host_session ();
				pid = yield host_session.spawn (program, raw_options);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}

			return pid;
		}

		public uint spawn_sync (string program, SpawnOptions? options = null) throws Error {
			var task = create<SpawnTask> () as SpawnTask;
			task.program = program;
			task.options = options;
			return task.start_and_wait_for_completion ();
		}

		private class SpawnTask : DeviceTask<uint> {
			public string program;
			public SpawnOptions? options;

			protected override async uint perform_operation () throws Error {
				return yield parent.spawn (program, options);
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
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}

			try {
				yield host_session.kill (pid);
			} catch (GLib.Error e) {
				/* The process being killed might be the other end of the connection. */
				if (!(e is IOError.CLOSED))
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
				agent_sessions[agent_session_id] = session;

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
				var session_id = entry.key;
				var detach_request = entry.value;
				detach_request.set_value (true);
				pending_detach_requests.unset (session_id);
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

			foreach (var session in agent_sessions.values.to_array ()) {
				yield session._do_close (reason, null, may_block);
			}
			agent_sessions.clear ();

			provider.host_session_closed.disconnect (on_host_session_closed);
			provider.agent_session_closed.disconnect (on_agent_session_closed);

			if (host_session != null) {
				host_session.spawn_added.disconnect (on_spawn_added);
				host_session.spawn_removed.disconnect (on_spawn_removed);
				host_session.child_added.disconnect (on_child_added);
				host_session.child_removed.disconnect (on_child_removed);
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

			lost ();

			close_request.set_value (true);
		}

		public async void _release_session (Session session, bool may_block) {
			AgentSessionId? session_id = null;
			foreach (var entry in agent_sessions.entries) {
				if (entry.value == session) {
					session_id = entry.key;
					break;
				}
			}
			assert (session_id != null);
			agent_sessions.unset (session_id);

			if (may_block) {
				var detach_request = new Gee.Promise<bool> ();

				pending_detach_requests[session_id] = detach_request;

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
				host_session.spawn_added.connect (on_spawn_added);
				host_session.spawn_removed.connect (on_spawn_removed);
				host_session.child_added.connect (on_child_added);
				host_session.child_removed.connect (on_child_removed);
				host_session.output.connect (on_output);
				host_session.uninjected.connect (on_uninjected);
				ensure_request.set_value (true);
			} catch (Error e) {
				ensure_request.set_exception (e);
				ensure_request = null;
				throw e;
			}
		}

		private void on_spawn_added (HostSpawnInfo info) {
			spawn_added (spawn_from_info (info));
		}

		private void on_spawn_removed (HostSpawnInfo info) {
			spawn_removed (spawn_from_info (info));
		}

		private void on_child_added (HostChildInfo info) {
			child_added (child_from_info (info));
		}

		private void on_child_removed (HostChildInfo info) {
			child_removed (child_from_info (info));
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

			host_session.spawn_added.disconnect (on_spawn_added);
			host_session.spawn_removed.disconnect (on_spawn_removed);
			host_session.output.disconnect (on_output);
			host_session.uninjected.disconnect (on_uninjected);
			host_session = null;

			ensure_request = null;
		}

		private void on_agent_session_closed (AgentSessionId id, SessionDetachReason reason, string? crash_report) {
			var session = agent_sessions[id];
			if (session != null)
				session._do_close.begin (reason, crash_report, false);

			Gee.Promise<bool> detach_request;
			if (pending_detach_requests.unset (id, out detach_request))
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
		REMOTE,
		USB
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
			construct;
		}

		public string name {
			get;
			construct;
		}

		public uint pid {
			get;
			construct;
		}

		public Icon? small_icon {
			get;
			construct;
		}

		public Icon? large_icon {
			get;
			construct;
		}

		public Application (string identifier, string name, uint pid, Icon? small_icon, Icon? large_icon) {
			Object (
				identifier: identifier,
				name: name,
				pid: pid,
				small_icon: small_icon,
				large_icon: large_icon
			);
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
			construct;
		}

		public string name {
			get;
			construct;
		}

		public Icon? small_icon {
			get;
			construct;
		}

		public Icon? large_icon {
			get;
			construct;
		}

		public Process (uint pid, string name, Icon? small_icon, Icon? large_icon) {
			Object (
				pid: pid,
				name: name,
				small_icon: small_icon,
				large_icon: large_icon
			);
		}
	}

	public class SpawnOptions : Object {
		public string[]? argv {
			get;
			set;
		}

		public string[]? envp {
			get;
			set;
		}

		public string[]? env {
			get;
			set;
		}

		public string? cwd {
			get;
			set;
		}

		public Stdio stdio {
			get;
			set;
			default = INHERIT;
		}

		public VariantDict aux {
			get {
				return _aux;
			}
		}
		private VariantDict _aux = new VariantDict ();

		internal Bytes get_aux_bytes () {
			var variant = _aux.end ();
			var bytes = variant.get_data_as_bytes ();
			_aux = new VariantDict (variant);
			return bytes;
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
			construct;
		}

		public string? identifier {
			get;
			construct;
		}

		public Spawn (uint pid, string? identifier) {
			Object (
				pid: pid,
				identifier: identifier
			);
		}
	}

	public class ChildList : Object {
		private Gee.List<Child> items;

		public ChildList (Gee.List<Child> items) {
			this.items = items;
		}

		public int size () {
			return items.size;
		}

		public new Child get (int index) {
			return items.get (index);
		}
	}

	public class Child : Object {
		public uint pid {
			get;
			construct;
		}

		public uint parent_pid {
			get;
			construct;
		}

		public ChildOrigin origin {
			get;
			construct;
		}

		public string? identifier {
			get;
			construct;
		}

		public string? path {
			get;
			construct;
		}

		public string[]? argv {
			get;
			construct;
		}

		public string[]? envp {
			get;
			construct;
		}

		public Child (uint pid, uint parent_pid, ChildOrigin origin, string? identifier, string? path, string[]? argv, string[]? envp) {
			Object (
				pid: pid,
				parent_pid: parent_pid,
				origin: origin,
				identifier: identifier,
				path: path,
				argv: argv,
				envp: envp
			);
		}
	}

	public class Icon : Object {
		public int width {
			get;
			construct;
		}

		public int height {
			get;
			construct;
		}

		public int rowstride {
			get;
			construct;
		}

		public Bytes pixels {
			get;
			construct;
		}

		public Icon (int width, int height, int rowstride, Bytes pixels) {
			Object (
				width: width,
				height: height,
				rowstride: rowstride,
				pixels: pixels
			);
		}
	}

	public class Session : Object {
		public signal void detached (SessionDetachReason reason, string? crash_report);

		public uint pid {
			get;
			construct;
		}

		public AgentSession session {
			get;
			construct;
		}

		public weak Device device {
			get;
			construct;
		}

		public MainContext main_context {
			get;
			construct;
		}

		private Gee.Promise<bool> close_request;

		private Gee.HashMap<AgentScriptId?, Script> scripts =
			new Gee.HashMap<AgentScriptId?, Script> (AgentScriptId.hash, AgentScriptId.equal);

		private Debugger debugger;

		public Session (Device device, uint pid, AgentSession agent_session) {
			Object (
				pid: pid,
				session: agent_session,
				device: device,
				main_context: device.main_context
			);
		}

		construct {
			session.message_from_script.connect (on_message_from_script);
		}

		public bool is_detached () {
			return close_request != null;
		}

		public async void detach () {
			yield _do_close (SessionDetachReason.APPLICATION_REQUESTED, null, true);
		}

		public void detach_sync () {
			try {
				(create<DetachTask> () as DetachTask).start_and_wait_for_completion ();
			} catch (Error e) {
				assert_not_reached ();
			}
		}

		private class DetachTask : SessionTask<void> {
			protected override async void perform_operation () throws Error {
				yield parent.detach ();
			}
		}

		public async void enable_child_gating () throws Error {
			check_open ();

			try {
				yield session.enable_child_gating ();
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public void enable_child_gating_sync () throws Error {
			(create<EnableChildGatingTask> () as EnableChildGatingTask).start_and_wait_for_completion ();
		}

		private class EnableChildGatingTask : SessionTask<void> {
			protected override async void perform_operation () throws Error {
				yield parent.enable_child_gating ();
			}
		}

		public async void disable_child_gating () throws Error {
			check_open ();

			try {
				yield session.disable_child_gating ();
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public void disable_child_gating_sync () throws Error {
			(create<DisableChildGatingTask> () as DisableChildGatingTask).start_and_wait_for_completion ();
		}

		private class DisableChildGatingTask : SessionTask<void> {
			protected override async void perform_operation () throws Error {
				yield parent.disable_child_gating ();
			}
		}

		public async Script create_script (string? name, string source) throws Error {
			check_open ();

			AgentScriptId script_id;
			try {
				script_id = yield session.create_script ((name == null) ? "" : name, source);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}

			check_open ();

			var script = new Script (this, script_id);
			scripts[script_id] = script;

			return script;
		}

		public Script create_script_sync (string? name, string source) throws Error {
			var task = create<CreateScriptTask> () as CreateScriptTask;
			task.name = name;
			task.source = source;
			return task.start_and_wait_for_completion ();
		}

		private class CreateScriptTask : SessionTask<Script> {
			public string? name;
			public string source;

			protected override async Script perform_operation () throws Error {
				return yield parent.create_script (name, source);
			}
		}

		public async Script create_script_from_bytes (Bytes bytes) throws Error {
			check_open ();

			AgentScriptId script_id;
			try {
				script_id = yield session.create_script_from_bytes (bytes.get_data ());
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}

			check_open ();

			var script = new Script (this, script_id);
			scripts[script_id] = script;

			return script;
		}

		public Script create_script_from_bytes_sync (Bytes bytes) throws Error {
			var task = create<CreateScriptFromBytesTask> () as CreateScriptFromBytesTask;
			task.bytes = bytes;
			return task.start_and_wait_for_completion ();
		}

		private class CreateScriptFromBytesTask : SessionTask<Script> {
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

		private class CompileScriptTask : SessionTask<Bytes> {
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

			debugger = new Debugger (port, session);
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

		private class EnableScriptDebuggerTask : SessionTask<void> {
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

		private class DisableScriptDebuggerTask : SessionTask<void> {
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

		private class EnableJitTask : SessionTask<void> {
			protected override async void perform_operation () throws Error {
				yield parent.enable_jit ();
			}
		}

		private void on_message_from_script (AgentScriptId script_id, string message, bool has_data, uint8[] data) {
			var script = scripts[script_id];
			if (script != null)
				script.message (message, has_data ? new Bytes (data) : null);
		}

		public void _release_script (AgentScriptId script_id) {
			var script_did_exist = scripts.unset (script_id);
			assert (script_did_exist);
		}

		private void check_open () throws Error {
			if (close_request != null)
				throw new Error.INVALID_OPERATION ("Session is detached");
		}

		public async void _do_close (SessionDetachReason reason, string? crash_report, bool may_block) {
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

			foreach (var script in scripts.values.to_array ())
				yield script._do_close (may_block);

			if (may_block)
				session.close.begin ();
			session.message_from_script.disconnect (on_message_from_script);

			yield device._release_session (this, may_block);

			detached (reason, crash_report);
			close_request.set_value (true);
		}

		private Object create<T> () {
			return Object.new (typeof (T), main_context: main_context, parent: this);
		}

		private abstract class SessionTask<T> : AsyncTask<T> {
			public weak Session parent {
				get;
				construct;
			}
		}
	}

	public class Script : Object {
		public signal void destroyed ();
		public signal void message (string message, Bytes? data);

		public uint id {
			get;
			construct;
		}

		public weak Session session {
			get;
			construct;
		}

		public MainContext main_context {
			get;
			construct;
		}

		private Gee.Promise<bool> close_request;

		public Script (Session session, AgentScriptId script_id) {
			Object (
				id: script_id.handle,
				session: session,
				main_context: session.main_context
			);
		}

		public bool is_destroyed () {
			return close_request != null;
		}

		public async void load () throws Error {
			check_open ();

			try {
				yield session.session.load_script (AgentScriptId (id));
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

		public async void eternalize () throws Error {
			check_open ();

			try {
				yield session.session.eternalize_script (AgentScriptId (id));
				yield _do_close (false);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public void eternalize_sync () throws Error {
			(create<EternalizeTask> () as EternalizeTask).start_and_wait_for_completion ();
		}

		private class EternalizeTask : ScriptTask<void> {
			protected override async void perform_operation () throws Error {
				yield parent.eternalize ();
			}
		}

		public async void post (string message, Bytes? data = null) throws Error {
			check_open ();

			var has_data = data != null;
			var data_param = has_data ? data.get_data () : new uint8[0];

			try {
				yield session.session.post_to_script (AgentScriptId (id), message, has_data, data_param);
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
			if (close_request != null)
				throw new Error.INVALID_OPERATION ("Script is destroyed");
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

			var parent = session;
			var script_id = AgentScriptId (id);

			parent._release_script (script_id);

			if (may_block) {
				try {
					yield parent.session.destroy_script (script_id);
				} catch (GLib.Error ignored_error) {
				}
			}

			destroyed ();

			close_request.set_value (true);
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

		public abstract async uint demonitor_and_clone_state (uint id) throws Error;

		public uint demonitor_and_clone_state_sync (uint id) throws Error {
			var task = create<DemonitorAndCloneStateTask> () as DemonitorAndCloneStateTask;
			task.id = id;
			return task.start_and_wait_for_completion ();
		}

		private class DemonitorAndCloneStateTask : InjectorTask<uint> {
			public uint id;

			protected override async uint perform_operation () throws Error {
				return yield parent.demonitor_and_clone_state (id);
			}
		}

		public abstract async void recreate_thread (uint pid, uint id) throws Error;

		public void recreate_thread_sync (uint pid, uint id) throws Error {
			var task = create<RecreateThreadTask> () as RecreateThreadTask;
			task.pid = pid;
			task.id = id;
			task.start_and_wait_for_completion ();
		}

		private class RecreateThreadTask : InjectorTask<void> {
			public uint pid;
			public uint id;

			protected override async void perform_operation () throws Error {
				yield parent.recreate_thread (pid, id);
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

			bool collected_everything = Thread.garbage_collect ();

			gc_mutex.lock ();
			bool same_generation = generation == gc_generation;
			bool repeat = !collected_everything || !same_generation;
			if (!repeat)
				gc_scheduled = false;
			gc_mutex.unlock ();

			return repeat;
		});
	}
}
