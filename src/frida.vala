namespace Frida {
	public extern void init ();
	public extern void init_with_runtime (Runtime runtime);
	public extern void shutdown ();
	public extern void deinit ();
	public extern unowned MainContext get_main_context ();

	public extern void unref (void * obj);

	public extern void version (out uint major, out uint minor, out uint micro, out uint nano);
	public extern unowned string version_string ();

	public enum Runtime {
		GLIB,
		OTHER;

		public string to_nick () {
			return Marshal.enum_to_nick<Runtime> (this);
		}
	}

	public class DeviceManager : Object {
		public signal void added (Device device);
		public signal void removed (Device device);
		public signal void changed ();

		public delegate bool Predicate (Device device);

		private Promise<bool> start_request;
		private Promise<bool> stop_request;

		private HostSessionService service = null;
		private Gee.ArrayList<Device> devices = new Gee.ArrayList<Device> ();
		private Gee.ArrayList<DeviceObserverEntry> on_device_added = new Gee.ArrayList<DeviceObserverEntry> ();

		private Cancellable io_cancellable = new Cancellable ();

		public async void close (Cancellable? cancellable = null) throws IOError {
			yield stop_service (cancellable);
		}

		public void close_sync (Cancellable? cancellable = null) throws IOError {
			try {
				create<CloseTask> ().execute (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}
		}

		private class CloseTask : ManagerTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.close (cancellable);
			}
		}

		public async Device get_device_by_id (string id, int timeout = 0, Cancellable? cancellable = null) throws Error, IOError {
			return check_device (yield find_device_by_id (id, timeout, cancellable));
		}

		public Device get_device_by_id_sync (string id, int timeout = 0, Cancellable? cancellable = null) throws Error, IOError {
			return check_device (find_device_by_id_sync (id, timeout, cancellable));
		}

		public async Device get_device_by_type (DeviceType type, int timeout = 0, Cancellable? cancellable = null)
				throws Error, IOError {
			return check_device (yield find_device_by_type (type, timeout, cancellable));
		}

		public Device get_device_by_type_sync (DeviceType type, int timeout = 0, Cancellable? cancellable = null)
				throws Error, IOError {
			return check_device (find_device_by_type_sync (type, timeout, cancellable));
		}

		public async Device get_device (Predicate predicate, int timeout = 0, Cancellable? cancellable = null)
				throws Error, IOError {
			return check_device (yield find_device (predicate, timeout, cancellable));
		}

		public Device get_device_sync (Predicate predicate, int timeout = 0, Cancellable? cancellable = null)
				throws Error, IOError {
			return check_device (find_device_sync (predicate, timeout, cancellable));
		}

		private Device check_device (Device? device) throws Error {
			if (device == null)
				throw new Error.INVALID_ARGUMENT ("Device not found");
			return device;
		}

		public async Device? find_device_by_id (string id, int timeout = 0, Cancellable? cancellable = null) throws Error, IOError {
			return yield find_device ((device) => { return device.id == id; }, timeout, cancellable);
		}

		public Device? find_device_by_id_sync (string id, int timeout = 0, Cancellable? cancellable = null) throws Error, IOError {
			return find_device_sync ((device) => { return device.id == id; }, timeout, cancellable);
		}

		public async Device? find_device_by_type (DeviceType type, int timeout = 0, Cancellable? cancellable = null)
				throws Error, IOError {
			return yield find_device ((device) => { return device.dtype == type; }, timeout, cancellable);
		}

		public Device? find_device_by_type_sync (DeviceType type, int timeout = 0, Cancellable? cancellable = null)
				throws Error, IOError {
			return find_device_sync ((device) => { return device.dtype == type; }, timeout, cancellable);
		}

		public async Device? find_device (Predicate predicate, int timeout = 0, Cancellable? cancellable = null)
				throws Error, IOError {
			check_open ();

			foreach (var device in devices) {
				if (predicate (device))
					return device;
			}

			bool started = start_request != null && start_request.future.ready;
			if (started && timeout == 0)
				return null;

			Device? added_device = null;
			var addition_observer = new DeviceObserverEntry ((device) => {
				if (predicate (device)) {
					added_device = device;
					find_device.callback ();
				}
			});
			on_device_added.add (addition_observer);

			Source? timeout_source = null;
			if (timeout > 0) {
				timeout_source = new TimeoutSource (timeout);
				timeout_source.set_callback (find_device.callback);
				timeout_source.attach (MainContext.get_thread_default ());
			}

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (find_device.callback);
			cancel_source.attach (MainContext.get_thread_default ());

			bool waiting = false;

			if (!started) {
				ensure_service_and_then_call.begin (() => {
						if (waiting && timeout == 0)
							find_device.callback ();
						return false;
					}, io_cancellable);
			}

			waiting = true;
			yield;
			waiting = false;

			cancel_source.destroy ();

			if (timeout_source != null)
				timeout_source.destroy ();

			on_device_added.remove (addition_observer);

			return added_device;
		}

		public Device? find_device_sync (Predicate predicate, int timeout = 0, Cancellable? cancellable = null)
				throws Error, IOError {
			var task = create<FindDeviceTask> () as FindDeviceTask;
			task.predicate = (device) => {
				return predicate (device);
			};
			task.timeout = timeout;
			return task.execute (cancellable);
		}

		private class FindDeviceTask : ManagerTask<Device?> {
			public Predicate predicate;
			public int timeout;

			protected override async Device? perform_operation () throws Error, IOError {
				return yield parent.find_device (predicate, timeout, cancellable);
			}
		}

		public async DeviceList enumerate_devices (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			yield ensure_service (cancellable);

			return new DeviceList (devices.slice (0, devices.size));
		}

		public DeviceList enumerate_devices_sync (Cancellable? cancellable = null) throws Error, IOError {
			return create<EnumerateDevicesTask> ().execute (cancellable);
		}

		private class EnumerateDevicesTask : ManagerTask<DeviceList> {
			protected override async DeviceList perform_operation () throws Error, IOError {
				return yield parent.enumerate_devices (cancellable);
			}
		}

		public async Device add_remote_device (string address, RemoteDeviceOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var socket_device = yield get_device ((device) => {
					return device.provider is SocketHostSessionProvider;
				}, 0, cancellable);

			string id = "socket@" + address;

			foreach (var device in devices) {
				if (device.id == id)
					return device;
			}

			unowned string name = address;

			var raw_options = new HostSessionOptions ();
			var opts = raw_options.map;
			opts["address"] = address;
			if (options != null) {
				TlsCertificate? cert = options.certificate;
				if (cert != null)
					opts["certificate"] = cert;

				string? token = options.token;
				if (token != null)
					opts["token"] = token;
			}

			var device = new Device (this, id, name, HostSessionProviderKind.REMOTE, socket_device.provider, raw_options);
			devices.add (device);
			added (device);
			changed ();

			return device;
		}

		public Device add_remote_device_sync (string address, RemoteDeviceOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			var task = create<AddRemoteDeviceTask> ();
			task.address = address;
			task.options = options;
			return task.execute (cancellable);
		}

		private class AddRemoteDeviceTask : ManagerTask<Device> {
			public string address;
			public RemoteDeviceOptions? options;

			protected override async Device perform_operation () throws Error, IOError {
				return yield parent.add_remote_device (address, options, cancellable);
			}
		}

		public async void remove_remote_device (string address, Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			yield ensure_service (cancellable);

			string id = "socket@" + address;

			foreach (var device in devices) {
				if (device.id == id) {
					yield device._do_close (APPLICATION_REQUESTED, true, cancellable);
					removed (device);
					changed ();
					return;
				}
			}

			throw new Error.INVALID_ARGUMENT ("Device not found");
		}

		public void remove_remote_device_sync (string address, Cancellable? cancellable = null) throws Error, IOError {
			var task = create<RemoveRemoteDeviceTask> ();
			task.address = address;
			task.execute (cancellable);
		}

		private class RemoveRemoteDeviceTask : ManagerTask<void> {
			public string address;

			protected override async void perform_operation () throws Error, IOError {
				yield parent.remove_remote_device (address, cancellable);
			}
		}

		public void _release_device (Device device) {
			var device_did_exist = devices.remove (device);
			assert (device_did_exist);
		}

		private async void ensure_service (Cancellable? cancellable) throws Error, IOError {
			if (start_request == null) {
				start_request = new Promise<bool> ();
				start_service.begin ();
			}

			try {
				yield start_request.future.wait_async (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			} catch (IOError e) {
				cancellable.set_error_if_cancelled ();
				throw new Error.INVALID_OPERATION ("DeviceManager is closing");
			}
		}

		private async void ensure_service_and_then_call (owned SourceFunc callback, Cancellable cancellable) {
			var source = new IdleSource ();
			source.set_callback (ensure_service_and_then_call.callback);
			source.attach (MainContext.get_thread_default ());
			yield;

			try {
				yield ensure_service (cancellable);
			} catch (GLib.Error e) {
			}

			callback ();
		}

		private async void start_service () {
			service = new HostSessionService.with_default_backends ();
			try {
				service.provider_available.connect (on_provider_available);
				service.provider_unavailable.connect (on_provider_unavailable);

				yield service.start (io_cancellable);

				start_request.resolve (true);
			} catch (IOError e) {
				service.provider_available.disconnect (on_provider_available);
				service.provider_unavailable.disconnect (on_provider_unavailable);
				service = null;

				start_request.reject (e);
				start_request = null;
			}
		}

		private void on_provider_available (HostSessionProvider provider) {
			var device = new Device (this, provider.id, provider.name, provider.kind, provider);
			devices.add (device);

			foreach (var observer in on_device_added.to_array ())
				observer.func (device);

			var started = start_request.future.ready;
			if (started) {
				added (device);
				changed ();
			}
		}

		private void on_provider_unavailable (HostSessionProvider provider) {
			var started = start_request.future.ready;

			foreach (var device in devices) {
				if (device.provider == provider) {
					if (started)
						removed (device);
					device._do_close.begin (DEVICE_LOST, false, io_cancellable);
					break;
				}
			}

			if (started)
				changed ();
		}

		private void check_open () throws Error {
			if (stop_request != null)
				throw new Error.INVALID_OPERATION ("Device manager is closed");
		}

		private async void stop_service (Cancellable? cancellable) throws IOError {
			while (stop_request != null) {
				try {
					yield stop_request.future.wait_async (cancellable);
					return;
				} catch (GLib.Error e) {
					assert (e is IOError.CANCELLED);
					cancellable.set_error_if_cancelled ();
				}
			}
			stop_request = new Promise<bool> ();

			io_cancellable.cancel ();

			try {
				if (start_request != null) {
					try {
						yield ensure_service (cancellable);
					} catch (GLib.Error e) {
						cancellable.set_error_if_cancelled ();
					}
				}

				foreach (var device in devices.to_array ())
					yield device._do_close (APPLICATION_REQUESTED, true, cancellable);
				devices.clear ();

				if (service != null) {
					yield service.stop (cancellable);
					service.provider_available.disconnect (on_provider_available);
					service.provider_unavailable.disconnect (on_provider_unavailable);
					service = null;
				}

				stop_request.resolve (true);
			} catch (IOError e) {
				stop_request.reject (e);
				stop_request = null;
				throw e;
			}
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		private abstract class ManagerTask<T> : AsyncTask<T> {
			public weak DeviceManager parent {
				get;
				construct;
			}
		}

		private delegate void DeviceObserverFunc (Device device);

		private class DeviceObserverEntry {
			public DeviceObserverFunc func;

			public DeviceObserverEntry (owned DeviceObserverFunc func) {
				this.func = (owned) func;
			}
		}
	}

	public class DeviceList : Object {
		private Gee.List<Device> items;

		internal DeviceList (Gee.List<Device> items) {
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
		public signal void process_crashed (Crash crash);
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

		public weak DeviceManager? manager {
			get;
			construct;
		}

		public delegate bool ProcessPredicate (Process process);

		private HostSessionOptions? host_session_options;
		private Promise<HostSession>? host_session_request;
		private Promise<bool>? close_request;

		internal HostSession? current_host_session;
		private Gee.HashMap<AgentSessionId?, Session> agent_sessions =
			new Gee.HashMap<AgentSessionId?, Session> (AgentSessionId.hash, AgentSessionId.equal);
		private Gee.HashSet<Promise<Session>> pending_attach_requests = new Gee.HashSet<Promise<Session>> ();
		private Gee.HashMap<AgentSessionId?, Promise<bool>> pending_detach_requests =
			new Gee.HashMap<AgentSessionId?, Promise<bool>> (AgentSessionId.hash, AgentSessionId.equal);

		internal Device (DeviceManager? manager, string id, string name, HostSessionProviderKind kind, HostSessionProvider provider,
				HostSessionOptions? options = null) {
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
				manager: manager
			);

			host_session_options = options;
		}

		construct {
			provider.host_session_detached.connect (on_host_session_detached);
			provider.agent_session_detached.connect (on_agent_session_detached);
		}

		public bool is_lost () {
			return close_request != null;
		}

		public async Application? get_frontmost_application (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var host_session = yield get_host_session (cancellable);

			try {
				var app = yield host_session.get_frontmost_application (cancellable);

				if (app.pid == 0)
					return null;

				return new Application (
					app.identifier,
					app.name,
					app.pid,
					Icon.from_image_data (app.small_icon),
					Icon.from_image_data (app.large_icon));
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public Application? get_frontmost_application_sync (Cancellable? cancellable = null) throws Error, IOError {
			return create<GetFrontmostApplicationTask> ().execute (cancellable);
		}

		private class GetFrontmostApplicationTask : DeviceTask<Application?> {
			protected override async Application? perform_operation () throws Error, IOError {
				return yield parent.get_frontmost_application (cancellable);
			}
		}

		public async ApplicationList enumerate_applications (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var host_session = yield get_host_session (cancellable);

			HostApplicationInfo[] applications;
			try {
				applications = yield host_session.enumerate_applications (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			var result = new Gee.ArrayList<Application> ();
			foreach (var p in applications) {
				result.add (new Application (
					p.identifier,
					p.name,
					p.pid,
					Icon.from_image_data (p.small_icon),
					Icon.from_image_data (p.large_icon)));
			}
			return new ApplicationList (result);
		}

		public ApplicationList enumerate_applications_sync (Cancellable? cancellable = null) throws Error, IOError {
			return create<EnumerateApplicationsTask> ().execute (cancellable);
		}

		private class EnumerateApplicationsTask : DeviceTask<ApplicationList> {
			protected override async ApplicationList perform_operation () throws Error, IOError {
				return yield parent.enumerate_applications (cancellable);
			}
		}

		public async Process get_process_by_pid (uint pid, Cancellable? cancellable = null) throws Error, IOError {
			return check_process (yield find_process_by_pid (pid, cancellable));
		}

		public Process get_process_by_pid_sync (uint pid, Cancellable? cancellable = null) throws Error, IOError {
			return check_process (find_process_by_pid_sync (pid, cancellable));
		}

		public async Process get_process_by_name (string name, int timeout = 0, Cancellable? cancellable = null)
				throws Error, IOError {
			return check_process (yield find_process_by_name (name, timeout, cancellable));
		}

		public Process get_process_by_name_sync (string name, int timeout = 0, Cancellable? cancellable = null)
				throws Error, IOError {
			return check_process (find_process_by_name_sync (name, timeout, cancellable));
		}

		public async Process get_process (ProcessPredicate predicate, int timeout = 0, Cancellable? cancellable = null)
				throws Error, IOError {
			return check_process (yield find_process (predicate, timeout, cancellable));
		}

		public Process get_process_sync (ProcessPredicate predicate, int timeout = 0, Cancellable? cancellable = null)
				throws Error, IOError {
			return check_process (find_process_sync (predicate, timeout, cancellable));
		}

		private Process check_process (Process? process) throws Error {
			if (process == null)
				throw new Error.INVALID_ARGUMENT ("Process not found");
			return process;
		}

		public async Process? find_process_by_pid (uint pid, Cancellable? cancellable = null) throws Error, IOError {
			return yield find_process ((process) => { return process.pid == pid; }, 0, cancellable);
		}

		public Process? find_process_by_pid_sync (uint pid, Cancellable? cancellable = null) throws Error, IOError {
			return find_process_sync ((process) => { return process.pid == pid; }, 0, cancellable);
		}

		public async Process? find_process_by_name (string name, int timeout = 0, Cancellable? cancellable = null)
				throws Error, IOError {
			var folded_name = name.casefold ();
			return yield find_process ((process) => { return process.name.casefold () == folded_name; }, timeout, cancellable);
		}

		public Process? find_process_by_name_sync (string name, int timeout = 0, Cancellable? cancellable = null)
				throws Error, IOError {
			var folded_name = name.casefold ();
			return find_process_sync ((process) => { return process.name.casefold () == folded_name; }, timeout, cancellable);
		}

		public async Process? find_process (ProcessPredicate predicate, int timeout = 0, Cancellable? cancellable = null)
				throws Error, IOError {
			Process? process = null;
			bool done = false;
			bool waiting = false;
			var main_context = MainContext.get_thread_default ();

			Source? timeout_source = null;
			if (timeout > 0) {
				timeout_source = new TimeoutSource (timeout);
				timeout_source.set_callback (() => {
					done = true;
					if (waiting)
						find_process.callback ();
					return false;
				});
				timeout_source.attach (main_context);
			}

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (() => {
				done = true;
				if (waiting)
					find_process.callback ();
				return false;
			});
			cancel_source.attach (MainContext.get_thread_default ());

			try {
				while (!done) {
					var processes = yield enumerate_processes (cancellable);

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

					var delay_source = new TimeoutSource (500);
					delay_source.set_callback (find_process.callback);
					delay_source.attach (main_context);

					waiting = true;
					yield;
					waiting = false;

					delay_source.destroy ();
				}
			} finally {
				cancel_source.destroy ();

				if (timeout_source != null)
					timeout_source.destroy ();
			}

			return process;
		}

		public Process? find_process_sync (ProcessPredicate predicate, int timeout = 0, Cancellable? cancellable = null)
				throws Error, IOError {
			var task = create<FindProcessTask> ();
			task.predicate = (process) => {
				return predicate (process);
			};
			task.timeout = timeout;
			return task.execute (cancellable);
		}

		private class FindProcessTask : DeviceTask<Process?> {
			public ProcessPredicate predicate;
			public int timeout;

			protected override async Process? perform_operation () throws Error, IOError {
				return yield parent.find_process (predicate, timeout, cancellable);
			}
		}

		public async ProcessList enumerate_processes (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var host_session = yield get_host_session (cancellable);

			HostProcessInfo[] processes;
			try {
				processes = yield host_session.enumerate_processes (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			var result = new Gee.ArrayList<Process> ();
			foreach (var p in processes) {
				result.add (new Process (
					p.pid,
					p.name,
					Icon.from_image_data (p.small_icon),
					Icon.from_image_data (p.large_icon)));
			}
			return new ProcessList (result);
		}

		public ProcessList enumerate_processes_sync (Cancellable? cancellable = null) throws Error, IOError {
			return create<EnumerateProcessesTask> ().execute (cancellable);
		}

		private class EnumerateProcessesTask : DeviceTask<ProcessList> {
			protected override async ProcessList perform_operation () throws Error, IOError {
				return yield parent.enumerate_processes (cancellable);
			}
		}

		private static Icon? icon_from_image (Image? image) {
			if (image == null)
				return null;
			return Icon.from_image_data (image.data);
		}

		public async void enable_spawn_gating (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var host_session = yield get_host_session (cancellable);

			try {
				yield host_session.enable_spawn_gating (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public void enable_spawn_gating_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<EnableSpawnGatingTask> ().execute (cancellable);
		}

		private class EnableSpawnGatingTask : DeviceTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.enable_spawn_gating (cancellable);
			}
		}

		public async void disable_spawn_gating (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var host_session = yield get_host_session (cancellable);

			try {
				yield host_session.disable_spawn_gating (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public void disable_spawn_gating_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<DisableSpawnGatingTask> ().execute (cancellable);
		}

		private class DisableSpawnGatingTask : DeviceTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.disable_spawn_gating (cancellable);
			}
		}

		public async SpawnList enumerate_pending_spawn (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var host_session = yield get_host_session (cancellable);

			HostSpawnInfo[] pending_spawn;
			try {
				pending_spawn = yield host_session.enumerate_pending_spawn (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			var result = new Gee.ArrayList<Spawn> ();
			foreach (var p in pending_spawn)
				result.add (Spawn.from_info (p));
			return new SpawnList (result);
		}

		public SpawnList enumerate_pending_spawn_sync (Cancellable? cancellable = null) throws Error, IOError {
			return create<EnumeratePendingSpawnTask> ().execute (cancellable);
		}

		private class EnumeratePendingSpawnTask : DeviceTask<SpawnList> {
			protected override async SpawnList perform_operation () throws Error, IOError {
				return yield parent.enumerate_pending_spawn (cancellable);
			}
		}

		public async ChildList enumerate_pending_children (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var host_session = yield get_host_session (cancellable);

			HostChildInfo[] pending_children;
			try {
				pending_children = yield host_session.enumerate_pending_children (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			var result = new Gee.ArrayList<Child> ();
			foreach (var p in pending_children)
				result.add (Child.from_info (p));
			return new ChildList (result);
		}

		public ChildList enumerate_pending_children_sync (Cancellable? cancellable = null) throws Error, IOError {
			return create<EnumeratePendingChildrenTask> ().execute (cancellable);
		}

		private class EnumeratePendingChildrenTask : DeviceTask<ChildList> {
			protected override async ChildList perform_operation () throws Error, IOError {
				return yield parent.enumerate_pending_children (cancellable);
			}
		}

		public async uint spawn (string program, SpawnOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
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

			var host_session = yield get_host_session (cancellable);

			uint pid;
			try {
				pid = yield host_session.spawn (program, raw_options, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			return pid;
		}

		public uint spawn_sync (string program, SpawnOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			var task = create<SpawnTask> ();
			task.program = program;
			task.options = options;
			return task.execute (cancellable);
		}

		private class SpawnTask : DeviceTask<uint> {
			public string program;
			public SpawnOptions? options;

			protected override async uint perform_operation () throws Error, IOError {
				return yield parent.spawn (program, options, cancellable);
			}
		}

		public async void input (uint pid, Bytes data, Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var host_session = yield get_host_session (cancellable);

			try {
				yield host_session.input (pid, data.get_data (), cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public void input_sync (uint pid, Bytes data, Cancellable? cancellable = null) throws Error, IOError {
			var task = create<InputTask> ();
			task.pid = pid;
			task.data = data;
			task.execute (cancellable);
		}

		private class InputTask : DeviceTask<void> {
			public uint pid;
			public Bytes data;

			protected override async void perform_operation () throws Error, IOError {
				yield parent.input (pid, data, cancellable);
			}
		}

		public async void resume (uint pid, Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var host_session = yield get_host_session (cancellable);

			try {
				yield host_session.resume (pid, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public void resume_sync (uint pid, Cancellable? cancellable = null) throws Error, IOError {
			var task = create<ResumeTask> ();
			task.pid = pid;
			task.execute (cancellable);
		}

		private class ResumeTask : DeviceTask<void> {
			public uint pid;

			protected override async void perform_operation () throws Error, IOError {
				yield parent.resume (pid, cancellable);
			}
		}

		public async void kill (uint pid, Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var host_session = yield get_host_session (cancellable);

			try {
				yield host_session.kill (pid, cancellable);
			} catch (GLib.Error e) {
				/* The process being killed might be the other end of the connection. */
				if (!(e is IOError.CLOSED))
					throw_dbus_error (e);
			}
		}

		public void kill_sync (uint pid, Cancellable? cancellable = null) throws Error, IOError {
			var task = create<KillTask> ();
			task.pid = pid;
			task.execute (cancellable);
		}

		private class KillTask : DeviceTask<void> {
			public uint pid;

			protected override async void perform_operation () throws Error, IOError {
				yield parent.kill (pid, cancellable);
			}
		}

		public async Session attach (uint pid, SessionOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			SessionOptions opts = (options != null) ? options : new SessionOptions ();

			var attach_request = new Promise<Session> ();
			pending_attach_requests.add (attach_request);

			Session session = null;
			try {
				var host_session = yield get_host_session (cancellable);

				var raw_options = AgentSessionOptions ();
				raw_options.data = opts._serialize ().get_data ();

				AgentSessionId id;
				try {
					id = yield host_session.attach (pid, raw_options, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}

				try {
					session = new Session (this, pid, id, opts);
					session.active_session = yield provider.link_agent_session (host_session, id, session, cancellable);
					agent_sessions[id] = session;

					attach_request.resolve (session);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
			} catch (Error e) {
				attach_request.reject (e);
				throw e;
			} catch (IOError e) {
				attach_request.reject (e);
				throw e;
			} finally {
				pending_attach_requests.remove (attach_request);
			}

			return session;
		}

		public Session attach_sync (uint pid, SessionOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			var task = create<AttachTask> ();
			task.pid = pid;
			task.options = options;
			return task.execute (cancellable);
		}

		private class AttachTask : DeviceTask<Session> {
			public uint pid;
			public SessionOptions? options;

			protected override async Session perform_operation () throws Error, IOError {
				return yield parent.attach (pid, options, cancellable);
			}
		}

		public async uint inject_library_file (uint pid, string path, string entrypoint, string data,
				Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var host_session = yield get_host_session (cancellable);

			try {
				var id = yield host_session.inject_library_file (pid, path, entrypoint, data, cancellable);

				return id.handle;
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public uint inject_library_file_sync (uint pid, string path, string entrypoint, string data,
				Cancellable? cancellable = null) throws Error, IOError {
			var task = create<InjectLibraryFileTask> ();
			task.pid = pid;
			task.path = path;
			task.entrypoint = entrypoint;
			task.data = data;
			return task.execute (cancellable);
		}

		private class InjectLibraryFileTask : DeviceTask<uint> {
			public uint pid;
			public string path;
			public string entrypoint;
			public string data;

			protected override async uint perform_operation () throws Error, IOError {
				return yield parent.inject_library_file (pid, path, entrypoint, data, cancellable);
			}
		}

		public async uint inject_library_blob (uint pid, Bytes blob, string entrypoint, string data,
				Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var host_session = yield get_host_session (cancellable);

			try {
				var id = yield host_session.inject_library_blob (pid, blob.get_data (), entrypoint, data, cancellable);

				return id.handle;
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public uint inject_library_blob_sync (uint pid, Bytes blob, string entrypoint, string data, Cancellable? cancellable = null)
				throws Error, IOError {
			var task = create<InjectLibraryBlobTask> ();
			task.pid = pid;
			task.blob = blob;
			task.entrypoint = entrypoint;
			task.data = data;
			return task.execute (cancellable);
		}

		private class InjectLibraryBlobTask : DeviceTask<uint> {
			public uint pid;
			public Bytes blob;
			public string entrypoint;
			public string data;

			protected override async uint perform_operation () throws Error, IOError {
				return yield parent.inject_library_blob (pid, blob, entrypoint, data, cancellable);
			}
		}

		public async IOStream open_channel (string address, Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var channel_provider = provider as ChannelProvider;
			if (channel_provider == null)
				throw new Error.NOT_SUPPORTED ("Channels are not supported by this device");

			return yield channel_provider.open_channel (address, cancellable);
		}

		public IOStream open_channel_sync (string address, Cancellable? cancellable = null) throws Error, IOError {
			var task = create<OpenChannelTask> ();
			task.address = address;
			return task.execute (cancellable);
		}

		private class OpenChannelTask : DeviceTask<IOStream> {
			public string address;

			protected override async IOStream perform_operation () throws Error, IOError {
				return yield parent.open_channel (address, cancellable);
			}
		}

		public async Bus get_bus (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var host_session = yield get_host_session (cancellable);

			DBusProxy proxy = host_session as DBusProxy;
			if (proxy == null)
				throw new Error.NOT_SUPPORTED ("Bus is not available on this device");

			BusSession session;
			try {
				session = yield proxy.g_connection.get_proxy (null, ObjectPath.BUS_SESSION, DO_NOT_LOAD_PROPERTIES,
					cancellable);
			} catch (IOError e) {
				throw_dbus_error (e);
			}

			return new Bus (session);
		}

		public Bus get_bus_sync (Cancellable? cancellable = null) throws Error, IOError {
			return create<GetBusTask> ().execute (cancellable);
		}

		private class GetBusTask : DeviceTask<Bus> {
			protected override async Bus perform_operation () throws Error, IOError {
				return yield parent.get_bus (cancellable);
			}
		}

		private void check_open () throws Error {
			if (close_request != null)
				throw new Error.INVALID_OPERATION ("Device is gone");
		}

		public async HostSession get_host_session (Cancellable? cancellable) throws Error, IOError {
			while (host_session_request != null) {
				try {
					return yield host_session_request.future.wait_async (cancellable);
				} catch (Error e) {
					throw e;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}
			host_session_request = new Promise<HostSession> ();

			try {
				var session = yield provider.create (host_session_options, cancellable);
				attach_host_session (session);

				current_host_session = session;
				host_session_request.resolve (session);

				return session;
			} catch (GLib.Error e) {
				host_session_request.reject (e);
				host_session_request = null;

				throw_api_error (e);
			}
		}

		public HostSession get_host_session_sync (Cancellable? cancellable = null) throws Error, IOError {
			return create<GetHostSessionTask> ().execute (cancellable);
		}

		private class GetHostSessionTask : DeviceTask<HostSession> {
			protected override async HostSession perform_operation () throws Error, IOError {
				return yield parent.get_host_session (cancellable);
			}
		}

		private void on_host_session_detached (HostSession session) {
			if (session != current_host_session)
				return;

			detach_host_session (session);

			current_host_session = null;
			host_session_request = null;
		}

		private void attach_host_session (HostSession session) {
			session.spawn_added.connect (on_spawn_added);
			session.spawn_removed.connect (on_spawn_removed);
			session.child_added.connect (on_child_added);
			session.child_removed.connect (on_child_removed);
			session.process_crashed.connect (on_process_crashed);
			session.output.connect (on_output);
			session.uninjected.connect (on_uninjected);
		}

		private void detach_host_session (HostSession session) {
			session.spawn_added.disconnect (on_spawn_added);
			session.spawn_removed.disconnect (on_spawn_removed);
			session.child_added.disconnect (on_child_added);
			session.child_removed.disconnect (on_child_removed);
			session.process_crashed.disconnect (on_process_crashed);
			session.output.disconnect (on_output);
			session.uninjected.disconnect (on_uninjected);
		}

		internal async void _do_close (SessionDetachReason reason, bool may_block, Cancellable? cancellable) throws IOError {
			while (close_request != null) {
				try {
					yield close_request.future.wait_async (cancellable);
					return;
				} catch (GLib.Error e) {
					assert (e is IOError.CANCELLED);
					cancellable.set_error_if_cancelled ();
				}
			}
			close_request = new Promise<bool> ();

			try {
				while (!pending_detach_requests.is_empty) {
					var iterator = pending_detach_requests.entries.iterator ();
					iterator.next ();
					var entry = iterator.get ();

					var session_id = entry.key;
					var detach_request = entry.value;

					detach_request.resolve (true);
					pending_detach_requests.unset (session_id);
				}

				while (!pending_attach_requests.is_empty) {
					var iterator = pending_attach_requests.iterator ();
					iterator.next ();
					var attach_request = iterator.get ();
					try {
						yield attach_request.future.wait_async (cancellable);
					} catch (GLib.Error e) {
						cancellable.set_error_if_cancelled ();
					}
				}

				if (host_session_request != null) {
					try {
						yield get_host_session (cancellable);
					} catch (Error e) {
					}
				}

				var no_crash = CrashInfo.empty ();
				foreach (var session in agent_sessions.values.to_array ())
					yield session._do_close (reason, no_crash, may_block, cancellable);
				agent_sessions.clear ();

				provider.host_session_detached.disconnect (on_host_session_detached);
				provider.agent_session_detached.disconnect (on_agent_session_detached);

				if (current_host_session != null) {
					detach_host_session (current_host_session);

					if (may_block) {
						try {
							yield provider.destroy (current_host_session, cancellable);
						} catch (Error e) {
						}
					}

					current_host_session = null;
					host_session_request = null;
				}

				if (manager != null)
					manager._release_device (this);

				lost ();

				close_request.resolve (true);
			} catch (IOError e) {
				close_request.reject (e);
				close_request = null;
				throw e;
			}
		}

		public async void _release_session (Session session, bool may_block, Cancellable? cancellable) throws IOError {
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
				var detach_request = new Promise<bool> ();

				pending_detach_requests[session_id] = detach_request;

				try {
					yield detach_request.future.wait_async (cancellable);
				} catch (Error e) {
					assert_not_reached ();
				}
			}
		}

		private void on_agent_session_detached (AgentSessionId id, SessionDetachReason reason, CrashInfo crash) {
			var session = agent_sessions[id];
			if (session != null)
				session._on_detached (reason, crash);

			Promise<bool> detach_request;
			if (pending_detach_requests.unset (id, out detach_request))
				detach_request.resolve (true);
		}

		private void on_spawn_added (HostSpawnInfo info) {
			spawn_added (Spawn.from_info (info));
		}

		private void on_spawn_removed (HostSpawnInfo info) {
			spawn_removed (Spawn.from_info (info));
		}

		private void on_child_added (HostChildInfo info) {
			child_added (Child.from_info (info));
		}

		private void on_child_removed (HostChildInfo info) {
			child_removed (Child.from_info (info));
		}

		private void on_process_crashed (CrashInfo info) {
			process_crashed (Crash.from_info (info));
		}

		private void on_output (uint pid, int fd, uint8[] data) {
			output (pid, fd, new Bytes (data));
		}

		private void on_uninjected (InjectorPayloadId id) {
			uninjected (id.handle);
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
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
		USB;

		public string to_nick () {
			return Marshal.enum_to_nick<DeviceType> (this);
		}
	}

	public class RemoteDeviceOptions : Object {
		public TlsCertificate? certificate {
			get;
			set;
		}

		public string? token {
			get;
			set;
		}
	}

	public class ApplicationList : Object {
		private Gee.List<Application> items;

		internal ApplicationList (Gee.List<Application> items) {
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

		internal Application (string identifier, string name, uint pid, Icon? small_icon, Icon? large_icon) {
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

		internal ProcessList (Gee.List<Process> items) {
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

		internal Process (uint pid, string name, Icon? small_icon, Icon? large_icon) {
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

		internal SpawnList (Gee.List<Spawn> items) {
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

		internal Spawn (uint pid, string? identifier) {
			Object (
				pid: pid,
				identifier: identifier
			);
		}

		internal static Spawn from_info (HostSpawnInfo info) {
			var identifier = info.identifier;
			return new Spawn (info.pid, (identifier.length > 0) ? identifier : null);
		}
	}

	public class ChildList : Object {
		private Gee.List<Child> items;

		internal ChildList (Gee.List<Child> items) {
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

		internal Child (uint pid, uint parent_pid, ChildOrigin origin, string? identifier, string? path, string[]? argv,
				string[]? envp) {
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

		internal static Child from_info (HostChildInfo info) {
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
	}

	public class Crash : Object {
		public uint pid {
			get;
			construct;
		}

		public string process_name {
			get;
			construct;
		}

		public string summary {
			get;
			construct;
		}

		public string report {
			get;
			construct;
		}

		private Bytes raw_parameters;

		internal Crash (uint pid, string process_name, string summary, string report, Bytes raw_parameters) {
			Object (
				pid: pid,
				process_name: process_name,
				summary: summary,
				report: report
			);
			this.raw_parameters = raw_parameters;
		}

		public VariantDict load_parameters () {
			return new VariantDict (new Variant.from_bytes (VariantType.VARDICT, raw_parameters, false));
		}

		internal static Crash? from_info (CrashInfo info) {
			if (info.pid == 0)
				return null;
			return new Crash (
				info.pid,
				info.process_name,
				info.summary,
				info.report,
				new Bytes (info.parameters)
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

		internal Icon (int width, int height, int rowstride, Bytes pixels) {
			Object (
				width: width,
				height: height,
				rowstride: rowstride,
				pixels: pixels
			);
		}

		internal static Icon? from_image_data (ImageData image) {
			if (image.width == 0)
				return null;
			return new Icon (image.width, image.height, image.rowstride, new Bytes.take (Base64.decode (image.pixels)));
		}

		internal static ImageData to_image_data (Icon? icon) {
			if (icon == null)
				return ImageData.empty ();
			return ImageData (icon.width, icon.height, icon.rowstride, Base64.encode (icon.pixels.get_data ()));
		}
	}

	public class Bus : Object {
		public signal void message (string message, Bytes? data);

		public BusSession session {
			get;
			construct;
		}

		internal Bus (BusSession session) {
			Object (session: session);
		}

		construct {
			session.message.connect (on_message);
		}

		public async void post (string message, Bytes? data = null, Cancellable? cancellable = null) throws Error, IOError {
			var has_data = data != null;
			var data_param = has_data ? data.get_data () : new uint8[0];

			try {
				yield session.post (message, has_data, data_param, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public void post_sync (string message, Bytes? data = null, Cancellable? cancellable = null) throws Error, IOError {
			var task = create<PostTask> ();
			task.message = message;
			task.data = data;
			task.execute (cancellable);
		}

		private class PostTask : BusTask<void> {
			public string message;
			public Bytes? data;

			protected override async void perform_operation () throws Error, IOError {
				yield parent.post (message, data, cancellable);
			}
		}

		private void on_message (string message, bool has_data, uint8[] data) {
			this.message (message, has_data ? new Bytes (data) : null);
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		private abstract class BusTask<T> : AsyncTask<T> {
			public weak Bus parent {
				get;
				construct;
			}
		}
	}

	public class Session : Object, AgentMessageSink {
		public signal void detached (SessionDetachReason reason, Crash? crash);

		public uint pid {
			get;
			construct;
		}

		public AgentSessionId id {
			get;
			construct;
		}

		public AgentSession session {
			get {
				return active_session;
			}
		}

		public uint persist_timeout {
			get;
			construct;
		}

		public weak Device device {
			get;
			construct;
		}

		private State state = ATTACHED;
		private Promise<bool> close_request;

		internal AgentSession active_session;
		private AgentSession? obsolete_session;

		private Gee.HashMap<AgentScriptId?, Script> scripts =
			new Gee.HashMap<AgentScriptId?, Script> (AgentScriptId.hash, AgentScriptId.equal);

		private Debugger? debugger;

		private uint64 last_script_message_serial = 0;
		private uint64 last_debugger_message_serial = 0;

#if HAVE_NICE
		private Nice.Agent? nice_agent;
		private uint nice_stream_id;
		private uint nice_component_id;
		private IOStream? nice_stream;
		private DBusConnection? nice_connection;
		private Cancellable? nice_cancellable;

		private MainContext? dbus_context;
#endif

		private enum State {
			ATTACHED,
			INTERRUPTED,
			DETACHED,
		}

		internal Session (Device device, uint pid, AgentSessionId id, SessionOptions options) {
			Object (
				pid: pid,
				id: id,
				persist_timeout: options.persist_timeout,
				device: device
			);
		}

		public async void detach (Cancellable? cancellable = null) throws IOError {
			yield _do_close (APPLICATION_REQUESTED, CrashInfo.empty (), true, cancellable);
		}

		public void detach_sync (Cancellable? cancellable = null) throws IOError {
			try {
				create<DetachTask> ().execute (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}
		}

		private class DetachTask : SessionTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.detach (cancellable);
			}
		}

		public async void resume (Cancellable? cancellable = null) throws Error, IOError {
			switch (state) {
				case ATTACHED:
					return;
				case INTERRUPTED:
					break;
				case DETACHED:
					throw new Error.INVALID_OPERATION ("Session is gone");
			}

			var host_session = yield device.get_host_session (cancellable);

			try {
				yield host_session.reattach (id, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			var agent_session = yield device.provider.link_agent_session (host_session, id, this, cancellable);

			begin_migration (agent_session);
			commit_migration (agent_session);

			try {
				yield agent_session.resume (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			state = ATTACHED;
		}

		public void resume_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<ResumeTask> ().execute (cancellable);
		}

		private class ResumeTask : SessionTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.resume (cancellable);
			}
		}

		public async void enable_child_gating (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			try {
				yield session.enable_child_gating (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public void enable_child_gating_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<EnableChildGatingTask> ().execute (cancellable);
		}

		private class EnableChildGatingTask : SessionTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.enable_child_gating (cancellable);
			}
		}

		public async void disable_child_gating (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			try {
				yield session.disable_child_gating (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public void disable_child_gating_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<DisableChildGatingTask> ().execute (cancellable);
		}

		private class DisableChildGatingTask : SessionTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.disable_child_gating (cancellable);
			}
		}

		public async Script create_script (string source, ScriptOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			check_open ();

			var raw_options = AgentScriptOptions ();
			if (options != null)
				raw_options.data = options._serialize ().get_data ();

			AgentScriptId script_id;
			try {
				script_id = yield session.create_script (source, raw_options, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			check_open ();

			var script = new Script (this, script_id);
			scripts[script_id] = script;

			return script;
		}

		public Script create_script_sync (string source, ScriptOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			var task = create<CreateScriptTask> ();
			task.source = source;
			task.options = options;
			return task.execute (cancellable);
		}

		private class CreateScriptTask : SessionTask<Script> {
			public string source;
			public ScriptOptions? options;

			protected override async Script perform_operation () throws Error, IOError {
				return yield parent.create_script (source, options, cancellable);
			}
		}

		public async Script create_script_from_bytes (Bytes bytes, ScriptOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			check_open ();

			var raw_options = AgentScriptOptions ();
			if (options != null)
				raw_options.data = options._serialize ().get_data ();

			AgentScriptId script_id;
			try {
				script_id = yield session.create_script_from_bytes (bytes.get_data (), raw_options,
					cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			check_open ();

			var script = new Script (this, script_id);
			scripts[script_id] = script;

			return script;
		}

		public Script create_script_from_bytes_sync (Bytes bytes, ScriptOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			var task = create<CreateScriptFromBytesTask> ();
			task.bytes = bytes;
			task.options = options;
			return task.execute (cancellable);
		}

		private class CreateScriptFromBytesTask : SessionTask<Script> {
			public Bytes bytes;
			public ScriptOptions? options;

			protected override async Script perform_operation () throws Error, IOError {
				return yield parent.create_script_from_bytes (bytes, options, cancellable);
			}
		}

		public async Bytes compile_script (string source, ScriptOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			check_open ();

			var raw_options = AgentScriptOptions ();
			if (options != null)
				raw_options.data = options._serialize ().get_data ();

			uint8[] data;
			try {
				data = yield session.compile_script (source, raw_options, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			return new Bytes (data);
		}

		public Bytes compile_script_sync (string source, ScriptOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			var task = create<CompileScriptTask> ();
			task.source = source;
			task.options = options;
			return task.execute (cancellable);
		}

		private class CompileScriptTask : SessionTask<Bytes> {
			public string source;
			public ScriptOptions? options;

			protected override async Bytes perform_operation () throws Error, IOError {
				return yield parent.compile_script (source, options, cancellable);
			}
		}

		public async void enable_debugger (uint16 port = 0, Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			if (debugger != null)
				throw new Error.INVALID_OPERATION ("Debugger is already enabled");

			debugger = new Debugger (port, session);
			var enabled = false;
			try {
				yield debugger.enable (cancellable);
				enabled = true;
			} finally {
				if (!enabled)
					debugger = null;
			}
		}

		public void enable_debugger_sync (uint16 port = 0, Cancellable? cancellable = null) throws Error, IOError {
			var task = create<EnableScriptDebuggerTask> ();
			task.port = port;
			task.execute (cancellable);
		}

		private class EnableScriptDebuggerTask : SessionTask<void> {
			public uint16 port;

			protected override async void perform_operation () throws Error, IOError {
				yield parent.enable_debugger (port, cancellable);
			}
		}

		public async void disable_debugger (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			if (debugger == null)
				return;

			yield debugger.disable (cancellable);
			debugger = null;
		}

		public void disable_debugger_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<DisableScriptDebuggerTask> ().execute (cancellable);
		}

		private class DisableScriptDebuggerTask : SessionTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.disable_debugger (cancellable);
			}
		}

#if HAVE_NICE
		public async void setup_peer_connection (PeerOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			AgentSession server_session = active_session;

			dbus_context = yield get_dbus_context ();

			var agent = new Nice.Agent.full (dbus_context, Nice.Compatibility.RFC5245, RELIABLE | ICE_TRICKLE);
			agent.controlling_mode = true;

			uint stream_id = agent.add_stream (1);
			if (stream_id == 0)
				throw new Error.NOT_SUPPORTED ("Unable to add stream");
			uint component_id = 1;
			agent.set_stream_name (stream_id, "application");

			if (options != null) {
				string? stun_server = options.stun_server;
				if (stun_server != null) {
					InetSocketAddress? addr;
					try {
						var enumerator = NetworkAddress.parse (stun_server, 3478).enumerate ();
						addr = (InetSocketAddress) yield enumerator.next_async (cancellable);
					} catch (GLib.Error e) {
						throw new Error.INVALID_ARGUMENT ("Invalid STUN server address: %s", e.message);
					}
					if (addr == null)
						throw new Error.INVALID_ARGUMENT ("Invalid STUN server address");
					agent.stun_server = addr.get_address ().to_string ();
					agent.stun_server_port = addr.get_port ();
				}

				var relays = new Gee.ArrayList<Relay> ();
				options.enumerate_relays (relay => {
					relays.add (relay);
				});
				foreach (var relay in relays) {
					InetSocketAddress? addr;
					try {
						var enumerator = NetworkAddress.parse (relay.address, 3478).enumerate ();
						addr = (InetSocketAddress) yield enumerator.next_async (cancellable);
					} catch (GLib.Error e) {
						throw new Error.INVALID_ARGUMENT ("Invalid relay server address: %s", e.message);
					}
					if (addr == null)
						throw new Error.INVALID_ARGUMENT ("Invalid relay server address");
					agent.set_relay_info (stream_id, component_id, addr.get_address ().to_string (),
						addr.get_port (), relay.username, relay.password,
						relay_kind_to_libnice (relay.kind));
				}
			}

			string offer_sdp = agent.generate_local_sdp ();

			var raw_options = AgentPeerOptions ();
			if (options != null)
				raw_options.data = options._serialize ().get_data ();

			// TODO: generate on separate thread
			string cert_pem, key_pem;
			_generate_certificate (out cert_pem, out key_pem);

			TlsCertificate certificate;
			try {
				certificate = new TlsCertificate.from_pem (cert_pem + key_pem, -1);
			} catch (GLib.Error e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}

			IOStream stream = null;
			server_session.new_candidates.connect (on_new_candidates);
			server_session.candidate_gathering_done.connect (on_candidate_gathering_done);
			try {
				string answer_sdp;
				try {
					yield server_session.offer_peer_connection (offer_sdp, raw_options, cert_pem, cancellable,
						out answer_sdp);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}

				if (agent.parse_remote_sdp (answer_sdp) < 0)
					throw new Error.INVALID_ARGUMENT ("Invalid SDP");

				if (nice_agent != null)
					throw new Error.INVALID_OPERATION ("Peer connection already exists");

				nice_agent = agent;
				nice_cancellable = new Cancellable ();
				nice_stream_id = stream_id;
				nice_component_id = component_id;

				var open_request = new Promise<IOStream> ();

				schedule_on_dbus_thread (() => {
					open_peer_connection.begin (server_session, certificate, open_request);
					return false;
				});

				stream = yield open_request.future.wait_async (cancellable);
			} finally {
				server_session.candidate_gathering_done.disconnect (on_candidate_gathering_done);
				server_session.new_candidates.disconnect (on_new_candidates);
			}

			try {
				nice_connection = yield new DBusConnection (stream, null, 0, null, nice_cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
			nice_connection.on_closed.connect (on_nice_connection_closed);

			AgentSession peer_session;
			try {
				peer_session = yield nice_connection.get_proxy (null, ObjectPath.AGENT_SESSION, DO_NOT_LOAD_PROPERTIES,
					nice_cancellable);
			} catch (IOError e) {
				throw_dbus_error (e);
			}

			try {
				yield server_session.begin_migration (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			begin_migration (peer_session);

			try {
				yield server_session.commit_migration (cancellable);
			} catch (GLib.Error e) {
				cancel_migration (peer_session);
				throw_dbus_error (e);
			}
			commit_migration (peer_session);
		}

		private async void teardown_peer_connection (Cancellable? cancellable) {
			DBusConnection? conn = nice_connection;
			if (conn != null) {
				conn.on_closed.disconnect (on_nice_connection_closed);
				nice_connection = null;
				try {
					yield conn.close (cancellable);
				} catch (GLib.Error e) {
				}
			}

			if (nice_agent != null) {
				schedule_on_dbus_thread (() => {
					nice_agent.close_async.begin ();

					schedule_on_frida_thread (() => {
						teardown_peer_connection.callback ();
						return false;
					});

					return false;
				});
				yield;
			}

			nice_component_id = 0;
			nice_stream_id = 0;
			nice_cancellable = null;
			nice_agent = null;
		}

		private async void open_peer_connection (AgentSession server_session, TlsCertificate certificate,
				Promise<IOStream> promise) {
			Nice.Agent agent = nice_agent;
			ulong candidate_handler = 0;
			ulong gathering_handler = 0;
			try {
				agent.component_state_changed.connect (on_component_state_changed);

				var pending_candidates = new Gee.ArrayList<string> ();
				candidate_handler = agent.new_candidate_full.connect (candidate => {
					string candidate_sdp = agent.generate_local_candidate_sdp (candidate);
					pending_candidates.add (candidate_sdp);
					if (pending_candidates.size == 1) {
						schedule_on_dbus_thread (() => {
							var stolen_candidates = pending_candidates;
							pending_candidates = new Gee.ArrayList<string> ();

							schedule_on_frida_thread (() => {
								if (nice_agent == null)
									return false;

								server_session.add_candidates.begin (stolen_candidates.to_array (),
									nice_cancellable);

								return false;
							});

							return false;
						});
					}
				});

				gathering_handler = agent.candidate_gathering_done.connect (stream_id => {
					schedule_on_dbus_thread (() => {
						schedule_on_frida_thread (() => {
							if (nice_agent == null)
								return false;
							server_session.notify_candidate_gathering_done.begin (nice_cancellable);
							return false;
						});
						return false;
					});
				});

				if (!agent.gather_candidates (nice_stream_id))
					throw new Error.NOT_SUPPORTED ("Unable to gather local candidates");

				nice_stream = nice_agent.get_io_stream (nice_stream_id, nice_component_id);

				uint8 hello[1];
				yield nice_stream.input_stream.read_async (hello, Priority.DEFAULT, nice_cancellable);

				var tc = TlsServerConnection.new (nice_stream, certificate);
				tc.set_database (null);
				tc.set_certificate (certificate);
				yield tc.handshake_async (Priority.DEFAULT, nice_cancellable);
				nice_stream = tc;

				schedule_on_frida_thread (() => {
					promise.resolve (nice_stream);
					return false;
				});
			} catch (GLib.Error e) {
				nice_stream = null;

				string message = (e is IOError.CANCELLED)
					? "Unable to establish peer connection"
					: e.message;
				Error error = new Error.TRANSPORT ("%s", message);
				schedule_on_frida_thread (() => {
					nice_component_id = 0;
					nice_stream_id = 0;
					nice_cancellable = null;
					nice_agent = null;

					promise.reject (error);
					return false;
				});
			} finally {
				if (gathering_handler != 0)
					agent.disconnect (gathering_handler);
				if (candidate_handler != 0)
					agent.disconnect (candidate_handler);
			}
		}

		private void on_component_state_changed (uint stream_id, uint component_id, Nice.ComponentState state) {
			switch (state) {
				case CONNECTED:
					write_hello.begin ();
					break;
				case FAILED:
					nice_cancellable.cancel ();
					break;
				default:
					break;
			}
		}

		private void on_new_candidates (string[] candidate_sdps) {
			Nice.Agent? agent = nice_agent;
			if (agent == null)
				return;

			string[] candidate_sdps_copy = candidate_sdps;
			schedule_on_dbus_thread (() => {
				var candidates = new SList<Nice.Candidate> ();
				int i = 0;
				foreach (unowned string sdp in candidate_sdps_copy) {
					var candidate = agent.parse_remote_candidate_sdp (nice_stream_id, sdp);
					if (candidate == null)
						return false;
					candidates.append (candidate);
					i++;
				}

				agent.set_remote_candidates (nice_stream_id, nice_component_id, candidates);

				return false;
			});
		}

		private void on_candidate_gathering_done () {
			Nice.Agent? agent = nice_agent;
			if (agent == null)
				return;

			schedule_on_dbus_thread (() => {
				agent.peer_candidate_gathering_done (nice_stream_id);

				return false;
			});
		}

		private async void write_hello () {
			try {
				uint8 hello[1] = { 42 };
				yield nice_stream.output_stream.write_async (hello, Priority.DEFAULT, nice_cancellable);
			} catch (GLib.Error e) {
				nice_cancellable.cancel ();
			}
		}

		private void on_nice_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			_do_close.begin (SessionDetachReason.PROCESS_TERMINATED, CrashInfo.empty (), false, null);
		}

		private void schedule_on_frida_thread (owned SourceFunc function) {
			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (get_main_context ());
		}

		private void schedule_on_dbus_thread (owned SourceFunc function) {
			assert (dbus_context != null);

			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (dbus_context);
		}

		private static Nice.RelayType relay_kind_to_libnice (RelayKind kind) {
			switch (kind) {
				case TURN_UDP: return Nice.RelayType.TURN_UDP;
				case TURN_TCP: return Nice.RelayType.TURN_TCP;
				case TURN_TLS: return Nice.RelayType.TURN_TLS;
			}
			assert_not_reached ();
		}
#else
		public async void setup_peer_connection (PeerOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Peer-to-peer support not available due to build configuration");
		}

		private async void teardown_peer_connection (Cancellable? cancellable) {
		}
#endif

		public void setup_peer_connection_sync (PeerOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			var task = create<SetupPeerConnectionTask> ();
			task.options = options;
			task.execute (cancellable);
		}

		private class SetupPeerConnectionTask : SessionTask<void> {
			public PeerOptions? options;

			protected override async void perform_operation () throws Error, IOError {
				yield parent.setup_peer_connection (options, cancellable);
			}
		}

		public async PortalMembership join_portal (string address, PortalOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			check_open ();

			var raw_options = AgentPortalOptions ();
			if (options != null)
				raw_options.data = options._serialize ().get_data ();

			PortalMembershipId membership_id;
			try {
				membership_id = yield session.join_portal (address, raw_options, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			return new PortalMembership (this, membership_id);
		}

		public PortalMembership join_portal_sync (string address, PortalOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			var task = create<JoinPortalTask> ();
			task.address = address;
			task.options = options;
			return task.execute (cancellable);
		}

		private class JoinPortalTask : SessionTask<PortalMembership> {
			public string address;
			public PortalOptions? options;

			protected override async PortalMembership perform_operation () throws Error, IOError {
				return yield parent.join_portal (address, options, cancellable);
			}
		}

		protected async void post_script_messages (AgentScriptMessage[] messages,
				Cancellable? cancellable) throws Error, IOError {
			foreach (var m in messages) {
				uint64 serial = m.serial;
				if (serial <= last_script_message_serial && last_script_message_serial - serial < uint32.MAX / 2) {
					continue;
				}

				var script = scripts[m.script_id];
				if (script != null)
					script.message (m.json, m.has_data ? new Bytes (m.data) : null);

				last_script_message_serial = serial;
			}
		}

		protected async void post_debugger_messages (AgentDebuggerMessage[] messages,
				Cancellable? cancellable) throws Error, IOError {
			if (debugger == null)
				return;

			foreach (var m in messages) {
				uint64 serial = m.serial;
				if (serial <= last_debugger_message_serial && last_debugger_message_serial - serial < uint32.MAX / 2) {
					continue;
				}

				debugger.handle_message_from_backend (m.payload);

				last_debugger_message_serial = serial;
			}
		}

		public void _release_script (AgentScriptId script_id) {
			var script_did_exist = scripts.unset (script_id);
			assert (script_did_exist);
		}

		private void check_open () throws Error {
			switch (state) {
				case ATTACHED:
					break;
				case INTERRUPTED:
					throw new Error.INVALID_OPERATION ("Session was interrupted; call resume()");
				case DETACHED:
					throw new Error.INVALID_OPERATION ("Session is gone");
			}
		}

		internal void _on_detached (SessionDetachReason reason, CrashInfo crash) {
			if (persist_timeout != 0 && reason == CONNECTION_TERMINATED) {
				state = INTERRUPTED;
				detached (reason, null);
			} else {
				_do_close.begin (reason, crash, false, null);
			}
		}

		internal async void _do_close (SessionDetachReason reason, CrashInfo crash, bool may_block,
				Cancellable? cancellable) throws IOError {
			while (close_request != null) {
				try {
					yield close_request.future.wait_async (cancellable);
					return;
				} catch (GLib.Error e) {
					assert (e is IOError.CANCELLED);
					cancellable.set_error_if_cancelled ();
				}
			}
			close_request = new Promise<bool> ();

			state = DETACHED;

			try {
				if (debugger != null) {
					try {
						yield debugger.disable (cancellable);
					} catch (Error e) {
					}
					debugger = null;
				}

				foreach (var script in scripts.values.to_array ())
					yield script._do_close (may_block, cancellable);

				if (may_block)
					session.close.begin (cancellable);

				yield teardown_peer_connection (cancellable);

				yield device._release_session (this, may_block, cancellable);

				detached (reason, Crash.from_info (crash));

				close_request.resolve (true);
			} catch (IOError e) {
				close_request.reject (e);
				close_request = null;
				throw e;
			}
		}

		private void begin_migration (AgentSession new_session) {
			assert (obsolete_session == null);

			obsolete_session = active_session;

			active_session = new_session;

			if (debugger != null)
				debugger.begin_migration (new_session);
		}

		private void commit_migration (AgentSession new_session) {
			assert (new_session == active_session);
			assert (obsolete_session != null);

			obsolete_session = null;

			if (debugger != null)
				debugger.commit_migration (new_session);
		}

#if HAVE_NICE
		private void cancel_migration (AgentSession new_session) {
			assert (new_session == active_session);
			assert (obsolete_session != null);

			active_session = obsolete_session;
			obsolete_session = null;

			if (debugger != null)
				debugger.cancel_migration (new_session);
		}
#endif

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		private abstract class SessionTask<T> : AsyncTask<T> {
			public weak Session parent {
				get;
				construct;
			}
		}

		public extern static void _generate_certificate (out string cert_pem, out string key_pem);
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

		private Promise<bool> close_request;

		internal Script (Session session, AgentScriptId script_id) {
			Object (id: script_id.handle, session: session);
		}

		public bool is_destroyed () {
			return close_request != null;
		}

		public async void load (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			try {
				yield session.session.load_script (AgentScriptId (id), cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public void load_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<LoadTask> ().execute (cancellable);
		}

		private class LoadTask : ScriptTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.load (cancellable);
			}
		}

		public async void unload (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			yield _do_close (true, cancellable);
		}

		public void unload_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<UnloadTask> ().execute (cancellable);
		}

		private class UnloadTask : ScriptTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.unload (cancellable);
			}
		}

		public async void eternalize (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			try {
				yield session.session.eternalize_script (AgentScriptId (id), cancellable);

				yield _do_close (false, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public void eternalize_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<EternalizeTask> ().execute (cancellable);
		}

		private class EternalizeTask : ScriptTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.eternalize (cancellable);
			}
		}

		public async void post (string message, Bytes? data = null, Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var has_data = data != null;
			var data_param = has_data ? data.get_data () : new uint8[0];

			try {
				yield session.session.post_to_script (AgentScriptId (id), message, has_data, data_param, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public void post_sync (string message, Bytes? data = null, Cancellable? cancellable = null) throws Error, IOError {
			var task = create<PostTask> ();
			task.message = message;
			task.data = data;
			task.execute (cancellable);
		}

		private class PostTask : ScriptTask<void> {
			public string message;
			public Bytes? data;

			protected override async void perform_operation () throws Error, IOError {
				yield parent.post (message, data, cancellable);
			}
		}

		private void check_open () throws Error {
			if (close_request != null)
				throw new Error.INVALID_OPERATION ("Script is destroyed");
		}

		internal async void _do_close (bool may_block, Cancellable? cancellable) throws IOError {
			while (close_request != null) {
				try {
					yield close_request.future.wait_async (cancellable);
					return;
				} catch (GLib.Error e) {
					assert (e is IOError.CANCELLED);
					cancellable.set_error_if_cancelled ();
				}
			}
			close_request = new Promise<bool> ();

			var parent = session;
			var script_id = AgentScriptId (id);

			parent._release_script (script_id);

			if (may_block) {
				try {
					yield parent.session.destroy_script (script_id, cancellable);
				} catch (GLib.Error e) {
				}
			}

			destroyed ();

			close_request.resolve (true);
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		private abstract class ScriptTask<T> : AsyncTask<T> {
			public weak Script parent {
				get;
				construct;
			}
		}
	}

	public class PortalMembership : Object {
		public uint id {
			get;
			construct;
		}

		public Session session {
			get;
			construct;
		}

		internal PortalMembership (Session session, PortalMembershipId membership_id) {
			Object (id: membership_id.handle, session: session);
		}

		public async void terminate (Cancellable? cancellable = null) throws Error, IOError {
			try {
				yield session.session.leave_portal (PortalMembershipId (id), cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public void terminate_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<TerminateTask> ().execute (cancellable);
		}

		private class TerminateTask : PortalMembershipTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.terminate (cancellable);
			}
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		private abstract class PortalMembershipTask<T> : AsyncTask<T> {
			public weak PortalMembership parent {
				get;
				construct;
			}
		}
	}

	public interface Injector : Object {
		public signal void uninjected (uint id);

		public static Injector new () {
#if WINDOWS
			var tempdir = new TemporaryDirectory ();
			var helper = new WindowsHelperProcess (tempdir);
			return new Winjector (helper, true, tempdir);
#endif
#if DARWIN
			var tempdir = new TemporaryDirectory ();
			var helper = new DarwinHelperProcess (tempdir);
			return new Fruitjector (helper, true, tempdir);
#endif
#if LINUX
			var tempdir = new TemporaryDirectory ();
			var helper = new LinuxHelperProcess (tempdir);
			return new Linjector (helper, true, tempdir);
#endif
#if QNX
			return new Qinjector ();
#endif
		}

		public static Injector new_inprocess () {
#if WINDOWS
			var tempdir = new TemporaryDirectory ();
			var helper = new WindowsHelperBackend (PrivilegeLevel.NORMAL);
			return new Winjector (helper, true, tempdir);
#endif
#if DARWIN
			var tempdir = new TemporaryDirectory ();
			var helper = new DarwinHelperBackend ();
			return new Fruitjector (helper, true, tempdir);
#endif
#if LINUX
			var tempdir = new TemporaryDirectory ();
			var helper = new LinuxHelperBackend ();
			return new Linjector (helper, true, tempdir);
#endif
#if QNX
			return new Qinjector ();
#endif
		}

		public abstract async void close (Cancellable? cancellable = null) throws IOError;

		public void close_sync (Cancellable? cancellable = null) throws IOError {
			try {
				((CloseTask) create<CloseTask> ()).execute (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}
		}

		private class CloseTask : InjectorTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.close (cancellable);
			}
		}

		public abstract async uint inject_library_file (uint pid, string path, string entrypoint, string data,
			Cancellable? cancellable = null) throws Error, IOError;

		public uint inject_library_file_sync (uint pid, string path, string entrypoint, string data,
				Cancellable? cancellable = null) throws Error, IOError {
			var task = create<InjectLibraryFileTask> () as InjectLibraryFileTask;
			task.pid = pid;
			task.path = path;
			task.entrypoint = entrypoint;
			task.data = data;
			return task.execute (cancellable);
		}

		private class InjectLibraryFileTask : InjectorTask<uint> {
			public uint pid;
			public string path;
			public string entrypoint;
			public string data;

			protected override async uint perform_operation () throws Error, IOError {
				return yield parent.inject_library_file (pid, path, entrypoint, data, cancellable);
			}
		}

		public abstract async uint inject_library_blob (uint pid, Bytes blob, string entrypoint, string data,
			Cancellable? cancellable = null) throws Error, IOError;

		public uint inject_library_blob_sync (uint pid, Bytes blob, string entrypoint, string data,
				Cancellable? cancellable = null) throws Error, IOError {
			var task = create<InjectLibraryBlobTask> () as InjectLibraryBlobTask;
			task.pid = pid;
			task.blob = blob;
			task.entrypoint = entrypoint;
			task.data = data;
			return task.execute (cancellable);
		}

		private class InjectLibraryBlobTask : InjectorTask<uint> {
			public uint pid;
			public Bytes blob;
			public string entrypoint;
			public string data;

			protected override async uint perform_operation () throws Error, IOError {
				return yield parent.inject_library_blob (pid, blob, entrypoint, data, cancellable);
			}
		}

		public abstract async uint demonitor_and_clone_state (uint id, Cancellable? cancellable = null) throws Error, IOError;

		public uint demonitor_and_clone_state_sync (uint id, Cancellable? cancellable = null) throws Error, IOError {
			var task = create<DemonitorAndCloneStateTask> () as DemonitorAndCloneStateTask;
			task.id = id;
			return task.execute (cancellable);
		}

		private class DemonitorAndCloneStateTask : InjectorTask<uint> {
			public uint id;

			protected override async uint perform_operation () throws Error, IOError {
				return yield parent.demonitor_and_clone_state (id, cancellable);
			}
		}

		public abstract async void recreate_thread (uint pid, uint id, Cancellable? cancellable = null) throws Error, IOError;

		public void recreate_thread_sync (uint pid, uint id, Cancellable? cancellable = null) throws Error, IOError {
			var task = create<RecreateThreadTask> () as RecreateThreadTask;
			task.pid = pid;
			task.id = id;
			task.execute (cancellable);
		}

		private class RecreateThreadTask : InjectorTask<void> {
			public uint pid;
			public uint id;

			protected override async void perform_operation () throws Error, IOError {
				yield parent.recreate_thread (pid, id, cancellable);
			}
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		private abstract class InjectorTask<T> : AsyncTask<T> {
			public weak Injector parent {
				get;
				construct;
			}
		}
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
