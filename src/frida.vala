[CCode (gir_namespace = "Frida", gir_version = "1.0")]
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

		public static Runtime from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<Runtime> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<Runtime> (this);
		}
	}

	public sealed class DeviceManager : Object {
		public signal void added (Device device);
		public signal void removed (Device device);
		public signal void changed ();

		public delegate bool Predicate (Device device);

		private Promise<bool>? start_request;
		private Promise<bool>? stop_request;

		private HostSessionService? service;
		private Gee.ArrayList<Device> devices = new Gee.ArrayList<Device> ();
		private Gee.ArrayList<DeviceObserverEntry> on_device_added = new Gee.ArrayList<DeviceObserverEntry> ();

		private Cancellable io_cancellable = new Cancellable ();

		public DeviceManager () {
			service = new HostSessionService.with_default_backends ();
		}

		public DeviceManager.with_nonlocal_backends_only () {
			service = new HostSessionService.with_nonlocal_backends_only ();
		}

		public DeviceManager.with_socket_backend_only () {
			service = new HostSessionService.with_socket_backend_only ();
		}

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
#if HAVE_SOCKET_BACKEND
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

				string? origin = options.origin;
				if (origin != null)
					opts["origin"] = origin;

				string? token = options.token;
				if (token != null)
					opts["token"] = token;

				int interval = options.keepalive_interval;
				if (interval != -1)
					opts["keepalive_interval"] = interval;
			}

			var device = new Device (this, socket_device.provider, id, name, raw_options);
			devices.add (device);
			added (device);
			changed ();

			return device;
#else
			throw new Error.NOT_SUPPORTED ("Socket backend not available");
#endif
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

		internal void _release_device (Device device) {
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
			try {
				service.provider_available.connect (on_provider_available);
				service.provider_unavailable.connect (on_provider_unavailable);

				yield service.start (io_cancellable);

				start_request.resolve (true);
			} catch (IOError e) {
				start_request.reject (e);
			}
		}

		private void on_provider_available (HostSessionProvider provider) {
			var device = new Device (this, provider);
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

					foreach (var device in devices.to_array ())
						yield device._do_close (APPLICATION_REQUESTED, true, cancellable);
					devices.clear ();

					yield service.stop (cancellable);
					service.provider_available.disconnect (on_provider_available);
					service.provider_unavailable.disconnect (on_provider_unavailable);
				}

				service = null;

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

	public sealed class DeviceList : Object {
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

	public sealed class Device : Object {
		public signal void spawn_added (Spawn spawn);
		public signal void spawn_removed (Spawn spawn);
		public signal void child_added (Child child);
		public signal void child_removed (Child child);
		public signal void process_crashed (Crash crash);
		public signal void output (uint pid, int fd, Bytes data);
		public signal void uninjected (uint id);
		public signal void lost ();

		public string id {
			get {
				if (_id != null)
					return _id;
				return provider.id;
			}
		}

		public string name {
			get {
				if (_name != null)
					return _name;
				return provider.name;
			}
		}

		public Variant? icon {
			get;
			construct;
		}

		public DeviceType dtype {
			get {
				switch (provider.kind) {
					case HostSessionProviderKind.LOCAL:
						return DeviceType.LOCAL;
					case HostSessionProviderKind.REMOTE:
						return DeviceType.REMOTE;
					case HostSessionProviderKind.USB:
						return DeviceType.USB;
					default:
						assert_not_reached ();
				}
			}
		}

		public Bus bus {
			get {
				return _bus;
			}
		}

		private string? _id;
		private string? _name;
		internal HostSessionProvider provider;
		private unowned DeviceManager? manager;

		private HostSessionOptions? host_session_options;
		private Promise<HostSession>? host_session_request;
		private Promise<bool>? close_request;

		internal HostSession? current_host_session;
		private Gee.HashMap<AgentSessionId?, Session> agent_sessions =
			new Gee.HashMap<AgentSessionId?, Session> (AgentSessionId.hash, AgentSessionId.equal);
		private Gee.HashSet<Promise<Session>> pending_attach_requests = new Gee.HashSet<Promise<Session>> ();
		private Gee.HashMap<AgentSessionId?, Promise<bool>> pending_detach_requests =
			new Gee.HashMap<AgentSessionId?, Promise<bool>> (AgentSessionId.hash, AgentSessionId.equal);
		private Bus _bus;

		public delegate bool ProcessPredicate (Process process);

		internal Device (DeviceManager? mgr, HostSessionProvider prov, string? id = null, string? name = null,
				HostSessionOptions? options = null) {
			Object (icon: prov.icon);

			_id = id;
			_name = name;
			manager = mgr;
			host_session_options = options;

			assign_provider (prov);
		}

		construct {
			_bus = new Bus (this);
		}

		private void assign_provider (HostSessionProvider prov) {
			provider = prov;
			provider.host_session_detached.connect (on_host_session_detached);
			provider.agent_session_detached.connect (on_agent_session_detached);
		}

		public bool is_lost () {
			return close_request != null;
		}

		public async HashTable<string, Variant> query_system_parameters (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var host_session = yield get_host_session (cancellable);

			try {
				return yield host_session.query_system_parameters (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public HashTable<string, Variant> query_system_parameters_sync (Cancellable? cancellable = null) throws Error, IOError {
			return create<QuerySystemParametersTask> ().execute (cancellable);
		}

		private class QuerySystemParametersTask : DeviceTask<HashTable<string, Variant>> {
			protected override async HashTable<string, Variant> perform_operation () throws Error, IOError {
				return yield parent.query_system_parameters (cancellable);
			}
		}

		public async Application? get_frontmost_application (FrontmostQueryOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var raw_options = (options != null) ? options._serialize () : make_parameters_dict ();

			var host_session = yield get_host_session (cancellable);

			try {
				var app = yield host_session.get_frontmost_application (raw_options, cancellable);

				if (app.pid == 0)
					return null;

				return new Application (app.identifier, app.name, app.pid, app.parameters);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public Application? get_frontmost_application_sync (FrontmostQueryOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			var task = create<GetFrontmostApplicationTask> ();
			task.options = options;
			return task.execute (cancellable);
		}

		private class GetFrontmostApplicationTask : DeviceTask<Application?> {
			public FrontmostQueryOptions? options;

			protected override async Application? perform_operation () throws Error, IOError {
				return yield parent.get_frontmost_application (options, cancellable);
			}
		}

		public async ApplicationList enumerate_applications (ApplicationQueryOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var raw_options = (options != null) ? options._serialize () : make_parameters_dict ();

			var host_session = yield get_host_session (cancellable);

			HostApplicationInfo[] applications;
			try {
				applications = yield host_session.enumerate_applications (raw_options, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			var result = new Gee.ArrayList<Application> ();
			foreach (var app in applications)
				result.add (new Application (app.identifier, app.name, app.pid, app.parameters));
			return new ApplicationList (result);
		}

		public ApplicationList enumerate_applications_sync (ApplicationQueryOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			var task = create<EnumerateApplicationsTask> ();
			task.options = options;
			return task.execute (cancellable);
		}

		private class EnumerateApplicationsTask : DeviceTask<ApplicationList> {
			public ApplicationQueryOptions? options;

			protected override async ApplicationList perform_operation () throws Error, IOError {
				return yield parent.enumerate_applications (options, cancellable);
			}
		}

		public async Process get_process_by_pid (uint pid, ProcessMatchOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			return check_process (yield find_process_by_pid (pid, options, cancellable));
		}

		public Process get_process_by_pid_sync (uint pid, ProcessMatchOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			return check_process (find_process_by_pid_sync (pid, options, cancellable));
		}

		public async Process get_process_by_name (string name, ProcessMatchOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			return check_process (yield find_process_by_name (name, options, cancellable));
		}

		public Process get_process_by_name_sync (string name, ProcessMatchOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			return check_process (find_process_by_name_sync (name, options, cancellable));
		}

		public async Process get_process (ProcessPredicate predicate, ProcessMatchOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			return check_process (yield find_process (predicate, options, cancellable));
		}

		public Process get_process_sync (ProcessPredicate predicate, ProcessMatchOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			return check_process (find_process_sync (predicate, options, cancellable));
		}

		private Process check_process (Process? process) throws Error {
			if (process == null)
				throw new Error.INVALID_ARGUMENT ("Process not found");
			return process;
		}

		public async Process? find_process_by_pid (uint pid, ProcessMatchOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			return yield find_process ((process) => { return process.pid == pid; }, options, cancellable);
		}

		public Process? find_process_by_pid_sync (uint pid, ProcessMatchOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			return find_process_sync ((process) => { return process.pid == pid; }, options, cancellable);
		}

		public async Process? find_process_by_name (string name, ProcessMatchOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			var folded_name = name.casefold ();
			return yield find_process ((process) => { return process.name.casefold () == folded_name; }, options, cancellable);
		}

		public Process? find_process_by_name_sync (string name, ProcessMatchOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			var folded_name = name.casefold ();
			return find_process_sync ((process) => { return process.name.casefold () == folded_name; }, options, cancellable);
		}

		public async Process? find_process (ProcessPredicate predicate, ProcessMatchOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			Process? process = null;
			bool done = false;
			bool waiting = false;
			var main_context = MainContext.get_thread_default ();

			ProcessMatchOptions opts = (options != null) ? options : new ProcessMatchOptions ();
			int timeout = opts.timeout;

			ProcessQueryOptions enumerate_options = new ProcessQueryOptions ();
			enumerate_options.scope = opts.scope;

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
					var processes = yield enumerate_processes (enumerate_options, cancellable);

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

		public Process? find_process_sync (ProcessPredicate predicate, ProcessMatchOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			var task = create<FindProcessTask> ();
			task.predicate = (process) => {
				return predicate (process);
			};
			task.options = options;
			return task.execute (cancellable);
		}

		private class FindProcessTask : DeviceTask<Process?> {
			public ProcessPredicate predicate;
			public ProcessMatchOptions? options;

			protected override async Process? perform_operation () throws Error, IOError {
				return yield parent.find_process (predicate, options, cancellable);
			}
		}

		public async ProcessList enumerate_processes (ProcessQueryOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var raw_options = (options != null) ? options._serialize () : make_parameters_dict ();

			var host_session = yield get_host_session (cancellable);

			HostProcessInfo[] processes;
			try {
				processes = yield host_session.enumerate_processes (raw_options, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			var result = new Gee.ArrayList<Process> ();
			foreach (var p in processes)
				result.add (new Process (p.pid, p.name, p.parameters));
			return new ProcessList (result);
		}

		public ProcessList enumerate_processes_sync (ProcessQueryOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			var task = create<EnumerateProcessesTask> ();
			task.options = options;
			return task.execute (cancellable);
		}

		private class EnumerateProcessesTask : DeviceTask<ProcessList> {
			public ProcessQueryOptions? options;

			protected override async ProcessList perform_operation () throws Error, IOError {
				return yield parent.enumerate_processes (options, cancellable);
			}
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

				raw_options.aux = options.aux;
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

				var raw_options = (options != null) ? options._serialize () : make_parameters_dict ();

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

			var host_session = yield get_host_session (cancellable);

			ChannelId id;
			try {
				id = yield host_session.open_channel (address, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			return yield provider.link_channel (host_session, id, cancellable);
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

		public async Service open_service (string address, Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var host_session = yield get_host_session (cancellable);

			ServiceSessionId id;
			try {
				id = yield host_session.open_service (address, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			var service_session = yield provider.link_service_session (host_session, id, cancellable);

			return new Service (service_session);
		}

		public Service open_service_sync (string address, Cancellable? cancellable = null) throws Error, IOError {
			var task = create<OpenServiceTask> ();
			task.address = address;
			return task.execute (cancellable);
		}

		private class OpenServiceTask : DeviceTask<Service> {
			public string address;

			protected override async Service perform_operation () throws Error, IOError {
				return yield parent.open_service (address, cancellable);
			}
		}

		public async void unpair (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var pairable = provider as Pairable;
			if (pairable == null)
				throw new Error.NOT_SUPPORTED ("Pairing functionality is not supported by this device");

			yield pairable.unpair (cancellable);
		}

		public void unpair_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<UnpairTask> ().execute (cancellable);
		}

		private class UnpairTask : DeviceTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.unpair (cancellable);
			}
		}

		private void check_open () throws Error {
			if (close_request != null)
				throw new Error.INVALID_OPERATION ("Device is gone");
		}

		internal async HostSession get_host_session (Cancellable? cancellable) throws Error, IOError {
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

		private void on_host_session_detached (HostSession session) {
			if (session != current_host_session)
				return;

			_bus._detach.begin (session);

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

		internal async void _release_session (Session session, bool may_block, Cancellable? cancellable) throws IOError {
			AgentSessionId? session_id = null;
			foreach (var entry in agent_sessions.entries) {
				if (entry.value == session) {
					session_id = entry.key;
					break;
				}
			}
			if (session_id == null)
				return;

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
			else if (session != null)
				agent_sessions.unset (id);
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

		public static DeviceType from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<DeviceType> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<DeviceType> (this);
		}
	}

	public sealed class RemoteDeviceOptions : Object {
		public TlsCertificate? certificate {
			get;
			set;
		}

		public string? origin {
			get;
			set;
		}

		public string? token {
			get;
			set;
		}

		public int keepalive_interval {
			get;
			set;
			default = -1;
		}
	}

	public sealed class ApplicationList : Object {
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

	public sealed class Application : Object {
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

		public HashTable<string, Variant> parameters {
			get;
			construct;
		}

		internal Application (string identifier, string name, uint pid, HashTable<string, Variant> parameters) {
			Object (identifier: identifier, name: name, pid: pid, parameters: parameters);
		}
	}

	public sealed class ProcessList : Object {
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

	public sealed class Process : Object {
		public uint pid {
			get;
			construct;
		}

		public string name {
			get;
			construct;
		}

		public HashTable<string, Variant> parameters {
			get;
			construct;
		}

		internal Process (uint pid, string name, HashTable<string, Variant> parameters) {
			Object (pid: pid, name: name, parameters: parameters);
		}
	}

	public sealed class ProcessMatchOptions : Object {
		public int timeout {
			get;
			set;
			default = 0;
		}

		public Scope scope {
			get;
			set;
			default = MINIMAL;
		}
	}

	public sealed class SpawnOptions : Object {
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

		public HashTable<string, Variant> aux {
			get;
			set;
			default = make_parameters_dict ();
		}
	}

	public sealed class SpawnList : Object {
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

	public sealed class Spawn : Object {
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

	public sealed class ChildList : Object {
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

	public sealed class Child : Object {
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

	public sealed class Crash : Object {
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

		public HashTable<string, Variant> parameters {
			get;
			construct;
		}

		internal Crash (uint pid, string process_name, string summary, string report, HashTable<string, Variant> parameters) {
			Object (
				pid: pid,
				process_name: process_name,
				summary: summary,
				report: report,
				parameters: parameters
			);
		}

		internal static Crash? from_info (CrashInfo info) {
			if (info.pid == 0)
				return null;
			return new Crash (
				info.pid,
				info.process_name,
				info.summary,
				info.report,
				info.parameters
			);
		}
	}

	public sealed class Bus : Object {
		public signal void detached ();
		public signal void message (string json, Bytes? data);

		private weak Device device;

		private Promise<BusSession>? attach_request;
		private BusSession? active_session;

		private Cancellable io_cancellable = new Cancellable ();

		internal Bus (Device device) {
			this.device = device;
		}

		public bool is_detached () {
			return attach_request == null;
		}

		public async void attach (Cancellable? cancellable = null) throws Error, IOError {
			while (attach_request != null) {
				try {
					yield attach_request.future.wait_async (cancellable);
					return;
				} catch (Error e) {
					throw e;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}
			attach_request = new Promise<BusSession> ();

			try {
				var host_session = yield device.get_host_session (cancellable);

				DBusProxy proxy = host_session as DBusProxy;
				if (proxy == null)
					throw new Error.NOT_SUPPORTED ("Bus is not available on this device");

				try {
					active_session = yield proxy.g_connection.get_proxy (null, ObjectPath.BUS_SESSION,
						DO_NOT_LOAD_PROPERTIES, cancellable);
					active_session.message.connect (on_message);

					yield active_session.attach (cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}

				attach_request.resolve (active_session);
			} catch (GLib.Error e) {
				attach_request.reject (e);
				attach_request = null;

				throw_api_error (e);
			}
		}

		public void attach_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<AttachTask> ().execute (cancellable);
		}

		private class AttachTask : BusTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.attach (cancellable);
			}
		}

		internal async void _detach (HostSession dead_host_session) {
			if (attach_request == null)
				return;

			DBusConnection dead_connection = ((DBusProxy) dead_host_session).g_connection;

			io_cancellable.cancel ();
			io_cancellable = new Cancellable ();

			while (attach_request != null) {
				try {
					var some_session = yield attach_request.future.wait_async (null);
					if (((DBusProxy) some_session).g_connection == dead_connection) {
						some_session.message.disconnect (on_message);
						active_session = null;
						attach_request = null;
					} else {
						return;
					}
				} catch (GLib.Error e) {
				}
			}

			detached ();
		}

		public void post (string json, Bytes? data = null) {
			MainContext context = get_main_context ();
			if (context.is_owner ()) {
				do_post (json, data);
			} else {
				var source = new IdleSource ();
				source.set_callback (() => {
					do_post (json, data);
					return false;
				});
				source.attach (context);
			}
		}

		private void do_post (string json, Bytes? data) {
			if (active_session == null)
				return;
			var has_data = data != null;
			var data_param = has_data ? data.get_data () : new uint8[0];
			active_session.post.begin (json, has_data, data_param, io_cancellable);
		}

		private void on_message (string json, bool has_data, uint8[] data) {
			message (json, has_data ? new Bytes (data) : null);
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

	public sealed class Service : Object {
		public signal void close ();
		public signal void message (Variant message);

		private ServiceSession? session;
		private bool disposed = false;

		internal Service (ServiceSession session) {
			this.session = session;

			session.close.connect (on_close);
			session.message.connect (on_message);
		}

		public override void dispose () {
			if (!disposed) {
				disposed = true;

				MainContext context = get_main_context ();
				if (context.is_owner ()) {
					abandon ();
				} else {
					var source = new IdleSource ();
					source.set_callback (() => {
						abandon ();
						return false;
					});
					source.attach (context);
				}
			}

			base.dispose ();
		}

		~Service () {
			forget_session ();
		}

		private void abandon () {
			var s = session;
			if (s != null) {
				forget_session ();
				s.cancel.begin (null);
			}
		}

		private void forget_session () {
			session.close.disconnect (on_close);
			session.message.disconnect (on_message);
			session = null;
		}

		public bool is_closed () {
			return session == null;
		}

		public async void activate (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			try {
				yield session.activate (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public void activate_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<ActivateTask> ().execute (cancellable);
		}

		private class ActivateTask : ServiceTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.activate (cancellable);
			}
		}

		public async void cancel (Cancellable? cancellable = null) throws IOError {
			if (session == null)
				return;

			try {
				yield session.cancel (cancellable);
			} catch (GLib.Error e) {
				if (e is IOError.CANCELLED)
					cancellable.set_error_if_cancelled ();
			}
		}

		public void cancel_sync (Cancellable? cancellable = null) throws IOError {
			try {
				create<CancelTask> ().execute (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}
		}

		private class CancelTask : ServiceTask<void> {
			protected override async void perform_operation () throws IOError {
				yield parent.cancel (cancellable);
			}
		}

		public async Variant request (Variant parameters, Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			try {
				return yield session.request (parameters, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public Variant request_sync (Variant parameters, Cancellable? cancellable = null) throws Error, IOError {
			var task = create<RequestTask> () as RequestTask;
			task.parameters = parameters;
			return task.execute (cancellable);
		}

		private class RequestTask : ServiceTask<Variant> {
			public Variant parameters;

			protected override async Variant perform_operation () throws Error, IOError {
				return yield parent.request (parameters, cancellable);
			}
		}

		private void check_open () throws Error {
			if (session == null)
				throw new Error.INVALID_OPERATION ("Session is gone");
		}

		private void on_close () {
			forget_session ();
			close ();
		}

		private void on_message (Variant v) {
			message (v);
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		private abstract class ServiceTask<T> : AsyncTask<T> {
			public weak Service parent {
				get;
				construct;
			}
		}
	}

	public sealed class Session : Object, AgentMessageSink {
		public signal void detached (SessionDetachReason reason, Crash? crash);

		public uint pid {
			get;
			construct;
		}

		public uint persist_timeout {
			get;
			construct;
		}

		private AgentSessionId id;
		private unowned Device device;

		private State state = ATTACHED;
		private Promise<bool> close_request;

		internal AgentSession active_session;
		private AgentSession? obsolete_session;

		private uint last_rx_batch_id = 0;
		private Gee.LinkedList<PendingMessage> pending_messages = new Gee.LinkedList<PendingMessage> ();
		private int next_serial = 1;
		private uint pending_deliveries = 0;
		private Cancellable delivery_cancellable = new Cancellable ();

		private Gee.HashMap<AgentScriptId?, Script> scripts =
			new Gee.HashMap<AgentScriptId?, Script> (AgentScriptId.hash, AgentScriptId.equal);

		private PeerOptions? nice_options;
#if HAVE_NICE
		private Nice.Agent? nice_agent;
		private uint nice_stream_id;
		private uint nice_component_id;
		private SctpConnection? nice_iostream;
		private DBusConnection? nice_connection;
		private uint nice_registration_id;
		private Cancellable? nice_cancellable;

		private MainContext? frida_context;
		private MainContext? dbus_context;
#endif

		private enum State {
			ATTACHED,
			INTERRUPTED,
			DETACHED,
		}

		internal Session (Device device, uint pid, AgentSessionId id, SessionOptions options) {
			Object (pid: pid, persist_timeout: options.persist_timeout);

			this.id = id;
			this.device = device;
		}

		public bool is_detached () {
			return state != ATTACHED;
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

			DBusConnection old_connection = ((DBusProxy) active_session).g_connection;
			if (old_connection.is_closed ()) {
				var host_session = yield device.get_host_session (cancellable);

				try {
					yield host_session.reattach (id, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}

				var agent_session = yield device.provider.link_agent_session (host_session, id, this, cancellable);

				begin_migration (agent_session);
			}

			if (nice_options != null) {
				yield do_setup_peer_connection (nice_options, cancellable);
			}

			uint last_tx_batch_id;
			try {
				yield active_session.resume (last_rx_batch_id, cancellable, out last_tx_batch_id);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			if (last_tx_batch_id != 0) {
				PendingMessage? m;
				while ((m = pending_messages.peek ()) != null && m.delivery_attempts > 0 && m.serial <= last_tx_batch_id) {
					pending_messages.poll ();
				}
			}

			delivery_cancellable = new Cancellable ();
			state = ATTACHED;

			maybe_deliver_pending_messages ();
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
				yield active_session.enable_child_gating (cancellable);
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
				yield active_session.disable_child_gating (cancellable);
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

			var raw_options = (options != null) ? options._serialize () : make_parameters_dict ();

			AgentScriptId script_id;
			try {
				script_id = yield active_session.create_script (source, raw_options, cancellable);
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

			var raw_options = (options != null) ? options._serialize () : make_parameters_dict ();

			AgentScriptId script_id;
			try {
				script_id = yield active_session.create_script_from_bytes (bytes.get_data (), raw_options,
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

			var raw_options = (options != null) ? options._serialize () : make_parameters_dict ();

			uint8[] data;
			try {
				data = yield active_session.compile_script (source, raw_options, cancellable);
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

		public async Bytes snapshot_script (string embed_script, SnapshotOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			check_open ();

			var raw_options = (options != null) ? options._serialize () : make_parameters_dict ();

			uint8[] data;
			try {
				data = yield active_session.snapshot_script (embed_script, raw_options, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			return new Bytes (data);
		}

		public Bytes snapshot_script_sync (string embed_script, SnapshotOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			var task = create<SnapshotScriptTask> ();
			task.embed_script = embed_script;
			task.options = options;
			return task.execute (cancellable);
		}

		private class SnapshotScriptTask : SessionTask<Bytes> {
			public string embed_script;
			public SnapshotOptions? options;

			protected override async Bytes perform_operation () throws Error, IOError {
				return yield parent.snapshot_script (embed_script, options, cancellable);
			}
		}

		public async void setup_peer_connection (PeerOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			yield do_setup_peer_connection (options, cancellable);
		}

#if HAVE_NICE
		private async void do_setup_peer_connection (PeerOptions? options, Cancellable? cancellable) throws Error, IOError {
			AgentSession server_session = active_session;

			frida_context = get_main_context ();
			dbus_context = yield get_dbus_context ();

			var agent = new Nice.Agent.full (dbus_context, Nice.Compatibility.RFC5245, ICE_TRICKLE);
			agent.set_software ("Frida");
			agent.controlling_mode = true;
			agent.ice_tcp = false;

			uint stream_id = agent.add_stream (1);
			if (stream_id == 0)
				throw new Error.NOT_SUPPORTED ("Unable to add stream");
			uint component_id = 1;
			agent.set_stream_name (stream_id, "application");

			yield PeerConnection.configure_agent (agent, stream_id, component_id, options, cancellable);

			uint8[] cert_der;
			string cert_pem, key_pem;
			yield generate_certificate (out cert_der, out cert_pem, out key_pem);

			TlsCertificate certificate;
			try {
				certificate = new TlsCertificate.from_pem (cert_pem + key_pem, -1);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			var offer = new PeerSessionDescription ();
			offer.session_id = PeerSessionId.generate ();
			agent.get_local_credentials (stream_id, out offer.ice_ufrag, out offer.ice_pwd);
			offer.ice_trickle = true;
			offer.fingerprint = PeerConnection.compute_certificate_fingerprint (cert_der);
			offer.setup = ACTPASS;

			string offer_sdp = offer.to_sdp ();

			var raw_options = (options != null) ? options._serialize () : make_parameters_dict ();

			IOStream stream = null;
			server_session.new_candidates.connect (on_new_candidates);
			server_session.candidate_gathering_done.connect (on_candidate_gathering_done);
			try {
				string answer_sdp;
				try {
					yield server_session.offer_peer_connection (offer_sdp, raw_options, cancellable, out answer_sdp);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}

				var answer = PeerSessionDescription.parse (answer_sdp);
				agent.set_remote_credentials (stream_id, answer.ice_ufrag, answer.ice_pwd);

				if (nice_agent != null)
					throw new Error.INVALID_OPERATION ("Peer connection already exists");

				nice_agent = agent;
				nice_cancellable = new Cancellable ();
				nice_stream_id = stream_id;
				nice_component_id = component_id;

				var open_request = new Promise<IOStream> ();

				schedule_on_dbus_thread (() => {
					open_peer_connection.begin (server_session, certificate, answer, open_request);
					return false;
				});

				stream = yield open_request.future.wait_async (cancellable);
			} finally {
				server_session.candidate_gathering_done.disconnect (on_candidate_gathering_done);
				server_session.new_candidates.disconnect (on_new_candidates);
			}

			try {
				nice_connection = yield new DBusConnection (stream, null, DELAY_MESSAGE_PROCESSING, null, nice_cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
			nice_connection.on_closed.connect (on_nice_connection_closed);

			try {
				nice_registration_id = nice_connection.register_object (ObjectPath.AGENT_MESSAGE_SINK,
					(AgentMessageSink) this);
			} catch (IOError io_error) {
				assert_not_reached ();
			}

			nice_connection.start_message_processing ();

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

			nice_options = (options != null) ? options : new PeerOptions ();
		}

		private async void teardown_peer_connection (Cancellable? cancellable) throws IOError {
			Nice.Agent? agent = nice_agent;
			DBusConnection? conn = nice_connection;

			discard_peer_connection ();

			if (conn != null) {
				try {
					yield conn.close (cancellable);
				} catch (GLib.Error e) {
				}
			}

			if (agent != null) {
				schedule_on_dbus_thread (() => {
					agent.close_async.begin ();

					schedule_on_frida_thread (() => {
						teardown_peer_connection.callback ();
						return false;
					});

					return false;
				});
				yield;
			}
		}

		private void discard_peer_connection () {
			nice_cancellable = null;

			if (nice_registration_id != 0) {
				nice_connection.unregister_object (nice_registration_id);
				nice_registration_id = 0;
			}

			if (nice_connection != null) {
				nice_connection.on_closed.disconnect (on_nice_connection_closed);
				nice_connection = null;
			}

			nice_iostream = null;

			nice_component_id = 0;
			nice_stream_id = 0;

			nice_agent = null;
		}

		private async void open_peer_connection (AgentSession server_session, TlsCertificate certificate,
				PeerSessionDescription answer, Promise<IOStream> promise) {
			Nice.Agent agent = nice_agent;
			DtlsConnection? tc = null;
			ulong candidate_handler = 0;
			ulong gathering_handler = 0;
			ulong accept_handler = 0;
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

				var socket = new PeerSocket (agent, nice_stream_id, nice_component_id);

				if (answer.setup == ACTIVE) {
					var dsc = DtlsServerConnection.new (socket, certificate);
					dsc.authentication_mode = REQUIRED;
					tc = dsc;
				} else {
					tc = DtlsClientConnection.new (socket, null);
					tc.set_certificate (certificate);
				}
				tc.set_database (null);
				accept_handler = tc.accept_certificate.connect ((peer_cert, errors) => {
					return PeerConnection.compute_certificate_fingerprint (peer_cert.certificate.data) == answer.fingerprint;
				});
				yield tc.handshake_async (Priority.DEFAULT, nice_cancellable);

				nice_iostream = new SctpConnection (tc, answer.setup, answer.sctp_port, answer.max_message_size);

				schedule_on_frida_thread (() => {
					promise.resolve (nice_iostream);
					return false;
				});
			} catch (GLib.Error e) {
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
				if (accept_handler != 0)
					tc.disconnect (accept_handler);
				if (gathering_handler != 0)
					agent.disconnect (gathering_handler);
				if (candidate_handler != 0)
					agent.disconnect (candidate_handler);
			}
		}

		private void on_component_state_changed (uint stream_id, uint component_id, Nice.ComponentState state) {
			if (state == FAILED)
				nice_cancellable.cancel ();
		}

		private void on_new_candidates (string[] candidate_sdps) {
			Nice.Agent? agent = nice_agent;
			if (agent == null)
				return;

			string[] candidate_sdps_copy = candidate_sdps;
			schedule_on_dbus_thread (() => {
				var candidates = new SList<Nice.Candidate> ();
				foreach (unowned string sdp in candidate_sdps_copy) {
					var candidate = agent.parse_remote_candidate_sdp (nice_stream_id, sdp);
					if (candidate != null)
						candidates.append (candidate);
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

		private void on_nice_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			handle_nice_connection_closure.begin ();
		}

		private async void handle_nice_connection_closure () {
			try {
				yield teardown_peer_connection (null);
			} catch (IOError e) {
				assert_not_reached ();
			}

			if (persist_timeout != 0) {
				if (state != ATTACHED)
					return;
				state = INTERRUPTED;
				active_session = obsolete_session;
				obsolete_session = null;
				delivery_cancellable.cancel ();
				detached (CONNECTION_TERMINATED, null);
			} else {
				_do_close.begin (CONNECTION_TERMINATED, CrashInfo.empty (), false, null);
			}
		}

		private void schedule_on_frida_thread (owned SourceFunc function) {
			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (frida_context);
		}

		private void schedule_on_dbus_thread (owned SourceFunc function) {
			assert (dbus_context != null);

			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (dbus_context);
		}
#else
		private async void do_setup_peer_connection (PeerOptions? options, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Peer-to-peer support not available due to build configuration");
		}

		private async void teardown_peer_connection (Cancellable? cancellable) throws IOError {
		}

		private void discard_peer_connection () {
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

			var raw_options = (options != null) ? options._serialize () : make_parameters_dict ();

			PortalMembershipId membership_id;
			try {
				membership_id = yield active_session.join_portal (address, raw_options, cancellable);
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

		protected async void post_messages (AgentMessage[] messages, uint batch_id,
				Cancellable? cancellable) throws Error, IOError {
			if (state == INTERRUPTED)
				throw new Error.INVALID_OPERATION ("Cannot receive messages while interrupted");

			foreach (var m in messages) {
				switch (m.kind) {
					case SCRIPT: {
						var script = scripts[m.script_id];
						if (script != null)
							script.message (m.text, m.has_data ? new Bytes (m.data) : null);
						break;
					}
					case DEBUGGER:
						var script = scripts[m.script_id];
						if (script != null)
							script.on_debugger_message_from_backend (m.text);
						break;
				}
			}

			last_rx_batch_id = batch_id;
		}

		internal void _post_to_agent (AgentMessageKind kind, AgentScriptId script_id, string text, Bytes? data = null) {
			if (state == DETACHED)
				return;
			pending_messages.offer (new PendingMessage (next_serial++, kind, script_id, text, data));
			maybe_deliver_pending_messages ();
		}

		private void maybe_deliver_pending_messages () {
			if (state != ATTACHED)
				return;

			AgentSession sink = active_session;

			if (pending_messages.is_empty)
				return;

			var batch = new Gee.ArrayList<PendingMessage> ();
			void * items = null;
			int n_items = 0;
			size_t total_size = 0;
			size_t max_size = 4 * 1024 * 1024;
			PendingMessage? m;
			while ((m = pending_messages.peek ()) != null) {
				size_t message_size = m.estimate_size_in_bytes ();
				if (total_size + message_size > max_size && !batch.is_empty)
					break;
				pending_messages.poll ();
				batch.add (m);

				n_items++;
				items = realloc (items, n_items * sizeof (AgentMessage));

				AgentMessage * am = (AgentMessage *) items + n_items - 1;

				am->kind = m.kind;
				am->script_id = m.script_id;

				*((void **) &am->text) = m.text;

				unowned Bytes? data = m.data;
				am->has_data = data != null;
				*((void **) &am->data) = am->has_data ? data.get_data () : null;
				am->data.length = am->has_data ? data.length : 0;

				total_size += message_size;
			}

			if (persist_timeout == 0)
				emit_batch (sink, batch, items);
			else
				deliver_batch.begin (sink, batch, items);
		}

		private void emit_batch (AgentSession sink, Gee.ArrayList<PendingMessage> messages, void * items) {
			unowned AgentMessage[] items_arr = (AgentMessage[]) items;
			items_arr.length = messages.size;

			sink.post_messages.begin (items_arr, 0, delivery_cancellable);

			free (items);
		}

		private async void deliver_batch (AgentSession sink, Gee.ArrayList<PendingMessage> messages, void * items) {
			bool success = false;
			pending_deliveries++;
			try {
				int n = messages.size;

				foreach (var message in messages)
					message.delivery_attempts++;

				unowned AgentMessage[] items_arr = (AgentMessage[]) items;
				items_arr.length = n;

				uint batch_id = messages[n - 1].serial;

				yield sink.post_messages (items_arr, batch_id, delivery_cancellable);

				success = true;
			} catch (GLib.Error e) {
				pending_messages.add_all (messages);
				pending_messages.sort ((a, b) => a.serial - b.serial);
			} finally {
				pending_deliveries--;
				if (pending_deliveries == 0 && success)
					next_serial = 1;

				free (items);
			}
		}

		private class PendingMessage {
			public int serial;
			public AgentMessageKind kind;
			public AgentScriptId script_id;
			public string text;
			public Bytes? data;
			public uint delivery_attempts;

			public PendingMessage (int serial, AgentMessageKind kind, AgentScriptId script_id, string text,
					Bytes? data = null) {
				this.serial = serial;
				this.kind = kind;
				this.script_id = script_id;
				this.text = text;
				this.data = data;
			}

			public size_t estimate_size_in_bytes () {
				return sizeof (AgentMessage) + text.length + 1 + ((data != null) ? data.length : 0);
			}
		}

		internal void _release_script (AgentScriptId script_id) {
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
				if (state != ATTACHED)
					return;
				state = INTERRUPTED;
				delivery_cancellable.cancel ();
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
				foreach (var script in scripts.values.to_array ())
					yield script._do_close (may_block, cancellable);

				if (may_block)
					close_session_and_peer_connection.begin (cancellable);
				else
					discard_peer_connection ();

				yield device._release_session (this, may_block, cancellable);

				detached (reason, Crash.from_info (crash));

				close_request.resolve (true);
			} catch (IOError e) {
				close_request.reject (e);
				close_request = null;
				throw e;
			}
		}

		private async void close_session_and_peer_connection (Cancellable? cancellable) throws IOError {
			try {
				yield active_session.close (cancellable);
			} catch (GLib.Error e) {
				if (e is IOError.CANCELLED) {
					discard_peer_connection ();
					return;
				}
			}

			yield teardown_peer_connection (cancellable);
		}

		private void begin_migration (AgentSession new_session) {
			obsolete_session = active_session;
			active_session = new_session;
		}

#if HAVE_NICE
		private void cancel_migration (AgentSession new_session) {
			active_session = obsolete_session;
			obsolete_session = null;
		}
#endif

		public DBusConnection _get_connection () {
			return ((DBusProxy) active_session).g_connection;
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		private abstract class SessionTask<T> : AsyncTask<T> {
			public weak Session parent {
				get;
				construct;
			}
		}
	}

	public sealed class Script : Object {
		public signal void destroyed ();
		public signal void message (string json, Bytes? data);

		private AgentScriptId id;
		private unowned Session session;

		private Promise<bool> close_request;

		private Gum.InspectorServer? inspector_server;

		internal Script (Session session, AgentScriptId script_id) {
			Object ();

			this.id = script_id;
			this.session = session;
		}

		public bool is_destroyed () {
			return close_request != null;
		}

		public async void load (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			try {
				yield session.active_session.load_script (id, cancellable);
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
				yield session.active_session.eternalize_script (id, cancellable);

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

		public void post (string json, Bytes? data = null) {
			MainContext context = get_main_context ();
			if (context.is_owner ()) {
				do_post (json, data);
			} else {
				var source = new IdleSource ();
				source.set_callback (() => {
					do_post (json, data);
					return false;
				});
				source.attach (context);
			}
		}

		private void do_post (string json, Bytes? data) {
			if (close_request != null)
				return;

			session._post_to_agent (AgentMessageKind.SCRIPT, id, json, data);
		}

		public async void enable_debugger (uint16 port = 0, Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			if (inspector_server != null)
				throw new Error.INVALID_OPERATION ("Debugger is already enabled");

			inspector_server = (port != 0)
				? new Gum.InspectorServer.with_port (port)
				: new Gum.InspectorServer ();
			inspector_server.message.connect (on_debugger_message_from_frontend);

			try {
				yield session.active_session.enable_debugger (id, cancellable);
			} catch (GLib.Error e) {
				inspector_server = null;

				throw_dbus_error (e);
			}

			if (inspector_server != null) {
				try {
					inspector_server.start ();
				} catch (Gum.Error e) {
					inspector_server = null;

					try {
						yield session.active_session.disable_debugger (id, cancellable);
					} catch (GLib.Error e) {
					}

					throw new Error.ADDRESS_IN_USE ("%s", e.message);
				}
			}
		}

		public void enable_debugger_sync (uint16 port = 0, Cancellable? cancellable = null) throws Error, IOError {
			var task = create<EnableScriptDebuggerTask> ();
			task.port = port;
			task.execute (cancellable);
		}

		private class EnableScriptDebuggerTask : ScriptTask<void> {
			public uint16 port;

			protected override async void perform_operation () throws Error, IOError {
				yield parent.enable_debugger (port, cancellable);
			}
		}

		public async void disable_debugger (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			if (inspector_server == null)
				return;

			inspector_server.message.disconnect (on_debugger_message_from_frontend);
			inspector_server.stop ();
			inspector_server = null;

			try {
				yield session.active_session.disable_debugger (id, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public void disable_debugger_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<DisableScriptDebuggerTask> ().execute (cancellable);
		}

		private class DisableScriptDebuggerTask : ScriptTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.disable_debugger (cancellable);
			}
		}

		private void on_debugger_message_from_frontend (string message) {
			session._post_to_agent (AgentMessageKind.DEBUGGER, id, message);
		}

		internal void on_debugger_message_from_backend (string message) {
			if (inspector_server != null)
				inspector_server.post_message (message);
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

			parent._release_script (id);

			if (inspector_server != null) {
				inspector_server.message.disconnect (on_debugger_message_from_frontend);
				inspector_server.stop ();
				inspector_server = null;
			}

			if (may_block) {
				try {
					yield parent.active_session.destroy_script (id, cancellable);
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

	public sealed class PortalMembership : Object {
		private uint id;
		private Session session;

		internal PortalMembership (Session session, PortalMembershipId membership_id) {
			Object ();

			this.id = membership_id.handle;
			this.session = session;
		}

		public async void terminate (Cancellable? cancellable = null) throws Error, IOError {
			try {
				yield session.active_session.leave_portal (PortalMembershipId (id), cancellable);
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
#if HAVE_LOCAL_BACKEND
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
#if FREEBSD
			return new Binjector ();
#endif
#if QNX
			return new Qinjector ();
#endif
#else
			assert_not_reached ();
#endif
		}

		public static Injector new_inprocess () {
#if HAVE_LOCAL_BACKEND
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
#if FREEBSD
			return new Binjector ();
#endif
#if QNX
			return new Qinjector ();
#endif
#else
			assert_not_reached ();
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

		public abstract async void demonitor (uint id, Cancellable? cancellable = null) throws Error, IOError;

		public void demonitor_sync (uint id, Cancellable? cancellable = null) throws Error, IOError {
			var task = create<DemonitorTask> () as DemonitorTask;
			task.id = id;
			task.execute (cancellable);
		}

		private class DemonitorTask : InjectorTask<void> {
			public uint id;

			protected override async void perform_operation () throws Error, IOError {
				yield parent.demonitor (id, cancellable);
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
