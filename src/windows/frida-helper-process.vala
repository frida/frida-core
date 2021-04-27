namespace Frida {
	public class WindowsHelperProcess : Object, WindowsHelper {
		public TemporaryDirectory tempdir {
			get;
			construct;
		}

		private WindowsHelperBackend inprocess_backend = new WindowsHelperBackend (PrivilegeLevel.NORMAL);

		private HelperFactory _normal_factory = new HelperFactory (PrivilegeLevel.NORMAL);
		private HelperFactory _elevated_factory = new HelperFactory (PrivilegeLevel.ELEVATED);

		private ResourceStore _resource_store;

		public WindowsHelperProcess (TemporaryDirectory tempdir) {
			Object (tempdir: tempdir);
		}

		construct {
			inprocess_backend.uninjected.connect (on_uninjected);
			_normal_factory.uninjected.connect (on_uninjected);
			_elevated_factory.uninjected.connect (on_uninjected);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			inprocess_backend.uninjected.disconnect (on_uninjected);
			_normal_factory.uninjected.disconnect (on_uninjected);
			_elevated_factory.uninjected.disconnect (on_uninjected);

			yield _normal_factory.close (cancellable);
			yield _elevated_factory.close (cancellable);

			yield inprocess_backend.close (cancellable);

			_resource_store = null;
		}

		private HelperFactory get_normal_factory () throws Error {
			if (_normal_factory.resource_store == null)
				_normal_factory.resource_store = get_resource_store ();
			return _normal_factory;
		}

		private HelperFactory get_elevated_factory () throws Error {
			if (_elevated_factory.resource_store == null)
				_elevated_factory.resource_store = get_resource_store ();
			return _elevated_factory;
		}

		private ResourceStore get_resource_store () throws Error {
			if (_resource_store == null)
				_resource_store = new ResourceStore (tempdir);
			return _resource_store;
		}

		public async void inject_library_file (uint pid, PathTemplate path_template, string entrypoint, string data,
				string[] dependencies, uint id, Cancellable? cancellable) throws Error, IOError {
			bool permission_denied = false;
			try {
				unowned string local_arch = sizeof (void *) == 8 ? "64" : "32";
				unowned string remote_arch = WindowsProcess.is_x64 (pid) ? "64" : "32";
				if (remote_arch == local_arch) {
					yield inprocess_backend.inject_library_file (pid, path_template, entrypoint, data, dependencies,
						id, cancellable);
					return;
				}
			} catch (Error e) {
				if (e is Error.PERMISSION_DENIED)
					permission_denied = true;
				else
					throw e;
			}

			if (!permission_denied && !_elevated_factory.running) {
				var normal_factory = get_normal_factory ();
				var normal_helper = yield normal_factory.obtain (cancellable);
				try {
					yield normal_helper.inject_library_file (pid, path_template, entrypoint, data, dependencies, id,
						cancellable);
					return;
				} catch (Error e) {
					if (!(e is Error.PERMISSION_DENIED))
						throw e;
				}
			}

			var elevated_factory = get_elevated_factory ();
			HelperInstance elevated_helper;
			try {
				elevated_helper = yield elevated_factory.obtain (cancellable);
			} catch (Error elevate_error) {
				throw new Error.PERMISSION_DENIED (
					"Unable to access process with pid %u from the current user account".printf (pid));
			}
			yield elevated_helper.inject_library_file (pid, path_template, entrypoint, data, dependencies, id, cancellable);
		}

		private void on_uninjected (uint id) {
			uninjected (id);
		}
	}

	private class HelperFactory {
		public signal void uninjected (uint id);

		public bool running {
			get {
				return helper != null;
			}
		}

		public ResourceStore? resource_store {
			get;
			set;
		}

		private PrivilegeLevel level;
		private MainContext main_context;

		private HelperInstance? helper;

		private Promise<HelperInstance>? obtain_request;
		private PipeTransport? transport;
		private Future<IOStream>? stream_request;

		private Cancellable io_cancellable = new Cancellable ();

		public HelperFactory (PrivilegeLevel level) {
			this.level = level;
			this.main_context = MainContext.get_thread_default ();
		}

		public async void close (Cancellable? cancellable) throws IOError {
			io_cancellable.cancel ();

			if (helper != null) {
				helper.uninjected.disconnect (on_uninjected);

				yield helper.close (cancellable);
				helper = null;
			}

			resource_store = null;
		}

		public async HelperInstance obtain (Cancellable? cancellable) throws Error, IOError {
			if (helper != null)
				return helper;

			if (obtain_request == null) {
				obtain_request = new Promise<HelperInstance> ();

				try {
					transport = new PipeTransport ();
				} catch (Error error) {
					obtain_request.reject (error);
					obtain_request = null;

					throw error;
				}

				stream_request = Pipe.open (transport.local_address, cancellable);

				new Thread<bool> ("frida-helper-factory", obtain_worker);
			}

			return yield obtain_request.future.wait_async (cancellable);
		}

		private bool obtain_worker () {
			HelperInstance? instance = null;
			Error? error = null;

			try {
				string native_helper_path = WindowsSystem.is_x64 ()
					? resource_store.helper64.path
					: resource_store.helper32.path;
				string level_str = (level == PrivilegeLevel.ELEVATED) ? "ELEVATED" : "NORMAL";
				void * process = spawn (native_helper_path,
					"MANAGER %s %s".printf (level_str, transport.remote_address),
					level);
				instance = new HelperInstance (resource_store.helper32, resource_store.helper64, transport,
					stream_request, process);
			} catch (Error e) {
				error = e;
			}

			var source = new IdleSource ();
			source.set_callback (() => {
				complete_obtain.begin (instance, error);
				return false;
			});
			source.attach (main_context);

			return error == null;
		}

		private async void complete_obtain (HelperInstance? instance, Error? error) {
			HelperInstance? completed_instance = instance;
			GLib.Error? completed_error = error;

			if (instance != null) {
				try {
					yield instance.open (io_cancellable);

					if (completed_instance.is_alive) {
						helper = completed_instance;
						helper.terminated.connect (on_terminated);
						helper.uninjected.connect (on_uninjected);
					}
				} catch (GLib.Error e) {
					completed_instance = null;
					completed_error = e;
				}
			}

			stream_request = null;
			transport = null;

			if (completed_instance != null)
				obtain_request.resolve (completed_instance);
			else
				obtain_request.reject (completed_error);
			obtain_request = null;
		}

		private void on_terminated () {
			helper.terminated.disconnect (on_terminated);
			helper.uninjected.disconnect (on_uninjected);
			helper = null;
		}

		private void on_uninjected (uint id) {
			uninjected (id);
		}

		private extern static void * spawn (string path, string parameters, PrivilegeLevel level) throws Error;
	}

	private class HelperInstance {
		public signal void terminated ();
		public signal void uninjected (uint id);

		public bool is_alive {
			get {
				return connection != null;
			}
		}

		private TemporaryFile helper32;
		private TemporaryFile helper64;
		private PipeTransport transport;
		private Future<IOStream> stream_request;
		private DBusConnection connection;
		private WindowsRemoteHelper proxy;
		private void * process;

		private Gee.Set<uint> injectee_ids = new Gee.HashSet<uint> ();

		public HelperInstance (TemporaryFile helper32, TemporaryFile helper64, PipeTransport transport,
				Future<IOStream> stream_request, void * process) {
			this.helper32 = helper32;
			this.helper64 = helper64;
			this.transport = transport;
			this.stream_request = stream_request;
			this.process = process;
		}

		~HelperInstance () {
			if (process != null)
				close_process_handle (process);
		}

		public async void open (Cancellable? cancellable) throws Error, IOError {
			try {
				var stream = yield stream_request.wait_async (cancellable);

				connection = yield new DBusConnection (stream, null, DBusConnectionFlags.NONE, null, cancellable);
				connection.on_closed.connect (on_connection_closed);
			} catch (GLib.Error e) {
				throw new Error.PERMISSION_DENIED ("%s", e.message);
			}

			try {
				proxy = yield connection.get_proxy (null, ObjectPath.HELPER, DO_NOT_LOAD_PROPERTIES, cancellable);
			} catch (IOError e) {
				throw new Error.PROTOCOL ("%s", e.message);
			}

			proxy.uninjected.connect (on_uninjected);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			if (connection != null) {
				connection.on_closed.disconnect (on_connection_closed);
				connection = null;
			}

			proxy.uninjected.disconnect (on_uninjected);

			try {
				yield proxy.stop (cancellable);
			} catch (GLib.Error e) {
				if (e is IOError.CANCELLED)
					throw (IOError) e;
			}

			if (process == null)
				return;

			var main_context = MainContext.get_thread_default ();

			var poll_source = new TimeoutSource (50);
			poll_source.set_callback (() => {
				close.callback ();
				return true;
			});
			poll_source.attach (main_context);

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (close.callback);
			cancel_source.attach (main_context);

			while (is_process_still_running (process) && !cancellable.is_cancelled ())
				yield;

			poll_source.destroy ();
			if (cancellable.is_cancelled ()) {
				cancel_source.destroy ();
				cancellable.set_error_if_cancelled ();
			}

			close_process_handle (process);
			process = null;

			/* HACK: Give it a bit more time. */
			var delay_source = new TimeoutSource (20);
			delay_source.set_callback (close.callback);
			delay_source.attach (main_context);

			yield;

			delay_source.destroy ();
			cancel_source.destroy ();
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			this.connection = null;

			foreach (var id in injectee_ids)
				uninjected (id);
			injectee_ids.clear ();

			terminated ();
		}

		public async void inject_library_file (uint pid, PathTemplate path_template, string entrypoint, string data,
				string[] dependencies, uint id, Cancellable? cancellable) throws Error, IOError {
			try {
				yield proxy.inject_library_file (pid, path_template, entrypoint, data, dependencies, id, cancellable);
				injectee_ids.add (id);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		private void on_uninjected (uint id) {
			injectee_ids.remove (id);

			uninjected (id);
		}

		private extern static bool is_process_still_running (void * handle);
		private extern static void close_process_handle (void * handle);
	}

	private class ResourceStore {
		public TemporaryFile helper32 {
			get;
			private set;
		}

		public TemporaryFile helper64 {
			get;
			private set;
		}

		public ResourceStore (TemporaryDirectory tempdir) throws Error {
			var blob32 = Frida.Data.Windows.get_frida_helper_32_exe_blob ();
			helper32 = new TemporaryFile.from_stream ("frida-helper-32.exe",
				new MemoryInputStream.from_data (blob32.data, null),
				tempdir);

			var blob64 = Frida.Data.Windows.get_frida_helper_64_exe_blob ();
			helper64 = new TemporaryFile.from_stream ("frida-helper-64.exe",
				new MemoryInputStream.from_data (blob64.data, null),
				tempdir);
		}
	}
}
