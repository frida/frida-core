namespace Frida {
	public class Winjector : Object, Injector {
		private ResourceStore _normal_resource_store;
		private ResourceStore _elevated_resource_store;

		private HelperFactory _normal_helper_factory = new HelperFactory (PrivilegeLevel.NORMAL);
		private HelperFactory _elevated_helper_factory = new HelperFactory (PrivilegeLevel.ELEVATED);

		private Gee.HashMap<uint, uint> pid_by_id = new Gee.HashMap<uint, uint> ();
		private Gee.HashMap<uint, TemporaryFile> blob_file_by_id = new Gee.HashMap<uint, TemporaryFile> ();
		private uint next_blob_id = 1;

		construct {
			_normal_helper_factory.uninjected.connect (on_uninjected);
			_elevated_helper_factory.uninjected.connect (on_uninjected);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			_normal_helper_factory.uninjected.disconnect (on_uninjected);
			_elevated_helper_factory.uninjected.disconnect (on_uninjected);

			yield _normal_helper_factory.close (cancellable);
			yield _elevated_helper_factory.close (cancellable);

			_normal_resource_store = null;
			_elevated_resource_store = null;
		}

		public ResourceStore get_normal_resource_store () throws Error {
			if (_normal_resource_store == null)
				_normal_resource_store = new ResourceStore ();
			return _normal_resource_store;
		}

		public ResourceStore get_elevated_resource_store () throws Error {
			if (_elevated_resource_store == null)
				_elevated_resource_store = new ResourceStore ();
			return _elevated_resource_store;
		}

		private HelperFactory get_normal_helper_factory () throws Error {
			if (_normal_helper_factory.resource_store == null)
				_normal_helper_factory.resource_store = get_normal_resource_store ();
			return _normal_helper_factory;
		}

		private HelperFactory get_elevated_helper_factory () throws Error {
			if (_elevated_helper_factory.resource_store == null)
				_elevated_helper_factory.resource_store = get_elevated_resource_store ();
			return _elevated_helper_factory;
		}

		public async uint inject_library_file (uint pid, string path, string entrypoint, string data, Cancellable? cancellable)
				throws Error, IOError {
			uint id = 0;

			var normal_factory = get_normal_helper_factory ();
			var normal_helper = yield normal_factory.obtain (cancellable);
			bool injected = false;
			try {
				id = yield normal_helper.inject_library_file (pid, path, entrypoint, data, cancellable);
				injected = true;
			} catch (Error inject_error) {
				if (!(inject_error is Error.PERMISSION_DENIED))
					throw inject_error;
			}

			if (!injected) {
				var elevated_factory = get_elevated_helper_factory ();
				HelperInstance elevated_helper;
				try {
					elevated_helper = yield elevated_factory.obtain (cancellable);
				} catch (Error elevate_error) {
					throw new Error.PERMISSION_DENIED (
						"Unable to access process with pid %u from the current user account".printf (pid));
				}
				id = yield elevated_helper.inject_library_file (pid, path, entrypoint, data, cancellable);
			}

			pid_by_id[id] = pid;

			return id;
		}

		public async uint inject_library_blob (uint pid, Bytes blob, string entrypoint, string data, Cancellable? cancellable)
				throws Error, IOError {
			uint id = 0;

			var name = "blob%u.dll".printf (next_blob_id++);
			var file = new TemporaryFile.from_stream (name, new MemoryInputStream.from_bytes (blob),
				get_normal_resource_store ().tempdir);

			var normal_factory = get_normal_helper_factory ();
			var normal_helper = yield normal_factory.obtain (cancellable);
			bool injected = false;
			try {
				id = yield normal_helper.inject_library_file (pid, file.path, entrypoint, data, cancellable);
				injected = true;
			} catch (Error inject_error) {
				if (!(inject_error is Error.PERMISSION_DENIED))
					throw inject_error;
			}

			if (!injected) {
				file = new TemporaryFile.from_stream (name, new MemoryInputStream.from_bytes (blob),
					get_elevated_resource_store ().tempdir);

				var elevated_factory = get_elevated_helper_factory ();
				HelperInstance elevated_helper;
				try {
					elevated_helper = yield elevated_factory.obtain (cancellable);
				} catch (Error elevate_error) {
					throw new Error.PERMISSION_DENIED (
						"Unable to access process with pid %u from the current user account".printf (pid));
				}
				id = yield elevated_helper.inject_library_file (pid, file.path, entrypoint, data, cancellable);
			}

			pid_by_id[id] = pid;
			blob_file_by_id[id] = file;

			return id;
		}

		public async uint inject_library_resource (uint pid, AgentDescriptor resource, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			uint id = 0;

			var path = get_normal_resource_store ().ensure_copy_of (resource);

			var normal_factory = get_normal_helper_factory ();
			var normal_helper = yield normal_factory.obtain (cancellable);
			bool injected = false;
			try {
				id = yield normal_helper.inject_library_file (pid, path, entrypoint, data, cancellable);
				injected = true;
			} catch (Error inject_error) {
				if (!(inject_error is Error.PERMISSION_DENIED))
					throw inject_error;
			}

			if (!injected) {
				path = get_elevated_resource_store ().ensure_copy_of (resource);

				var elevated_factory = get_elevated_helper_factory ();
				HelperInstance elevated_helper;
				try {
					elevated_helper = yield elevated_factory.obtain (cancellable);
				} catch (Error elevate_error) {
					throw new Error.PERMISSION_DENIED (
						"Unable to access process with pid %u from the current user account".printf (pid));
				}
				id = yield elevated_helper.inject_library_file (pid, path, entrypoint, data, cancellable);
			}

			pid_by_id[id] = pid;

			return id;
		}

		public async uint demonitor_and_clone_state (uint id, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not supported on this OS");
		}

		public async void recreate_thread (uint pid, uint id, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not supported on this OS");
		}

		public bool any_still_injected () {
			return !pid_by_id.is_empty;
		}

		public bool is_still_injected (uint id) {
			return pid_by_id.has_key (id);
		}

		private void on_uninjected (uint id) {
			pid_by_id.unset (id);
			blob_file_by_id.unset (id);

			uninjected (id);
		}

		private class HelperInstance {
			public signal void uninjected (uint id);

			private TemporaryFile helper32;
			private TemporaryFile helper64;
			private PipeTransport transport;
			private Future<IOStream> stream_request;
			private DBusConnection connection;
			private WinjectorHelper proxy;
			private void * process;

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
				} catch (GLib.Error e) {
					throw new Error.PERMISSION_DENIED ("%s", e.message);
				}

				try {
					proxy = yield connection.get_proxy (null, WinjectorObjectPath.HELPER, DBusProxyFlags.NONE,
						cancellable);
				} catch (IOError e) {
					throw new Error.PROTOCOL ("%s", e.message);
				}

				proxy.uninjected.connect (on_uninjected);
			}

			public async void close (Cancellable? cancellable) throws IOError {
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

			public async uint inject_library_file (uint pid, string path_template, string entrypoint, string data,
					Cancellable? cancellable) throws Error, IOError {
				try {
					return yield proxy.inject_library_file (pid, path_template, entrypoint, data, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
			}

			private void on_uninjected (uint id) {
				uninjected (id);
			}

			private extern static bool is_process_still_running (void * handle);
			private extern static void close_process_handle (void * handle);
		}

		protected enum PrivilegeLevel {
			NORMAL,
			ELEVATED
		}

		private class HelperFactory {
			public signal void uninjected (uint id);

			private PrivilegeLevel level;
			private MainContext main_context;

			private HelperInstance? helper;

			private Promise<HelperInstance>? obtain_request;
			private PipeTransport? transport;
			private Future<IOStream>? stream_request;

			private Cancellable io_cancellable = new Cancellable ();

			public ResourceStore? resource_store {
				get;
				set;
			}

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

					new Thread<bool> ("frida-winjector", obtain_worker);
				}

				return yield obtain_request.future.wait_async (cancellable);
			}

			private bool obtain_worker () {
				HelperInstance? instance = null;
				Error? error = null;

				try {
					string level_str = (level == PrivilegeLevel.ELEVATED) ? "ELEVATED" : "NORMAL";
					void * process = spawn (resource_store.helper32.path,
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

						helper = completed_instance;
						helper.uninjected.connect (on_uninjected);
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

			private void on_uninjected (uint id) {
				uninjected (id);
			}

			private extern static void * spawn (string path, string parameters, PrivilegeLevel level) throws Error;
		}

		public class ResourceStore {
			private extern static void set_acls_as_needed (string path) throws Error;

			public TemporaryDirectory tempdir {
				get;
				private set;
			}

			public TemporaryFile helper32 {
				get;
				private set;
			}

			public TemporaryFile helper64 {
				get;
				private set;
			}

			private Gee.HashMap<string, TemporaryAgent> agents = new Gee.HashMap<string, TemporaryAgent> ();
			private Gee.HashMap<string, TemporaryFile> resources = new Gee.HashMap<string, TemporaryFile> ();

			public ResourceStore () throws Error {
				tempdir = new TemporaryDirectory ();
				set_acls_as_needed (tempdir.path);

				var blob32 = Frida.Data.Winjector.get_winjector_helper_32_exe_blob ();
				helper32 = new TemporaryFile.from_stream ("frida-winjector-helper-32.exe",
					new MemoryInputStream.from_data (blob32.data, null),
					tempdir);

				var blob64 = Frida.Data.Winjector.get_winjector_helper_64_exe_blob ();
				helper64 = new TemporaryFile.from_stream ("frida-winjector-helper-64.exe",
					new MemoryInputStream.from_data (blob64.data, null),
					tempdir);
			}

			~ResourceStore () {
				foreach (var tempfile in agents.values)
					tempfile.destroy ();
				tempdir.destroy ();
			}

			public string ensure_copy_of (AgentDescriptor desc) throws Error {
				var temp_agent = agents[desc.name_template];
				if (temp_agent == null) {
					temp_agent = new TemporaryAgent (desc, tempdir);
					agents[desc.name_template] = temp_agent;
				}

				foreach (var resource in desc.resources) {
					var temp_resource = resources[resource.name];
					if (temp_resource == null) {
						temp_resource = new TemporaryFile.from_stream (resource.name, resource.data, tempdir);
						resources[resource.name] = temp_resource;
					}
				}

				return temp_agent.filename_template;
			}
		}

		private class TemporaryAgent {
			public string filename_template {
				get;
				private set;
			}

			private TemporaryFile dll32;
			private TemporaryFile dll64;

			public TemporaryAgent (AgentDescriptor desc, TemporaryDirectory tempdir) throws Error {
				filename_template = Path.build_filename (tempdir.path, desc.name_template);

				dll32 = new TemporaryFile.from_stream (desc.name_template.printf (32), desc.dll32, tempdir);
				dll64 = new TemporaryFile.from_stream (desc.name_template.printf (64), desc.dll64, tempdir);
			}

			~TemporaryAgent () {
				destroy ();
			}

			public void destroy () {
				if (dll32 != null) {
					dll32.destroy ();
					dll32 = null;
				}
				if (dll64 != null) {
					dll64.destroy ();
					dll64 = null;
				}
			}
		}
	}

	public class AgentDescriptor : Object {
		public string name_template {
			get;
			construct;
		}

		public InputStream dll32 {
			get {
				reset_stream (_dll32);
				return _dll32;
			}
		}
		private InputStream _dll32;

		public InputStream dll64 {
			get {
				reset_stream (_dll64);
				return _dll64;
			}
		}
		private InputStream _dll64;

		public AgentResource[] resources;

		public AgentDescriptor (string name_template, InputStream dll32, InputStream dll64) {
			Object (name_template: name_template);

			this._dll32 = dll32;
			this._dll64 = dll64;

			this.resources = new AgentResource[] {};
		}

		public AgentDescriptor.with_resources (string name_template, InputStream dll32, InputStream dll64,
				AgentResource[] resources) {
			Object (name_template: name_template);

			this._dll32 = dll32;
			this._dll64 = dll64;

			this.resources = resources;
		}

		private void reset_stream (InputStream stream) {
			try {
				((Seekable) stream).seek (0, SeekType.SET);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
		}
	}

	public class AgentResource : Object {
		public string name {
			get;
			construct;
		}

		public InputStream data {
			get {
				reset_stream (_data);
				return _data;
			}
		}
		private InputStream _data;

		public AgentResource (string name, InputStream data) {
			Object (name: name);

			_data = data;
		}

		private void reset_stream (InputStream stream) {
			try {
				((Seekable) stream).seek (0, SeekType.SET);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
		}
	}
}
