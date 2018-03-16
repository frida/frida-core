namespace Frida {
	public class Winjector : Object, Injector {
		public ResourceStore normal_resource_store {
			get {
				if (_normal_resource_store == null) {
					try {
						_normal_resource_store = new ResourceStore ();
					} catch (Error e) {
						assert_not_reached ();
					}
				}
				return _normal_resource_store;
			}
		}
		private ResourceStore _normal_resource_store;

		public ResourceStore elevated_resource_store {
			get {
				if (_elevated_resource_store == null) {
					try {
						_elevated_resource_store = new ResourceStore ();
					} catch (Error e) {
						assert_not_reached ();
					}
				}
				return _elevated_resource_store;
			}
		}
		private ResourceStore _elevated_resource_store;

		private HelperFactory normal_helper_factory {
			get {
				if (_normal_helper_factory.resource_store == null)
					_normal_helper_factory.resource_store = normal_resource_store;
				return _normal_helper_factory;
			}
		}
		private HelperFactory _normal_helper_factory = new HelperFactory (PrivilegeLevel.NORMAL);

		private HelperFactory elevated_helper_factory {
			get {
				if (_elevated_helper_factory.resource_store == null)
					_elevated_helper_factory.resource_store = elevated_resource_store;
				return _elevated_helper_factory;
			}
		}
		private HelperFactory _elevated_helper_factory = new HelperFactory (PrivilegeLevel.ELEVATED);

		private Gee.HashMap<uint, uint> pid_by_id = new Gee.HashMap<uint, uint> ();
		private Gee.HashMap<uint, TemporaryFile> blob_file_by_id = new Gee.HashMap<uint, TemporaryFile> ();
		private uint next_blob_id = 1;

		construct {
			_normal_helper_factory.uninjected.connect (on_uninjected);
			_elevated_helper_factory.uninjected.connect (on_uninjected);
		}

		public async void close () {
			_normal_helper_factory.uninjected.disconnect (on_uninjected);
			_elevated_helper_factory.uninjected.disconnect (on_uninjected);

			yield _normal_helper_factory.close ();
			yield _elevated_helper_factory.close ();

			_normal_resource_store = null;
			_elevated_resource_store = null;
		}

		public async uint inject_library_file (uint pid, string path, string entrypoint, string data) throws Error {
			uint id = 0;

			var normal_helper = yield normal_helper_factory.obtain ();
			bool injected = false;
			try {
				id = yield normal_helper.inject_library_file (pid, path, entrypoint, data);
				injected = true;
			} catch (Error inject_error) {
				if (!(inject_error is Error.PERMISSION_DENIED))
					throw inject_error;
			}

			if (!injected) {
				HelperInstance elevated_helper;
				try {
					elevated_helper = yield elevated_helper_factory.obtain ();
				} catch (Error elevate_error) {
					throw new Error.PERMISSION_DENIED ("Unable to access process with pid %u from the current user account".printf (pid));
				}
				id = yield elevated_helper.inject_library_file (pid, path, entrypoint, data);
			}

			pid_by_id[id] = pid;

			return id;
		}

		public async uint inject_library_blob (uint pid, Bytes blob, string entrypoint, string data) throws Error {
			uint id = 0;

			var name = "blob%u.dll".printf (next_blob_id++);
			var file = new TemporaryFile.from_stream (name, new MemoryInputStream.from_bytes (blob), normal_resource_store.tempdir);

			var normal_helper = yield normal_helper_factory.obtain ();
			bool injected = false;
			try {
				id = yield normal_helper.inject_library_file (pid, file.path, entrypoint, data);
				injected = true;
			} catch (Error inject_error) {
				if (!(inject_error is Error.PERMISSION_DENIED))
					throw inject_error;
			}

			if (!injected) {
				file = new TemporaryFile.from_stream (name, new MemoryInputStream.from_bytes (blob), elevated_resource_store.tempdir);

				HelperInstance elevated_helper;
				try {
					elevated_helper = yield elevated_helper_factory.obtain ();
				} catch (Error elevate_error) {
					throw new Error.PERMISSION_DENIED ("Unable to access process with pid %u from the current user account".printf (pid));
				}
				id = yield elevated_helper.inject_library_file (pid, file.path, entrypoint, data);
			}

			pid_by_id[id] = pid;
			blob_file_by_id[id] = file;

			return id;
		}

		public async uint inject_library_resource (uint pid, AgentDescriptor resource, string entrypoint, string data) throws Error {
			uint id = 0;

			var path = normal_resource_store.ensure_copy_of (resource);

			var normal_helper = yield normal_helper_factory.obtain ();
			bool injected = false;
			try {
				id = yield normal_helper.inject_library_file (pid, path, entrypoint, data);
				injected = true;
			} catch (Error inject_error) {
				if (!(inject_error is Error.PERMISSION_DENIED))
					throw inject_error;
			}

			if (!injected) {
				path = elevated_resource_store.ensure_copy_of (resource);

				HelperInstance elevated_helper;
				try {
					elevated_helper = yield elevated_helper_factory.obtain ();
				} catch (Error elevate_error) {
					throw new Error.PERMISSION_DENIED ("Unable to access process with pid %u from the current user account".printf (pid));
				}
				id = yield elevated_helper.inject_library_file (pid, path, entrypoint, data);
			}

			pid_by_id[id] = pid;

			return id;
		}

		public async uint demonitor_and_clone_state (uint id) throws Error {
			throw new Error.NOT_SUPPORTED ("Not supported on this OS");
		}

		public async void recreate_thread (uint pid, uint id) throws Error {
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
			private Pipe pipe;
			private DBusConnection connection;
			private WinjectorHelper proxy;
			private void * process;

			public HelperInstance (TemporaryFile helper32, TemporaryFile helper64, PipeTransport transport, Pipe pipe, void * process) {
				this.helper32 = helper32;
				this.helper64 = helper64;
				this.transport = transport;
				this.pipe = pipe;
				this.process = process;
			}

			~HelperInstance () {
				if (process != null)
					close_process_handle (process);
			}

			public async void open () throws Error {
				try {
					connection = yield new DBusConnection (pipe, null, DBusConnectionFlags.NONE);
				} catch (GLib.Error e) {
					throw new Error.PERMISSION_DENIED (e.message);
				}

				try {
					proxy = yield connection.get_proxy (null, WinjectorObjectPath.HELPER);
				} catch (IOError e) {
					throw new Error.PROTOCOL (e.message);
				}

				proxy.uninjected.connect (on_uninjected);
			}

			public async void close () {
				proxy.uninjected.disconnect (on_uninjected);

				try {
					yield proxy.stop ();
				} catch (GLib.Error e) {
				}

				if (is_process_still_running (process)) {
					var source = new TimeoutSource (50);
					source.set_callback (() => {
						if (is_process_still_running (process))
							return true; /* wait and try again */
						close.callback ();
						return false;
					});
					source.attach (MainContext.get_thread_default ());
					yield;
				}

				close_process_handle (process);
				process = null;

				/* HACK: give it a bit more time */
				var delay = new TimeoutSource (20);
				delay.set_callback (() => {
					close.callback ();
					return false;
				});
				delay.attach (MainContext.get_thread_default ());
				yield;
			}

			public async uint inject_library_file (uint pid, string path_template, string entrypoint, string data) throws Error {
				try {
					return yield proxy.inject_library_file (pid, path_template, entrypoint, data);
				} catch (GLib.Error e) {
					throw Marshal.from_dbus (e);
				}
			}

			private void on_uninjected (uint id) {
				uninjected (id);
			}

			private static extern bool is_process_still_running (void * handle);
			private static extern void close_process_handle (void * handle);
		}

		protected enum PrivilegeLevel {
			NORMAL,
			ELEVATED
		}

		private class HelperFactory {
			public signal void uninjected (uint id);

			private PrivilegeLevel level;
			private MainContext main_context;
			private HelperInstance helper;
			private Gee.ArrayList<ObtainRequest> obtain_requests = new Gee.ArrayList<ObtainRequest> ();

			public ResourceStore? resource_store {
				get;
				set;
			}

			public HelperFactory (PrivilegeLevel level) {
				this.level = level;
				this.main_context = MainContext.get_thread_default ();
			}

			public async void close () {
				if (helper != null) {
					helper.uninjected.disconnect (on_uninjected);

					yield helper.close ();
					helper = null;
				}

				resource_store = null;
			}

			public async HelperInstance obtain () throws Error {
				if (helper != null)
					return helper;

				if (obtain_requests.size == 0) {
					new Thread<bool> ("frida-winjector", obtain_worker);
				}

				var request = new ObtainRequest (() => obtain.callback ());
				obtain_requests.add (request);
				yield;

				return request.get_result ();
			}

			private bool obtain_worker () {
				HelperInstance instance = null;
				Error error = null;

				try {
					var transport = new PipeTransport ();
					var pipe = new Pipe (transport.local_address);
					var level_str = (level == PrivilegeLevel.ELEVATED) ? "ELEVATED" : "NORMAL";
					void * process = spawn (resource_store.helper32.path, "MANAGER %s %s".printf (level_str, transport.remote_address), level);
					instance = new HelperInstance (resource_store.helper32, resource_store.helper64, transport, pipe, process);
				} catch (Error e) {
					error = e;
				} catch (IOError e) {
					error = new Error.PERMISSION_DENIED (e.message);
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
				HelperInstance completed_instance = instance;
				Error completed_error = error;

				if (instance != null) {
					try {
						yield instance.open ();
					} catch (Error e) {
						completed_instance = null;
						completed_error = e;
					}
				}

				this.helper = completed_instance;
				this.helper.uninjected.connect (on_uninjected);

				foreach (var request in obtain_requests)
					request.complete (completed_instance, completed_error);
				obtain_requests.clear ();
			}

			private void on_uninjected (uint id) {
				uninjected (id);
			}

			private class ObtainRequest {
				public delegate void CompletionHandler ();
				private CompletionHandler handler;

				private HelperInstance helper;
				private Error error;

				public ObtainRequest (owned CompletionHandler handler) {
					this.handler = (owned) handler;
				}

				public void complete (HelperInstance? helper, Error? error) {
					this.helper = helper;
					this.error = error;
					handler ();
				}

				public HelperInstance get_result () throws Error {
					if (helper == null)
						throw error;
					return helper;
				}
			}

			private static extern void * spawn (string path, string parameters, PrivilegeLevel level) throws Error;
		}

		public class ResourceStore {
			private static extern void set_acls_as_needed (string path) throws Error;

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

		public AgentResource[] resources {
			get;
			private set;
		}

		public AgentDescriptor (string name_template, InputStream dll32, InputStream dll64) {
			Object (name_template: name_template);

			this._dll32 = dll32;
			this._dll64 = dll64;

			this.resources = new AgentResource[] {};
		}

		public AgentDescriptor.with_resources (string name_template, InputStream dll32, InputStream dll64, AgentResource[] resources) {
			Object (name_template: name_template);

			this._dll32 = dll32;
			this._dll64 = dll64;

			this.resources = resources;
		}

		private void reset_stream (InputStream stream) {
			try {
				(stream as Seekable).seek (0, SeekType.SET);
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
				(stream as Seekable).seek (0, SeekType.SET);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
		}
	}
}
