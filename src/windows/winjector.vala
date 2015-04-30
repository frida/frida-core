#if WINDOWS
namespace Frida {
	public class Winjector : Object {
		private ResourceStore normal_resource_store;
		private HelperFactory normal_helper_factory = new HelperFactory (PrivilegeLevel.NORMAL);

		private ResourceStore elevated_resource_store;
		private HelperFactory elevated_helper_factory = new HelperFactory (PrivilegeLevel.ELEVATED);

		public async void close () {
			yield normal_helper_factory.close ();
			yield elevated_helper_factory.close ();

			normal_resource_store = null;
			elevated_resource_store = null;
		}

		public async void inject (uint pid, AgentDescriptor desc, string data_string) throws Error {
			if (normal_resource_store == null) {
				normal_resource_store = new ResourceStore ();
				normal_helper_factory.resource_store = normal_resource_store;
			}

			var filename = normal_resource_store.ensure_copy_of (desc);

			bool injected = false;

			var normal_helper = yield normal_helper_factory.obtain ();
			try {
				yield normal_helper.inject (pid, filename, data_string);
				injected = true;
			} catch (Error inject_error) {
				if (!(inject_error is Error.PERMISSION_DENIED))
					throw inject_error;
			}

			if (!injected) {
				if (elevated_resource_store == null) {
					elevated_resource_store = new ResourceStore ();
					elevated_helper_factory.resource_store = elevated_resource_store;
				}

				filename = elevated_resource_store.ensure_copy_of (desc);

				HelperInstance elevated_helper;
				try {
					elevated_helper = yield elevated_helper_factory.obtain ();
				} catch (Error elevate_error) {
					throw new Error.PERMISSION_DENIED ("Unable to access process with pid %u from the current user account".printf (pid));
				}
				yield elevated_helper.inject (pid, filename, data_string);
			}
		}

		private class HelperInstance {
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
					connection = yield DBusConnection.new (pipe, null, DBusConnectionFlags.NONE);
				} catch (GLib.Error e) {
					throw new Error.PERMISSION_DENIED (e.message);
				}

				try {
					proxy = yield connection.get_proxy (null, WinjectorObjectPath.HELPER);
				} catch (IOError e) {
					throw new Error.PROTOCOL (e.message);
				}
			}

			public async void close () {
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

			public async void inject (uint pid, string filename_template, string data_string) throws Error {
				try {
					yield proxy.inject (pid, filename_template, data_string);
				} catch (GLib.Error e) {
					throw Marshal.from_dbus (e);
				}
			}

			private static extern bool is_process_still_running (void * handle);
			private static extern void close_process_handle (void * handle);
		}

		protected enum PrivilegeLevel {
			NORMAL,
			ELEVATED
		}

		private class HelperFactory {
			private PrivilegeLevel level;
			private MainContext main_context;
			private HelperInstance helper;
			private Gee.ArrayList<ObtainRequest> obtain_requests = new Gee.ArrayList<ObtainRequest> ();

			public ResourceStore resource_store {
				get;
				set;
			}

			public HelperFactory (PrivilegeLevel level) {
				this.level = level;
				this.main_context = MainContext.get_thread_default ();
			}

			public async void close () {
				if (helper != null) {
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

				foreach (var request in obtain_requests)
					request.complete (completed_instance, completed_error);
				obtain_requests.clear ();
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

		private class ResourceStore {
			private TemporaryDirectory tempdir;

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

			construct {
				_dll32 = value;
			}
		}
		private InputStream _dll32;

		public InputStream dll64 {
			get {
				reset_stream (_dll64);
				return _dll64;
			}

			construct {
				_dll64 = value;
			}
		}
		private InputStream _dll64;

		public AgentResource[] resources {
			get;
			private set;
		}

		public AgentDescriptor (string name_template, InputStream dll32, InputStream dll64) {
			AgentDescriptor.with_resources (name_template, dll32, dll64, new AgentResource[] {});
		}

		public AgentDescriptor.with_resources (string name_template, InputStream dll32, InputStream dll64, AgentResource[] resources) {
			Object (name_template: name_template, dll32: dll32, dll64: dll64);

			assert (dll32 is Seekable);
			assert (dll64 is Seekable);

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

			construct {
				_data = value;
			}
		}
		private InputStream _data;

		public AgentResource (string name, InputStream data) {
			Object (name: name, data: data);

			assert (data is Seekable);
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
#endif
