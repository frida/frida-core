using Gee;

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

		public async void inject (uint pid, AgentDescriptor desc, string data_string, Cancellable? cancellable = null) throws IOError {
			if (normal_resource_store == null) {
				normal_resource_store = new ResourceStore ();
				normal_helper_factory.resource_store = normal_resource_store;
			}

			var filename = normal_resource_store.ensure_copy_of (desc);

			bool injected = false;

			var normal_helper = yield normal_helper_factory.obtain ();
			try {
				yield normal_helper.inject (pid, filename, data_string, cancellable);
				injected = true;
			} catch (IOError inject_error) {
				var permission_error = new IOError.PERMISSION_DENIED ("");
				if (inject_error.code != permission_error.code)
					throw inject_error;
			}

			if (!injected) {
				if (elevated_resource_store == null) {
					elevated_resource_store = new ResourceStore ();
					elevated_helper_factory.resource_store = elevated_resource_store;
				}

				filename = elevated_resource_store.ensure_copy_of (desc);

				var elevated_helper = yield elevated_helper_factory.obtain ();
				yield elevated_helper.inject (pid, filename, data_string, cancellable);
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

			private const uint ESTABLISH_TIMEOUT_MSEC = 30 * 1000;

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

			public async void open () throws IOError {
				try {
					connection = yield DBusConnection.new_for_stream (pipe, null, DBusConnectionFlags.NONE);
				} catch (Error e) {
					throw new IOError.FAILED (e.message);
				}
				proxy = yield connection.get_proxy (null, WinjectorObjectPath.HELPER);
			}

			public async void close () {
				try {
					yield proxy.stop ();
				} catch (IOError e) {
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

			public async void inject (uint pid, string filename_template, string data_string, Cancellable? cancellable) throws IOError {
				yield proxy.inject (pid, filename_template, data_string);
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
			private ArrayList<ObtainRequest> obtain_requests = new ArrayList<ObtainRequest> ();

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

			public async HelperInstance obtain () throws IOError {
				if (helper != null)
					return helper;

				if (obtain_requests.size == 0) {
					try {
						Thread.create<bool> (obtain_worker, false);
					} catch (ThreadError e) {
						error (e.message);
					}
				}

				var request = new ObtainRequest (() => obtain.callback ());
				obtain_requests.add (request);
				yield;

				return request.get_result ();
			}

			private bool obtain_worker () {
				HelperInstance instance = null;
				IOError error = null;

				try {
					var transport = new PipeTransport.with_pid (0);
					var pipe = new Pipe (transport.local_address);
					void * process = resource_store.helper32.execute ("MANAGER " + transport.remote_address, level);
					instance = new HelperInstance (resource_store.helper32, resource_store.helper64, transport, pipe, process);
				} catch (IOError e) {
					error = e;
				}

				var source = new IdleSource ();
				source.set_callback (() => {
					complete_obtain (instance, error);
					return false;
				});
				source.attach (main_context);

				return error == null;
			}

			private async void complete_obtain (HelperInstance? instance, IOError? error) {
				HelperInstance completed_instance = instance;
				IOError completed_error = error;

				if (instance != null) {
					try {
						yield instance.open ();
					} catch (IOError e) {
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
				private IOError error;

				public ObtainRequest (owned CompletionHandler handler) {
					this.handler = (owned) handler;
				}

				public void complete (HelperInstance? helper, IOError? error) {
					this.helper = helper;
					this.error = error;
					handler ();
				}

				public HelperInstance get_result () throws IOError {
					if (helper == null)
						throw error;
					return helper;
				}
			}
		}

		private class ResourceStore {
			private TemporaryDirectory tempdir = new TemporaryDirectory ();

			public TemporaryFile helper32 {
				get;
				private set;
			}

			public TemporaryFile helper64 {
				get;
				private set;
			}

			private HashMap<string, TemporaryAgent> agents = new HashMap<string, TemporaryAgent> ();

			public ResourceStore () throws IOError {
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

			public string ensure_copy_of (AgentDescriptor desc) throws IOError {
				var temp_agent = agents[desc.name_template];
				if (temp_agent == null) {
					temp_agent = new TemporaryAgent (desc, tempdir);
					agents[desc.name_template] = temp_agent;
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

			public TemporaryAgent (AgentDescriptor desc, TemporaryDirectory tempdir) throws IOError {
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

		protected class TemporaryDirectory {
			public string path {
				get;
				private set;
			}

			public TemporaryDirectory () {
				path = create_tempdir ();
			}

			~TemporaryDirectory () {
				destroy ();
			}

			public void destroy () {
				destroy_tempdir (path);
			}

			private static extern string create_tempdir ();
			private static extern void destroy_tempdir (string path);
		}

		protected class TemporaryFile {
			protected File file;
			private TemporaryDirectory directory;

			public TemporaryFile.from_stream (string name, InputStream istream, TemporaryDirectory directory) throws IOError {
				this.file = File.new_for_path (Path.build_filename (directory.path, name));
				this.directory = directory;

				try {
					var ostream = file.create (FileCreateFlags.NONE, null);

					var buf_size = 128 * 1024;
					var buf = new uint8[buf_size];

					while (true) {
						var bytes_read = istream.read (buf);
						if (bytes_read == 0)
							break;
						buf.resize ((int) bytes_read);

						size_t bytes_written;
						ostream.write_all (buf, out bytes_written);
					}

					ostream.close (null);
				} catch (Error e) {
					throw new IOError.FAILED (e.message);
				}
			}

			private TemporaryFile (File file, TemporaryDirectory directory) {
				this.file = file;
				this.directory = directory;
			}

			~TemporaryFile () {
				destroy ();
			}

			public void destroy () {
				if (file != null) {
					try {
						file.delete (null);
					} catch (Error e) {
					}
					file = null;
				}
				directory = null;
			}

			public extern void * execute (string parameters, PrivilegeLevel level) throws IOError;
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

		public AgentDescriptor (string name_template, InputStream dll32, InputStream dll64) {
			Object (name_template: name_template, dll32: dll32, dll64: dll64);

			assert (dll32 is Seekable);
			assert (dll64 is Seekable);
		}

		private void reset_stream (InputStream stream) {
			try {
				(stream as Seekable).seek (0, SeekType.SET);
			} catch (Error e) {
				assert_not_reached ();
			}
		}
	}
}
