using Gee;

namespace Zed.Service {
	public class Winjector : Object {
		private ResourceStore resource_store;
		private HelperFactory normal_helper_factory = new HelperFactory (PrivilegeLevel.NORMAL);
		private HelperFactory elevated_helper_factory = new HelperFactory (PrivilegeLevel.ELEVATED);

		public async void close () {
			yield normal_helper_factory.close ();
			yield elevated_helper_factory.close ();
		}

		public async WinIpc.Proxy inject (uint32 target_pid, AgentDescriptor desc, Cancellable? cancellable = null) throws WinjectorError {
			if (resource_store == null) {
				resource_store = new ResourceStore ();

				normal_helper_factory.resource_store = resource_store;
				elevated_helper_factory.resource_store = resource_store;
			}

			var filename = resource_store.ensure_copy_of (desc);

			var proxy = new WinIpc.ServerProxy ();

			bool injected = false;

			var normal_helper = yield normal_helper_factory.obtain ();
			try {
				yield normal_helper.inject (target_pid, filename, proxy.address, cancellable);
				injected = true;
			} catch (WinjectorError inject_error) {
				var permission_error = new WinjectorError.ACCESS_DENIED ("");
				if (inject_error.code != permission_error.code)
					throw inject_error;
			}

			if (!injected) {
				var elevated_helper = yield elevated_helper_factory.obtain ();
				yield elevated_helper.inject (target_pid, filename, proxy.address, cancellable);
			}

			try {
				yield proxy.establish ();
			} catch (WinIpc.ProxyError proxy_error) {
				throw new WinjectorError.FAILED (proxy_error.message);
			}

			return proxy;
		}

		private class Helper {
			private TemporaryFile helper32;
			private TemporaryFile helper64;
			private WinIpc.ServerProxy manager_proxy;
			private void * manager_process;

			private const uint ESTABLISH_TIMEOUT_MSEC = 30 * 1000;

			public Helper (TemporaryFile helper32, TemporaryFile helper64, WinIpc.ServerProxy manager_proxy, void * manager_process) {
				this.helper32 = helper32;
				this.helper64 = helper64;
				this.manager_proxy = manager_proxy;
				this.manager_process = manager_process;
			}

			~Helper () {
				if (manager_process != null)
					close_process_handle (manager_process);
			}

			public async void open () throws WinjectorError {
				try {
					yield manager_proxy.establish (ESTABLISH_TIMEOUT_MSEC);
				} catch (WinIpc.ProxyError e) {
					throw new WinjectorError.EXECUTE_FAILED (e.message);
				}
			}

			public async void close () {
				try {
					yield manager_proxy.emit ("Stop");
				} catch (WinIpc.ProxyError e) {
				}

				if (is_process_still_running (manager_process)) {
					Timeout.add (10, () => {
						if (is_process_still_running (manager_process))
							return true; /* wait and try again */
						close.callback ();
						return false;
					});
					yield;
				}

				close_process_handle (manager_process);
				manager_process = null;
			}

			public async void inject (uint32 target_pid, string filename_template, string ipc_server_address, Cancellable? cancellable) throws WinjectorError {
				yield WinjectorIpc.invoke_inject (target_pid, filename_template, ipc_server_address, manager_proxy);
			}

			private static extern bool is_process_still_running (void * handle);
			private static extern void close_process_handle (void * handle);
		}

		private enum PrivilegeLevel {
			NORMAL,
			ELEVATED
		}

		private class HelperFactory {
			private PrivilegeLevel level;
			private Helper helper;
			private ArrayList<ObtainRequest> obtain_requests = new ArrayList<ObtainRequest> ();

			public ResourceStore resource_store {
				get;
				set;
			}

			public HelperFactory (PrivilegeLevel level) {
				this.level = level;
			}

			public async void close () {
				if (helper != null) {
					yield helper.close ();
					helper = null;
				}
			}

			public async Helper obtain () throws WinjectorError {
				if (helper != null)
					return helper;

				if (obtain_requests.size == 0) {
					try {
						Thread.create (obtain_worker, false);
					} catch (ThreadError e) {
						error (e.message);
					}
				}

				var request = new ObtainRequest (() => obtain.callback ());
				obtain_requests.add (request);
				yield;

				return request.get_result ();
			}

			private void * obtain_worker () {
				Helper instance = null;
				WinjectorError error = null;

				try {
					var manager_proxy = new WinIpc.ServerProxy ();
					void * manager_process = resource_store.helper32.execute ("MANAGER " + manager_proxy.address, level);

					instance = new Helper (resource_store.helper32, resource_store.helper64, manager_proxy, manager_process);
				} catch (WinjectorError e) {
					error = e;
				}

				Idle.add (() => {
					complete_obtain (instance, error);
					return false;
				});

				return null;
			}

			private async void complete_obtain (Helper? instance, WinjectorError? error) {
				Helper completed_instance = instance;
				WinjectorError completed_error = error;

				if (instance != null) {
					try {
						yield instance.open ();
					} catch (WinjectorError e) {
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

				private Helper helper;
				private WinjectorError error;

				public ObtainRequest (CompletionHandler handler) {
					this.handler = handler;
				}

				public void complete (Helper? helper, WinjectorError? error) {
					this.helper = helper;
					this.error = error;
					handler ();
				}

				public Helper get_result () throws WinjectorError {
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

			public ResourceStore () throws WinjectorError {
				helper32 = new TemporaryFile.from_stream ("zed-winjector-helper-32.exe",
					new MemoryInputStream.from_data (get_helper_32_data (), get_helper_32_size (), null),
					tempdir);
				helper64 = new TemporaryFile.from_stream ("zed-winjector-helper-64.exe",
					new MemoryInputStream.from_data (get_helper_64_data (), get_helper_64_size (), null),
					tempdir);
			}

			public string ensure_copy_of (AgentDescriptor desc) throws WinjectorError {
				var temp_agent = agents[desc.name_template];
				if (temp_agent == null) {
					temp_agent = new TemporaryAgent (desc, tempdir);
					agents[desc.name_template] = temp_agent;
				}

				return temp_agent.filename_template;
			}

			private static extern void * get_helper_32_data ();
			private static extern uint get_helper_32_size ();

			private static extern void * get_helper_64_data ();
			private static extern uint get_helper_64_size ();
		}

		private class TemporaryAgent {
			public string filename_template {
				get;
				private set;
			}

			private TemporaryFile dll32;
			private TemporaryFile dll64;

			public TemporaryAgent (AgentDescriptor desc, TemporaryDirectory tempdir) throws WinjectorError {
				filename_template = Path.build_filename (tempdir.path, desc.name_template);

				dll32 = new TemporaryFile.from_stream (desc.name_template.printf (32), desc.dll32, tempdir);
				dll64 = new TemporaryFile.from_stream (desc.name_template.printf (64), desc.dll64, tempdir);
			}
		}

		private class TemporaryDirectory {
			public string path {
				get;
				private set;
			}

			public TemporaryDirectory () {
				path = create_tempdir ();
			}

			~TemporaryDirectory () {
				destroy_tempdir (path);
			}

			private static extern string create_tempdir ();
			private static extern void destroy_tempdir (string path);
		}

		private class TemporaryFile {
			private File file;
			private TemporaryDirectory directory;

			public TemporaryFile.from_stream (string name, InputStream istream, TemporaryDirectory directory) throws WinjectorError {
				this.file = File.new_for_path (Path.build_filename (directory.path, name));
				this.directory = directory;

				try {
					var ostream = file.create (FileCreateFlags.NONE, null);

					var buf_size = 128 * 1024;
					var buf = new uint8[buf_size];

					while (true) {
						var bytes_read = istream.read (buf, buf_size, null);
						if (bytes_read == 0)
							break;

						size_t bytes_written;
						ostream.write_all (buf, bytes_read, out bytes_written, null);
					}

					ostream.close (null);
				} catch (Error e) {
					throw new WinjectorError.FAILED (e.message);
				}
			}

			private TemporaryFile (File file, TemporaryDirectory directory) {
				this.file = file;
				this.directory = directory;
			}

			~TemporaryFile () {
				try {
					file.delete (null);
				} catch (Error e) {
				}
			}

			public extern void * execute (string parameters, PrivilegeLevel level) throws WinjectorError;
		}
	}

	public class AgentDescriptor : Object {
		public string name_template {
			get;
			construct;
		}

		public InputStream dll32 {
			get;
			construct;
		}

		public InputStream dll64 {
			get;
			construct;
		}

		public AgentDescriptor (string name_template, InputStream dll32, InputStream dll64) {
			Object (name_template: name_template, dll32: dll32, dll64: dll64);
		}
	}
}
