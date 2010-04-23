using Gee;

namespace Zed.Service {
	public class Winjector : Object {
		private HelperFactory normal_helper_factory = new HelperFactory (PrivilegeLevel.NORMAL);
		private HelperFactory elevated_helper_factory = new HelperFactory (PrivilegeLevel.ELEVATED);

		public async void inject (uint32 target_pid, string filename, Cancellable? cancellable = null) throws WinjectorError {
			/*
			var normal_helper = yield normal_helper_factory.obtain ();
			try {
				yield normal_helper.inject (target_pid, filename, cancellable);
			} catch (WinjectorError e) {
				var permission_error = new WinjectorError.PERMISSION_DENIED ("");
				if (e.code != permission_error.code)
					throw e;
			}
			*/

			var elevated_helper = yield elevated_helper_factory.obtain ();
			yield elevated_helper.inject (target_pid, filename, cancellable);
		}

		private class Helper {
			private TemporaryExecutable helper32;
			private TemporaryExecutable helper64;
			private ManagerProxy manager_proxy;

			private const uint ESTABLISH_TIMEOUT_MSEC = 1000;

			public Helper (TemporaryExecutable helper32, TemporaryExecutable helper64, ManagerProxy manager_proxy) {
				this.helper32 = helper32;
				this.helper64 = helper64;
				this.manager_proxy = manager_proxy;
			}

			public async void open () throws WinjectorError {
				try {
					yield manager_proxy.establish (ESTABLISH_TIMEOUT_MSEC);
				} catch (WinIpc.ProxyError e) {
					throw new WinjectorError.EXECUTE_FAILED (e.message);
				}
			}

			public async void inject (uint32 target_pid, string filename, Cancellable? cancellable) throws WinjectorError {
				print ("inject\n");
				yield manager_proxy.inject (target_pid, filename);
				print ("inject succeeded\n");
			}
		}

		private class ManagerProxy : WinIpc.ServerProxy {
			private const string INJECT_RESPONSE = "(bus)";

			public async void inject (uint32 target_pid, string dll_path) throws WinjectorError {
				Variant response;

				try {
					response = yield query ("Inject", new Variant ("(us)", target_pid, dll_path), INJECT_RESPONSE);
				} catch (WinIpc.ProxyError e) {
					throw new WinjectorError.FAILED (e.message);
				}

				bool success;
				uint error_code;
				string error_message;
				response.get (INJECT_RESPONSE, out success, out error_code, out error_message);
				if (!success) {
					var permission_error = new WinjectorError.PERMISSION_DENIED (error_message);
					if (error_code == permission_error.code)
						throw permission_error;
					else
						throw new WinjectorError.FAILED (error_message);
				}
			}
		}

		private enum PrivilegeLevel {
			NORMAL,
			ELEVATED
		}

		private class HelperFactory {
			private PrivilegeLevel level;
			private Helper helper;
			private ArrayList<ObtainRequest> obtain_requests = new ArrayList<ObtainRequest> ();

			public HelperFactory (PrivilegeLevel level) {
				this.level = level;
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
					var tempdir = new TemporaryDirectory ();
					var helper32 = new TemporaryExecutable (tempdir, "zed-winjector-helper-32", get_helper_32_data (), get_helper_32_size ());
					var helper64 = new TemporaryExecutable (tempdir, "zed-winjector-helper-64", get_helper_64_data (), get_helper_64_size ());

					var manager_proxy = new ManagerProxy ();
					helper32.execute ("MANAGER " + manager_proxy.address, level);

					instance = new Helper (helper32, helper64, manager_proxy);
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

			private static extern void * get_helper_32_data ();
			private static extern uint get_helper_32_size ();

			private static extern void * get_helper_64_data ();
			private static extern uint get_helper_64_size ();
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

		private class TemporaryExecutable {
			private TemporaryDirectory directory;
			private File file;

			public TemporaryExecutable (TemporaryDirectory directory, string name, void * data, uint size) throws WinjectorError {
				this.directory = directory;
				this.file = File.new_for_path (Path.build_filename (directory.path, name + ".exe"));

				try {
					var ostream = file.create (FileCreateFlags.NONE, null);
					size_t bytes_written;
					ostream.write_all (data, size, out bytes_written, null);
					ostream.close (null);
				} catch (Error e) {
					throw new WinjectorError.EXECUTE_FAILED (e.message);
				}
			}

			~TemporaryExecutable () {
				try {
					file.delete (null);
				} catch (Error e) {
				}
			}

			public extern void execute (string parameters, PrivilegeLevel level) throws WinjectorError;
		}
	}
}
