namespace Frida {
	public class WindowsHelperBackend : Object, WindowsHelper {
		private MainContext main_context;

		private Promise<bool> close_request;
		private uint pending = 0;

		construct {
			main_context = MainContext.get_thread_default ();
		}

		public async void close (Cancellable? cancellable) throws IOError {
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

			if (pending == 0) {
				close_request.resolve (true);
				return;
			}

			try {
				yield close_request.future.wait_async (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}
		}

		public async void inject_library_file (uint pid, PathTemplate path_template, string entrypoint, string data, uint id,
				Cancellable? cancellable) throws Error {
			string path = path_template.expand (WindowsProcess.is_x64 (pid) ? "64" : "32");

			void * instance, waitable_thread_handle;
			_inject_library_file (pid, path, entrypoint, data, out instance, out waitable_thread_handle);
			if (waitable_thread_handle != null) {
				pending++;
				var source = WaitHandleSource.create (waitable_thread_handle, true);
				source.set_callback (() => {
					bool is_resident;
					_free_inject_instance (instance, out is_resident);

					uninjected (id);

					pending--;
					if (close_request != null && pending == 0)
						close_request.resolve (true);

					return false;
				});
				source.attach (main_context);
			}
		}

		protected extern static void _inject_library_file (uint32 pid, string path, string entrypoint, string data,
			out void * inject_instance, out void * waitable_thread_handle) throws Error;
		protected extern static void _free_inject_instance (void * inject_instance, out bool is_resident);
	}

	namespace WindowsSystem {
		public extern static bool is_x64 ();
	}

	namespace WindowsProcess {
		public extern static bool is_x64 (uint32 pid) throws Error;
	}

	namespace WaitHandleSource {
		public extern Source create (void * handle, bool owns_handle);
	}
}
