namespace Frida.Test {
	public class Process : Object {
		public void * handle {
			get;
			construct;
		}

		public uint id {
			get;
			construct;
		}

		public unowned string filename {
			get {
				if (_filename == null) {
					_filename = ProcessBackend.filename_of (handle).replace ("/./", "/");
				}

				return _filename;
			}
		}
		private string _filename = null;

		public static Process current {
			owned get {
				return new Process (ProcessBackend.self_handle (), ProcessBackend.self_id ());
			}
		}

		private Process (void * handle, uint id) {
			Object (handle: handle, id: id);
		}

		public static Process start (string path, string[] argv, string[] envp, Arch arch) throws IOError {
			void * handle;
			uint id;
			ProcessBackend.do_start (path, argv, envp, arch, out handle, out id);
			return new Process (handle, id);
		}

		public int join (uint timeout_msec = 0) throws IOError {
			return ProcessBackend.do_join (handle, timeout_msec);
		}
	}

	namespace ProcessBackend {
		private extern void * self_handle ();
		private extern uint self_id ();
		private extern string filename_of (void * handle);
		private extern void do_start (string path, string[] argv, string[] envp, Arch arch, out void * handle, out uint id) throws IOError;
		private extern int do_join (void * handle, uint timeout_msec) throws IOError;
	}
}
