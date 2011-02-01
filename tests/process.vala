namespace Zed.Test {
	public class Process : Object {
		public void * handle {
			get;
			construct;
		}

		public ulong id {
			get;
			construct;
		}

		public unowned string filename {
			get {
				if (_filename == null) {
					_filename = ProcessBackend.filename_of (handle);
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

		private Process (void * handle, ulong id) {
			Object (handle: handle, id: id);
		}

		public static Process start (string filename) throws IOError {
			void * handle;
			ulong id;
			ProcessBackend.do_start (filename, out handle, out id);
			return new Process (handle, id);
		}

		public int join (uint timeout_msec = 0) throws IOError {
			return ProcessBackend.do_join (handle, timeout_msec);
		}
	}

	namespace ProcessBackend {
		private extern void * self_handle ();
		private extern ulong self_id ();
		private extern string filename_of (void * handle);
		private extern void do_start (string filename, out void * handle, out ulong id) throws IOError;
		private extern int do_join (void * handle, uint timeout_msec) throws IOError;
	}
}
