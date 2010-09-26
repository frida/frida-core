namespace Zed.Test {
	public class Process : Object {
		public void * handle {
			get;
			construct;
		}

		public long id {
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

		private Process (void * handle, long id) {
			Object (handle: handle, id: id);
		}

		public static Process? start (string filename) {
			void * handle;
			long id;
			if (ProcessBackend.do_start (filename, out handle, out id))
				return new Process (handle, id);
			else
				return null;
		}

		public long join (uint timeout_msec = 0) throws ProcessError {
			return ProcessBackend.do_join (handle, timeout_msec);
		}
	}

	public errordomain ProcessError {
		TIMED_OUT
	}

	namespace ProcessBackend {
		private extern void * self_handle ();
		private extern long self_id ();
		private extern string filename_of (void * handle);
		private extern bool do_start (string filename, out void * handle, out long id);
		private extern long do_join (void * handle, uint timeout_msec) throws ProcessError;
	}
}
