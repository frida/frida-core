namespace Zid.Test {
	public class Process : Object {
		public void * handle {
			get;
			construct;
		}

		public long id {
			get;
			construct;
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

		public long join (uint timeout_msec = 0) throws IOError {
			return ProcessBackend.do_join (handle, timeout_msec);
		}
	}

	namespace ProcessBackend {
		private extern bool do_start (string filename, out void * handle, out long id);
		private extern long do_join (void * handle, uint timeout_msec) throws IOError;
	}
}
