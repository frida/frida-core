namespace Zed.Test {
	public class Process : Object {
		public int id {
			get;
			construct;
		}

		private Process (int id) {
			Object (id: id);
		}

		public static Process start (string filename) throws IOError {
			return new Process (ProcessBackend.do_start (filename));
		}

		public int join (uint timeout_msec = 0) throws IOError {
			return ProcessBackend.do_join (id, timeout_msec);
		}
	}

	namespace ProcessBackend {
		private extern int do_start (string filename) throws IOError;
		private extern int do_join (int pid, uint timeout_msec) throws IOError;
	}
}
