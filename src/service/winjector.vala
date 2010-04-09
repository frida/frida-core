using Gee;

namespace Zed.Service {
	public class Winjector : Object {
		private Mutex mutex = new Mutex ();
		private Cond cond = new Cond ();

		private unowned Thread worker_thread;
		private ArrayList<void *> requests = new ArrayList<void *> ();

		private void * helper_tempdir;
		private void * helper32;
		private void * helper64;

		~Winjector () {
			if (worker_thread != null) {
				mutex.lock ();
				unowned Thread thread = worker_thread;
				worker_thread = null;
				cond.signal ();
				mutex.unlock ();

				thread.join ();
			}

			assert (requests.size == 0);
		}

		public extern async void inject_async (string filename, long target_pid, Cancellable? cancellable = null) throws WinjectorError;

		protected void ensure_worker_running () {
			if (worker_thread == null) {
				try {
					worker_thread = Thread.create (worker, true);
				} catch (ThreadError e) {
					error (e.message);
				}
			}
		}

		private void * worker () {
			mutex.lock ();
			while (true) {
				while (worker_thread != null && requests.size == 0)
					cond.wait (mutex);

				if (worker_thread == null)
					break;

				void * request = requests.remove_at (0);

				mutex.unlock ();
				process_request (request);
				mutex.lock ();
			}
			mutex.unlock ();

			ensure_helper_closed ();
			assert (helper_tempdir == null);
			assert (helper32 == null);
			assert (helper64 == null);

			return null;
		}

		protected void queue_request (void * request) {
			mutex.lock ();
			requests.add (request);
			cond.signal ();
			mutex.unlock ();
		}

		private extern void ensure_helper_closed ();

		private extern void process_request (void * request);
	}

	public errordomain WinjectorError {
		UNKNOWN,
		OPEN_PROCESS_FAILED,
		GRAB_THREAD_FAILED,
		TRICK_THREAD_FAILED
	}
}

