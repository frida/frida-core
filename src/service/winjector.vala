using Gee;

namespace Zed.Service {
	public class Winjector : Object {
		private Mutex mutex = new Mutex ();
		private Cond cond = new Cond ();

		private unowned Thread worker_thread;
		private ArrayList<void *> requests = new ArrayList<void *> ();

		~Winjector () {
			if (worker_thread != null) {
				mutex.lock ();
				worker_thread = null;
				cond.signal ();
				mutex.unlock ();

				worker_thread.join ();
			}

			foreach (void * request in requests)
				free_request (request);
			requests.clear ();
		}

		protected void ensure_worker_running () {
			if (worker_thread == null) {
				try {
					worker_thread = Thread.create (worker, true);
				} catch (ThreadError e) {
					error (e.message);
				}
			}
		}

		protected void queue_request (void * request) {
			mutex.lock ();
			requests.add (request);
			cond.signal ();
			mutex.unlock ();
		}

		private extern void process_request (void * request);
		private extern void free_request (void * request);

		private void * worker () {
			mutex.lock ();
			while (worker_thread != null) {
				while (requests.size == 0)
					cond.wait (mutex);

				if (worker_thread == null)
					break;

				void * request = requests.remove_at (0);

				mutex.unlock ();
				process_request (request);
				mutex.lock ();

				free_request (request);
			}
			mutex.unlock ();

			return null;
		}

		public extern async void inject_async (string filename, long target_pid, Cancellable? cancellable = null) throws WinjectorError;
	}

	public errordomain WinjectorError {
		UNKNOWN,
		OPEN_PROCESS_FAILED,
		GRAB_THREAD_FAILED,
		TRICK_THREAD_FAILED
	}
}

