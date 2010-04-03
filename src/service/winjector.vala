namespace Zed.Service {
	public class Winjector : Object {
		public extern async void inject_async (string filename, long target_pid, Cancellable? cancellable = null) throws WinjectorError;
	}

	public errordomain WinjectorError {
		UNKNOWN,
		OPEN_PROCESS_FAILED,
		GRAB_THREAD_FAILED
	}
}

