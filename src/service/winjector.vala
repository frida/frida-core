namespace Zed.Service {
	public class Winjector : Object {
		public extern async void inject_async (string filename, long target_pid, Cancellable? cancellable = null) throws WinjectorError;
	}

	public errordomain WinjectorError {
		UNKNOWN
	}
}

