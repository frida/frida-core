namespace Zed.Ipc {
	public struct Result {
		public bool success;
		public unowned string error_message;

		public Result.ok () {
		}

		public Result.failure (string error_message) {
			this.success = false;
			this.error_message = error_message;
		}
	}
}
