namespace Zed.Ipc {
	public struct SimpleResult {
		public bool success;
		public unowned string error_message;

		public SimpleResult.ok () {
			this.success = true;
			this.error_message = "";
		}

		public SimpleResult.failure (string error_message) {
			this.success = false;
			this.error_message = error_message;
		}

		public const string TYPE_SIGNATURE = "(bs)";
	}
}
