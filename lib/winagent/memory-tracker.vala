using Gee;

namespace Zed {
	public class MemoryTracker : Object {
		private WinIpc.Proxy proxy;
		private uint begin_handler_id;
		private uint end_handler_id;
		private uint peek_handler_id;

		private Gum.InstanceTracker instance_tracker;

		public MemoryTracker (WinIpc.Proxy proxy) {
			this.proxy = proxy;
			register_query_handlers ();
		}

		~MemoryTracker () {
			unregister_query_handlers ();
		}

		private void register_query_handlers () {
			begin_handler_id = proxy.register_query_sync_handler ("BeginInstanceTrace", "", (arg) => {
				if (instance_tracker == null) {
					instance_tracker = new Gum.InstanceTracker ();
					return Ipc.Result.ok ();
				} else {
					return Ipc.Result.failure ("trace already in progress");
				}
			});

			end_handler_id = proxy.register_query_sync_handler ("EndInstanceTrace", "", (arg) => {
				if (instance_tracker != null) {
					instance_tracker = null;
					return Ipc.Result.ok ();
				} else {
					return Ipc.Result.failure ("no trace in progress");
				}
			});

			peek_handler_id = proxy.register_query_sync_handler ("PeekInstances", "", (arg) => {
				if (instance_tracker != null) {
					instance_tracker.peek_stale ();
					return Ipc.Result.ok ();
				} else {
					return Ipc.Result.failure ("no trace in progress");
				}
			});
		}

		private void unregister_query_handlers () {
			proxy.unregister_query_handler (begin_handler_id);
			proxy.unregister_query_handler (end_handler_id);
		}
	}
}
