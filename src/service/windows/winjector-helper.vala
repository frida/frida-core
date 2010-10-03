using Zed.Service;

namespace Winjector {
	public int main (string[] args) {
		HelperMode mode = HelperMode.SERVICE;

		if (args.length > 1) {
			var mode_str = args[1].up ();
			switch (mode_str) {
				case "MANAGER":	    mode = HelperMode.MANAGER;	  break;
				case "STANDALONE":  mode = HelperMode.STANDALONE; break;
				case "SERVICE":	    mode = HelperMode.SERVICE;	  break;
				default:					  return 1;
			}
		}

		if (mode == HelperMode.MANAGER) {
			if (args.length != 3)
				return 1;
			var parent_address = args[2];

			var manager = new Winjector.Manager (parent_address);
			return manager.run ();
		}

		Service service;
		if (mode == HelperMode.STANDALONE)
			service = new StandaloneService ();
		else
			service = new ManagedService ();
		service.run ();

		return 0;
	}

	public enum HelperMode {
		MANAGER,
		STANDALONE,
		SERVICE
	}

	public class Manager : Object, WinIpc.QueryAsyncHandler {
		public string parent_address {
			get;
			construct;
		}

		private MainLoop loop = new MainLoop ();
		private int run_result = 0;
		private bool stopping = false;

		private WinIpc.ClientProxy parent;
		private WinIpc.ServerProxy helper32;
		private WinIpc.ServerProxy helper64;

		public Manager (string parent_address) {
			Object (parent_address: parent_address);
		}

		construct {
			parent = new WinIpc.ClientProxy (parent_address);
			parent.closed.connect ((remote_peer_vanished) => {
				if (remote_peer_vanished)
					stop ();
			});
			parent.add_notify_handler ("Stop", "", (arg) => stop ());
			parent.register_query_async_handler ("Inject", WinjectorIpc.INJECT_SIGNATURE, this);

			helper32 = new WinIpc.ServerProxy (Service.derive_svcname_for_suffix ("32"));
			if (System.is_x64 ()) {
				helper64 = new WinIpc.ServerProxy (Service.derive_svcname_for_suffix ("64"));
			}
		}

		public int run () {
			var ctx = start_services (Service.derive_basename ());

			Idle.add (() => {
				establish ();
				return false;
			});
			loop.run ();

			stop_services (ctx);

			return run_result;
		}

		private void stop () {
			if (stopping)
				return;
			stopping = true;

			if (System.is_x64 ())
				helper64.emit ("Stop");
			helper32.emit ("Stop");

			// HACK: give child processes some time to shut down
			Timeout.add (100, () => {
				loop.quit ();
				return false;
			});
		}

		private async void establish () {
			try {
				yield helper32.establish ();
				if (System.is_x64 ())
					yield helper64.establish ();
				yield parent.establish ();
			} catch (WinIpc.ProxyError e) {
				stderr.printf ("establish failed: %s\n", e.message);
				run_result = 1;
				loop.quit ();
			}
		}

		private async Variant? handle_query (string id, Variant? argument) {
			uint32 target_pid;
			string filename_template;
			string ipc_server_address;
			argument.get (WinjectorIpc.INJECT_SIGNATURE, out target_pid, out filename_template, out ipc_server_address);

			WinIpc.Proxy helper;
			string filename;
			if (Process.is_x64 (target_pid)) {
				helper = helper64;
				filename = filename_template.printf (64);
			} else {
				helper = helper32;
				filename = filename_template.printf (32);
			}

			var helper_argument = new Variant (WinjectorIpc.INJECT_SIGNATURE, target_pid, filename, ipc_server_address);

			try {
				return yield helper.query (id, helper_argument);
			} catch (WinIpc.ProxyError e) {
				var failed = new WinjectorError.FAILED (e.message);
				return new Variant (WinjectorIpc.INJECT_RESPONSE, false, failed.code, failed.message);
			}
		}

		private static extern void * start_services (string service_basename);
		private static extern void stop_services (void * context);
	}

	public abstract class Service : Object {
		protected WinIpc.ClientProxy manager;

		public Service () {
			manager = new WinIpc.ClientProxy (derive_svcname_for_self ());
			manager.register_query_sync_handler ("Inject", WinjectorIpc.INJECT_SIGNATURE, (arg) => {
				return WinjectorIpc.marshal_inject (arg, inject);
			});

			Idle.add (() => {
				establish ();
				return false;
			});
		}

		public abstract void run ();

		private void inject (uint32 target_pid, string filename, string ipc_server_address) throws WinjectorError {
			Process.inject (target_pid, filename, ipc_server_address);
		}

		protected async void establish () {
			try {
				yield manager.establish ();
			} catch (WinIpc.ProxyError e) {
				/* REVISIT: might be worthwhile reporting an error here */
			}
		}

		public static extern string derive_basename ();
		public static extern string derive_filename_for_suffix (string suffix);
		public static extern string derive_svcname_for_self ();
		public static extern string derive_svcname_for_suffix (string suffix);
	}

	public class StandaloneService : Service {
		private MainLoop loop;

		public override void run () {
			manager.add_notify_handler ("Stop", "", (arg) => {
				Idle.add (() => {
					loop.quit ();
					return false;
				});
			});

			loop = new MainLoop ();
			loop.run ();
		}
	}

	public class ManagedService : Service {
		public override void run () {
			enter_dispatcher_and_main_loop ();
		}

		private static extern void enter_dispatcher_and_main_loop ();
	}

	namespace System {
		public static extern bool is_x64 ();
	}

	namespace Process {
		public static extern bool is_x64 (uint32 process_id);
		public static extern void inject (uint32 process_id, string dll_path, string ipc_server_address) throws WinjectorError;
	}
}
