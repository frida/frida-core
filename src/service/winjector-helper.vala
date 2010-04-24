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
			var result = manager.run ();
			if (result != 0)
				Thread.usleep (60 * 1000000);

			return result;
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
		private MainLoop loop = new MainLoop ();
		private int run_result = 0;

		private WinIpc.ClientProxy parent;
		private WinIpc.ServerProxy helper32;
		private WinIpc.ServerProxy helper64;

		public Manager (string parent_address) {
			parent = new WinIpc.ClientProxy (parent_address);
			parent.register_query_async_handler ("Inject", Ipc.INJECT_SIGNATURE, this);

			helper32 = new WinIpc.ServerProxy (Service.derive_svcname_for_suffix ("32"));
			if (system_is_x64 ()) {
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

		private async void establish () {
			try {
				yield helper32.establish ();
				if (system_is_x64 ())
					yield helper64.establish ();
				yield parent.establish ();
			} catch (WinIpc.ProxyError e) {
				stderr.printf ("establish failed: %s\n", e.message);
				run_result = 1;
				loop.quit ();
			}
		}

		private async Variant? handle_query (string id, Variant? argument) {
			/*
			uint32 process_id;
			string dll_path;
			arg.get (Ipc.INJECT_SIGNATURE, out process_id, out dll_path);*/

			try {
				var result = yield helper32.query (id, argument);
				print ("got result!\n");
				return result;
			} catch (WinIpc.ProxyError e) {
				print ("caught exception\n");
				var failed = new WinjectorError.FAILED (e.message);
				return new Variant (Ipc.INJECT_RESPONSE, false, failed.code, failed.message);
			}
		}

		private static extern bool system_is_x64 ();

		private static extern void * start_services (string service_basename);
		private static extern void stop_services (void * context);
	}

	public abstract class Service : Object {
		protected WinIpc.ClientProxy manager;

		public Service () {
			manager = new WinIpc.ClientProxy (derive_svcname_for_self ());
			manager.register_query_sync_handler ("Inject", Ipc.INJECT_SIGNATURE, (arg) => {
				return Ipc.marshal_inject (arg, inject);
			});

			Idle.add (() => {
				establish ();
				return false;
			});
		}

		public abstract void run ();

		private void inject (uint32 target_pid, string filename) throws WinjectorError {
			throw new WinjectorError.PERMISSION_DENIED ("yeah!");
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
		public override void run () {
			var loop = new MainLoop ();
			loop.run ();
		}
	}

	public class ManagedService : Service {
		public override void run () {
			enter_dispatcher_and_main_loop ();
		}

		private static extern void enter_dispatcher_and_main_loop ();
	}

	namespace Ipc {
		public const string INJECT_SIGNATURE = "(us)";
		public const string INJECT_RESPONSE = "(bus)";
		public delegate void InjectFunc (uint32 process_id, string dll_path) throws WinjectorError;

		public Variant? marshal_inject (Variant? arg, InjectFunc func) {
			uint32 process_id;
			string dll_path;
			arg.get (INJECT_SIGNATURE, out process_id, out dll_path);

			bool success = true;
			uint32 error_code = 0;
			string error_message = "";

			try {
				func (process_id, dll_path);
			} catch (WinjectorError e) {
				success = false;
				error_code = e.code;
				error_message = e.message;
			}

			return new Variant (INJECT_RESPONSE, success, error_code, error_message);
		}

		public async void invoke_inject (uint32 target_pid, string filename, WinIpc.Proxy proxy) throws WinjectorError {
			Variant response;

			try {
				response = yield proxy.query ("Inject", new Variant (INJECT_SIGNATURE, target_pid, filename), INJECT_RESPONSE);
			} catch (WinIpc.ProxyError e) {
				throw new WinjectorError.FAILED (e.message);
			}

			bool success;
			uint error_code;
			string error_message;
			response.get (INJECT_RESPONSE, out success, out error_code, out error_message);
			if (!success) {
				var permission_error = new WinjectorError.PERMISSION_DENIED (error_message);
				if (error_code == permission_error.code)
					throw permission_error;
				else
					throw new WinjectorError.FAILED (error_message);
			}
		}
	}
}
