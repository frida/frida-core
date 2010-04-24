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

	public class Manager : Object {
		private MainLoop loop = new MainLoop ();
		private int run_result = 0;

		private WinIpc.ClientProxy proxy;

		private const string INJECT_SIGNATURE = "(us)";

		public Manager (string parent_address) {
			proxy = new WinIpc.ClientProxy (parent_address);
			proxy.register_query_handler ("Inject", INJECT_SIGNATURE, (arg) => {
				uint32 process_id;
				string dll_path;
				arg.get (INJECT_SIGNATURE, out process_id, out dll_path);

				bool success = true;
				uint32 error_code = 0;
				string error_message = "";

				try {
					inject (process_id, dll_path);
				} catch (WinjectorError e) {
					success = false;
					error_code = e.code;
					error_message = e.message;
				}

				return new Variant ("(bus)", success, error_code, error_message);
			});
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
				yield proxy.establish ();
			} catch (WinIpc.ProxyError e) {
				stderr.printf ("establish failed: %s\n", e.message);
				run_result = 1;
				loop.quit ();
			}
		}

		private void inject (uint32 process_id, string dll_path) throws WinjectorError {
			stdout.printf ("inject(process_id=%u, dll_path='%s')\n", process_id, dll_path);
			throw new WinjectorError.PERMISSION_DENIED ("yo mama");
		}

		private static extern void * start_services (string service_basename);
		private static extern void stop_services (void * context);
	}

	public abstract class Service : Object {
		public abstract void run ();

		public static extern string derive_basename ();
		public static extern string derive_filename (string suffix);
	}

	public class StandaloneService : Service {
		public override void run () {
		}
	}

	public class ManagedService : Service {
		public override void run () {
			enter_dispatcher ();
		}

		private static extern void enter_dispatcher ();
	}
}
