namespace Frida {
	public interface PolicySoftener : Object {
		public abstract async void soften (uint pid) throws Error;
	}

	public class NullPolicySoftener : Object, PolicySoftener {
		public async void soften (uint pid) throws Error {
		}
	}

	public class ElectraPolicySoftener : Object, PolicySoftener {
		private const string JAILBREAKD_CLIENT_PATH = "/electra/jailbreakd_client";

		private enum Operation {
			ENTITLE_AND_PLATFORMIZE = 1,
		}

		private Gee.Promise<bool> ensure_request;

		public static bool is_available () {
			return FileUtils.test (JAILBREAKD_CLIENT_PATH, FileTest.IS_EXECUTABLE);
		}

		public async void soften (uint pid) throws Error {
			yield ensure_self_softened ();
			yield do_soften (pid);
		}

		private async void do_soften (uint pid) throws Error {
			try {
				var argv = new string[] {
					JAILBREAKD_CLIENT_PATH,
					pid.to_string (),
					((int) Operation.ENTITLE_AND_PLATFORMIZE).to_string ()
				};
				var client = new Subprocess.newv (argv, SubprocessFlags.INHERIT_FDS);
				yield client.wait_async ();
			} catch (GLib.Error e) {
				throw new Error.NOT_SUPPORTED (e.message);
			}
		}

		private async void ensure_self_softened () throws Error {
			if (ensure_request != null) {
				var future = ensure_request.future;
				try {
					yield future.wait_async ();
				} catch (Gee.FutureError e) {
					throw (Error) future.exception;
				}
				return;
			}
			ensure_request = new Gee.Promise<bool> ();

			try {
				yield do_soften (Posix.getpid ());

				ensure_request.set_value (true);
			} catch (Error e) {
				ensure_request.set_exception (e);
				ensure_request = null;
				throw e;
			}
		}
	}
}
