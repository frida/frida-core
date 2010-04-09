using WinIpc;

namespace Zed.Test {
	private static void winipc_add_tests () {
		GLib.Test.add_func ("/winipc/proxy/establish-already-connected", () => {
			var h = new IpcHarness ();
			var loop = new MainLoop ();
			Idle.add (() => {
				h.establish_fast (loop);
				return false;
			});
			loop.run ();
		});

		GLib.Test.add_func ("/winipc/proxy/establish-delayed", () => {
			var h = new IpcHarness ();
			var loop = new MainLoop ();
			Idle.add (() => {
				h.establish_delayed (loop);
				return false;
			});
			loop.run ();
		});
	}

	private class IpcHarness : Object {
		public ServerProxy server {
			get;
			private set;
		}

		public ClientProxy client {
			get;
			private set;
		}

		construct {
			server = new ServerProxy ();
			client = new ClientProxy (server.address);
		}

		public async void establish_fast (MainLoop loop) {
			try {
				yield client.establish ();
				yield server.establish ();
			} catch (WinIpc.EstablishError e) {
				assert_not_reached ();
			}

			loop.quit ();
		}

		public async void establish_delayed (MainLoop loop) {
			try {
				Timeout.add (100, () => {
					establish_client ();
					return false;
				});
				yield server.establish ();
			} catch (WinIpc.EstablishError e) {
				assert_not_reached ();
			}

			loop.quit ();
		}

		private async void establish_client () {
			try {
				yield client.establish ();
			} catch (WinIpc.EstablishError e) {
				assert_not_reached ();
			}
		}
	}
}
