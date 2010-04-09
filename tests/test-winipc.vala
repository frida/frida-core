using WinIpc;

namespace Zed.Test {
	private static void winipc_add_tests () {
		GLib.Test.add_func ("/winipc/proxy/establish-already-connected", () => {
			var h = new IpcHarness ();
			h.run (h.establish_fast);
		});

		GLib.Test.add_func ("/winipc/proxy/establish-delayed", () => {
			var h = new IpcHarness ();
			h.run (h.establish_delayed);
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

		public delegate void TestSequenceFunc (MainLoop loop);

		public void run (TestSequenceFunc f) {
			var timed_out = false;

			var loop = new MainLoop ();

			Timeout.add (1000, () => {
				timed_out = true;
				loop.quit ();
				return false;
			});

			Idle.add (() => {
				f (loop);
				return false;
			});

			loop.run ();

			assert (!timed_out);
		}

		public void establish_fast (MainLoop loop) {
			do_establish_fast (loop);
		}

		private async void do_establish_fast (MainLoop loop) {
			try {
				yield client.establish ();
				yield server.establish ();
			} catch (WinIpc.EstablishError e) {
				assert_not_reached ();
			}

			loop.quit ();
		}

		public void establish_delayed (MainLoop loop) {
			do_establish_delayed (loop);
		}

		private async void do_establish_delayed (MainLoop loop) {
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
