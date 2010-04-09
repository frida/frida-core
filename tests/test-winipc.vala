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

		GLib.Test.add_func ("/winipc/proxy/establish-error", () => {
			var h = new IpcHarness ();
			h.run (h.establish_client_without_server);
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

		public void establish_fast (MainLoop loop) {
			do_establish_fast (loop);
		}

		private async void do_establish_fast (MainLoop loop) {
			try {
				yield client.establish ();
				yield server.establish ();
			} catch (ProxyError e) {
				assert_not_reached ();
			}

			loop.quit ();
		}

		public void establish_delayed (MainLoop loop) {
			do_establish_delayed (loop);
		}

		private async void do_establish_delayed (MainLoop loop) {
			try {
				var timeout = new TimeoutSource (100);
				timeout.set_callback (() => {
					establish_client ();
					return false;
				});
				timeout.attach (loop.get_context ());

				yield server.establish ();
			} catch (ProxyError e) {
				assert_not_reached ();
			}

			loop.quit ();
		}

		public void establish_client_without_server (MainLoop loop) {
			do_establish_client_without_server (loop);
		}

		private async void do_establish_client_without_server (MainLoop loop) {
			server = null;

			try {
				yield client.establish ();
			} catch (ProxyError e) {
				var expected = new ProxyError.SERVER_NOT_FOUND ("CreateFile failed: 2");
				assert (e.code == expected.code);
				assert (e.message == expected.message);

				loop.quit ();
				return;
			}

			assert_not_reached ();
		}

		private async void establish_client () {
			try {
				yield client.establish ();
			} catch (ProxyError e) {
				assert_not_reached ();
			}
		}

		public delegate void TestSequenceFunc (MainLoop loop);

		public void run (TestSequenceFunc f) {
			var timed_out = false;

			var ctx = new MainContext ();
			var loop = new MainLoop (ctx);

			var timeout = new TimeoutSource.seconds (1);
			timeout.set_callback (() => {
				timed_out = true;
				loop.quit ();
				return false;
			});
			timeout.attach (ctx);

			var idle = new IdleSource ();
			idle.set_callback (() => {
				f (loop);
				return false;
			});
			idle.attach (ctx);

			ctx.push_thread_default ();
			loop.run ();
			ctx.pop_thread_default ();

			assert (!timed_out);
		}
	}
}
