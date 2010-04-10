using WinIpc;

namespace Zed.Test.WinIpc {
	public static void add_tests () {
		GLib.Test.add_func ("/WinIpc/Proxy/establish-already-connected", () => {
			var h = new IpcHarness ((h) => establish_already_connected (h));
			h.run ();
		});

		GLib.Test.add_func ("/WinIpc/Proxy/establish-delayed", () => {
			var h = new IpcHarness ((h) => establish_delayed (h));
			h.run ();
		});

		GLib.Test.add_func ("/WinIpc/Proxy/establish-error-no-server", () => {
			var h = new IpcHarness ((h) => establish_error_no_server (h));
			h.run ();
		});

		GLib.Test.add_func ("/WinIpc/Proxy/query-sequence", () => {
			var h = new IpcHarness ((h) => query_sequence (h));
			h.run ();
		});
	}

	private static async void establish_already_connected (IpcHarness h) {
		try {
			yield h.client.establish ();
			yield h.server.establish ();
		} catch (ProxyError e) {
			assert_not_reached ();
		}

		h.done ();
	}

	private static async void establish_delayed (IpcHarness h) {
		try {
			var timeout = new TimeoutSource (100);
			timeout.set_callback (() => {
				h.client.establish ();
				return false;
			});
			timeout.attach (MainContext.get_thread_default ());

			yield h.server.establish ();
		} catch (ProxyError e) {
			assert_not_reached ();
		}

		h.done ();
	}

	private async void establish_error_no_server (IpcHarness h) {
		h.remove_server ();

		try {
			yield h.client.establish ();
		} catch (ProxyError e) {
			var expected = new ProxyError.SERVER_NOT_FOUND ("CreateFile failed: 2");
			assert (e.code == expected.code);
			assert (e.message == expected.message);

			h.done ();
			return;
		}

		assert_not_reached ();
	}

	private static async void query_sequence (IpcHarness h) {
		try {
			yield h.client.establish ();
			yield h.server.establish ();
		} catch (ProxyError unexpected1) {
			assert_not_reached ();
		}

		try {
			yield h.client.query ("TellMeAJoke");
			assert_not_reached ();
		} catch (ProxyError e) {
			var expected = new ProxyError.INVALID_QUERY ("No handler for TellMeAJoke");
			assert (e.code == expected.code);
			assert (e.message == expected.message);
		}

		h.server.register_query_handler ("TellMeAJoke", () => {
			return "Nah";
		});

		try {
			var joke_response = yield h.client.query ("TellMeAJoke");
			assert (joke_response == "Nah");
		} catch (ProxyError unexpected2) {
			assert_not_reached ();
		}

		h.server.register_query_handler ("MakeMeASandwich", () => {
			return "Booya!";
		});

		try {
			var sandwich_response = yield h.client.query ("MakeMeASandwich");
			assert (sandwich_response == "Booya!");
		} catch (ProxyError unexpected3) {
			assert_not_reached ();
		}

		h.done ();
	}

	private class IpcHarness : Object {
		public delegate void TestSequenceFunc (IpcHarness h);
		private TestSequenceFunc test_sequence;

		public ServerProxy server {
			get;
			private set;
		}

		public ClientProxy client {
			get;
			private set;
		}

		private MainContext main_context;
		private MainLoop main_loop;

		public IpcHarness (TestSequenceFunc func) {
			test_sequence = func;
		}

		construct {
			server = new ServerProxy ();
			client = new ClientProxy (server.address);
			main_context = new MainContext ();
			main_loop = new MainLoop (main_context);
		}

		public void run () {
			var timed_out = false;

			var timeout = new TimeoutSource.seconds (1);
			timeout.set_callback (() => {
				timed_out = true;
				main_loop.quit ();
				return false;
			});
			timeout.attach (main_context);

			var idle = new IdleSource ();
			var func = test_sequence; /* FIXME: workaround for bug in valac */
			idle.set_callback (() => {
				func (this);
				return false;
			});
			idle.attach (main_context);

			main_context.push_thread_default ();
			main_loop.run ();
			main_context.pop_thread_default ();

			assert (!timed_out);
		}

		public void remove_server () {
			server = null;
		}

		public void done () {
			main_loop.quit ();
		}
	}
}
