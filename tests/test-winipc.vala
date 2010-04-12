using WinIpc;

namespace Zed.Test.WinIpc {
	public static void add_tests () {
		GLib.Test.add_func ("/WinIpc/Proxy/establish/already-connected", () => {
			var h = new IpcHarness ((h) => Establish.already_connected (h));
			h.run ();
		});

		GLib.Test.add_func ("/WinIpc/Proxy/establish/delayed", () => {
			var h = new IpcHarness ((h) => Establish.delayed (h));
			h.run ();
		});

		GLib.Test.add_func ("/WinIpc/Proxy/establish/no-server", () => {
			var h = new IpcHarness ((h) => Establish.no_server (h));
			h.run ();
		});

		GLib.Test.add_func ("/WinIpc/Proxy/query/invalid", () => {
			var h = new IpcHarness ((h) => Query.invalid (h));
			h.run ();
		});

		GLib.Test.add_func ("/WinIpc/Proxy/query/simple", () => {
			var h = new IpcHarness ((h) => Query.simple (h));
			h.run ();
		});

		GLib.Test.add_func ("/WinIpc/Proxy/query/with-value", () => {
			var h = new IpcHarness ((h) => Query.with_argument (h));
			h.run ();
		});
	}

	namespace Establish {

		private static async void already_connected (IpcHarness h) {
			try {
				yield h.client.establish ();
				yield h.server.establish ();
			} catch (ProxyError e) {
				assert_not_reached ();
			}

			h.done ();
		}

		private static async void delayed (IpcHarness h) {
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

		private async void no_server (IpcHarness h) {
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

	}

	namespace Query {

		private static async void invalid (IpcHarness h) {
			yield h.establish_client_and_server ();

			try {
				yield h.client.query ("TellMeAJoke");
				assert_not_reached ();
			} catch (ProxyError e) {
				var expected = new ProxyError.INVALID_QUERY ("No handler for TellMeAJoke");
				assert (e.code == expected.code);
				assert (e.message == expected.message);
			}

			h.done ();
		}

		private static async void simple (IpcHarness h) {
			yield h.establish_client_and_server ();

			h.server.register_query_handler ("TellMeAJoke", (arg) => {
				return new Variant.string ("Nah");
			});

			try {
				var joke_response = yield h.client.query ("TellMeAJoke");
				assert (joke_response.get_string () == "Nah");
			} catch (ProxyError e) {
				assert_not_reached ();
			}

			h.done ();
		}

		private static async void with_argument (IpcHarness h) {
			yield h.establish_client_and_server ();

			h.client.register_query_handler ("AddTwoNumbers", (arg) => {
				uint a, b;
				arg.get ("(uu)", out a, out b);
				return new Variant.uint32 (a + b);
			});

			try {
				var sandwich_response = yield h.server.query ("AddTwoNumbers", new Variant ("(uu)", 42, 1337));
				assert (sandwich_response.get_uint32 () == 1379);
			} catch (ProxyError e) {
				assert_not_reached ();
			}

			h.done ();
		}

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

		public async void establish_client_and_server () {
			try {
				yield client.establish ();
				yield server.establish ();
			} catch (ProxyError e) {
				assert_not_reached ();
			}
		}

		public void remove_server () {
			server = null;
		}

		public void done () {
			main_loop.quit ();
		}
	}
}
