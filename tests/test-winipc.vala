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

		GLib.Test.add_func ("/WinIpc/Proxy/query/simple", () => {
			var h = new IpcHarness ((h) => Query.simple (h));
			h.run ();
		});

		GLib.Test.add_func ("/WinIpc/Proxy/query/with-value", () => {
			var h = new IpcHarness ((h) => Query.with_argument (h));
			h.run ();
		});

		GLib.Test.add_func ("/WinIpc/Proxy/query/no-handler", () => {
			var h = new IpcHarness ((h) => Query.no_handler (h));
			h.run ();
		});

		GLib.Test.add_func ("/WinIpc/Proxy/query/handler-response-validation", () => {
			var h = new IpcHarness ((h) => Query.handler_response_validation (h));
			h.run ();
		});

		GLib.Test.add_func ("/WinIpc/Proxy/query/handler-argument-validation", () => {
			var h = new IpcHarness ((h) => Query.handler_argument_validation (h));
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

		private static async void simple (IpcHarness h) {
			yield h.establish_client_and_server ();

			h.server.register_query_handler ("TellMeAJoke", null, (arg) => {
				return new Variant.string ("Nah");
			});

			try {
				var result = yield h.client.query ("TellMeAJoke");
				assert (result.get_string () == "Nah");
			} catch (ProxyError e) {
				assert_not_reached ();
			}

			h.done ();
		}

		private static async void with_argument (IpcHarness h) {
			yield h.establish_client_and_server ();

			h.client.register_query_handler ("AddTwoNumbers", null, (arg) => {
				uint a, b;
				arg.get ("(uu)", out a, out b);
				return new Variant.uint32 (a + b);
			});

			try {
				var result = yield h.server.query ("AddTwoNumbers", new Variant ("(uu)", 42, 1337));
				assert (result.get_uint32 () == 1379);
			} catch (ProxyError e) {
				assert_not_reached ();
			}

			h.done ();
		}

		private static async void no_handler (IpcHarness h) {
			yield h.establish_client_and_server ();

			try {
				yield h.client.query ("TellMeAJoke");
				assert_not_reached ();
			} catch (ProxyError e) {
				var expected = new ProxyError.INVALID_QUERY ("No matching handler for TellMeAJoke");
				assert (e.code == expected.code);
				assert (e.message == expected.message);
			}

			h.done ();
		}

		private static async void handler_response_validation (IpcHarness h) {
			yield h.establish_client_and_server ();

			h.server.register_query_handler ("TellMeAJoke", null, (arg) => {
				return new Variant.uint32 (1337);
			});

			try {
				yield h.client.query ("TellMeAJoke", null, "s");
				assert_not_reached ();
			} catch (ProxyError error_a) {
				var expected_a = new ProxyError.INVALID_RESPONSE ("Invalid response for TellMeAJoke");
				assert (error_a.code == expected_a.code);
				assert (error_a.message == expected_a.message);
			}

			try {
				yield h.client.query ("TellMeAJoke", null, "u");
			} catch (ProxyError error_b) {
				assert_not_reached ();
			}

			h.server.register_query_handler ("NoReturn", null, (arg) => {
				return null;
			});

			try {
				yield h.client.query ("TellMeAJoke", null, "");
				assert_not_reached ();
			} catch (ProxyError error_c) {
				var expected_c = new ProxyError.INVALID_RESPONSE ("Invalid response for TellMeAJoke");
				assert (error_c.code == expected_c.code);
				assert (error_c.message == expected_c.message);
			}

			try {
				yield h.client.query ("NoReturn", null, "");
			} catch (ProxyError error_d) {
				assert_not_reached ();
			}

			h.done ();
		}

		private static async void handler_argument_validation (IpcHarness h) {
			yield h.establish_client_and_server ();

			h.client.register_query_handler ("AddTwoNumbers", "(uu)", (arg) => {
				uint a, b;
				arg.get ("(uu)", out a, out b);
				return new Variant.uint32 (a + b);
			});

			try {
				yield h.server.query ("AddTwoNumbers", new Variant ("(uuu)", 42, 43, 44));
				assert_not_reached ();
			} catch (ProxyError error_a) {
				var expected_a = new ProxyError.INVALID_QUERY ("No matching handler for AddTwoNumbers");
				assert (error_a.code == expected_a.code);
				assert (error_a.message == expected_a.message);
			}

			try {
				var add_result = yield h.server.query ("AddTwoNumbers", new Variant ("(uu)", 42, 1));
				assert (add_result.get_uint32 () == 43);
			} catch (ProxyError eb) {
				assert_not_reached ();
			}

			h.client.register_query_handler ("DoSomething", "", (arg) => {
				return new Variant.boolean (true);
			});

			try {
				yield h.server.query ("DoSomething", new Variant ("u", 3));
				assert_not_reached ();
			} catch (ProxyError error_b) {
				var expected_b = new ProxyError.INVALID_QUERY ("No matching handler for DoSomething");
				assert (error_b.code == expected_b.code);
				assert (error_b.message == expected_b.message);
			}

			try {
				var do_something_result = yield h.server.query ("DoSomething");
				assert (do_something_result.get_boolean () == true);
			} catch (ProxyError error_c) {
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
