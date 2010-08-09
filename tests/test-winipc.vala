using WinIpc;

namespace Zed.WinIpcTest {
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

		GLib.Test.add_func ("/WinIpc/Proxy/establish/server-with-timeout", () => {
			var h = new IpcHarness ((h) => Establish.server_with_timeout (h));
			h.run ();
		});

		GLib.Test.add_func ("/WinIpc/Proxy/establish/custom-server-address", () => {
			var h = new IpcHarness ((h) => Establish.custom_server_address (h));
			h.run ();
		});

		GLib.Test.add_func ("/WinIpc/Proxy/establish/sudden-disconnect", () => {
			var h = new IpcHarness ((h) => Establish.sudden_disconnect (h));
			h.run ();
		});

		GLib.Test.add_func ("/WinIpc/Proxy/query/simple", () => {
			var h = new IpcHarness ((h) => Query.simple (h));
			h.run ();
		});

		GLib.Test.add_func ("/WinIpc/Proxy/query/with-argument", () => {
			var h = new IpcHarness ((h) => Query.with_argument (h));
			h.run ();
		});

		GLib.Test.add_func ("/WinIpc/Proxy/query/async-handler", () => {
			var h = new IpcHarness ((h) => Query.async_handler (h));
			h.run ();
		});

		GLib.Test.add_func ("/WinIpc/Proxy/query/overlapping-queries", () => {
			var h = new IpcHarness ((h) => Query.overlapping_queries (h));
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

		GLib.Test.add_func ("/WinIpc/Proxy/query/unregister-handler", () => {
			var h = new IpcHarness ((h) => Query.unregister_handler (h));
			h.run ();
		});

		GLib.Test.add_func ("/WinIpc/Proxy/notify/simple", () => {
			var h = new IpcHarness ((h) => Notify.simple (h));
			h.run ();
		});

		GLib.Test.add_func ("/WinIpc/Proxy/notify/with-argument", () => {
			var h = new IpcHarness ((h) => Notify.with_argument (h));
			h.run ();
		});

		GLib.Test.add_func ("/WinIpc/Proxy/notify/remove-handler", () => {
			var h = new IpcHarness ((h) => Notify.remove_handler (h));
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

		private async void server_with_timeout (IpcHarness h) {
			try {
				yield h.server.establish (100);
			} catch (ProxyError e) {
				var expected = new ProxyError.IO_ERROR ("Operation timed out");
				assert (e.code == expected.code);
				assert (e.message == expected.message);

				h.done ();
				return;
			}

			assert_not_reached ();
		}

		private async void custom_server_address (IpcHarness h) {
			try {
				var server = new ServerProxy ("my-custom-address-1234");
				var client = new ClientProxy ("my-custom-address-1234");
				yield client.establish ();
				yield server.establish ();
			} catch (ProxyError e) {
				assert_not_reached ();
			}

			h.done ();
		}

		private async void sudden_disconnect (IpcHarness h) {
			try {
				yield h.client.establish ();
				yield h.server.establish ();
			} catch (ProxyError e) {
				assert_not_reached ();
			}

			h.remove_client ();

			h.done ();
		}

	}

	namespace Query {

		private static async void simple (IpcHarness h) {
			yield h.establish_client_and_server ();

			h.server.register_query_sync_handler ("TellMeAJoke", null, (arg) => {
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

			h.client.register_query_sync_handler ("AddTwoNumbers", null, (arg) => {
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

		private class LongRunningTaskHandler : Object, QueryAsyncHandler {
			public async Variant? handle_query (string id, Variant? argument) {
				assert (id == "LongRunningTask");

				var timeout = new TimeoutSource (100);
				timeout.set_callback (() => {
					handle_query.callback ();
					return false;
				});
				timeout.attach (MainContext.get_thread_default ());
				yield;

				return new Variant.string ("took a while");
			}
		}

		private static async void async_handler (IpcHarness h) {
			yield h.establish_client_and_server ();

			h.client.register_query_async_handler ("LongRunningTask", null, new LongRunningTaskHandler ());

			try {
				var result = yield h.server.query ("LongRunningTask");
				assert (result.get_string () == "took a while");
			} catch (ProxyError e) {
				assert_not_reached ();
			}

			h.done ();
		}

		private class ForeverTaskHandler : Object, QueryAsyncHandler {
			private Source completion_source;

			public async Variant? handle_query (string id, Variant? argument) {
				assert (id == "ForeverTask");

				completion_source = new IdleSource ();
				completion_source.set_callback (() => {
					handle_query.callback ();
					return false;
				});
				yield;

				return new Variant.string ("that took forever");
			}

			public void schedule_completion () {
				completion_source.attach (MainContext.get_thread_default ());
				completion_source = null;
			}
		}

		private class ForeverQuery {
			public string result {
				get;
				set;
			}
		}

		private static async void overlapping_queries (IpcHarness h) {
			yield h.establish_client_and_server ();

			var forever_handler = new ForeverTaskHandler ();
			h.client.register_query_async_handler ("ForeverTask", null, forever_handler);
			h.client.register_query_sync_handler ("QuickTask", null, (arg) => {
				return new Variant.string ("quick and easy");
			});

			var forever_query = new ForeverQuery ();
			do_forever_query (h.server, forever_query);

			try {
				var quick_result = yield h.server.query ("QuickTask");
				assert (quick_result.get_string () == "quick and easy");
			} catch (ProxyError e) {
				assert_not_reached ();
			}

			assert (forever_query.result == null);
			forever_handler.schedule_completion ();
			yield h.process_events ();
			assert (forever_query.result == "that took forever");

			h.done ();
		}

		private async void do_forever_query (Proxy proxy, ForeverQuery query) {
			try {
				var val = yield proxy.query ("ForeverTask");
				query.result = val.get_string ();
			} catch (ProxyError e) {
				assert_not_reached ();
			}
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

			h.server.register_query_sync_handler ("TellMeAJoke", null, (arg) => {
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

			h.server.register_query_sync_handler ("NoReturn", null, (arg) => {
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

			h.client.register_query_sync_handler ("AddTwoNumbers", "(uu)", (arg) => {
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

			h.client.register_query_sync_handler ("DoSomething", "", (arg) => {
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

		private static async void unregister_handler (IpcHarness h) {
			yield h.establish_client_and_server ();

			var handler_tag = h.server.register_query_sync_handler ("TellMeAJoke", null, (arg) => {
				return new Variant.string ("Nah");
			});
			h.server.unregister_query_handler (handler_tag);

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

	}

	namespace Notify {

		private static async void simple (IpcHarness h) {
			yield h.establish_client_and_server ();

			bool first_handler_got_notify = false;
			bool second_handler_got_notify = false;

			h.server.add_notify_handler ("ChickenCrossedTheRoad", null, (arg) => {
				first_handler_got_notify = true;
			});
			h.server.add_notify_handler ("ChickenCrossedTheRoad", null, (arg) => {
				second_handler_got_notify = true;
			});

			try {
				yield h.client.emit ("ChickenCrossedTheRoad");
				yield h.process_events ();
				assert (first_handler_got_notify);
				assert (second_handler_got_notify);
			} catch (ProxyError e) {
				assert_not_reached ();
			}

			h.done ();
		}

		private static async void with_argument (IpcHarness h) {
			yield h.establish_client_and_server ();

			bool first_handler_got_notify = false;
			bool second_handler_got_notify = false;

			h.server.add_notify_handler ("VolcanoAlert", "u", (arg) => {
				assert (arg.get_uint32 () == 3);
				first_handler_got_notify = true;
			});
			h.server.add_notify_handler ("VolcanoAlert", "s", (arg) => {
				assert (arg.get_string () == "yay");
				second_handler_got_notify = true;
			});

			try {
				yield h.client.emit ("VolcanoAlert", new Variant ("u", 3));
				yield h.process_events ();
				assert (first_handler_got_notify);
				assert (!second_handler_got_notify);

				first_handler_got_notify = false;

				yield h.client.emit ("VolcanoAlert", new Variant ("s", "yay"));
				yield h.process_events ();
				assert (!first_handler_got_notify);
				assert (second_handler_got_notify);

				second_handler_got_notify = false;

				yield h.client.emit ("VolcanoAlert", new Variant ("b", true));
				yield h.process_events ();
				assert (!first_handler_got_notify);
				assert (!second_handler_got_notify);
			} catch (ProxyError e) {
				assert_not_reached ();
			}

			h.done ();
		}

		private static async void remove_handler (IpcHarness h) {
			yield h.establish_client_and_server ();

			bool handler_got_notify = false;

			var handler_tag = h.server.add_notify_handler ("Yikes", null, (arg) => {
				handler_got_notify = true;
			});

			try {
				yield h.client.emit ("Yikes");
				yield h.process_events ();
				assert (handler_got_notify);

				h.server.remove_notify_handler (handler_tag);
				handler_got_notify = false;

				yield h.client.emit ("Yikes");
				yield h.process_events ();
				assert (!handler_got_notify);
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

		public async void process_events () {
			var timeout = new TimeoutSource (10);
			timeout.set_callback (() => {
				process_events.callback ();
				return false;
			});
			timeout.attach (main_context);
			yield;

			return;
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

		public void remove_client () {
			client = null;
		}

		public void done () {
			main_loop.quit ();
		}
	}
}
