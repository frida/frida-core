namespace Zed.AgentTest {
	public static void add_tests () {
		GLib.Test.add_func ("/Agent/Script/attach-and-receive-messages", () => {
			var h = new Harness ((h) => Script.attach_and_receive_messages (h));
			h.run ();
		});
	}

	namespace Script {

		private static async void attach_and_receive_messages (Harness h) {
			var session = yield h.load_agent ();

			AgentScriptInfo script;
			try {
				script = yield session.attach_script_to ("SendInt32FromArgument 0\nSendNarrowStringFromArgument 1", (uint64) target_function);
			} catch (IOError attach_error) {
				assert_not_reached ();
			}

			target_function (1337, "Frida rocks");

			var msg = yield h.wait_for_message ();
			assert (msg.sender_id == script.id);
			assert (msg.content.print (false) == "(1337, 'Frida rocks')");

			yield h.unload_agent ();

			h.done ();
		}

		public static uint target_function (int level, string message) {
			var bogus_result = 0;

			for (var i = 0; i != 42; i++)
				bogus_result += i;

			return bogus_result;
		}
	}

	private class Harness : Object {
		public delegate void TestSequenceFunc (Harness h);
		private TestSequenceFunc test_sequence;

		private GLib.Module module;
		[CCode (has_target = false)]
		private delegate void AgentMainFunc (string data_string);
		private AgentMainFunc main_impl;
		private string listen_address = "tcp:host=127.0.0.1,port=42042";
		private unowned Thread main_thread;
		private DBusConnection connection;
		private AgentSession session;

		private Gee.LinkedList<ScriptMessage> message_queue = new Gee.LinkedList<ScriptMessage> ();

		private MainContext main_context;
		private MainLoop main_loop;
		private TimeoutSource timeout_source;

		public Harness (TestSequenceFunc func) {
			test_sequence = func;
		}

		construct {
			main_context = new MainContext ();
			main_loop = new MainLoop (main_context);
		}

		public async AgentSession load_agent () {
			var intermediate_root_dir = Path.get_dirname (Path.get_dirname (Zed.Test.Process.current.filename));
			string agent_filename;
			if (sizeof (void *) == 4)
				agent_filename = Path.build_filename (intermediate_root_dir, "zed-agent-32", "zed-agent-32.dll");
			else
				agent_filename = Path.build_filename (intermediate_root_dir, "zed-agent-64", "zed-agent-64.dll");

			module = GLib.Module.open (agent_filename, 0);
			assert (module != null);

			void * main_func_symbol;
			var main_func_found = module.symbol ("zed_agent_main", out main_func_symbol);
			assert (main_func_found);
			main_impl = (AgentMainFunc) main_func_symbol;

			try {
				main_thread = Thread.create (agent_main_worker, true);
			} catch (ThreadError thread_error) {
				assert_not_reached ();
			}

			for (int i = 0; connection == null; i++) {
				try {
					connection = yield DBusConnection.new_for_address (listen_address, DBusConnectionFlags.AUTHENTICATION_CLIENT);
				} catch (Error conn_error) {
					if (i != 10 - 1) {
						Timeout.add (20, () => {
							load_agent.callback ();
							return false;
						});
						yield;
					} else {
						break;
					}
				}
			}
			assert (connection != null);

			try {
				session = connection.get_proxy_sync (null, ObjectPath.AGENT_SESSION);
			} catch (Error get_proxy_error) {
				assert_not_reached ();
			}

			session.message_from_script.connect ((script_id, msg) => message_queue.add (new ScriptMessage (script_id, msg)));

			return session;
		}

		public async void unload_agent () {
			try {
				yield session.close ();
			} catch (IOError session_error) {
				assert_not_reached ();
			}

			session = null;

			try {
				yield connection.close ();
				connection = null;
			} catch (IOError conn_error) {
				assert_not_reached ();
			}

			main_thread.join ();
			main_thread = null;

			module = null;
		}

		public async ScriptMessage wait_for_message () {
			ScriptMessage msg = null;

			do {
				msg = message_queue.poll ();
				if (msg == null)
					yield process_events ();
			}
			while (msg == null);

			return msg;
		}

		public class ScriptMessage {
			public uint sender_id {
				get;
				private set;
			}

			public Variant content {
				get;
				private set;
			}

			public ScriptMessage (uint sender_id, Variant content) {
				this.sender_id = sender_id;
				this.content = content;
			}
		}

		private void * agent_main_worker () {
			main_impl (listen_address);
			return null;
		}

		public void run () {
			var timed_out = false;

			timeout_source = new TimeoutSource.seconds (5);
			timeout_source.set_callback (() => {
				timed_out = true;
				main_loop.quit ();
				return false;
			});
			timeout_source.attach (main_context);

			var idle = new IdleSource ();
			idle.set_callback (() => {
				test_sequence (this);
				return false;
			});
			idle.attach (main_context);

			main_context.push_thread_default ();
			main_loop.run ();
			main_context.pop_thread_default ();

			assert (!timed_out);
			timeout_source = null;
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

		public void done () {
			/* Queue an idle handler, allowing MainContext to perform any outstanding completions, in turn cleaning up resources */
			var idle = new IdleSource ();
			idle.set_callback (() => {
				main_loop.quit ();
				return false;
			});
			idle.attach (main_context);
		}
	}
}
