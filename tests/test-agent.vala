namespace Zed.AgentTest {
	public static void add_tests () {
		GLib.Test.add_func ("/Agent/Script/load-and-receive-messages", () => {
			var h = new Harness ((h) => Script.load_and_receive_messages (h as Harness));
			h.run ();
		});
	}

	namespace Script {
		private static async void load_and_receive_messages (Harness h) {
			var session = yield h.load_agent ();

			AgentScriptId sid;
			try {
				sid = yield session.load_script (
					("Interceptor.attach (0x%" + size_t.FORMAT_MODIFIER + "x, {" +
					 "  onEnter: function(args) {" +
					 "    send({ first_argument: args[0], second_argument: Memory.readUtf8String(args[1]) });" +
					 "  }" +
					 "});").printf ((size_t) target_function));
			} catch (IOError attach_error) {
				assert_not_reached ();
			}

			target_function (1337, "Frida rocks");

			var msg = yield h.wait_for_message ();
			assert (msg.sender_id.handle == sid.handle);
			assert (msg.content == "{\"type\":\"send\",\"payload\":{\"first_argument\":1337,\"second_argument\":\"Frida rocks\"}}");

			yield h.unload_agent ();

			h.done ();
		}

		public extern static uint target_function (int level, string message);
	}

	private class Harness : Zed.Test.AsyncHarness {
		private GLib.Module module;
		[CCode (has_target = false)]
		private delegate void AgentMainFunc (string data_string);
		private AgentMainFunc main_impl;
		private string listen_address = "tcp:host=127.0.0.1,port=42042";
		private unowned Thread<bool> main_thread;
		private DBusConnection connection;
		private AgentSession session;

		private Gee.LinkedList<ScriptMessage> message_queue = new Gee.LinkedList<ScriptMessage> ();

		public Harness (owned Zed.Test.AsyncHarness.TestSequenceFunc func) {
			base ((owned) func);
		}

		public async AgentSession load_agent () {
			string agent_filename;
#if WINDOWS
			var intermediate_root_dir = Path.get_dirname (Path.get_dirname (Zed.Test.Process.current.filename));
			if (sizeof (void *) == 4)
				agent_filename = Path.build_filename (intermediate_root_dir, "zed-agent-32", "zed-agent-32.dll");
			else
				agent_filename = Path.build_filename (intermediate_root_dir, "zed-agent-64", "zed-agent-64.dll");
#else
			string shlib_extension;
#if DARWIN
			shlib_extension = "dylib";
#else
			shlib_extension = "so";
#endif
			var frida_root_dir = Path.get_dirname (Path.get_dirname (Zed.Test.Process.current.filename));
			agent_filename = Path.build_filename (frida_root_dir, "lib", "zed", "zed-agent." + shlib_extension);
			if (!FileUtils.test (agent_filename, FileTest.EXISTS))
				agent_filename = Path.build_filename (frida_root_dir, "lib", "agent", ".libs", "libzed-agent." + shlib_extension);
#endif

			module = GLib.Module.open (agent_filename, 0);
			assert (module != null);

			void * main_func_symbol;
			var main_func_found = module.symbol ("zed_agent_main", out main_func_symbol);
			assert (main_func_found);
			main_impl = (AgentMainFunc) main_func_symbol;

			try {
				main_thread = Thread.create<bool> (agent_main_worker, true);
			} catch (ThreadError thread_error) {
				assert_not_reached ();
			}

			for (int i = 0; connection == null; i++) {
				try {
					connection = yield DBusConnection.new_for_address (listen_address, DBusConnectionFlags.AUTHENTICATION_CLIENT);
				} catch (Error conn_error) {
					if (i != 10 - 1) {
						var timeout = new TimeoutSource (20);
						timeout.set_callback (() => {
							load_agent.callback ();
							return false;
						});
						timeout.attach (main_context);
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

			session.message_from_script.connect ((sid, msg) => message_queue.add (new ScriptMessage (sid, msg)));

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
			} catch (Error conn_error) {
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
			public AgentScriptId sender_id {
				get;
				private set;
			}

			public string content {
				get;
				private set;
			}

			public ScriptMessage (AgentScriptId sender_id, string content) {
				this.sender_id = sender_id;
				this.content = content;
			}
		}

		private bool agent_main_worker () {
			main_impl (listen_address);
			return true;
		}
	}
}
