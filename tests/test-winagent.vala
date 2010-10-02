namespace Zed.WinAgentTest {
	public static void add_tests () {
		GLib.Test.add_func ("/WinAgent/Script/attach-and-receive-messages", () => {
			var h = new Harness ((h) => Script.attach_and_receive_messages (h as Harness));
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

			target_function (42, "Hello Frida");

			var msg = yield h.wait_for_message ();
			assert (msg.sender_id == script.id);
			assert (msg.content.print (false) == "(42, 'Hello Frida')");

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

	private class Harness : Zed.Test.AsyncHarness {
		private GLib.Module module;
		[CCode (has_target = false)]
		private delegate void AgentMainFunc (string data_string);
		private AgentMainFunc main_impl;
		private string server_address;
		private unowned Thread main_thread;
		private AgentSession session;

		private Gee.LinkedList<ScriptMessage> message_queue = new Gee.LinkedList<ScriptMessage> ();

		public Harness (Zed.Test.AsyncHarness.TestSequenceFunc func) {
			base (func);
		}

		public async AgentSession load_agent () {
			var intermediate_root_dir = Path.get_dirname (Path.get_dirname (Zed.Test.Process.current.filename));
			string agent_filename;
			if (sizeof (void *) == 4)
				agent_filename = Path.build_filename (intermediate_root_dir, "zed-winagent-32", "zed-winagent-32.dll");
			else
				agent_filename = Path.build_filename (intermediate_root_dir, "zed-winagent-64", "zed-winagent-64.dll");

			module = GLib.Module.open (agent_filename, 0);
			assert (module != null);

			void * main_func_symbol;
			var main_func_found = module.symbol ("zed_agent_main", out main_func_symbol);
			assert (main_func_found);
			main_impl = (AgentMainFunc) main_func_symbol;

			var proxy = new WinIpc.ServerProxy ();
			server_address = proxy.address;

			try {
				main_thread = Thread.create (agent_main_worker, true);
			} catch (ThreadError thread_error) {
				assert_not_reached ();
			}

			try {
				yield proxy.establish ();
			} catch (WinIpc.ProxyError proxy_error) {
				assert_not_reached ();
			}

			session = new Zed.Service.WindowsAgentSession (proxy);
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
			main_impl (server_address);
			return null;
		}
	}
}
