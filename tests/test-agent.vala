namespace Zed.AgentTest {
	public static void add_tests () {
		GLib.Test.add_func ("/Agent/Script/load-and-receive-messages", () => {
			var h = new Harness ((h) => Script.load_and_receive_messages (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Agent/Script/performance", () => {
			var h = new Harness ((h) => Script.performance (h as Harness));
			h.run ();
		});
	}

	namespace Script {
		private static async void load_and_receive_messages (Harness h) {
			var session = yield h.load_agent ();

			unowned TargetFunc func = (TargetFunc) target_function;

			AgentScriptId sid;
			try {
				sid = yield session.create_script (
					("Interceptor.attach (ptr(\"0x%" + size_t.FORMAT_MODIFIER + "x\"), {" +
					 "  onEnter: function(args) {" +
					 "    send({ first_argument: args[0].toInt32(), second_argument: Memory.readUtf8String(args[1]) });" +
					 "  }" +
					 "});").printf ((size_t) func));
				yield session.load_script (sid);
			} catch (IOError attach_error) {
				assert_not_reached ();
			}

			func (1337, "Frida rocks");

			var message = yield h.wait_for_message ();
			assert (message.sender_id.handle == sid.handle);
			assert (message.content == "{\"type\":\"send\",\"payload\":{\"first_argument\":1337,\"second_argument\":\"Frida rocks\"}}");

			yield h.unload_agent ();

			h.done ();
		}

		private static async void performance (Harness h) {
			var session = yield h.load_agent ();

			var size = 4096;
			var buf = new uint8[size];

			AgentScriptId sid;
			try {
				sid = yield session.create_script (
					("var buf = Memory.readByteArray(ptr(\"0x%" + size_t.FORMAT_MODIFIER + "x\"), %d);" +
					 "var startTime = new Date();" +
					 "var sendNext = function sendNext() {" +
					 "  send({}, buf);" +
					 "  if (new Date().getTime() - startTime.getTime() <= 1000) {" +
					 "    setTimeout(sendNext, 0);" +
					 "  } else {" +
					 "    send(null);" +
					 "  }" +
					 "};" +
					 "sendNext();"
					).printf ((size_t) buf, size));
				yield session.load_script (sid);
			} catch (IOError attach_error) {
				assert_not_reached ();
			}

			var firstMessage = yield h.wait_for_message ();
			assert (firstMessage.content == "{\"type\":\"send\",\"payload\":{}}");

			var timer = new Timer ();
			int count = 0;
			while (true) {
				var message = yield h.wait_for_message ();
				count++;
				if (message.content != "{\"type\":\"send\",\"payload\":{}}") {
					assert (message.content == "{\"type\":\"send\",\"payload\":null}");
					break;
				}
			}

			stdout.printf ("<got %d bytes or %d messages in %f seconds> ", count * size, count, timer.elapsed ());

			yield h.unload_agent ();

			h.done ();
		}

		[CCode (has_target=false)]
		private delegate void TargetFunc (int level, string message);

		public extern static uint target_function (int level, string message);
	}

	private class Harness : Zed.Test.AsyncHarness {
		private GLib.Module module;
		[CCode (has_target = false)]
		private delegate void AgentMainFunc (string data_string);
		private AgentMainFunc main_impl;
		private PipeTransport transport;
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
				transport = new PipeTransport.with_pid (Zed.Test.Process.current.id);
			} catch (IOError transport_error) {
				printerr ("failed to create transport: %s\n", transport_error.message);
				assert_not_reached ();
			}

			try {
				main_thread = Thread.create<bool> (agent_main_worker, true);
			} catch (ThreadError thread_error) {
				assert_not_reached ();
			}

			try {
				connection = yield DBusConnection.new_for_stream (new Pipe (transport.local_address), null, DBusConnectionFlags.NONE);
				session = yield connection.get_proxy (null, ObjectPath.AGENT_SESSION);
			} catch (Error dbus_error) {
				assert_not_reached ();
			}

			session.message_from_script.connect ((sid, message, data) => message_queue.add (new ScriptMessage (sid, message)));

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
			} catch (Error connection_error) {
				assert_not_reached ();
			}
			connection = null;

			main_thread.join ();
			main_thread = null;

			module = null;
		}

		public async ScriptMessage wait_for_message () {
			ScriptMessage message = null;

			do {
				message = message_queue.poll ();
				if (message == null)
					yield process_events ();
			}
			while (message == null);

			return message;
		}

		/*
		protected override uint provide_timeout () {
			return 120;
		}
		*/

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
			main_impl (transport.remote_address);
			return true;
		}
	}
}
