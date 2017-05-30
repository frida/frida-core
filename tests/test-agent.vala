namespace Frida.AgentTest {
	public static void add_tests () {
		GLib.Test.add_func ("/Agent/Script/load-and-receive-messages", () => {
			var h = new Harness ((h) => Script.load_and_receive_messages.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Agent/Script/performance", () => {
			var h = new Harness ((h) => Script.performance.begin (h as Harness));
			h.run ();
		});

#if DARWIN
		GLib.Test.add_func ("/Agent/Script/Darwin/launch-scenario", () => {
			var h = new Harness ((h) => Script.launch_scenario.begin (h as Harness));
			h.run ();
		});
#endif
	}

	namespace Script {
		private static async void load_and_receive_messages (Harness h) {
			var session = yield h.load_agent ();

			unowned TargetFunc func = (TargetFunc) target_function;

			AgentScriptId sid;
			try {
				sid = yield session.create_script ("load-and-receive-messages",
					("Interceptor.attach (ptr(\"0x%" + size_t.FORMAT_MODIFIER + "x\"), {" +
					 "  onEnter: function(args) {" +
					 "    send({ first_argument: args[0].toInt32(), second_argument: Memory.readUtf8String(args[1]) });" +
					 "  }" +
					 "});").printf ((size_t) func));
				yield session.load_script (sid);
			} catch (GLib.Error attach_error) {
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
				sid = yield session.create_script ("performance",
					("var buf = Memory.readByteArray(ptr(\"0x%" + size_t.FORMAT_MODIFIER + "x\"), %d);" +
					 "var startTime = new Date();" +
					 "var iterations = 0;" +
					 "var sendNext = function sendNext() {" +
					 "  send({}, buf);" +
					 "  if (new Date().getTime() - startTime.getTime() <= 1000) {" +
					 "    setTimeout(sendNext, ((++iterations %% 10) === 0) ? 1 : 0);" +
					 "  } else {" +
					 "    send(null);" +
					 "  }" +
					 "};" +
					 "sendNext();"
					).printf ((size_t) buf, size));
				yield session.load_script (sid);
			} catch (GLib.Error attach_error) {
				assert_not_reached ();
			}

			var first_message = yield h.wait_for_message ();
			assert (first_message.content == "{\"type\":\"send\",\"payload\":{}}");

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

#if DARWIN
		private static async void launch_scenario (Harness h) {
			if (!GLib.Test.slow ()) {
				stdout.printf ("<skipping, run in slow mode> ");
				h.done ();
				return;
			}

			var session = yield h.load_agent ();

			AgentScriptId sid;
			try {
				sid = yield session.create_script ("launch-scenario", """
'use strict';

var readU16 = Memory.readU16;
var writeU16 = Memory.writeU16;
var readU32 = Memory.readU32;
var readPointer = Memory.readPointer;
var readString = Memory.readUtf8String;

var pointerSize = Process.pointerSize;

var POSIX_SPAWN_START_SUSPENDED = 0x0080;

var upcoming = {};
var gating = false;
var active = 0;

rpc.exports = {
  prepareForLaunch: function (identifier) {
    upcoming[identifier] = true;
    active++;
  },
  cancelLaunch: function (identifier) {
    if (upcoming[identifier] !== undefined) {
      delete upcoming[identifier];
      active--;
    }
  },
  enableSpawnGating: function () {
    if (gating)
      throw new Error('Spawn gating already enabled');
    gating = true;
    active++;
  },
  disableSpawnGating: function () {
    if (!gating)
      throw new Error('Spawn gating already disabled');
    gating = false;
    active--;
  },
};

Interceptor.attach(Module.findExportByName('/usr/lib/system/libsystem_kernel.dylib', '__posix_spawn'), {
  onEnter: function (args) {
    if (active === 0)
      return;

    var path = readString(args[1]);
    if (path !== '/bin/ls')
      return;

    var rawIdentifier = readString(readPointer(args[3].add(pointerSize)));

    var identifier, event;
    if (rawIdentifier.indexOf('UIKitApplication:') === 0) {
      identifier = rawIdentifier.substring(17, rawIdentifier.lastIndexOf('['));
      if (upcoming[identifier] !== undefined)
        event = 'launch:app';
      else if (gating)
        event = 'spawn';
      else
        return;
    } else if (gating) {
      identifier = rawIdentifier;
      event = 'spawn';
    } else {
      return;
    }

    var attrs = readPointer(args[2].add(pointerSize));

    var flags = readU16(attrs);
    flags |= POSIX_SPAWN_START_SUSPENDED;
    writeU16(attrs, flags);

    this.event = event;
    this.identifier = identifier;
    this.pidPtr = args[0];
  },
  onLeave: function (retval) {
    if (active === 0)
      return;

    var event = this.event;
    if (event === undefined)
      return;

    var identifier = this.identifier;

    if (event === 'launch:app') {
      delete upcoming[identifier];
      active--;
    }

    if (retval.toInt32() < 0)
      return;

    send([event, identifier, readU32(this.pidPtr)]);
  }
});
""");
				yield session.load_script (sid);

				h.disable_timeout ();

				print ("\n");

				for (uint i = 0; i != 1000000; i++) {
					int64 next_id = 1;

					var id = next_id++;
					print ("\nLaunch #%u\n", i);

					var request = new Json.Builder ()
						.begin_array ()
							.add_string_value ("frida:rpc")
							.add_int_value (id)
							.add_string_value ("call")
							.add_string_value ("prepareForLaunch")
							.begin_array ()
								.add_string_value ("foo.bar.Baz")
							.end_array ()
						.end_array ();
					var raw_request = Json.to_string (request.get_root (), false);
					yield session.post_to_script (sid, raw_request, false, new uint8[0] {});

					while (true) {
						var message = yield h.wait_for_message ();

						var reader = new Json.Reader (Json.from_string (message.content));

						reader.read_member ("type");
						if (reader.get_string_value () !=  "send") {
							printerr ("%s\n", message.content);
							continue;
						}
						reader.end_member ();

						reader.read_member ("payload");
						if (!reader.is_array ()) {
							printerr ("%s\n", Json.to_string (reader.get_value (), true));
							continue;
						}

						reader.read_element (0);
						assert (reader.get_string_value () ==  "frida:rpc");
						reader.end_element ();

						reader.read_element (1);
						assert (reader.get_int_value () == id);
						reader.end_element ();

						reader.read_element (2);
						assert (reader.get_string_value () ==  "ok");
						reader.end_element ();

						reader.read_element (3);
						assert (reader.get_null_value ());
						reader.end_element ();

						reader.end_member ();

						break;
					}

					var child = Frida.Test.Process.start ("/bin/ls", new string[] { "UIKitApplication:foo.bar.Baz[0x1234]" });

					while (true) {
						var message = yield h.wait_for_message ();
						printerr ("got message: %s\n", message.content);

						var reader = new Json.Reader (Json.from_string (message.content));

						reader.read_member ("type");
						if (reader.get_string_value () !=  "send") {
							printerr ("%s\n", message.content);
							continue;
						}
						reader.end_member ();

						reader.read_member ("payload");
						if (!reader.is_array ()) {
							printerr ("%s\n", Json.to_string (reader.get_value (), true));
							continue;
						}

						reader.read_element (0);
						assert (reader.get_string_value () ==  "launch:app");
						reader.end_element ();

						reader.read_element (1);
						assert (reader.get_string_value () == "foo.bar.Baz");
						reader.end_element ();

						reader.read_element (2);
						assert (reader.get_int_value () ==  child.id);
						reader.end_element ();

						reader.end_member ();

						break;
					}

					child.resume ();
					child.join (5000);

					Timeout.add (20 * 1000, () => {
						launch_scenario.callback ();
						return false;
					});
					print ("waiting 20s\n");
					yield;
					print ("waited 20s\n");
				}
			} catch (GLib.Error e) {
				printerr ("\n\nERROR: %s\n", e.message);
				assert_not_reached ();
			}

			yield h.unload_agent ();

			h.done ();
		}
#endif

		[CCode (has_target=false)]
		private delegate void TargetFunc (int level, string message);

		public extern static uint target_function (int level, string message);
	}

	private class Harness : Frida.Test.AsyncHarness {
		private GLib.Module module;
		[CCode (has_target = false)]
		private delegate void AgentMainFunc (string data, Gum.MemoryRange? mapped_range, Gum.ThreadId parent_thread_id);
		private AgentMainFunc main_impl;
		private PipeTransport transport;
		private Thread<bool> main_thread;
		private DBusConnection connection;
		private AgentSessionProvider provider;
		private AgentSession session;

		private Gee.LinkedList<ScriptMessage> message_queue = new Gee.LinkedList<ScriptMessage> ();

		public Harness (owned Frida.Test.AsyncHarness.TestSequenceFunc func) {
			base ((owned) func);
		}

		public async AgentSession load_agent () {
			string agent_filename;
#if WINDOWS
			var intermediate_root_dir = Path.get_dirname (Path.get_dirname (Frida.Test.Process.current.filename));
			if (sizeof (void *) == 4)
				agent_filename = Path.build_filename (intermediate_root_dir, "frida-agent-32", "frida-agent-32.dll");
			else
				agent_filename = Path.build_filename (intermediate_root_dir, "frida-agent-64", "frida-agent-64.dll");
#else
			string shlib_extension;
#if DARWIN
			shlib_extension = "dylib";
#else
			shlib_extension = "so";
#endif
			var frida_root_dir = Path.get_dirname (Path.get_dirname (Frida.Test.Process.current.filename));
			agent_filename = Path.build_filename (frida_root_dir, "lib", "frida", "frida-agent." + shlib_extension);
			if (!FileUtils.test (agent_filename, FileTest.EXISTS))
				agent_filename = Path.build_filename (frida_root_dir, "lib", "agent", "frida-agent." + shlib_extension);
#endif

			module = GLib.Module.open (agent_filename, 0);
			assert (module != null);

			void * main_func_symbol;
			var main_func_found = module.symbol ("frida_agent_main", out main_func_symbol);
			assert (main_func_found);
			main_impl = (AgentMainFunc) main_func_symbol;

			IOStream stream;
			try {
				transport = new PipeTransport ();
				stream = new Pipe (transport.local_address);
			} catch (IOError transport_error) {
				printerr ("Unable to create transport: %s\n", transport_error.message);
				assert_not_reached ();
			}

			main_thread = new Thread<bool> ("frida-test-agent-worker", agent_main_worker);

			try {
				connection = yield new DBusConnection (stream, null, DBusConnectionFlags.NONE);
				provider = yield connection.get_proxy (null, ObjectPath.AGENT_SESSION_PROVIDER);

				var session_id = AgentSessionId (1);
				yield provider.open (session_id);

				session = yield connection.get_proxy (null, ObjectPath.from_agent_session_id (session_id));
			} catch (GLib.Error dbus_error) {
				assert_not_reached ();
			}

			session.message_from_script.connect ((sid, message, has_data, data) => message_queue.add (new ScriptMessage (sid, message)));

			return session;
		}

		public async void unload_agent () {
			try {
				yield session.close ();
			} catch (GLib.Error session_error) {
				assert_not_reached ();
			}
			session = null;
			provider = null;

			try {
				yield connection.close ();
			} catch (GLib.Error connection_error) {
			}
			connection = null;

			Thread<bool> t = main_thread;
			t.join ();
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
			main_impl (transport.remote_address, null, 0);
			return true;
		}
	}
}
