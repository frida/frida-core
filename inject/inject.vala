namespace Frida.Inject {
	private static Application application;

	private static bool output_version;
	private static bool disable_jit;
	private static bool enable_development;
	private static int pid;
	private static string script_file;

	const OptionEntry[] options = {
		{ "version", 0, 0, OptionArg.NONE, ref output_version, "Output version information and exit", null },
		{ "disable-jit", 0, 0, OptionArg.NONE, ref disable_jit, "Disable the JIT runtime", null },
		{ "development", 'D', 0, OptionArg.NONE, ref enable_development, "Enable development mode", null },
		{ "pid", 'p', 0, OptionArg.INT, ref pid, null, "PID" },
		{ "script", 's', 0, OptionArg.FILENAME, ref script_file, null, "JAVASCRIPT_FILENAME" },
		{ null }
	};

	private static int main (string[] args) {
#if !WINDOWS
		Posix.setsid ();
#endif

		Environment.init ();

		pid = -1;
		script_file = "";

		try {
			var ctx = new OptionContext ();
			ctx.set_help_enabled (true);
			ctx.add_main_entries (options, null);
			ctx.parse (ref args);

			if (output_version) {
				print ("%s\n", version_string ());
				return 0;
			}
		} catch (OptionError e) {
			printerr ("%s\n", e.message);
			printerr ("Run '%s --help' to see a full list of available command line options.\n", args[0]);
			return 1;
		}

		if (pid == -1) {
			printerr ("PID must be specified\n");
			return 1;
		}

		if (script_file == "") {
			printerr ("Path to JavaScript file must be specified\n");
			return 1;
		}

		application = new Application ();

#if !WINDOWS
		Posix.signal (Posix.SIGINT, (sig) => {
			application.shutdown ();
		});
		Posix.signal (Posix.SIGTERM, (sig) => {
			application.shutdown ();
		});
#endif

		try {
			application.run (pid, script_file, disable_jit, enable_development);
		} catch (Error e) {
			printerr ("Unable to start: %s\n", e.message);
			return 1;
		}

		application = null;

        Environment.deinit ();
		return 0;
	}

	namespace Environment {
		public extern void init ();
		public extern void deinit ();
	}

	public class Application : Object {
		private DeviceManager device_manager;
		private int pid;
		private string script_file;
		private bool disable_jit;
		private bool enable_development;
		private ScriptRunner script_runner;

		private MainLoop loop;
		private bool stopping;

		public void run (int pid, string script_file, bool disable_jit, bool enable_development) throws Error {
			this.pid = pid;
			this.script_file = script_file;
			this.disable_jit = disable_jit;
			this.enable_development = enable_development;

			Idle.add (() => {
				start.begin ();
				return false;
			});

			loop = new MainLoop ();
			loop.run ();
		}

		private async void start () throws Error {
			device_manager = new DeviceManager ();
			var device_list = yield device_manager.enumerate_devices ();

			Device device = null;
			for (int i = 0; i != device_list.size (); i++) {
				Device current_device = device_list.get (i);
				if (current_device.dtype == DeviceType.LOCAL) {
					device = current_device;
					break;
				}
			}

			if (device == null)
				throw new Error.INVALID_OPERATION ("Couldn't find the local backend\n");

			var session = yield device.attach (pid);

			var r = new ScriptRunner (session, script_file, disable_jit, enable_development);
			try {
				yield r.start ();
				script_runner = r;
			} catch (Error e) {
				printerr ("Failed to load script: " + e.message + "\n");
			}
		}

		public void shutdown () {
			Idle.add (() => {
				stop.begin ();
				return false;
			});
		}

		private async void stop () {
			if (stopping)
				return;
			stopping = true;

			if (script_runner != null) {
				yield script_runner.stop ();
				script_runner = null;
			}

			yield device_manager.close ();
			device_manager = null;

			Idle.add (() => {
				loop.quit ();
				return false;
			});
		}
	}

	private class ScriptRunner : Object {
		private Script script;
		private string script_file;
		private FileMonitor script_monitor;
		private Source script_unchanged_timeout;
		private Session session;
		private bool load_in_progress = false;
		private bool enable_development = false;

		private Gee.HashMap<string, PendingResponse> pending = new Gee.HashMap<string, PendingResponse> ();
		private int64 next_request_id = 1;

		public ScriptRunner (Session session, string script_file, bool disable_jit, bool enable_development) {
			this.session = session;
			this.script_file = script_file;
			this.enable_development = enable_development;

			if (disable_jit)
				session.disable_jit.begin ();
		}

		public async void start () throws Error {
			yield load ();

			if (enable_development) {
				try {
					script_monitor = File.new_for_path (script_file).monitor_file (FileMonitorFlags.NONE);
					script_monitor.changed.connect (on_script_file_changed);
				} catch (GLib.Error e) {
					printerr (e.message + "\n");
				}
			}
		}

		public async void flush () {
			if (script != null) {
				try {
					yield call ("dispose", new Json.Node[] {});
				} catch (Error e) {
				}
			}
		}

		public async void stop () {
			yield flush ();

			if (script_monitor != null) {
				script_monitor.changed.disconnect (on_script_file_changed);
				script_monitor.cancel ();
				script_monitor = null;
			}

			yield session.detach ();
		}

		private async void try_reload () {
			try {
				yield load ();
			} catch (Error e) {
				printerr ("Failed to reload script: %s\n", e.message);
			}
		}

		private async void load () throws Error {
			load_in_progress = true;

			try {
				var name = Path.get_basename (script_file).split (".", 2)[0];

				string source;
				try {
					FileUtils.get_contents (script_file, out source);
				} catch (FileError e) {
					throw new Error.INVALID_ARGUMENT (e.message);
				}

				var s = yield session.create_script (name, source);

				if (script != null) {
					try {
						yield call ("dispose", new Json.Node[] {});
					} catch (Error e) {
					}

					yield script.unload ();
					script = null;
				}
				script = s;

				script.message.connect (on_message);
				yield script.load ();

				try {
					yield call ("init", new Json.Node[] {});
				} catch (Error e) {
				}
			} finally {
				load_in_progress = false;
			}
		}

		private async Json.Node call (string method, Json.Node[] args) throws Error {
			var request_id = next_request_id++;

			var builder = new Json.Builder ();
			builder
			.begin_array ()
			.add_string_value ("frida:rpc")
			.add_int_value (request_id)
			.add_string_value ("call")
			.add_string_value (method)
			.begin_array ();
			foreach (var arg in args)
				builder.add_value (arg);
			builder
			.end_array ()
			.end_array ();

			var generator = new Json.Generator ();
			generator.set_root (builder.get_root ());
			size_t length;
			var request = generator.to_data (out length);

			var response = new PendingResponse (() => call.callback ());
			pending[request_id.to_string ()] = response;

			post_call_request.begin (request, response);

			yield;

			if (response.error != null)
				throw response.error;

			return response.result;
		}

		private async void post_call_request (string request, PendingResponse response) {
			try {
				yield script.post_message (request);
			} catch (GLib.Error e) {
				response.complete_with_error (Marshal.from_dbus (e));
			}
		}

		private void on_script_file_changed (File file, File? other_file, FileMonitorEvent event_type) {
			if (event_type == FileMonitorEvent.CHANGES_DONE_HINT)
				return;

			var source = new TimeoutSource (50);
			source.set_callback (() => {
				if (load_in_progress)
					return true;
				try_reload.begin ();
				return false;
			});
			source.attach (Frida.get_main_context ());

			if (script_unchanged_timeout != null)
				script_unchanged_timeout.destroy ();
			script_unchanged_timeout = source;
		}

		private void on_message (string raw_message, uint8[] data) {
			var parser = new Json.Parser ();
			try {
				parser.load_from_data (raw_message);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
			var message = parser.get_root ().get_object ();

			bool handled = false;
			var type = message.get_string_member ("type");
			if (type == "send")
				handled = try_handle_rpc_message (message);
			else if (type == "log")
				handled = try_handle_log_message (message);

			if (!handled) {
				stdout.puts (raw_message);
				stdout.putc ('\n');
			}
		}

		private bool try_handle_rpc_message (Json.Object message) {
			var payload = message.get_member ("payload");
			if (payload == null || payload.get_node_type () != Json.NodeType.ARRAY)
				return false;
			var rpc_message = payload.get_array ();
			if (rpc_message.get_length () < 4)
				return false;
			else if (rpc_message.get_element (0).get_string () != "frida:rpc")
				return false;

			var request_id = rpc_message.get_int_element (1);
			PendingResponse response;
			pending.unset (request_id.to_string (), out response);
			var status = rpc_message.get_string_element (2);
			if (status == "ok")
				response.complete_with_result (rpc_message.get_element (3));
			else
				response.complete_with_error (new Error.NOT_SUPPORTED (rpc_message.get_string_element (3)));
			return true;
		}

		private bool try_handle_log_message (Json.Object message) {
			var level = message.get_string_member ("level");
			var payload = message.get_string_member ("payload");
			switch (level) {
				case "info":
					print ("%s\n", payload);
					break;

				case "warning":
					printerr ("\033[0;33m%s\033[0m\n", payload);
					break;

				case "error":
					printerr ("\033[0;31m%s\033[0m\n", payload);
					break;
			}
			return true;
		}

		private class PendingResponse {
			public delegate void CompletionHandler ();
			private CompletionHandler handler;

			public Json.Node? result {
				get;
				private set;
			}

			public Error? error {
				get;
				private set;
			}

			public PendingResponse (owned CompletionHandler handler) {
				this.handler = (owned) handler;
			}

			public void complete_with_result (Json.Node r) {
				result = r;
				handler ();
			}

			public void complete_with_error (Error e) {
				error = e;
				handler ();
			}
		}
	}
}
