namespace Frida.Inject {
	private static Application application;

	private static int target_pid = -1;
	private static string? target_name;
	private static string? script_path;
	private static string? parameters_str;
	private static bool eternalize;
	private static bool enable_jit;
	private static bool enable_development;
	private static bool output_version;

	const OptionEntry[] options = {
		{ "pid", 'p', 0, OptionArg.INT, ref target_pid, null, "PID" },
		{ "name", 'n', 0, OptionArg.STRING, ref target_name, null, "PID" },
		{ "script", 's', 0, OptionArg.FILENAME, ref script_path, null, "JAVASCRIPT_FILENAME" },
		{ "parameters",  's', 0, OptionArg.STRING, ref parameters_str, "Parameters as JSON, same as Gadget", "PARAMETERS_JSON" },
		{ "eternalize", 'e', 0, OptionArg.NONE, ref eternalize, "Eternalize script and exit", null },
		{ "enable-jit", 0, 0, OptionArg.NONE, ref enable_jit, "Enable the JIT runtime", null },
		{ "development", 'D', 0, OptionArg.NONE, ref enable_development, "Enable development mode", null },
		{ "version", 0, 0, OptionArg.NONE, ref output_version, "Output version information and exit", null },
		{ null }
	};

	private static int main (string[] args) {
#if !WINDOWS
		Posix.setsid ();
#endif

		Environment.init ();

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

		if (target_pid == -1 && target_name == null) {
			printerr ("PID or name must be specified\n");
			return 2;
		}

		if (script_path == null || script_path == "") {
			printerr ("Path to JavaScript file must be specified\n");
			return 3;
		}

		string? script_source = null;
		if (script_path == "-") {
			script_path = null;
			script_source = read_stdin ();
		}

		Json.Node parameters = new Json.Node (Json.NodeType.OBJECT);
		parameters.set_object (new Json.Object ()); 
		if (parameters_str != null && parameters_str != "") {
			try {
				var parser = new Json.Parser ();
				parser.load_from_data (parameters_str, -1);
				parameters.set_object (parser.get_root().get_object ());
			} catch (GLib.Error e) {
			}
		}

		application = new Application (target_pid, target_name, script_path, script_source, parameters, enable_jit, enable_development);

#if !WINDOWS
		Posix.signal (Posix.Signal.INT, (sig) => {
			application.shutdown ();
		});
		Posix.signal (Posix.Signal.TERM, (sig) => {
			application.shutdown ();
		});
#endif

		int exit_code = application.run ();

		application = null;

		Environment.deinit ();

		return exit_code;
	}

	private static string read_stdin () {
		var input = new StringBuilder ();
		var buffer = new char[1024];
		while (!stdin.eof ()) {
			string read_chunk = stdin.gets (buffer);
			if (read_chunk == null)
				break;
			input.append (read_chunk);
		}
		return input.str;
	}

	namespace Environment {
		public extern void init ();
		public extern void deinit ();
	}

	public class Application : Object {
		public int target_pid {
			get;
			construct;
		}

		public string? target_name {
			get;
			construct;
		}

		public string? script_path {
			get;
			construct;
		}

		public string? script_source {
			get;
			construct;
		}

		public Json.Node? parameters {
			get;
			construct;
		}

		public bool enable_jit {
			get;
			construct;
		}

		public bool enable_development {
			get;
			construct;
		}

		private DeviceManager device_manager;
		private ScriptRunner script_runner;

		private int exit_code;
		private MainLoop loop;
		private bool stopping;

		public Application (int target_pid, string? target_name, string? script_path, string? script_source, Json.Node? parameters, bool enable_jit, bool enable_development) {
			Object (
				target_pid: target_pid,
				target_name: target_name,
				script_path: script_path,
				script_source: script_source,
				parameters: parameters,
				enable_jit: enable_jit,
				enable_development: enable_development
			);
		}

		public int run () {
			Idle.add (() => {
				start.begin ();
				return false;
			});

			exit_code = 0;

			loop = new MainLoop ();
			loop.run ();

			return exit_code;
		}

		private async void start () {
			device_manager = new DeviceManager ();

			try {
				var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);

				uint pid;
				if (target_name != null) {
					var proc = yield device.get_process_by_name (target_name);
					pid = proc.pid;
				} else {
					pid = (uint) target_pid;
				}

				var session = yield device.attach (pid);

				var r = new ScriptRunner (session, script_path, script_source, parameters, enable_jit, enable_development);
				yield r.start ();
				script_runner = r;

				if (eternalize)
					stop.begin ();
			} catch (Error e) {
				printerr ("%s\n", e.message);
				exit_code = 4;
				stop.begin ();
				return;
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

	private class ScriptRunner : Object, RpcPeer {
		private Script script;
		private string? script_path;
		private string? script_source;
		private Json.Node? parameters;
		private GLib.FileMonitor script_monitor;
		private Source script_unchanged_timeout;
		private RpcClient rpc_client;
		private Session session;
		private bool load_in_progress = false;
		private bool enable_development = false;

		public ScriptRunner (Session session, string? script_path, string? script_source, Json.Node? parameters, bool enable_jit, bool enable_development) {
			this.session = session;
			this.script_path = script_path;
			this.script_source = script_source;
			this.parameters = parameters;
			this.enable_development = enable_development;

			if (enable_jit)
				session.enable_jit.begin ();
		}

		construct {
			rpc_client = new RpcClient (this);
		}

		public async void start () throws Error {
			yield load ();

			if (enable_development && script_path != null) {
				try {
					script_monitor = File.new_for_path (script_path).monitor_file (FileMonitorFlags.NONE);
					script_monitor.changed.connect (on_script_file_changed);
				} catch (GLib.Error e) {
					printerr (e.message + "\n");
				}
			}
		}

		public async void flush () {
			if (script != null && !eternalize) {
				try {
					yield rpc_client.call ("dispose", new Json.Node[] {});
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
				string source;

				var options = new ScriptOptions ();

				if (script_path != null) {
					try {
						FileUtils.get_contents (script_path, out source);
					} catch (FileError e) {
						throw new Error.INVALID_ARGUMENT (e.message);
					}

					options.name = Path.get_basename (script_path).split (".", 2)[0];
				} else {
					source = script_source;

					options.name = "frida";
				}

				var s = yield session.create_script (source, options);

				if (script != null) {
					try {
						yield rpc_client.call ("dispose", new Json.Node[] {});
					} catch (Error e) {
					}

					yield script.unload ();
					script = null;
				}
				script = s;

				script.message.connect (on_message);
				yield script.load ();

				call_init ();

				if (eternalize)
					yield script.eternalize ();
			} finally {
				load_in_progress = false;
			}
		}

		private async void call_init () {
			var stage = new Json.Node (Json.NodeType.VALUE);
			stage.set_string ("early");

			try {
				yield rpc_client.call ("init", new Json.Node[] { stage, parameters });
			} catch (Error e) {
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

		private void on_message (string raw_message, Bytes? data) {
			bool handled = rpc_client.try_handle_message (raw_message);
			if (handled)
				return;

			var parser = new Json.Parser ();
			try {
				parser.load_from_data (raw_message);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
			var message = parser.get_root ().get_object ();

			var type = message.get_string_member ("type");
			if (type == "log")
				handled = try_handle_log_message (message);

			if (!handled) {
				stdout.puts (raw_message);
				stdout.putc ('\n');
			}
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

		private async void post_rpc_message (string raw_message) throws Error {
			yield script.post (raw_message);
		}
	}
}
