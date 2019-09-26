namespace Frida.Inject {
	private static Application application;

	private static string? device_id;
	private static string? spawn_file;
	private static int target_pid = -1;
	private static string? target_name;
	private static string? script_path;
	private static string? script_runtime_str;
	private static string? parameters_str;
	private static bool eternalize;
	private static bool enable_development;
	private static bool output_version;

	const OptionEntry[] options = {
		{ "device", 'D', 0, OptionArg.STRING, ref device_id, "connect to device with the given ID", "ID" },
		{ "file", 'f', 0, OptionArg.STRING, ref spawn_file, "spawn FILE", "FILE" },
		{ "pid", 'p', 0, OptionArg.INT, ref target_pid, "attach to PID", "PID" },
		{ "name", 'n', 0, OptionArg.STRING, ref target_name, "attach to NAME", "NAME" },
		{ "script", 's', 0, OptionArg.FILENAME, ref script_path, null, "JAVASCRIPT_FILENAME" },
		{ "runtime", 'R', 0, OptionArg.STRING, ref script_runtime_str, "Script runtime to use", "duk|v8" },
		{ "parameters", 'P', 0, OptionArg.STRING, ref parameters_str, "Parameters as JSON, same as Gadget", "PARAMETERS_JSON" },
		{ "eternalize", 'e', 0, OptionArg.NONE, ref eternalize, "Eternalize script and exit", null },
		{ "development", 0, 0, OptionArg.NONE, ref enable_development, "Enable development mode", null },
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

		if (spawn_file == null && target_pid == -1 && target_name == null) {
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

		ScriptRuntime script_runtime = DEFAULT;
		if (script_runtime_str != null) {
			var klass = (EnumClass) typeof (ScriptRuntime).class_ref ();
			var v = klass.get_value_by_nick (script_runtime_str);
			if (v == null) {
				printerr ("Invalid script runtime\n");
				return 4;
			}
			script_runtime = (ScriptRuntime) v.value;
		}

		var parameters = new Json.Node.alloc ().init_object (new Json.Object ());
		if (parameters_str != null) {
			if (parameters_str == "") {
				printerr ("Parameters argument must be specified as JSON if present\n");
				return 5;
			}

			try {
				var root = Json.from_string (parameters_str);
				if (root.get_node_type () != OBJECT) {
					printerr ("Failed to parse parameters argument as JSON: not an object\n");
					return 6;
				}

				parameters.take_object (root.get_object ());
			} catch (GLib.Error e) {
				printerr ("Failed to parse parameters argument as JSON: %s\n", e.message);
				return 6;
			}
		}

		application = new Application (device_id, spawn_file, target_pid, target_name, script_path, script_source, script_runtime,
			parameters, enable_development);

#if !WINDOWS
		Posix.signal (Posix.Signal.INT, (sig) => {
			application.shutdown ();
		});
		Posix.signal (Posix.Signal.TERM, (sig) => {
			application.shutdown ();
		});
#endif

		return application.run ();
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
	}

	public class Application : Object {
		public string? device_id {
			get;
			construct;
		}

		public string? spawn_file {
			get;
			construct;
		}

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

		public ScriptRuntime script_runtime {
			get;
			construct;
		}

		public Json.Node parameters {
			get;
			construct;
		}

		public bool enable_development {
			get;
			construct;
		}

		private DeviceManager device_manager;
		private ScriptRunner script_runner;
		private Cancellable io_cancellable = new Cancellable ();
		private Cancellable stop_cancellable;

		private int exit_code;
		private MainLoop loop;

		public Application (string? device_id, string? spawn_file, int target_pid, string? target_name, string? script_path,
				string? script_source, ScriptRuntime script_runtime, Json.Node parameters, bool enable_development) {
			Object (
				device_id: device_id,
				spawn_file: spawn_file,
				target_pid: target_pid,
				target_name: target_name,
				script_path: script_path,
				script_source: script_source,
				script_runtime: script_runtime,
				parameters: parameters,
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
				Device device;
				if (device_id != null)
					device = yield device_manager.get_device_by_id (device_id, 0, io_cancellable);
				else
					device = yield device_manager.get_device_by_type (DeviceType.LOCAL, 0, io_cancellable);

				uint pid;
				if (spawn_file != null) {
					pid = yield device.spawn (spawn_file, null, io_cancellable);
				} else if (target_name != null) {
					var proc = yield device.get_process_by_name (target_name, 0, io_cancellable);
					pid = proc.pid;
				} else {
					pid = (uint) target_pid;
				}

				var session = yield device.attach (pid, io_cancellable);
				session.detached.connect (on_detached);

				var r = new ScriptRunner (session, script_path, script_source, script_runtime, parameters,
					enable_development, io_cancellable);
				yield r.start ();
				script_runner = r;

				if (spawn_file != null) {
					yield device.resume (pid);
				}

				if (eternalize)
					stop.begin ();
			} catch (GLib.Error e) {
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
			if (stop_cancellable != null) {
				stop_cancellable.cancel ();
				return;
			}
			stop_cancellable = new Cancellable ();

			io_cancellable.cancel ();

			try {
				if (script_runner != null) {
					yield script_runner.stop (stop_cancellable);
					script_runner = null;
				}

				yield device_manager.close (stop_cancellable);
				device_manager = null;
			} catch (IOError e) {
				assert (e is IOError.CANCELLED);
			}

			Idle.add (() => {
				loop.quit ();
				return false;
			});
		}

		private void on_detached (SessionDetachReason reason, Crash? crash) {
			if (reason == APPLICATION_REQUESTED)
				return;

			var message = new StringBuilder ();

			message.append ("\033[0;31m");
			if (crash == null) {
				var nick = reason.to_nick ();
				message.append_c (nick[0].toupper ());
				message.append (nick.substring (1).replace ("-", " "));
			} else {
				message.append_printf ("Process crashed: %s", crash.summary);
			}
			message.append ("\033[0m\n");

			if (crash != null) {
				message.append ("\n***\n");
				message.append (crash.report.strip ());
				message.append ("\n***\n");
			}

			printerr ("%s", message.str);

			shutdown ();
		}
	}

	private class ScriptRunner : Object, RpcPeer {
		private Script? script;
		private string? script_path;
		private string? script_source;
		private ScriptRuntime script_runtime;
		private Json.Node parameters;
		private GLib.FileMonitor script_monitor;
		private Source script_unchanged_timeout;
		private RpcClient rpc_client;
		private Session session;
		private bool load_in_progress = false;
		private bool enable_development = false;
		private Cancellable io_cancellable;

		public ScriptRunner (Session session, string? script_path, string? script_source, ScriptRuntime script_runtime,
				Json.Node parameters, bool enable_development, Cancellable io_cancellable) {
			this.session = session;
			this.script_path = script_path;
			this.script_source = script_source;
			this.script_runtime = script_runtime;
			this.parameters = parameters;
			this.enable_development = enable_development;
			this.io_cancellable = io_cancellable;
		}

		construct {
			rpc_client = new RpcClient (this);
		}

		public async void start () throws Error, IOError {
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

		public async void stop (Cancellable? cancellable) throws IOError {
			if (script_monitor != null) {
				script_monitor.changed.disconnect (on_script_file_changed);
				script_monitor.cancel ();
				script_monitor = null;
			}

			yield session.detach (cancellable);
		}

		private async void try_reload () {
			try {
				yield load ();
			} catch (GLib.Error e) {
				printerr ("Failed to reload script: %s\n", e.message);
			}
		}

		private async void load () throws Error, IOError {
			load_in_progress = true;

			try {
				string source;

				var options = new ScriptOptions ();

				if (script_path != null) {
					try {
						FileUtils.get_contents (script_path, out source);
					} catch (FileError e) {
						throw new Error.INVALID_ARGUMENT ("%s", e.message);
					}

					options.name = Path.get_basename (script_path).split (".", 2)[0];
				} else {
					source = script_source;

					options.name = "frida";
				}

				options.runtime = script_runtime;

				var s = yield session.create_script (source, options, io_cancellable);

				if (script != null) {
					yield script.unload (io_cancellable);
					script = null;
				}
				script = s;

				script.message.connect (on_message);
				yield script.load (io_cancellable);

				yield call_init ();

				if (eternalize)
					yield script.eternalize (io_cancellable);
			} finally {
				load_in_progress = false;
			}
		}

		private async void call_init () {
			var stage = new Json.Node.alloc ().init_string ("early");

			try {
				yield rpc_client.call ("init", new Json.Node[] { stage, parameters }, io_cancellable);
			} catch (GLib.Error e) {
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

		private async void post_rpc_message (string raw_message, Cancellable? cancellable) throws Error, IOError {
			yield script.post (raw_message, null, cancellable);
		}
	}
}
