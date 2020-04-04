namespace Frida.Gadget {
	private const string DEFAULT_LISTEN_ADDRESS = "127.0.0.1";
	private const uint16 DEFAULT_LISTEN_PORT = 27042;

	private class Config : Object, Json.Serializable {
		public Object interaction {
			get;
			set;
			default = new ListenInteraction ();
		}

		public TeardownRequirement teardown {
			get;
			set;
			default = TeardownRequirement.MINIMAL;
		}

		public RuntimeFlavor runtime {
			get;
			set;
			default = RuntimeFlavor.INTERPRETER;
		}

		public Gum.CodeSigningPolicy code_signing {
			get;
			set;
			default = Gum.CodeSigningPolicy.OPTIONAL;
		}

		private ObjectClass klass = (ObjectClass) typeof (Config).class_ref ();

		public Json.Node serialize_property (string property_name, GLib.Value value, GLib.ParamSpec pspec) {
			return default_serialize_property (property_name, value, pspec);
		}

		public bool deserialize_property (string property_name, out Value value, ParamSpec pspec, Json.Node property_node) {
			if (property_name == "interaction" && property_node.get_node_type () == Json.NodeType.OBJECT) {
				var interaction_node = property_node.get_object ();
				var interaction_type = interaction_node.get_string_member ("type");
				if (interaction_type != null) {
					Type t = 0;

					switch (interaction_type) {
						case "script":
							t = typeof (ScriptInteraction);
							break;
						case "script-directory":
							t = typeof (ScriptDirectoryInteraction);
							break;
						case "listen":
							t = typeof (ListenInteraction);
							break;
					}

					if (t != 0) {
						var obj = Json.gobject_deserialize (t, property_node);
						if (obj != null) {
							bool valid = true;

							if (obj is ScriptInteraction) {
								valid = ((ScriptInteraction) obj).path != null;
							} else if (obj is ScriptDirectoryInteraction) {
								valid = ((ScriptDirectoryInteraction) obj).path != null;
							}

							if (valid) {
								var v = Value (t);
								v.set_object (obj);
								value = v;
								return true;
							}
						}
					}
				}
			}

			value = Value (pspec.value_type);
			return false;
		}

		public unowned ParamSpec? find_property (string name) {
			return klass.find_property (name);
		}

		public new Value get_property (ParamSpec pspec) {
			var val = Value (pspec.value_type);
			base.get_property (pspec.name, ref val);
			return val;
		}

		public new void set_property (ParamSpec pspec, Value value) {
			base.set_property (pspec.name, value);
		}
	}

	private enum TeardownRequirement {
		MINIMAL,
		FULL
	}

	protected enum RuntimeFlavor {
		INTERPRETER,
		JIT
	}

	private class ScriptInteraction : Object, Json.Serializable {
		public string path {
			get;
			set;
			default = null;
		}

		public Json.Node parameters {
			get;
			set;
			default = make_empty_json_object ();
		}

		public Script.ChangeBehavior on_change {
			get;
			set;
			default = Script.ChangeBehavior.IGNORE;
		}

		private ObjectClass klass = (ObjectClass) typeof (ScriptInteraction).class_ref ();

		public Json.Node serialize_property (string property_name, GLib.Value value, GLib.ParamSpec pspec) {
			return default_serialize_property (property_name, value, pspec);
		}

		public bool deserialize_property (string property_name, out Value value, ParamSpec pspec, Json.Node property_node) {
			if (property_name == "parameters" && property_node.get_node_type () == Json.NodeType.OBJECT) {
				var v = Value (typeof (Json.Node));
				v.set_boxed (property_node);
				value = v;
				return true;
			}

			value = Value (pspec.value_type);
			return false;
		}

		public unowned ParamSpec? find_property (string name) {
			return klass.find_property (name);
		}

		public new Value get_property (ParamSpec pspec) {
			var val = Value (pspec.value_type);
			base.get_property (pspec.name, ref val);
			return val;
		}

		public new void set_property (ParamSpec pspec, Value value) {
			base.set_property (pspec.name, value);
		}
	}

	private class ScriptDirectoryInteraction : Object {
		public string path {
			get;
			set;
			default = null;
		}

		public ChangeBehavior on_change {
			get;
			set;
			default = ChangeBehavior.IGNORE;
		}

		public enum ChangeBehavior {
			IGNORE,
			RESCAN
		}
	}

	private class ScriptConfig : Object, Json.Serializable {
		public ProcessFilter? filter {
			get;
			set;
			default = null;
		}

		public Json.Node parameters {
			get;
			set;
			default = make_empty_json_object ();
		}

		public Script.ChangeBehavior on_change {
			get;
			set;
			default = Script.ChangeBehavior.IGNORE;
		}

		private ObjectClass klass = (ObjectClass) typeof (ScriptConfig).class_ref ();

		public Json.Node serialize_property (string property_name, GLib.Value value, GLib.ParamSpec pspec) {
			return default_serialize_property (property_name, value, pspec);
		}

		public bool deserialize_property (string property_name, out Value value, ParamSpec pspec, Json.Node property_node) {
			if (property_name == "parameters" && property_node.get_node_type () == Json.NodeType.OBJECT) {
				var v = Value (typeof (Json.Node));
				v.set_boxed (property_node.copy ());
				value = v;
				return true;
			}

			value = Value (pspec.value_type);
			return false;
		}

		public unowned ParamSpec? find_property (string name) {
			return klass.find_property (name);
		}

		public new Value get_property (ParamSpec pspec) {
			var val = Value (pspec.value_type);
			base.get_property (pspec.name, ref val);
			return val;
		}

		public new void set_property (ParamSpec pspec, Value value) {
			base.set_property (pspec.name, value);
		}
	}

	private class ProcessFilter : Object {
		public string[] executables {
			get;
			set;
			default = new string[0];
		}

		public string[] bundles {
			get;
			set;
			default = new string[0];
		}

		public string[] objc_classes {
			get;
			set;
			default = new string[0];
		}
	}

	private class ListenInteraction : Object {
		public string address {
			get;
			set;
			default = DEFAULT_LISTEN_ADDRESS;
		}

		public uint port {
			get;
			set;
			default = DEFAULT_LISTEN_PORT;
		}

		public PortConflictBehavior on_port_conflict {
			get;
			set;
			default = PortConflictBehavior.FAIL;
		}

		public LoadBehavior on_load {
			get;
			set;
			default = LoadBehavior.WAIT;
		}

		public enum PortConflictBehavior {
			FAIL,
			PICK_NEXT
		}

		public enum LoadBehavior {
			RESUME,
			WAIT
		}
	}

	private class Location : Object {
		public string executable_name {
			get;
			construct;
		}

		public string bundle_id {
			get {
				if (cached_bundle_id == null)
					cached_bundle_id = Environment.detect_bundle_id ();
				return cached_bundle_id;
			}
		}

		public string? path {
			get;
			construct;
		}

		public Gum.MemoryRange range {
			get;
			construct;
		}

		private string? cached_bundle_id = null;

		public Location (string executable_name, string? path, Gum.MemoryRange range) {
			Object (
				executable_name: executable_name,
				path: path,
				range: range
			);
		}

#if ANDROID
		construct {
			if (executable_name.has_prefix ("app_process")) {
				try {
					string cmdline;
					FileUtils.get_contents ("/proc/self/cmdline", out cmdline);
					if (cmdline != "zygote" && cmdline != "zygote64") {
						executable_name = cmdline;
						cached_bundle_id = cmdline.split (":", 2)[0];
					}
				} catch (FileError e) {
				}
			}
		}
#endif
	}

	private enum State {
		CREATED,
		STARTED,
		STOPPED
	}

	private bool loaded = false;
	private State state = State.CREATED;
	private Config config;
	private Location location;
	private bool wait_for_resume_needed;
	private MainLoop wait_for_resume_loop;
	private MainContext wait_for_resume_context;
	private ThreadIgnoreScope worker_ignore_scope;
	private Controller controller;
	private Gum.Exceptor exceptor;
	private Mutex mutex;
	private Cond cond;

	public void load (Gum.MemoryRange? mapped_range, string? config_data, int * result) {
		if (loaded)
			return;
		loaded = true;

		Environment.init ();

		Gee.Promise<int>? request = null;
		if (result != null)
			request = new Gee.Promise<int> ();

		location = detect_location (mapped_range);

		try {
			config = (config_data != null)
				? parse_config (config_data)
				: load_config (location);
		} catch (Error e) {
			log_warning (e.message);
			return;
		}

		Gum.Process.set_code_signing_policy (config.code_signing);

		Gum.Cloak.add_range (location.range);

		exceptor = Gum.Exceptor.obtain ();

		wait_for_resume_needed = true;

		var listen_interaction = config.interaction as ListenInteraction;
		if (listen_interaction != null && listen_interaction.on_load == ListenInteraction.LoadBehavior.RESUME) {
			wait_for_resume_needed = false;
		}

		if (!wait_for_resume_needed)
			resume ();

		if (wait_for_resume_needed && Environment.can_block_at_load_time ()) {
			var scheduler = Gum.ScriptBackend.get_scheduler ();

			scheduler.disable_background_thread ();

			wait_for_resume_context = scheduler.get_js_context ();

			var ignore_scope = new ThreadIgnoreScope ();

			start (request);

			var loop = new MainLoop (wait_for_resume_context, true);
			wait_for_resume_loop = loop;

			wait_for_resume_context.push_thread_default ();
			loop.run ();
			wait_for_resume_context.pop_thread_default ();

			scheduler.enable_background_thread ();

			ignore_scope = null;
		} else {
			start (request);
		}

		if (result != null) {
			try {
				*result = request.future.wait ();
			} catch (Gee.FutureError e) {
				*result = -1;
			}
		}
	}

	public void wait_for_permission_to_resume () {
		mutex.lock ();
		while (state != State.STARTED)
			cond.wait (mutex);
		mutex.unlock ();
	}

	public void unload () {
		if (!loaded)
			return;
		loaded = false;

		{
			var source = new IdleSource ();
			source.set_callback (() => {
				stop.begin ();
				return false;
			});
			source.attach (Environment.get_main_context ());
		}

		mutex.lock ();
		while (state != State.STOPPED)
			cond.wait (mutex);
		mutex.unlock ();

		if (config.teardown == TeardownRequirement.FULL) {
			config = null;

			Environment.deinit ();
		}
	}

	public void resume () {
		mutex.lock ();
		if (state != State.CREATED) {
			mutex.unlock ();
			return;
		}
		state = State.STARTED;
		cond.signal ();
		mutex.unlock ();

		if (wait_for_resume_context != null) {
			var source = new IdleSource ();
			source.set_callback (() => {
				wait_for_resume_loop.quit ();
				return false;
			});
			source.attach (wait_for_resume_context);
		}
	}

	private State peek_state () {
		State result;

		mutex.lock ();
		result = state;
		mutex.unlock ();

		return result;
	}

	private void start (Gee.Promise<int>? request) {
		var source = new IdleSource ();
		source.set_callback (() => {
			perform_start.begin (request);
			return false;
		});
		source.attach (Environment.get_main_context ());
	}

	private async void perform_start (Gee.Promise<int>? request) {
		worker_ignore_scope = new ThreadIgnoreScope ();

		Controller ctrl = null;
		try {
			var interaction = config.interaction;
			if (interaction is ScriptInteraction) {
				var runner = new ScriptRunner (config, location);
				yield runner.start ();
				ctrl = runner;

				resume ();

				if (request != null)
					request.set_value (0);
			} else if (interaction is ScriptDirectoryInteraction) {
				var runner = new ScriptDirectoryRunner (config, location);
				yield runner.start ();
				ctrl = runner;

				resume ();

				if (request != null)
					request.set_value (0);
			} else if (interaction is ListenInteraction) {
				var server = new Server (config, location);
				yield server.start ();
				ctrl = server;

				var listen_address = server.listen_address;
				var inet_address = listen_address as InetSocketAddress;
				if (inet_address != null) {
					uint16 listen_port = inet_address.get_port ();
					Environment.set_thread_name ("frida-gadget-tcp-%u".printf (listen_port));
					if (request != null) {
						request.set_value (listen_port);
					} else {
						log_info ("Listening on %s TCP port %u".printf (
							inet_address.get_address ().to_string (),
							listen_port));
					}
				} else {
#if !WINDOWS
					var unix_address = (UnixSocketAddress) listen_address;
					Environment.set_thread_name ("frida-gadget-unix");
					if (request != null) {
						request.set_value (0);
					} else {
						log_info ("Listening on UNIX socket at “%s”".printf (unix_address.get_path ()));
					}
#else
					assert_not_reached ();
#endif
				}
			} else {
				resume ();

				if (request != null) {
					request.set_exception (new Error.NOT_SUPPORTED ("Invalid interaction specified"));
				} else {
					log_warning ("Failed to start: invalid interaction specified");
				}
			}
		} catch (Error e) {
			resume ();

			if (request != null) {
				request.set_exception (e);
			} else {
				log_warning ("Failed to start: " + e.message);
			}
		}
		controller = ctrl;
	}

	private async void stop () {
		if (controller != null) {
			if (config.teardown == TeardownRequirement.MINIMAL) {
				yield controller.prepare_for_termination (TerminationReason.EXIT);
			} else {
				yield controller.stop ();
				controller = null;

				exceptor = null;
			}
		}

		worker_ignore_scope = null;

		mutex.lock ();
		state = State.STOPPED;
		cond.signal ();
		mutex.unlock ();
	}

	private Config load_config (Location location) throws Error {
		unowned string? gadget_path = location.path;
		if (gadget_path == null)
			return new Config ();

		var config_path = derive_config_path_from_file_path (gadget_path);

#if IOS
		if (!FileUtils.test (config_path, FileTest.EXISTS)) {
			var config_dir = Path.get_dirname (config_path);
			if (Path.get_basename (config_dir) == "Frameworks") {
				var app_dir = Path.get_dirname (config_dir);
				config_path = Path.build_filename (app_dir, Path.get_basename (config_path));
			}
		}
#endif

#if ANDROID
		if (!FileUtils.test (config_path, FileTest.EXISTS)) {
			var ext_index = config_path.last_index_of_char ('.');
			if (ext_index != -1) {
				config_path = config_path[0:ext_index] + ".config.so";
			} else {
				config_path = config_path + ".config.so";
			}
		}
#endif

		string config_data;
		try {
			FileUtils.get_contents (config_path, out config_data);
		} catch (FileError e) {
			if (e is FileError.NOENT)
				return new Config ();
			throw new Error.PERMISSION_DENIED ("%s", e.message);
		}

		try {
			return Json.gobject_from_data (typeof (Config), config_data) as Config;
		} catch (GLib.Error e) {
			throw new Error.INVALID_ARGUMENT ("Invalid config: %s", e.message);
		}
	}

	private Config parse_config (string config_data) throws Error {
		try {
			return Json.gobject_from_data (typeof (Config), config_data) as Config;
		} catch (GLib.Error e) {
			throw new Error.INVALID_ARGUMENT ("Invalid config: %s", e.message);
		}
	}

	private Location detect_location (Gum.MemoryRange? mapped_range) {
		string? executable_name = null;
		string? executable_path = null;
		Gum.MemoryRange? executable_range = null;
		string? our_path = null;
		Gum.MemoryRange? our_range = mapped_range;

		Gum.Address our_address = Gum.Address.from_pointer (Gum.strip_code_pointer ((void *) detect_location));

		var index = 0;
		Gum.Process.enumerate_modules ((details) => {
			var range = details.range;

			if (index == 0) {
				executable_name = details.name;
				executable_path = details.path;
				executable_range = details.range;
			}

			if (mapped_range != null)
				return false;

			if (our_address >= range.base_address && our_address < range.base_address + range.size) {
				our_path = details.path;
				our_range = range;
				return false;
			}

			index++;

			return true;
		});

		assert (our_range != null);

		return new Location (executable_name, our_path, our_range);
	}

	private interface Controller : Object {
		public abstract async void start () throws Error;
		public abstract async void prepare_for_termination (TerminationReason reason);
		public abstract async void stop ();
	}

	private abstract class BaseController : Object, Controller, ProcessInvader {
		public Config config {
			get;
			construct;
		}

		public Location location {
			get;
			construct;
		}

		private Gum.ScriptBackend? duk_backend;
		private Gum.ScriptBackend? v8_backend;

		public async void start () throws Error {
			yield on_start ();
		}

		protected abstract async void on_start () throws Error;

		public async void prepare_for_termination (TerminationReason reason) {
			yield on_terminate (reason);
		}

		protected abstract async void on_terminate (TerminationReason reason);

		public async void stop () {
			yield on_stop ();
		}

		protected abstract async void on_stop ();

		protected Gum.MemoryRange get_memory_range () {
			return location.range;
		}

		protected Gum.ScriptBackend get_script_backend (ScriptRuntime runtime) throws Error {
			switch (runtime) {
				case DEFAULT:
					break;
				case DUK:
					if (duk_backend == null) {
						duk_backend = Gum.ScriptBackend.obtain_duk ();
						if (duk_backend == null) {
							throw new Error.NOT_SUPPORTED (
								"Duktape runtime not available due to build configuration");
						}
					}
					return duk_backend;
				case V8:
					if (v8_backend == null) {
						v8_backend = Gum.ScriptBackend.obtain_v8 ();
						if (v8_backend == null) {
							throw new Error.NOT_SUPPORTED (
								"V8 runtime not available due to build configuration");
						}
					}
					return v8_backend;
			}

			if (config.runtime == INTERPRETER)
				return get_script_backend (DUK);

			return get_script_backend (V8);
		}

		protected Gum.ScriptBackend? get_active_script_backend () {
			return (v8_backend != null) ? v8_backend : duk_backend;
		}
	}

	private class ScriptRunner : BaseController {
		private ScriptEngine engine;
		private Script script;

		public ScriptRunner (Config config, Location location) {
			Object (config: config, location: location);
		}

		construct {
			engine = new ScriptEngine (this);

			var path = resolve_script_path (config, location);
			var interaction = config.interaction as ScriptInteraction;
			script = new Script (path, interaction.parameters, interaction.on_change, engine);
		}

		protected override async void on_start () throws Error {
			yield script.start ();
		}

		protected override async void on_terminate (TerminationReason reason) {
			yield script.prepare_for_termination (reason);
		}

		protected override async void on_stop () {
			yield script.stop ();

			yield engine.close ();
		}

		private static string resolve_script_path (Config config, Location location) {
			var raw_path = ((ScriptInteraction) config.interaction).path;

			if (!Path.is_absolute (raw_path)) {
				string? documents_dir = Environment.detect_documents_dir ();
				if (documents_dir != null) {
					var script_path = Path.build_filename (documents_dir, raw_path);
					if (FileUtils.test (script_path, FileTest.EXISTS))
						return script_path;
				}

				unowned string? gadget_path = location.path;
				if (gadget_path != null) {
					var base_dir = Path.get_dirname (gadget_path);
					return Path.build_filename (base_dir, raw_path);
				}
			}

			return raw_path;
		}
	}

	private class ScriptDirectoryRunner : BaseController {
		public string directory_path {
			get;
			construct;
		}

		private ScriptEngine engine;
		private Gee.HashMap<string, Script> scripts = new Gee.HashMap<string, Script> ();
		private bool scan_in_progress = false;
		private GLib.FileMonitor monitor;
		private Source unchanged_timeout;

		public ScriptDirectoryRunner (Config config, Location location) {
			Object (
				config: config,
				location: location,
				directory_path: parse_script_directory_path (config, location)
			);
		}

		construct {
			engine = new ScriptEngine (this);
		}

		protected override async void on_start () throws Error {
			var interaction = config.interaction as ScriptDirectoryInteraction;

			if (interaction.on_change == ScriptDirectoryInteraction.ChangeBehavior.RESCAN) {
				try {
					var path = directory_path;
					var monitor = File.new_for_path (path).monitor_directory (FileMonitorFlags.NONE);
					monitor.changed.connect (on_file_changed);
					this.monitor = monitor;
				} catch (GLib.Error e) {
					log_warning ("Failed to watch directory: " + e.message);
				}
			}

			yield scan ();
		}

		protected override async void on_terminate (TerminationReason reason) {
			foreach (var script in scripts.values.to_array ())
				yield script.prepare_for_termination (reason);
		}

		protected override async void on_stop () {
			if (monitor != null) {
				monitor.changed.disconnect (on_file_changed);
				monitor.cancel ();
				monitor = null;
			}

			foreach (var script in scripts.values.to_array ())
				yield script.stop ();
			scripts.clear ();

			yield engine.close ();
		}

		private async void scan () throws Error {
			scan_in_progress = true;

			try {
				var directory_path = this.directory_path;

				Dir dir;
				try {
					dir = Dir.open (directory_path);
				} catch (FileError e) {
					return;
				}

				string? name;
				var names_seen = new Gee.HashSet<string> ();
				while ((name = dir.read_name ()) != null) {
					if (name[0] == '.' || !name.has_suffix (".js"))
						continue;

					names_seen.add (name);

					var script_path = Path.build_filename (directory_path, name);
					var config_path = derive_config_path_from_file_path (script_path);

					try {
						var config = load_config (config_path);

						var matches_filter = current_process_matches (config.filter);
						if (matches_filter) {
							var script = scripts[name];
							var parameters = config.parameters;
							var on_change = config.on_change;

							if (script != null && (!script.parameters.equal (parameters) ||
									script.on_change != on_change)) {
								yield script.stop ();
								script = null;
							}

							if (script == null) {
								script = new Script (script_path, parameters, on_change, engine);
								yield script.start ();
							}

							scripts[name] = script;
						}

						Script script = null;
						if (!matches_filter && scripts.unset (name, out script)) {
							yield script.stop ();
						}
					} catch (Error e) {
						log_warning ("Skipping %s: %s".printf (name, e.message));
						continue;
					}
				}

				foreach (var script_name in scripts.keys.to_array ()) {
					var deleted = !names_seen.contains (script_name);
					if (deleted) {
						Script script;
						scripts.unset (script_name, out script);
						yield script.stop ();
					}
				}
			} finally {
				scan_in_progress = false;
			}
		}

		private bool current_process_matches (ProcessFilter? filter) {
			if (filter == null)
				return true;

			var executables = filter.executables;
			var num_executables = executables.length;
			if (num_executables > 0) {
				var executable_name = location.executable_name;

				for (var index = 0; index != num_executables; index++) {
					if (executables[index] == executable_name)
						return true;
				}
			}

			var bundles = filter.bundles;
			var num_bundles = bundles.length;
			if (num_bundles > 0) {
				var bundle_id = location.bundle_id;
				if (bundle_id != null) {
					for (var index = 0; index != num_bundles; index++) {
						if (bundles[index] == bundle_id)
							return true;
					}
				}
			}

			var classes = filter.objc_classes;
			var num_classes = classes.length;
			for (var index = 0; index != num_classes; index++) {
				if (Environment.has_objc_class (classes[index]))
					return true;
			}

			return false;
		}

		private void on_file_changed (File file, File? other_file, FileMonitorEvent event_type) {
			if (event_type == FileMonitorEvent.CHANGES_DONE_HINT)
				return;

			var source = new TimeoutSource (50);
			source.set_callback (() => {
				if (scan_in_progress)
					return true;
				scan.begin ();
				return false;
			});
			source.attach (Environment.get_main_context ());

			if (unchanged_timeout != null)
				unchanged_timeout.destroy ();
			unchanged_timeout = source;
		}

		private static string parse_script_directory_path (Config config, Location location) {
			var raw_path = ((ScriptDirectoryInteraction) config.interaction).path;

			if (!Path.is_absolute (raw_path)) {
				unowned string? gadget_path = location.path;
				if (gadget_path != null) {
					var base_dir = Path.get_dirname (gadget_path);
					return Path.build_filename (base_dir, raw_path);
				}
			}

			return raw_path;
		}

		private ScriptConfig load_config (string path) throws Error {
			string data;
			try {
				FileUtils.get_contents (path, out data);
			} catch (FileError e) {
				if (e is FileError.NOENT)
					return new ScriptConfig ();
				throw new Error.PERMISSION_DENIED ("%s", e.message);
			}

			try {
				return Json.gobject_from_data (typeof (ScriptConfig), data) as ScriptConfig;
			} catch (GLib.Error e) {
				throw new Error.INVALID_ARGUMENT ("Invalid config: %s", e.message);
			}
		}
	}

	private class Script : Object, RpcPeer {
		private const uint8 DUKTAPE_BYTECODE_MAGIC = 0xbf;

		public enum ChangeBehavior {
			IGNORE,
			RELOAD
		}

		public signal void message (string message, Bytes? data);

		public string path {
			get;
			construct;
		}

		public Json.Node parameters {
			get;
			construct;
		}

		public ChangeBehavior on_change {
			get;
			construct;
		}

		public ScriptEngine engine {
			get;
			construct;
		}

		private AgentScriptId id;
		private bool load_in_progress = false;
		private GLib.FileMonitor monitor;
		private Source unchanged_timeout;
		private RpcClient rpc_client;

		public Script (string path, Json.Node parameters, ChangeBehavior on_change, ScriptEngine engine) {
			Object (
				path: path,
				parameters: parameters,
				on_change: on_change,
				engine: engine
			);
		}

		construct {
			rpc_client = new RpcClient (this);
		}

		public async void start () throws Error {
			engine.message_from_script.connect (on_message);

			if (on_change == ChangeBehavior.RELOAD) {
				try {
					var monitor = File.new_for_path (path).monitor_file (FileMonitorFlags.NONE);
					monitor.changed.connect (on_file_changed);
					this.monitor = monitor;
				} catch (GLib.Error e) {
					log_warning ("Failed to watch %s: %s".printf (path, e.message));
				}

				yield try_reload ();
			} else {
				try {
					yield load ();
				} catch (Error e) {
					engine.message_from_script.disconnect (on_message);
					throw e;
				}
			}
		}

		public async void prepare_for_termination (TerminationReason reason) {
			yield engine.prepare_for_termination (reason);
		}

		public async void stop () {
			if (monitor != null) {
				monitor.changed.disconnect (on_file_changed);
				monitor.cancel ();
				monitor = null;
			}

			if (id.handle != 0) {
				try {
					yield engine.destroy_script (id);
				} catch (Error e) {
				}
				id = AgentScriptId (0);
			}

			engine.message_from_script.disconnect (on_message);
		}

		private async void try_reload () {
			try {
				yield load ();
			} catch (Error e) {
				log_warning ("Failed to load %s: %s".printf (path, e.message));
			}
		}

		private async void load () throws Error {
			load_in_progress = true;

			try {
				var path = this.path;

				uint8[] contents;
				try {
					FileUtils.get_data (path, out contents);
				} catch (FileError e) {
					throw new Error.INVALID_ARGUMENT ("%s", e.message);
				}

				var options = new ScriptOptions ();
				options.name = Path.get_basename (path).split (".", 2)[0];

				ScriptEngine.ScriptInstance instance;
				if (contents.length > 0 && contents[0] == DUKTAPE_BYTECODE_MAGIC) {
					instance = yield engine.create_script (null, new Bytes (contents), options);
				} else {
					instance = yield engine.create_script ((string) contents, null, options);
				}

				if (id.handle != 0)
					yield engine.destroy_script (id);
				id = instance.script_id;

				yield engine.load_script (id);
				yield call_init ();
			} finally {
				load_in_progress = false;
			}
		}

		private async void call_init () {
			var stage = new Json.Node.alloc ().init_string ((peek_state () == State.CREATED) ? "early" : "late");

			try {
				yield rpc_client.call ("init", new Json.Node[] { stage, parameters }, null);
			} catch (GLib.Error e) {
			}
		}

		private void on_file_changed (File file, File? other_file, FileMonitorEvent event_type) {
			if (event_type == FileMonitorEvent.CHANGES_DONE_HINT)
				return;

			var source = new TimeoutSource (50);
			source.set_callback (() => {
				if (load_in_progress)
					return true;
				try_reload.begin ();
				return false;
			});
			source.attach (Environment.get_main_context ());

			if (unchanged_timeout != null)
				unchanged_timeout.destroy ();
			unchanged_timeout = source;
		}

		private void on_message (AgentScriptId script_id, string raw_message, Bytes? data) {
			if (script_id != id)
				return;

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
			engine.post_to_script (id, raw_message);
		}
	}

	private class Server : BaseController {
		public SocketAddress listen_address {
			get;
			set;
		}

		private SocketService server = new SocketService ();
		private string guid = DBus.generate_guid ();
		private Gee.HashMap<DBusConnection, Client> clients = new Gee.HashMap<DBusConnection, Client> ();

		private Gee.ArrayList<Gum.Script> eternalized_scripts = new Gee.ArrayList<Gum.Script> ();

		private Cancellable io_cancellable = new Cancellable ();

		public Server (Config config, Location location) throws Error {
			Object (
				config: config,
				location: location,
				listen_address: parse_listen_address (config)
			);
		}

		construct {
			server.incoming.connect (on_server_connection);
		}

		protected override async void on_start () throws Error {
			SocketAddress? effective_address = null;
			InetSocketAddress? inet_address = listen_address as InetSocketAddress;
			if (inet_address != null) {
				var on_port_conflict = ((ListenInteraction) config.interaction).on_port_conflict;
				uint16 start_port = inet_address.get_port ();
				uint16 candidate_port = start_port;
				do {
					try {
						server.add_address (inet_address, SocketType.STREAM, SocketProtocol.DEFAULT, null,
							out effective_address);
					} catch (GLib.Error e) {
						if (e is IOError.ADDRESS_IN_USE && on_port_conflict == PICK_NEXT) {
							candidate_port++;
							if (candidate_port == start_port)
								throw new Error.ADDRESS_IN_USE ("Unable to bind to any port");
							if (candidate_port == 0)
								candidate_port = 1024;
							inet_address = new InetSocketAddress (inet_address.get_address (), candidate_port);
						} else {
							throw_listen_error (e);
						}
					}
				} while (effective_address == null);
			} else {
				try {
					server.add_address (listen_address, SocketType.STREAM, SocketProtocol.DEFAULT, null,
						out effective_address);
				} catch (GLib.Error e) {
					throw_listen_error (e);
				}
			}
			listen_address = effective_address;

			server.start ();
		}

		protected override async void on_terminate (TerminationReason reason) {
			foreach (var client in clients.values.to_array ())
				yield client.prepare_for_termination (reason);

			foreach (var connection in clients.keys.to_array ()) {
				try {
					yield connection.flush ();
				} catch (GLib.Error e) {
				}
			}
		}

		protected override async void on_stop () {
			if (server == null)
				return;

			server.stop ();

			while (!clients.is_empty) {
				var iterator = clients.keys.iterator ();
				iterator.next ();
				var connection = iterator.get ();

				Client client;
				clients.unset (connection, out client);
				yield client.shutdown ();

				detach_client (client);
			}

			io_cancellable.cancel ();
		}

		private bool on_server_connection (SocketConnection connection, Object? source_object) {
			handle_server_connection.begin (connection);
			return true;
		}

		private async void handle_server_connection (SocketConnection socket_connection) throws GLib.Error {
			var socket = socket_connection.socket;
			if (socket.get_family () != UNIX)
				Tcp.enable_nodelay (socket);

			var connection = yield new DBusConnection (socket_connection, guid,
				AUTHENTICATION_SERVER | AUTHENTICATION_ALLOW_ANONYMOUS | DELAY_MESSAGE_PROCESSING,
				null, io_cancellable);

			attach_client (connection);

			connection.start_message_processing ();
		}

		private void attach_client (DBusConnection connection) {
			var client = new Client (this, connection);
			clients[connection] = client;
			connection.on_closed.connect (on_connection_closed);

			client.script_eternalized.connect (on_script_eternalized);
		}

		private void detach_client (Client client) {
			client.script_eternalized.disconnect (on_script_eternalized);
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			Client client;
			if (clients.unset (connection, out client)) {
				client.shutdown.begin ();
				detach_client (client);
			}
		}

		private void on_script_eternalized (Gum.Script script) {
			eternalized_scripts.add (script);
		}

		private class Client : Object, HostSession {
			public signal void script_eternalized (Gum.Script script);

			private unowned Server server;
			private DBusConnection connection;
			private uint host_registration_id;
			private HostApplicationInfo this_app;
			private HostProcessInfo this_process;
			private Gee.HashSet<ClientSession> sessions = new Gee.HashSet<ClientSession> ();
			private uint next_session_id = 1;
			private bool resume_on_attach = true;

			public Client (Server s, DBusConnection c) {
				server = s;
				connection = c;

				try {
					host_registration_id = connection.register_object (Frida.ObjectPath.HOST_SESSION,
						this as HostSession);
				} catch (IOError e) {
					assert_not_reached ();
				}

				var pid = get_process_id ();
				var identifier = "re.frida.Gadget";
				var name = "Gadget";
				var no_icon = ImageData.empty ();
				this_app = HostApplicationInfo (identifier, name, pid, no_icon, no_icon);
				this_process = HostProcessInfo (pid, name, no_icon, no_icon);
			}

			public async void shutdown () {
				foreach (var session in sessions.to_array ()) {
					try {
						yield session.close (null);
					} catch (GLib.Error e) {
						assert_not_reached ();
					}
				}
				assert (sessions.is_empty);

				if (host_registration_id != 0) {
					connection.unregister_object (host_registration_id);
					host_registration_id = 0;
				}
			}

			public async void prepare_for_termination (TerminationReason reason) {
				foreach (var session in sessions.to_array ())
					yield session.prepare_for_termination (reason);
			}

			public async HostApplicationInfo get_frontmost_application (Cancellable? cancellable) throws Error, IOError {
				return this_app;
			}

			public async HostApplicationInfo[] enumerate_applications (Cancellable? cancellable) throws Error, IOError {
				return new HostApplicationInfo[] { this_app };
			}

			public async HostProcessInfo[] enumerate_processes (Cancellable? cancellable) throws Error, IOError {
				return new HostProcessInfo[] { this_process };
			}

			public async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
				throw new Error.NOT_SUPPORTED ("Not possible when embedded");
			}

			public async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
				throw new Error.NOT_SUPPORTED ("Not possible when embedded");
			}

			public async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws Error, IOError {
				throw new Error.NOT_SUPPORTED ("Not possible when embedded");
			}

			public async HostChildInfo[] enumerate_pending_children (Cancellable? cancellable) throws Error, IOError {
				throw new Error.NOT_SUPPORTED ("Not yet implemented");
			}

			public async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError {
				if (program != this_app.identifier)
					throw new Error.NOT_SUPPORTED ("Unable to spawn other apps when embedded");

				resume_on_attach = false;

				return this_process.pid;
			}

			public async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError {
				throw new Error.NOT_SUPPORTED ("Not possible when embedded");
			}

			public async void resume (uint pid, Cancellable? cancellable) throws Error, IOError {
				validate_pid (pid);

				Frida.Gadget.resume ();
			}

			public async void kill (uint pid, Cancellable? cancellable) throws Error, IOError {
				validate_pid (pid);

				_kill (this_process.pid);
			}

			public async AgentSessionId attach_to (uint pid, Cancellable? cancellable) throws Error, IOError {
				validate_pid (pid);

				if (resume_on_attach)
					Frida.Gadget.resume ();

				var id = AgentSessionId (next_session_id++);

				var session = new ClientSession (server, id);
				sessions.add (session);
				session.closed.connect (on_session_closed);
				session.script_eternalized.connect (on_script_eternalized);

				try {
					AgentSession s = session;
					session.registration_id = connection.register_object (ObjectPath.from_agent_session_id (id), s);
				} catch (IOError io_error) {
					assert_not_reached ();
				}

				return id;
			}

			public async InjectorPayloadId inject_library_file (uint pid, string path, string entrypoint, string data,
					Cancellable? cancellable) throws Error, IOError {
				throw new Error.NOT_SUPPORTED ("Unable to inject libraries when embedded");
			}

			public async InjectorPayloadId inject_library_blob (uint pid, uint8[] blob, string entrypoint, string data,
					Cancellable? cancellable) throws Error, IOError {
				throw new Error.NOT_SUPPORTED ("Unable to inject libraries when embedded");
			}

			private void on_session_closed (ClientSession session) {
				connection.unregister_object (session.registration_id);

				session.script_eternalized.disconnect (on_script_eternalized);
				session.closed.disconnect (on_session_closed);
				sessions.remove (session);

				agent_session_destroyed (session.id, APPLICATION_REQUESTED);
			}

			private void on_script_eternalized (Gum.Script script) {
				script_eternalized (script);
			}

			private void validate_pid (uint pid) throws Error {
				if (pid != this_process.pid)
					throw new Error.NOT_SUPPORTED ("Unable to act on other processes when embedded");
			}
		}

		private class ClientSession : Object, AgentSession {
			public signal void closed ();
			public signal void script_eternalized (Gum.Script script);

			public weak Server server {
				get;
				construct;
			}

			public AgentSessionId id {
				get;
				construct;
			}

			public uint registration_id {
				get;
				set;
			}

			private Promise<bool> close_request;

			private ScriptEngine script_engine;

			public ClientSession (Server server, AgentSessionId id) {
				Object (server: server, id: id);
			}

			construct {
				script_engine = new ScriptEngine (server);
				script_engine.message_from_script.connect (on_message_from_script);
				script_engine.message_from_debugger.connect (on_message_from_debugger);
			}

			public async void close (Cancellable? cancellable) throws IOError {
				while (close_request != null) {
					try {
						yield close_request.future.wait_async (cancellable);
						return;
					} catch (GLib.Error e) {
						assert (e is IOError.CANCELLED);
						cancellable.set_error_if_cancelled ();
					}
				}
				close_request = new Promise<bool> ();

				yield script_engine.close ();
				script_engine.message_from_script.disconnect (on_message_from_script);
				script_engine.message_from_debugger.disconnect (on_message_from_debugger);

				closed ();

				close_request.resolve (true);
			}

			public async void prepare_for_termination (TerminationReason reason) {
				yield script_engine.prepare_for_termination (reason);
			}

			public async void enable_child_gating (Cancellable? cancellable) throws Error, IOError {
				check_open ();

				throw new Error.NOT_SUPPORTED ("Not yet implemented");
			}

			public async void disable_child_gating (Cancellable? cancellable) throws Error, IOError {
				throw new Error.NOT_SUPPORTED ("Not yet implemented");
			}

			public async AgentScriptId create_script (string name, string source,
					Cancellable? cancellable) throws Error, IOError {
				check_open ();

				var options = new ScriptOptions ();
				if (name != "")
					options.name = name;

				var instance = yield script_engine.create_script (source, null, options);
				return instance.script_id;
			}

			public async AgentScriptId create_script_with_options (string source, AgentScriptOptions options,
					Cancellable? cancellable) throws Error, IOError {
				check_open ();

				var instance = yield script_engine.create_script (source, null, ScriptOptions._deserialize (options.data));
				return instance.script_id;
			}

			public async AgentScriptId create_script_from_bytes (uint8[] bytes, Cancellable? cancellable)
					throws Error, IOError {
				check_open ();

				var instance = yield script_engine.create_script (null, new Bytes (bytes), new ScriptOptions ());
				return instance.script_id;
			}

			public async AgentScriptId create_script_from_bytes_with_options (uint8[] bytes, AgentScriptOptions options,
					Cancellable? cancellable) throws Error, IOError {
				check_open ();

				var instance = yield script_engine.create_script (null, new Bytes (bytes),
					ScriptOptions._deserialize (options.data));
				return instance.script_id;
			}

			public async uint8[] compile_script (string name, string source, Cancellable? cancellable) throws Error, IOError {
				check_open ();

				var options = new ScriptOptions ();
				if (name != "")
					options.name = name;

				var bytes = yield script_engine.compile_script (source, options);
				return bytes.get_data ();
			}

			public async uint8[] compile_script_with_options (string source, AgentScriptOptions options,
					Cancellable? cancellable) throws Error, IOError {
				check_open ();

				var bytes = yield script_engine.compile_script (source, ScriptOptions._deserialize (options.data));
				return bytes.get_data ();
			}

			public async void destroy_script (AgentScriptId script_id, Cancellable? cancellable) throws Error, IOError {
				check_open ();

				yield script_engine.destroy_script (script_id);
			}

			public async void load_script (AgentScriptId script_id, Cancellable? cancellable) throws Error, IOError {
				check_open ();

				yield script_engine.load_script (script_id);
			}

			public async void eternalize_script (AgentScriptId script_id, Cancellable? cancellable) throws Error, IOError {
				check_open ();

				var script = script_engine.eternalize_script (script_id);
				script_eternalized (script);
			}

			public async void post_to_script (AgentScriptId script_id, string message, bool has_data, uint8[] data,
					Cancellable? cancellable) throws Error, IOError {
				check_open ();

				script_engine.post_to_script (script_id, message, has_data ? new Bytes (data) : null);
			}

			public async void enable_debugger (Cancellable? cancellable) throws Error, IOError {
				check_open ();

				script_engine.enable_debugger ();
			}

			public async void disable_debugger (Cancellable? cancellable) throws Error, IOError {
				check_open ();

				script_engine.disable_debugger ();
			}

			public async void post_message_to_debugger (string message, Cancellable? cancellable) throws Error, IOError {
				check_open ();

				script_engine.post_message_to_debugger (message);
			}

			public async void enable_jit (Cancellable? cancellable) throws Error, IOError {
				check_open ();

				script_engine.enable_jit ();
			}

			private void check_open () throws Error {
				if (close_request != null)
					throw new Error.INVALID_OPERATION ("Session is closing");
			}

			private void on_message_from_script (AgentScriptId script_id, string message, Bytes? data) {
				bool has_data = data != null;
				var data_param = has_data ? data.get_data () : new uint8[0];
				this.message_from_script (script_id, message, has_data, data_param);
			}

			private void on_message_from_debugger (string message) {
				this.message_from_debugger (message);
			}
		}

		private static SocketAddress parse_listen_address (Config config) throws Error {
			var interaction = config.interaction as ListenInteraction;

			unowned string raw_address = interaction.address;

#if !WINDOWS
			if (raw_address.has_prefix ("unix:")) {
				string path = raw_address.substring (5);

				UnixSocketAddressType type = UnixSocketAddress.abstract_names_supported ()
					? UnixSocketAddressType.ABSTRACT
					: UnixSocketAddressType.PATH;

				return new UnixSocketAddress.with_type (path, -1, type);
			}
#endif

			var address = new InetSocketAddress.from_string (raw_address, interaction.port);
			if (address == null)
				throw new Error.INVALID_ARGUMENT ("Invalid listen address");

			return address;
		}

		[NoReturn]
		private static void throw_listen_error (GLib.Error e) throws Error {
			if (e is IOError.ADDRESS_IN_USE)
				throw new Error.ADDRESS_IN_USE ("%s", e.message);

			if (e is IOError.PERMISSION_DENIED)
				throw new Error.PERMISSION_DENIED ("%s", e.message);

			throw new Error.NOT_SUPPORTED ("%s", e.message);
		}
	}

	private string derive_config_path_from_file_path (string path) {
		var dirname = Path.get_dirname (path);
		var filename = Path.get_basename (path);

		string stem;
		var ext_index = filename.last_index_of_char ('.');
		if (ext_index != -1)
			stem = filename[0:ext_index];
		else
			stem = filename;

		return Path.build_filename (dirname, stem + ".config");
	}

	private static Json.Node make_empty_json_object () {
		return new Json.Node.alloc ().init_object (new Json.Object ());
	}

	namespace Environment {
		private extern void init ();
		private extern void deinit ();

		private extern bool can_block_at_load_time ();

		private extern unowned MainContext get_main_context ();

		private extern string? detect_bundle_id ();
		private extern string? detect_documents_dir ();
		private extern bool has_objc_class (string name);

		private extern void set_thread_name (string name);
	}

	namespace Tcp {
		private extern void enable_nodelay (Socket socket);
	}

	public extern void _kill (uint pid);

	private extern void log_info (string message);
	private extern void log_warning (string message);

	private Mutex gc_mutex;
	private uint gc_generation = 0;
	private bool gc_scheduled = false;

	public void _on_pending_thread_garbage (void * data) {
		gc_mutex.lock ();
		gc_generation++;
		bool already_scheduled = gc_scheduled;
		gc_scheduled = true;
		gc_mutex.unlock ();

		if (already_scheduled)
			return;

		Timeout.add (50, () => {
			gc_mutex.lock ();
			uint generation = gc_generation;
			gc_mutex.unlock ();

			bool collected_everything = Thread.garbage_collect ();

			gc_mutex.lock ();
			bool same_generation = generation == gc_generation;
			bool repeat = !collected_everything || !same_generation;
			if (!repeat)
				gc_scheduled = false;
			gc_mutex.unlock ();

			return repeat;
		});
	}
}
