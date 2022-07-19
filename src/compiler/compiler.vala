namespace Frida {
	public class Compiler : Object {
		public signal void starting ();
		public signal void finished ();
		public signal void output (string bundle);
		public signal void diagnostics (Variant diagnostics);

		public DeviceManager manager {
			get;
			construct;
		}

		private Promise<Agent>? load_request;
		private Gee.Map<string, AgentFile> agent_files = new Gee.HashMap<string, AgentFile> ();
		private Gee.Map<uint, MonitorEntry> monitors = new Gee.HashMap<uint, MonitorEntry> ();
		private Gee.Set<MonitorEntry> dirty_monitors = new Gee.HashSet<MonitorEntry> ();
		private TimeoutSource? monitor_flush_timer;

		private Cancellable io_cancellable = new Cancellable ();

		public Compiler (DeviceManager manager) {
			Object (manager: manager);
		}

		public async string build (string entrypoint, BuildOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			var agent = yield get_agent (cancellable);

			starting ();
			try {
				string bundle = yield agent.build (entrypoint, options, cancellable);

				output (bundle);

				return bundle;
			} finally {
				finished ();
			}
		}

		public string build_sync (string entrypoint, BuildOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			var task = create<BuildTask> ();
			task.entrypoint = entrypoint;
			task.options = options;
			return task.execute (cancellable);
		}

		private class BuildTask : CompilerTask<string> {
			public string entrypoint;
			public BuildOptions? options;

			protected override async string perform_operation () throws Error, IOError {
				return yield parent.build (entrypoint, options, cancellable);
			}
		}

		public async void watch (string entrypoint, WatchOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			var agent = yield get_agent (cancellable);

			yield agent.watch (entrypoint, options, cancellable);
		}

		public void watch_sync (string entrypoint, WatchOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			var task = create<WatchTask> ();
			task.entrypoint = entrypoint;
			task.options = options;
			task.execute (cancellable);
		}

		private class WatchTask : CompilerTask<void> {
			public string entrypoint;
			public WatchOptions? options;

			protected override async void perform_operation () throws Error, IOError {
				yield parent.watch (entrypoint, options, cancellable);
			}
		}

		private void on_watch_add (uint id, string path, string type, int64 polling_interval) {
			var file = File.parse_name (path);

			GLib.FileMonitor monitor;
			try {
				if (type == "file")
					monitor = file.monitor_file (FileMonitorFlags.SEND_MOVED, io_cancellable);
				else if (type == "directory")
					monitor = file.monitor_directory (FileMonitorFlags.NONE, io_cancellable);
				else
					assert_not_reached ();
			} catch (GLib.Error e) {
				return;
			}

			if (polling_interval != 0)
				monitor.rate_limit = (int) polling_interval;

			var entry = new MonitorEntry (id, monitor);
			entry.file_changed.connect (on_file_changed);
			monitors[id] = entry;
		}

		private void on_watch_remove (uint id) {
			MonitorEntry? entry;
			if (!monitors.unset (id, out entry))
				return;
			dirty_monitors.remove (entry);

			entry.file_changed.disconnect (on_file_changed);
			entry.destroy ();
		}

		private void on_file_changed (MonitorEntry entry) {
			dirty_monitors.add (entry);

			if (monitor_flush_timer == null) {
				var source = new TimeoutSource (50);
				source.set_callback (on_monitor_flush_tick);
				source.attach (MainContext.get_thread_default ());
				monitor_flush_timer = source;
			}
		}

		private bool on_monitor_flush_tick () {
			var settled = new Gee.ArrayList<MonitorEntry> ();
			var now = get_monotonic_time ();
			settled.add_all_iterator (dirty_monitors.filter (m => now - m.last_change >= 50000));

			Agent agent = load_request.future.value;
			foreach (var entry in settled) {
				agent.notify_file_changed (entry.id, entry.state, io_cancellable);
				dirty_monitors.remove (entry);
			}

			if (!dirty_monitors.is_empty)
				return Source.CONTINUE;

			monitor_flush_timer = null;
			return Source.REMOVE;
		}

		private async Agent get_agent (Cancellable? cancellable) throws Error, IOError {
			Future<Agent> future;
			if (load_request != null) {
				future = load_request.future;
			} else {
				load_request = new Promise<Agent> ();
				future = load_request.future;

				load_agent.begin ();
			}

			return yield future.wait_async (cancellable);
		}

		private async void load_agent () {
			try {
				var agent_dirs = new string[0];
				agent_files.clear ();
				_foreach_agent_zip_entry ((name, contents) => {
					string path = "/" + name;
					if (contents != null)
						agent_files[path] = new AgentFile ((owned) contents);
					else
						agent_dirs += path[:-1];
				});

				var device = yield manager.get_device_by_type (LOCAL, 0, io_cancellable);
				var session = yield device.get_host_session (io_cancellable);
				var agent = new Agent (this, (BaseDBusHostSession) session, agent_files["/agent.js"].contents);

				yield agent.init (agent_dirs, agent_files, io_cancellable);

				load_request.resolve (agent);
			} catch (GLib.Error e) {
				if ((e is Error || e is IOError.CANCELLED))
					e = new Error.NOT_SUPPORTED ("%s", e.message);

				load_request.reject (e);
				load_request = null;
			}
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		private abstract class CompilerTask<T> : AsyncTask<T> {
			public weak Compiler parent {
				get;
				construct;
			}
		}

		public extern static void _foreach_agent_zip_entry (EachAgentZipEntryFunc func);

		public delegate void EachAgentZipEntryFunc (string name, owned string? contents);

		private class Agent : InternalAgent {
			public weak Compiler parent {
				get;
				construct;
			}

			public Agent (Compiler parent, BaseDBusHostSession host_session, string source) {
				Object (
					parent: parent,
					host_session: host_session,
					script_source: source,
					script_runtime: ScriptRuntime.V8
				);
			}

			public async string init (string[] directories, Gee.Map<string, AgentFile> files, Cancellable? cancellable)
					throws Error, IOError {
				var dirs_json = new Json.Builder ();
				dirs_json.begin_array ();
				foreach (unowned string name in directories)
					dirs_json.add_string_value (name);
				dirs_json.end_array ();

				var files_json = new Json.Builder ();
				files_json.begin_array ();
				foreach (var e in files.entries) {
					unowned string name = e.key;
					string address = ("0x%" + size_t.FORMAT_MODIFIER + "x").printf ((size_t) e.value.contents);
					files_json
						.begin_array ()
							.add_string_value (name)
							.add_string_value (address)
						.end_array ();
				}
				files_json.end_array ();

				Json.Node bundle = yield call ("init", new Json.Node[] {
						dirs_json.get_root (),
						files_json.get_root ()
					}, cancellable);
				return bundle.get_string ();
			}

			public async string build (string entrypoint, BuildOptions? options, Cancellable? cancellable)
					throws Error, IOError {
				BuildOptions opts = (options != null) ? options : new BuildOptions ();

				Json.Node bundle = yield call ("build", new Json.Node[] {
						new Json.Node.alloc ().init_string (compute_project_root (entrypoint, opts)),
						new Json.Node.alloc ().init_string (entrypoint),
						new Json.Node.alloc ().init_string (opts.source_maps.to_nick ()),
						new Json.Node.alloc ().init_string (opts.compression.to_nick ()),
					}, cancellable);
				return bundle.get_string ();
			}

			public async void watch (string entrypoint, WatchOptions? options, Cancellable? cancellable)
					throws Error, IOError {
				WatchOptions opts = (options != null) ? options : new WatchOptions ();

				yield call ("watch", new Json.Node[] {
						new Json.Node.alloc ().init_string (compute_project_root (entrypoint, opts)),
						new Json.Node.alloc ().init_string (entrypoint),
						new Json.Node.alloc ().init_string (opts.source_maps.to_nick ()),
						new Json.Node.alloc ().init_string (opts.compression.to_nick ()),
					}, cancellable);
			}

			private static string compute_project_root (string entrypoint, CompilerOptions options) {
				string? project_root = options.project_root;

				if (project_root != null)
					return project_root;

				if (Path.is_absolute (entrypoint))
					return Path.get_dirname (entrypoint);

				return Environment.get_current_dir ();
			}

			public void notify_file_changed (uint id, FileState state, Cancellable? cancellable) {
				var notification = new Json.Builder ();
				notification
					.begin_object ()
						.set_member_name ("type")
						.add_string_value ("watch:change")
						.set_member_name ("id")
						.add_int_value (id)
						.set_member_name ("state")
						.add_string_value (Marshal.enum_to_nick<FileState> (state))
					.end_object ();
				post.begin (notification.get_root (), cancellable);
			}

			protected override async uint get_target_pid (Cancellable? cancellable) throws Error, IOError {
				return 0;
			}

			protected override void on_event (string type, Json.Array event) {
				if (type == "diagnostics") {
					on_build_diagnostics (event.get_array_element (1));
				} else if (type == "watch:compilation-starting") {
					parent.starting ();
				} else if (type == "watch:compilation-finished") {
					parent.finished ();
				} else if (type == "watch:bundle-updated") {
					on_watch_bundle_updated (event.get_string_element (1));
				} else if (type == "watch:add") {
					parent.on_watch_add ((uint) event.get_int_element (1), event.get_string_element (2),
						event.get_string_element (3), event.get_int_element (4));
				} else if (type == "watch:remove") {
					parent.on_watch_remove ((uint) event.get_int_element (1));
				} else {
					assert_not_reached ();
				}
			}

			private void on_build_diagnostics (Json.Array diagnostics) {
				uint n = diagnostics.get_length ();

				var builder = new VariantBuilder (new VariantType.array (VariantType.VARDICT));
				for (uint i = 0; i != n; i++) {
					var diag = diagnostics.get_array_element (i);
					builder.open (VariantType.VARDICT);
					builder.add ("{sv}", "category", new Variant.string (diag.get_string_element (0)));
					builder.add ("{sv}", "code", new Variant.int64 (diag.get_int_element (1)));
					if (!diag.get_null_element (2)) {
						var file = diag.get_array_element (2);
						var b = new VariantBuilder (VariantType.VARDICT);
						b.add ("{sv}", "path", new Variant.string (file.get_string_element (0)));
						b.add ("{sv}", "line", new Variant.int64 (file.get_int_element (1)));
						b.add ("{sv}", "character", new Variant.int64 (file.get_int_element (2)));
						builder.add ("{sv}", "file", b.end ());
					}
					builder.add ("{sv}", "text", new Variant.string (diag.get_string_element (3)));
					builder.close ();
				}

				parent.diagnostics (builder.end ());
			}

			private void on_watch_bundle_updated (string bundle) {
				parent.output (bundle);
			}
		}

		private class AgentFile {
			public string contents;

			public AgentFile (owned string contents) {
				this.contents = (owned) contents;
			}
		}

		private class MonitorEntry : Object {
			public signal void file_changed ();

			public uint id;
			public GLib.FileMonitor monitor;

			public FileState state = PRISTINE;
			public int64 last_change = -1;

			public MonitorEntry (uint id, GLib.FileMonitor monitor) {
				this.id = id;
				this.monitor = monitor;

				monitor.changed.connect (on_file_changed);
			}

			public void destroy () {
				monitor.changed.disconnect (on_file_changed);
				monitor.cancel ();
			}

			private void on_file_changed (File file, File? other_file, FileMonitorEvent event) {
				switch (event) {
					case CREATED:
						state = PRISTINE;
						break;
					case CHANGED:
						if (state != PRISTINE)
							state = MODIFIED;
						break;
					case DELETED:
					case MOVED:
						state = DELETED;
						break;
					default:
						break;
				}

				last_change = get_monotonic_time ();

				file_changed ();
			}
		}

		private enum FileState {
			PRISTINE,
			MODIFIED,
			DELETED,
		}
	}

	public class CompilerOptions : Object {
		public string? project_root {
			get;
			set;
		}

		public SourceMaps source_maps {
			get;
			set;
			default = INCLUDED;
		}

		public JsCompression compression {
			get;
			set;
			default = NONE;
		}
	}

	public class BuildOptions : CompilerOptions {
	}

	public class WatchOptions : CompilerOptions {
	}

	public enum SourceMaps {
		INCLUDED,
		OMITTED;

		public static SourceMaps from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<SourceMaps> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<SourceMaps> (this);
		}
	}

	public enum JsCompression {
		NONE,
		TERSER;

		public static JsCompression from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<JsCompression> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<JsCompression> (this);
		}
	}
}
