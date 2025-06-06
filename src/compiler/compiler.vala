namespace Frida {
	public sealed class Compiler : Object {
		public signal void starting ();
		public signal void finished ();
		public signal void output (string bundle);
		public signal void diagnostics (Variant diagnostics);

		private size_t watch_session_handle = 0;
		private Gee.Queue<Diagnostic> pending_diagnostics = new Gee.ArrayQueue<Diagnostic> ();

		private MainContext main_context;

		// TODO: Remove the DeviceManager parameter.
		public Compiler (DeviceManager? manager = null) {
			Object ();
		}

		static construct {
			CompilerBackend.init ();
		}

		construct {
			main_context = Frida.get_main_context ();
		}

		~Compiler () {
			cancel_watch ();
		}

		public async string build (string entrypoint, BuildOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			BuildOptions opts = (options != null) ? options : new BuildOptions ();
			string project_root = compute_project_root (entrypoint, opts);

			starting ();
			try {
				string? bundle = null;
				string? error_message = null;
				CompilerBackend.BuildCompleteFunc on_complete = (b, e) => {
					bundle = b;
					error_message = e;
					schedule_on_frida_thread (build.callback);
				};

				CompilerBackend.build (project_root, entrypoint, opts.output_format, opts.bundle_format,
					(size_t) (opts.type_check == NONE), (size_t) (opts.source_maps == INCLUDED),
					(size_t) (opts.compression == TERSER), (owned) on_complete, on_diagnostic);
				yield;

				if (error_message != null)
					throw new Error.INVALID_ARGUMENT ("%s", error_message);

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
			WatchOptions opts = (options != null) ? options : new WatchOptions ();
			string project_root = compute_project_root (entrypoint, opts);

			cancel_watch ();

			size_t session_handle = 0;
			string? error_message = null;
			CompilerBackend.WatchReadyFunc on_ready = (h, e) => {
				session_handle = h;
				error_message = e;
				schedule_on_frida_thread (watch.callback);
			};

			CompilerBackend.watch (project_root, entrypoint, opts.output_format, opts.bundle_format,
				(size_t) (opts.type_check == NONE), (size_t) (opts.source_maps == INCLUDED),
				(size_t) (opts.compression == TERSER), (owned) on_ready, on_starting, on_finished,
				on_output, on_diagnostic);
			yield;

			if (error_message != null)
				throw new Error.INVALID_ARGUMENT ("%s", error_message);

			watch_session_handle = session_handle;
		}

		private void cancel_watch () {
			if (watch_session_handle != 0) {
				CompilerBackend.WatchSession.dispose (watch_session_handle);
				watch_session_handle = 0;
			}
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

		private void on_starting () {
			schedule_on_frida_thread (() => {
				starting ();
				return Source.REMOVE;
			});
		}

		private void on_finished () {
			schedule_on_frida_thread (() => {
				finished ();
				return Source.REMOVE;
			});
		}

		private void on_output (owned string bundle) {
			schedule_on_frida_thread (() => {
				output (bundle);
				return Source.REMOVE;
			});
		}

		private void on_diagnostic (owned string category, int code, owned string? path, int line, int character,
				owned string text) {
			var diag = new Diagnostic () {
				category = category,
				code = code,
				path = path,
				line = line,
				character = character,
				text = text,
			};

			bool schedule_emit = false;
			lock (pending_diagnostics) {
				schedule_emit = pending_diagnostics.is_empty;
				pending_diagnostics.add (diag);
			}

			if (schedule_emit) {
				schedule_on_frida_thread (() => {
					emit_pending_diagnostics ();
					return Source.REMOVE;
				});
			}
		}

		private void emit_pending_diagnostics () {
			var batch = new Gee.ArrayList<Diagnostic> ();
			lock (pending_diagnostics) {
				batch.add_all (pending_diagnostics);
				pending_diagnostics.clear ();
			}

			var builder = new VariantBuilder (new VariantType.array (VariantType.VARDICT));

			foreach (var d in batch) {
				builder.open (VariantType.VARDICT);
				builder.add ("{sv}", "category", new Variant.string (d.category));
				builder.add ("{sv}", "code", new Variant.int64 (d.code));
				if (d.path != null) {
					var b = new VariantBuilder (VariantType.VARDICT);
					b.add ("{sv}", "path", new Variant.string (d.path));
					b.add ("{sv}", "line", new Variant.int64 (d.line));
					b.add ("{sv}", "character", new Variant.int64 (d.character));
					builder.add ("{sv}", "file", b.end ());
				}
				builder.add ("{sv}", "text", new Variant.string (d.text));
				builder.close ();
			}

			diagnostics (builder.end ());
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		protected void schedule_on_frida_thread (owned SourceFunc function) {
			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (main_context);
		}

		private class Diagnostic {
			public string category;
			public int code;
			public string? path;
			public int line;
			public int character;
			public string text;
		}

		private abstract class CompilerTask<T> : AsyncTask<T> {
			public weak Compiler parent {
				get;
				construct;
			}
		}
	}

	namespace CompilerBackend {
		private extern void init ();

#if HAVE_COMPILER_BACKEND
		private extern void build (string project_root, string entrypoint, OutputFormat output_format, BundleFormat bundle_format,
			size_t disable_type_check, size_t source_map, size_t compress, owned BuildCompleteFunc on_complete,
			DiagnosticFunc on_diagnostic);
		private extern void watch (string project_root, string entrypoint, OutputFormat output_format, BundleFormat bundle_format,
			size_t disable_type_check, size_t source_map, size_t compress, owned WatchReadyFunc on_ready,
			StartingFunc on_starting, FinishedFunc on_finished, OutputFunc on_output, DiagnosticFunc on_diagnostic);

		namespace WatchSession {
			private extern void dispose (size_t handle);
		}
#else
		private const string DISABLED_MESSAGE = "Compiler backend disabled at build-time";

		private void build (string project_root, string entrypoint, OutputFormat output_format, BundleFormat bundle_format,
				size_t disable_type_check, size_t source_map, size_t compress, owned BuildCompleteFunc on_complete,
				DiagnosticFunc on_diagnostic) {
			on_complete (null, DISABLED_MESSAGE);
		}

		private void watch (string project_root, string entrypoint, OutputFormat output_format, BundleFormat bundle_format,
				size_t disable_type_check, size_t source_map, size_t compress, owned WatchReadyFunc on_ready,
				StartingFunc on_starting, FinishedFunc on_finished, OutputFunc on_output, DiagnosticFunc on_diagnostic) {
			on_ready (0, DISABLED_MESSAGE);
		}

		namespace WatchSession {
			private void dispose (size_t handle) {
				assert_not_reached ();
			}
		}
#endif

		private delegate void BuildCompleteFunc (owned string? bundle, owned string? error_message);
		private delegate void WatchReadyFunc (size_t session_handle, owned string? error_message);
		private delegate void StartingFunc ();
		private delegate void FinishedFunc ();
		private delegate void OutputFunc (owned string bundle);
		private delegate void DiagnosticFunc (owned string category, int code, owned string? path, int line, int character,
			owned string text);
	}

	private string compute_project_root (string entrypoint, CompilerOptions options) {
		string? project_root = options.project_root;

		if (project_root != null)
			return project_root;

		if (Path.is_absolute (entrypoint))
			return Path.get_dirname (entrypoint);

		return Environment.get_current_dir ();
	}

	public class CompilerOptions : Object {
		public string? project_root {
			get;
			set;
		}

		public OutputFormat output_format {
			get;
			set;
			default = UNESCAPED;
		}

		public BundleFormat bundle_format {
			get;
			set;
			default = ESM;
		}

		public TypeCheckMode type_check {
			get;
			set;
			default = FULL;
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

	public sealed class BuildOptions : CompilerOptions {
	}

	public sealed class WatchOptions : CompilerOptions {
	}

	public enum OutputFormat {
		UNESCAPED,
		HEX_BYTES,
		C_STRING;

		public static OutputFormat from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<OutputFormat> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<OutputFormat> (this);
		}
	}

	public enum BundleFormat {
		ESM,
		IIFE;

		public static BundleFormat from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<BundleFormat> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<BundleFormat> (this);
		}
	}

	public enum TypeCheckMode {
		FULL,
		NONE;

		public static TypeCheckMode from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<TypeCheckMode> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<TypeCheckMode> (this);
		}
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
