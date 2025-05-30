namespace Frida {
	public sealed class Compiler : Object {
		public signal void starting ();
		public signal void finished ();
		public signal void output (string bundle);
		public signal void diagnostics (Variant diagnostics);

		public DeviceManager manager {
			get;
			construct;
		}

		private Gee.Queue<Diagnostic> pending_diagnostics = new Gee.ArrayQueue<Diagnostic> ();

		private MainContext main_context;

		public Compiler (DeviceManager manager) {
			Object (manager: manager);
		}

		construct {
			main_context = Frida.get_main_context ();
		}

		public async string build (string entrypoint, BuildOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
#if HAVE_COMPILER_BACKEND
			BuildOptions opts = (options != null) ? options : new BuildOptions ();
			string project_root = compute_project_root (entrypoint, opts);

			string absolute_entrypoint = Path.is_absolute (entrypoint)
				? entrypoint
				: Path.build_filename (project_root, entrypoint);
			if (!absolute_entrypoint.has_prefix (project_root))
				throw new Error.INVALID_ARGUMENT ("Entrypoint must be inside the project root");

			starting ();
			try {
				string? bundle = null;
				string? error_message = null;
				CompilerBackend.BuildCompleteFunc on_complete = (b, e) => {
					bundle = b;
					error_message = e;
					schedule_on_frida_thread (build.callback);
				};

				CompilerBackend.build (project_root, absolute_entrypoint, opts.source_maps == INCLUDED,
					opts.compression == TERSER, (owned) on_complete, on_diagnostic);
				yield;

				if (error_message != null)
					throw new Error.INVALID_ARGUMENT ("%s", error_message);

				output (bundle);

				return bundle;
			} finally {
				finished ();
			}
#else
			throw_not_supported ();
#endif
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
#if HAVE_COMPILER_BACKEND
			throw new Error.NOT_SUPPORTED ("Not yet implemented");
#else
			throw_not_supported ();
#endif
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

#if HAVE_COMPILER_BACKEND
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
#else
		[NoReturn]
		private void throw_not_supported () throws Error {
			throw new Error.NOT_SUPPORTED ("Compiler backend disabled at build-time");
		}
#endif

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

#if HAVE_COMPILER_BACKEND
	namespace CompilerBackend {
		private extern static void build (string project_root, string entrypoint, bool source_map, bool compress,
			owned BuildCompleteFunc on_complete, owned DiagnosticFunc on_diagnostic);
		private extern static void watch (string project_root, string entrypoint, bool source_map, bool compress,
			owned WatchReadyFunc on_ready, owned OutputFunc on_output, owned DiagnosticFunc on_diagnostic);

		private delegate void BuildCompleteFunc (owned string? bundle, owned string? error_message);
		private delegate void WatchReadyFunc (owned string? error_message);
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
#endif

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

	public sealed class BuildOptions : CompilerOptions {
	}

	public sealed class WatchOptions : CompilerOptions {
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
