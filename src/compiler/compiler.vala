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

		public Compiler (DeviceManager manager) {
			Object (manager: manager);
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

			string? js_code;
			string? error_message;
			if (CompilerBackend.bundle_js (project_root, absolute_entrypoint, out js_code, out error_message) != 0)
				throw new Error.INVALID_ARGUMENT ("%s", error_message);

			return js_code;
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

#if !HAVE_COMPILER_BACKEND
		[NoReturn]
		private void throw_not_supported () throws Error {
			throw new Error.NOT_SUPPORTED ("Compiler backend disabled at build-time");
		}
#endif

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
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
		private extern static int bundle_js (string project_root, string entrypoint, out string? js_code,
			out string? error_message);
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
