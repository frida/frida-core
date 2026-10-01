namespace Frida {
	/**
	 * Compiles a TypeScript or JavaScript project into a single script bundle
	 * that can be loaded with {@link Session.create_script}.
	 */
	public sealed class Compiler : Object {
		/**
		 * Emitted when a build is starting.
		 */
		public signal void starting ();
		/**
		 * Emitted when a build has finished.
		 */
		public signal void finished ();
		/**
		 * Emitted with the freshly built bundle, primarily when watching.
		 *
		 * @param bundle the compiled script bundle
		 */
		public signal void output (string bundle);
		/**
		 * Emitted with compiler diagnostics, such as type errors and warnings.
		 *
		 * @param diagnostics the diagnostics, as a variant
		 */
		public signal void diagnostics (Variant diagnostics);

		private size_t watch_session_handle = 0;
		private Gee.Queue<Diagnostic> pending_diagnostics = new Gee.ArrayQueue<Diagnostic> ();

		private MainContext main_context;

		// TODO: Remove the DeviceManager parameter.
		/**
		 * Creates a compiler.
		 *
		 * @param manager unused; kept for compatibility
		 */
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

		/**
		 * Builds the project rooted at @entrypoint once.
		 *
		 * @param entrypoint path to the project's entrypoint module
		 * @param options build options, or null for the defaults
		 * @return the compiled script bundle
		 */
		public async string build (string entrypoint, BuildOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			CompilerBackend.check_available ();

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
					(size_t) (opts.compression == TERSER), opts.platform.to_nick (),
					opts.externals.to_array (), on_diagnostic, (owned) on_complete);
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

		/**
		 * Builds the project and keeps rebuilding it as its sources change,
		 * emitting {@link Compiler.output} with each fresh bundle.
		 *
		 * @param entrypoint path to the project's entrypoint module
		 * @param options watch options, or null for the defaults
		 */
		public async void watch (string entrypoint, WatchOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			CompilerBackend.check_available ();

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
				(size_t) (opts.compression == TERSER), opts.platform.to_nick (),
				opts.externals.to_array (), on_starting, on_finished, on_output, on_diagnostic,
				(owned) on_ready);
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

		private void on_output (string bundle) {
			string bundle_copy = bundle;
			schedule_on_frida_thread (() => {
				output (bundle_copy);
				return Source.REMOVE;
			});
		}

		private void on_diagnostic (string category, int code, string? path, int line, int character,
				string text) {
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

	/**
	 * Speaks the Language Server Protocol for a TypeScript or JavaScript
	 * project, powered by the same compiler as {@link Compiler}.
	 */
	public sealed class LanguageServer : Object {
		/**
		 * Emitted with each message from the server, as JSON-RPC.
		 *
		 * @param json the message
		 */
		public signal void message (string json);

		/**
		 * The project root directory.
		 */
		public string project_root {
			get;
			construct;
		}

		private size_t handle = 0;

		private MainContext main_context;

		/**
		 * Creates a language server for the project rooted at @project_root.
		 *
		 * @param project_root path to the project root directory
		 */
		public LanguageServer (string project_root) {
			Object (project_root: project_root);
		}

		static construct {
			CompilerBackend.init ();
		}

		construct {
			main_context = Frida.get_main_context ();
		}

		~LanguageServer () {
			stop ();
		}

		/**
		 * Starts the server, after which messages may be posted to it.
		 */
		public async void start (Cancellable? cancellable = null) throws Error, IOError {
			CompilerBackend.check_available ();

			size_t h = 0;
			string? error_message = null;
			CompilerBackend.LanguageServerReadyFunc on_ready = (handle, e) => {
				h = handle;
				error_message = e;
				schedule_on_frida_thread (start.callback);
			};

			CompilerBackend.LanguageServer.open (project_root, on_message, (owned) on_ready);
			yield;

			if (error_message != null)
				throw new Error.INVALID_ARGUMENT ("%s", error_message);

			handle = h;
		}

		public void start_sync (Cancellable? cancellable = null) throws Error, IOError {
			var task = create<StartTask> ();
			task.execute (cancellable);
		}

		private class StartTask : LanguageServerTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.start (cancellable);
			}
		}

		/**
		 * Stops the server. Send it the LSP shutdown and exit messages first
		 * to let it wind down its projects.
		 */
		public void stop () {
			if (handle == 0)
				return;
			CompilerBackend.LanguageServer.close (handle);
			handle = 0;
		}

		/**
		 * Posts a message to the server.
		 *
		 * @param json the JSON-RPC message
		 */
		public void post (string json) throws Error {
			if (handle == 0)
				throw new Error.INVALID_OPERATION ("Language server not started");

			string? error_message = CompilerBackend.LanguageServer.post (handle, json);
			if (error_message != null)
				throw new Error.PROTOCOL ("%s", error_message);
		}

		private void on_message (string json) {
			string json_copy = json;
			schedule_on_frida_thread (() => {
				message (json_copy);
				return Source.REMOVE;
			});
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		private void schedule_on_frida_thread (owned SourceFunc function) {
			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (main_context);
		}

		private abstract class LanguageServerTask<T> : AsyncTask<T> {
			public weak LanguageServer parent {
				get;
				construct;
			}
		}
	}

	/**
	 * Parses pattern language sources, describing the types they declare
	 * and decoding memory against them.
	 */
	public sealed class PatternCompiler : Object {
		private MainContext main_context;

		/**
		 * Creates a pattern compiler.
		 */
		public PatternCompiler () {
			Object ();
		}

		static construct {
			CompilerBackend.init ();
		}

		construct {
			main_context = Frida.get_main_context ();
		}

		/**
		 * Compiles @source, laying out its types for the target described by
		 * @options.
		 *
		 * @param source the pattern language source
		 * @param options the target to lay out the types for
		 * @return the module, whose diagnostics are non-empty when @source
		 *         could not be compiled
		 */
		public async PatternModule compile (string source, PatternCompileOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			CompilerBackend.check_available ();

			string platform = "";
			string arch = "";
			if (options != null) {
				if (options.platform != null)
					platform = options.platform;
				if (options.arch != null)
					arch = options.arch;
			}

			string? result = null;
			string? error_message = null;
			CompilerBackend.PatternResultFunc on_result = (r, e) => {
				result = r;
				error_message = e;
				schedule_on_frida_thread (compile.callback);
			};

			CompilerBackend.Patterns.describe (source, platform, arch, (owned) on_result);
			yield;

			if (error_message != null)
				throw new Error.INVALID_ARGUMENT ("%s", error_message);

			return PatternJson.parse_module (result, this, source, platform, arch);
		}

		public PatternModule compile_sync (string source, PatternCompileOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			var task = create<CompileTask> ();
			task.source = source;
			task.options = options;
			return task.execute (cancellable);
		}

		private class CompileTask : PatternCompilerTask<PatternModule> {
			public string source;
			public PatternCompileOptions? options;

			protected override async PatternModule perform_operation () throws Error, IOError {
				return yield parent.compile (source, options, cancellable);
			}
		}

		internal async PatternValue decode_value (string source, string platform, string arch, string type_name, Bytes data,
				uint64 address, PatternDecodeOptions? options, Cancellable? cancellable) throws Error, IOError {
			CompilerBackend.check_available ();

			string? result = null;
			string? error_message = null;
			CompilerBackend.PatternResultFunc on_result = (r, e) => {
				result = r;
				error_message = e;
				schedule_on_frida_thread (decode_value.callback);
			};

			CompilerBackend.Patterns.decode (source, type_name, data.get_data (), address, platform, arch,
				PatternJson.serialize_inputs (options), (owned) on_result);
			yield;

			if (error_message != null)
				throw new Error.INVALID_ARGUMENT ("%s", error_message);

			return PatternJson.parse_value (result);
		}

		internal async string call_value_function (string source, string platform, string arch, string type_name, Bytes data,
				uint64 address, uint pattern, string function, PatternDecodeOptions? options, Cancellable? cancellable)
				throws Error, IOError {
			CompilerBackend.check_available ();

			string? result = null;
			string? error_message = null;
			CompilerBackend.PatternResultFunc on_result = (r, e) => {
				result = r;
				error_message = e;
				schedule_on_frida_thread (call_value_function.callback);
			};

			CompilerBackend.Patterns.call (source, type_name, data.get_data (), address, platform, arch,
				PatternJson.serialize_inputs (options), pattern, function, (owned) on_result);
			yield;

			if (error_message != null)
				throw new Error.INVALID_ARGUMENT ("%s", error_message);

			return PatternJson.parse_output (result);
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		private void schedule_on_frida_thread (owned SourceFunc function) {
			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (main_context);
		}

		private abstract class PatternCompilerTask<T> : AsyncTask<T> {
			public weak PatternCompiler parent {
				get;
				construct;
			}
		}
	}

	/**
	 * Options for {@link PatternCompiler.compile}.
	 */
	public sealed class PatternCompileOptions : Object {
		/**
		 * The platform the decoded data comes from, as reported by
		 * Process.platform, or null for the one running the compiler.
		 */
		public string? platform {
			get;
			set;
		}

		/**
		 * The architecture the decoded data comes from, as reported by
		 * Process.arch, or null for the one running the compiler.
		 */
		public string? arch {
			get;
			set;
		}
	}

	/**
	 * A compiled pattern language source, with the types it declares.
	 */
	public sealed class PatternModule : Object {
		/**
		 * The declared types, in declaration order.
		 */
		public PatternTypeList types {
			get;
			construct;
		}

		/**
		 * The type made of the source's top-level placements, or null when
		 * it has none.
		 */
		public string? root_type {
			get;
			construct;
		}

		/**
		 * The values the source takes from outside, declared with `in`,
		 * which decode() accepts by name.
		 */
		public PatternInputList inputs {
			get;
			construct;
		}

		/**
		 * Problems found in the source. When non-empty, no types are
		 * available.
		 */
		public PatternDiagnosticList diagnostics {
			get;
			construct;
		}

		private PatternCompiler compiler;
		private string source;
		private string platform;
		private string arch;

		internal PatternModule (PatternCompiler compiler, string source, string platform, string arch, PatternTypeList types,
				string? root_type, PatternInputList inputs, PatternDiagnosticList diagnostics) {
			Object (types: types, root_type: root_type, inputs: inputs, diagnostics: diagnostics);

			this.compiler = compiler;
			this.source = source;
			this.platform = platform;
			this.arch = arch;
		}

		/**
		 * Looks up a declared type by name.
		 *
		 * @param name the type name
		 * @return the type, or null when not declared
		 */
		public PatternType? lookup (string name) {
			return types.lookup (name);
		}

		/**
		 * Decodes @data as an instance of @type_name.
		 *
		 * @param type_name the type to decode
		 * @param data the bytes to decode
		 * @param address the address @data was read from
		 * @param options the values to decode with
		 * @return the decoded value
		 */
		public async PatternValue decode (string type_name, Bytes data, uint64 address, PatternDecodeOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			return yield compiler.decode_value (source, platform, arch, type_name, data, address, options, cancellable);
		}

		public PatternValue decode_sync (string type_name, Bytes data, uint64 address, PatternDecodeOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			var task = create<DecodeTask> ();
			task.type_name = type_name;
			task.data = data;
			task.address = address;
			task.options = options;
			return task.execute (cancellable);
		}

		private class DecodeTask : PatternModuleTask<PatternValue> {
			public string type_name;
			public Bytes data;
			public uint64 address;
			public PatternDecodeOptions? options;

			protected override async PatternValue perform_operation () throws Error, IOError {
				return yield parent.decode (type_name, data, address, options, cancellable);
			}
		}

		/**
		 * Decodes @data as @type_name, then calls @function with the value
		 * identified by @pattern, the way hex::inline_visualize("button")
		 * does when clicked.
		 *
		 * @param type_name the type to decode
		 * @param data the bytes to decode
		 * @param address the address @data was read from
		 * @param pattern the PatternValue.id of the value to pass
		 * @param function the name of the function to call
		 * @param options the values to decode with
		 * @return what the function printed
		 */
		public async string call_function (string type_name, Bytes data, uint64 address, uint pattern, string function,
				PatternDecodeOptions? options = null, Cancellable? cancellable = null) throws Error, IOError {
			return yield compiler.call_value_function (source, platform, arch, type_name, data, address, pattern, function,
				options, cancellable);
		}

		public string call_function_sync (string type_name, Bytes data, uint64 address, uint pattern, string function,
				PatternDecodeOptions? options = null, Cancellable? cancellable = null) throws Error, IOError {
			var task = create<CallFunctionTask> ();
			task.type_name = type_name;
			task.data = data;
			task.address = address;
			task.pattern = pattern;
			task.function = function;
			task.options = options;
			return task.execute (cancellable);
		}

		private class CallFunctionTask : PatternModuleTask<string> {
			public string type_name;
			public Bytes data;
			public uint64 address;
			public uint pattern;
			public string function;
			public PatternDecodeOptions? options;

			protected override async string perform_operation () throws Error, IOError {
				return yield parent.call_function (type_name, data, address, pattern, function, options, cancellable);
			}
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		private abstract class PatternModuleTask<T> : AsyncTask<T> {
			public weak PatternModule parent {
				get;
				construct;
			}
		}
	}

	/**
	 * Options for {@link PatternModule.decode} and
	 * {@link PatternModule.call_function}.
	 */
	public sealed class PatternDecodeOptions : Object {
		/**
		 * Values for the module's `in` variables, by name.
		 */
		public HashTable<string, Variant> inputs {
			get;
			set;
			default = make_parameters_dict ();
		}
	}

	/**
	 * A list of pattern types.
	 */
	public sealed class PatternTypeList : Object {
		private Gee.List<PatternType> items;

		internal PatternTypeList (Gee.List<PatternType> items) {
			this.items = items;
		}

		/**
		 * Gets the number of types in the list.
		 *
		 * @return the count
		 */
		public int size () {
			return items.size;
		}

		/**
		 * Gets the type at the given position.
		 *
		 * @param index zero-based position
		 * @return the type
		 */
		public new PatternType get (int index) {
			return items.get (index);
		}

		internal PatternType? lookup (string name) {
			return items.first_match (t => t.name == name);
		}
	}

	/**
	 * A list of pattern inputs.
	 */
	public sealed class PatternInputList : Object {
		private Gee.List<PatternInput> items;

		internal PatternInputList (Gee.List<PatternInput> items) {
			this.items = items;
		}

		/**
		 * Gets the number of inputs in the list.
		 *
		 * @return the count
		 */
		public int size () {
			return items.size;
		}

		/**
		 * Gets the input at the given position.
		 *
		 * @param index zero-based position
		 * @return the input
		 */
		public new PatternInput get (int index) {
			return items.get (index);
		}
	}

	/**
	 * A value a pattern takes from outside, declared with `in`.
	 */
	public sealed class PatternInput : Object {
		/**
		 * The name to pass the value under.
		 */
		public string name {
			get;
			construct;
		}

		/**
		 * The declared type, or null for a string or an untyped input.
		 */
		public PatternTypeRef? type_ref {
			get;
			construct;
		}

		internal PatternInput (string name, PatternTypeRef? type_ref) {
			Object (name: name, type_ref: type_ref);
		}
	}

	/**
	 * A type declared by a pattern language source.
	 */
	public sealed class PatternType : Object {
		/**
		 * What kind of type this is.
		 */
		public PatternTypeKind kind {
			get;
			construct;
		}

		/**
		 * The declared name.
		 */
		public string name {
			get;
			construct;
		}

		/**
		 * Documentation from the source, if any.
		 */
		public string? doc {
			get;
			construct;
		}

		/**
		 * The file the type is declared in, or null for the source itself.
		 */
		public string? file {
			get;
			construct;
		}

		/**
		 * The zero-based line of the declaration.
		 */
		public uint line {
			get;
			construct;
		}

		/**
		 * The zero-based column of the declaration.
		 */
		public uint character {
			get;
			construct;
		}

		/**
		 * The size in bytes, or -1 when it depends on the data.
		 */
		public int64 size {
			get;
			construct;
		}

		/**
		 * The alignment in bytes.
		 */
		public uint align {
			get;
			construct;
		}

		/**
		 * The fields of a struct or union, in memory order.
		 */
		public PatternFieldList fields {
			get;
			construct;
		}

		/**
		 * The underlying integer type of an enum.
		 */
		public PatternTypeRef? underlying {
			get;
			construct;
		}

		/**
		 * The values of an enum.
		 */
		public PatternEnumValueList values {
			get;
			construct;
		}

		/**
		 * The members of a bitfield, from the least significant bit.
		 */
		public PatternBitList bits {
			get;
			construct;
		}

		/**
		 * The type an alias stands for.
		 */
		public PatternTypeRef? target {
			get;
			construct;
		}

		internal PatternType (PatternTypeKind kind, string name, string? doc, string? file, uint line, uint character, int64 size,
				uint align, PatternFieldList fields, PatternTypeRef? underlying, PatternEnumValueList values, PatternBitList bits,
				PatternTypeRef? target) {
			Object (
				kind: kind,
				name: name,
				doc: doc,
				file: file,
				line: line,
				character: character,
				size: size,
				align: align,
				fields: fields,
				underlying: underlying,
				values: values,
				bits: bits,
				target: target
			);
		}
	}

	/**
	 * The kind of a declared pattern type.
	 */
	public enum PatternTypeKind {
		STRUCT,
		UNION,
		ENUM,
		BITFIELD,
		ALIAS;

		public static PatternTypeKind from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<PatternTypeKind> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<PatternTypeKind> (this);
		}
	}

	/**
	 * A list of pattern fields.
	 */
	public sealed class PatternFieldList : Object {
		private Gee.List<PatternField> items;

		internal PatternFieldList (Gee.List<PatternField> items) {
			this.items = items;
		}

		/**
		 * Gets the number of fields in the list.
		 *
		 * @return the count
		 */
		public int size () {
			return items.size;
		}

		/**
		 * Gets the field at the given position.
		 *
		 * @param index zero-based position
		 * @return the field
		 */
		public new PatternField get (int index) {
			return items.get (index);
		}
	}

	/**
	 * A field of a struct or union.
	 */
	public sealed class PatternField : Object {
		/**
		 * The field name, empty for anonymous fields and padding.
		 */
		public string name {
			get;
			construct;
		}

		/**
		 * Documentation from the source, if any.
		 */
		public string? doc {
			get;
			construct;
		}

		/**
		 * Whether the source asked for the field to be hidden from views.
		 */
		public bool hidden {
			get;
			construct;
		}

		/**
		 * Whether the field is only present when a condition on earlier
		 * fields holds.
		 */
		public bool conditional {
			get;
			construct;
		}

		/**
		 * Whether the field overlaps whatever follows it, taking no space
		 * of its own.
		 */
		public bool no_unique_address {
			get;
			construct;
		}

		/**
		 * The field's type.
		 */
		public PatternTypeRef type_ref {
			get;
			construct;
		}

		/**
		 * The offset in bytes from the start of the containing type, or -1
		 * when it depends on the data.
		 */
		public int64 offset {
			get;
			construct;
		}

		/**
		 * The size in bytes, or -1 when it depends on the data.
		 */
		public int64 size {
			get;
			construct;
		}

		internal PatternField (string name, string? doc, bool hidden, bool conditional, bool no_unique_address,
				PatternTypeRef type_ref, int64 offset, int64 size) {
			Object (
				name: name,
				doc: doc,
				hidden: hidden,
				conditional: conditional,
				no_unique_address: no_unique_address,
				type_ref: type_ref,
				offset: offset,
				size: size
			);
		}
	}

	/**
	 * A reference to a type, as used by a field, pointer, array or alias.
	 */
	public sealed class PatternTypeRef : Object {
		/**
		 * What kind of type is referenced.
		 */
		public PatternTypeRefKind kind {
			get;
			construct;
		}

		/**
		 * The type as written in the source, e.g. "be u32" or "Player*".
		 */
		public string display {
			get;
			construct;
		}

		/**
		 * The name of a built-in or declared type.
		 */
		public string? name {
			get;
			construct;
		}

		/**
		 * The byte order of a built-in type.
		 */
		public PatternByteOrder order {
			get;
			construct;
		}

		/**
		 * The type a pointer points to.
		 */
		public PatternTypeRef? target {
			get;
			construct;
		}

		/**
		 * The integer type a pointer is stored as, or null for a native
		 * pointer.
		 */
		public PatternTypeRef? width {
			get;
			construct;
		}

		/**
		 * The element type of an array.
		 */
		public PatternTypeRef? element {
			get;
			construct;
		}

		/**
		 * The number of elements of an array, or -1 when it depends on the
		 * data.
		 */
		public int64 length {
			get;
			construct;
		}

		/**
		 * Whether an array runs until a null terminator.
		 */
		public bool null_terminated {
			get;
			construct;
		}

		/**
		 * The size of padding, in bytes.
		 */
		public int64 size {
			get;
			construct;
		}

		internal PatternTypeRef (PatternTypeRefKind kind, string display, string? name, PatternByteOrder order,
				PatternTypeRef? target, PatternTypeRef? width, PatternTypeRef? element, int64 length, bool null_terminated,
				int64 size) {
			Object (
				kind: kind,
				display: display,
				name: name,
				order: order,
				target: target,
				width: width,
				element: element,
				length: length,
				null_terminated: null_terminated,
				size: size
			);
		}
	}

	/**
	 * The kind of a referenced pattern type.
	 */
	public enum PatternTypeRefKind {
		PRIMITIVE,
		NAMED,
		POINTER,
		ARRAY,
		PADDING;

		public static PatternTypeRefKind from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<PatternTypeRefKind> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<PatternTypeRefKind> (this);
		}
	}

	/**
	 * The byte order of a built-in pattern type.
	 */
	public enum PatternByteOrder {
		NATIVE,
		LITTLE,
		BIG;

		public static PatternByteOrder from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<PatternByteOrder> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<PatternByteOrder> (this);
		}
	}

	/**
	 * A list of enum values.
	 */
	public sealed class PatternEnumValueList : Object {
		private Gee.List<PatternEnumValue> items;

		internal PatternEnumValueList (Gee.List<PatternEnumValue> items) {
			this.items = items;
		}

		/**
		 * Gets the number of values in the list.
		 *
		 * @return the count
		 */
		public int size () {
			return items.size;
		}

		/**
		 * Gets the value at the given position.
		 *
		 * @param index zero-based position
		 * @return the value
		 */
		public new PatternEnumValue get (int index) {
			return items.get (index);
		}
	}

	/**
	 * A named value of an enum.
	 */
	public sealed class PatternEnumValue : Object {
		/**
		 * The name.
		 */
		public string name {
			get;
			construct;
		}

		/**
		 * Documentation from the source, if any.
		 */
		public string? doc {
			get;
			construct;
		}

		/**
		 * The value, or the first value of a range.
		 */
		public int64 value {
			get;
			construct;
		}

		/**
		 * The last value of a range, equal to value otherwise.
		 */
		public int64 last {
			get;
			construct;
		}

		internal PatternEnumValue (string name, string? doc, int64 value, int64 last) {
			Object (name: name, doc: doc, value: value, last: last);
		}
	}

	/**
	 * A list of bitfield members.
	 */
	public sealed class PatternBitList : Object {
		private Gee.List<PatternBit> items;

		internal PatternBitList (Gee.List<PatternBit> items) {
			this.items = items;
		}

		/**
		 * Gets the number of members in the list.
		 *
		 * @return the count
		 */
		public int size () {
			return items.size;
		}

		/**
		 * Gets the member at the given position.
		 *
		 * @param index zero-based position
		 * @return the member
		 */
		public new PatternBit get (int index) {
			return items.get (index);
		}
	}

	/**
	 * A member of a bitfield.
	 */
	public sealed class PatternBit : Object {
		/**
		 * The name.
		 */
		public string name {
			get;
			construct;
		}

		/**
		 * Documentation from the source, if any.
		 */
		public string? doc {
			get;
			construct;
		}

		/**
		 * How the bits are interpreted.
		 */
		public PatternBitKind kind {
			get;
			construct;
		}

		/**
		 * The position of the least significant bit.
		 */
		public uint offset {
			get;
			construct;
		}

		/**
		 * The number of bits.
		 */
		public uint bits {
			get;
			construct;
		}

		/**
		 * The enum the bits are a value of, when typed as one.
		 */
		public string? enum_name {
			get;
			construct;
		}

		internal PatternBit (string name, string? doc, PatternBitKind kind, uint offset, uint bits, string? enum_name) {
			Object (name: name, doc: doc, kind: kind, offset: offset, bits: bits, enum_name: enum_name);
		}
	}

	/**
	 * How a bitfield member's bits are interpreted.
	 */
	public enum PatternBitKind {
		UNSIGNED,
		SIGNED,
		BOOL,
		ENUM;

		public static PatternBitKind from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<PatternBitKind> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<PatternBitKind> (this);
		}
	}

	/**
	 * A list of pattern diagnostics.
	 */
	public sealed class PatternDiagnosticList : Object {
		private Gee.List<PatternDiagnostic> items;

		internal PatternDiagnosticList (Gee.List<PatternDiagnostic> items) {
			this.items = items;
		}

		/**
		 * Gets the number of diagnostics in the list.
		 *
		 * @return the count
		 */
		public int size () {
			return items.size;
		}

		/**
		 * Gets the diagnostic at the given position.
		 *
		 * @param index zero-based position
		 * @return the diagnostic
		 */
		public new PatternDiagnostic get (int index) {
			return items.get (index);
		}
	}

	/**
	 * A problem found in a pattern language source.
	 */
	public sealed class PatternDiagnostic : Object {
		/**
		 * The zero-based line.
		 */
		public uint line {
			get;
			construct;
		}

		/**
		 * The zero-based character within the line.
		 */
		public uint character {
			get;
			construct;
		}

		/**
		 * What went wrong.
		 */
		public string message {
			get;
			construct;
		}

		internal PatternDiagnostic (uint line, uint character, string message) {
			Object (line: line, character: character, message: message);
		}
	}

	/**
	 * A list of decoded pattern values.
	 */
	public sealed class PatternValueList : Object {
		private Gee.List<PatternValue> items;

		internal PatternValueList (Gee.List<PatternValue> items) {
			this.items = items;
		}

		/**
		 * Gets the number of values in the list.
		 *
		 * @return the count
		 */
		public int size () {
			return items.size;
		}

		/**
		 * Gets the value at the given position.
		 *
		 * @param index zero-based position
		 * @return the value
		 */
		public new PatternValue get (int index) {
			return items.get (index);
		}
	}

	/**
	 * Memory decoded against a pattern type.
	 */
	public sealed class PatternValue : Object {
		/**
		 * Identifies the value within its decoded tree, for visualizer
		 * arguments to refer to it.
		 */
		public uint id {
			get;
			construct;
		}

		/**
		 * The field name, empty for the root and for array elements.
		 */
		public string name {
			get;
			construct;
		}

		/**
		 * The type as written in the source.
		 */
		public string type_name {
			get;
			construct;
		}

		/**
		 * The address the value was decoded from.
		 */
		public uint64 address {
			get;
			construct;
		}

		/**
		 * The offset in bytes from the root value.
		 */
		public uint64 offset {
			get;
			construct;
		}

		/**
		 * The size in bytes, or -1 when the data ended before it was known.
		 */
		public int64 size {
			get;
			construct;
		}

		/**
		 * The scalar value: an int64, uint64, double, boolean or string,
		 * with pointers as uint64. Null for composites, arrays and
		 * truncated values.
		 */
		public Variant? value {
			get;
			construct;
		}

		/**
		 * The enum name matching the value, if any.
		 */
		public string? label {
			get;
			construct;
		}

		/**
		 * The name to show instead of the field name, from [[name]] or
		 * std::core::set_display_name.
		 */
		public string? display_name {
			get;
			construct;
		}

		/**
		 * The value as a [[format]] function rendered it, if one applies.
		 */
		public string? formatted {
			get;
			construct;
		}

		/**
		 * A comment attached with [[comment]], if any.
		 */
		public string? comment {
			get;
			construct;
		}

		/**
		 * A highlight colour attached with [[color]], as RRGGBB, if any.
		 */
		public string? color {
			get;
			construct;
		}

		/**
		 * Whether the pattern asked for the value to be hidden.
		 */
		public bool hidden {
			get;
			construct;
		}

		/**
		 * Whether the pattern asked for the value's children to be shown in
		 * its parent's place.
		 */
		public bool inlined {
			get;
			construct;
		}

		/**
		 * Whether the pattern asked for the value's children to be kept
		 * out of view.
		 */
		public bool sealed {
			get;
			construct;
		}

		/**
		 * The bit position within the containing bitfield's storage, or -1
		 * for byte-addressed values.
		 */
		public int bit_offset {
			get;
			construct;
		}

		/**
		 * The width in bits of a bitfield member, or 0 otherwise.
		 */
		public uint bits {
			get;
			construct;
		}

		/**
		 * The number of elements of an array, or -1 for other values.
		 * Only the first elements are decoded for large arrays.
		 */
		public int64 count {
			get;
			construct;
		}

		/**
		 * The decoded fields of a struct, union or bitfield.
		 */
		public PatternValueList fields {
			get;
			construct;
		}

		/**
		 * The decoded elements of an array.
		 */
		public PatternValueList elements {
			get;
			construct;
		}

		/**
		 * Whether the data ended before the value could be fully decoded.
		 */
		public bool truncated {
			get;
			construct;
		}

		/**
		 * The section the value lives in: 0 for the decoded data, and a
		 * pattern-created section otherwise, where the address is an
		 * offset into that section.
		 */
		public uint64 section {
			get;
			construct;
		}

		/**
		 * The visualizer the pattern attached to this value, if any.
		 */
		public PatternVisualizer? visualizer {
			get;
			construct;
		}

		internal PatternValue (uint id, string name, string type_name, uint64 address, uint64 offset, int64 size, Variant? value,
				string? label, string? display_name, string? formatted, string? comment, string? color, bool hidden, bool inlined,
				bool sealed, int bit_offset, uint bits, int64 count, PatternValueList fields, PatternValueList elements,
				bool truncated, uint64 section, PatternVisualizer? visualizer) {
			Object (
				id: id,
				name: name,
				type_name: type_name,
				address: address,
				offset: offset,
				size: size,
				value: value,
				label: label,
				display_name: display_name,
				formatted: formatted,
				comment: comment,
				color: color,
				hidden: hidden,
				inlined: inlined,
				sealed: sealed,
				bit_offset: bit_offset,
				bits: bits,
				count: count,
				fields: fields,
				elements: elements,
				truncated: truncated,
				section: section,
				visualizer: visualizer
			);
		}

		/**
		 * Serializes the value and everything below it as a dictionary.
		 *
		 * @return the value as a variant of type a{sv}
		 */
		public Variant to_variant () {
			var dict = new VariantDict ();
			dict.insert_value ("id", id);
			dict.insert_value ("name", name);
			dict.insert_value ("type", type_name);
			dict.insert_value ("address", address);
			dict.insert_value ("offset", offset);
			dict.insert_value ("size", size);
			if (value != null)
				dict.insert_value ("value", value);
			if (label != null)
				dict.insert_value ("label", label);
			if (display_name != null)
				dict.insert_value ("display_name", display_name);
			if (formatted != null)
				dict.insert_value ("formatted", formatted);
			if (comment != null)
				dict.insert_value ("comment", comment);
			if (color != null)
				dict.insert_value ("color", color);
			if (hidden)
				dict.insert_value ("hidden", hidden);
			if (inlined)
				dict.insert_value ("inlined", inlined);
			if (sealed)
				dict.insert_value ("sealed", sealed);
			if (bit_offset >= 0) {
				dict.insert_value ("bit_offset", bit_offset);
				dict.insert_value ("bits", bits);
			}
			if (count >= 0)
				dict.insert_value ("count", count);
			if (fields.size () > 0)
				dict.insert_value ("fields", values_to_variant (fields));
			if (elements.size () > 0)
				dict.insert_value ("elements", values_to_variant (elements));
			if (truncated)
				dict.insert_value ("truncated", truncated);
			if (section != 0)
				dict.insert_value ("section", section);
			if (visualizer != null)
				dict.insert_value ("visualizer", visualizer.to_variant ());
			return dict.end ();
		}

		private static Variant values_to_variant (PatternValueList values) {
			var builder = new VariantBuilder (new VariantType ("aa{sv}"));
			int n = values.size ();
			for (int i = 0; i != n; i++)
				builder.add_value (values.get (i).to_variant ());
			return builder.end ();
		}
	}

	/**
	 * A visualizer a pattern attached to a value, with hex::visualize or
	 * hex::inline_visualize.
	 */
	public sealed class PatternVisualizer : Object {
		/**
		 * The visualizer's name, such as "image" or "line_plot".
		 */
		public string name {
			get;
			construct;
		}

		/**
		 * Whether the visualizer is shown on its own or in place of the value.
		 */
		public PatternVisualizerPresentation presentation {
			get;
			construct;
		}

		/**
		 * The arguments that follow the name.
		 */
		public PatternVisualizerArgumentList arguments {
			get;
			construct;
		}

		internal PatternVisualizer (string name, PatternVisualizerPresentation presentation,
				PatternVisualizerArgumentList arguments) {
			Object (name: name, presentation: presentation, arguments: arguments);
		}

		/**
		 * Serializes the visualizer as a dictionary.
		 *
		 * @return the visualizer as a variant of type a{sv}
		 */
		public Variant to_variant () {
			var dict = new VariantDict ();
			dict.insert_value ("name", name);
			dict.insert_value ("presentation", presentation.to_nick ());
			var builder = new VariantBuilder (new VariantType ("aa{sv}"));
			int n = arguments.size ();
			for (int i = 0; i != n; i++)
				builder.add_value (arguments.get (i).to_variant ());
			dict.insert_value ("arguments", builder.end ());
			return dict.end ();
		}
	}

	public enum PatternVisualizerPresentation {
		DETACHED,
		INLINE;

		public static PatternVisualizerPresentation from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<PatternVisualizerPresentation> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<PatternVisualizerPresentation> (this);
		}
	}

	/**
	 * A list of visualizer arguments.
	 */
	public sealed class PatternVisualizerArgumentList : Object {
		private Gee.List<PatternVisualizerArgument> items;

		internal PatternVisualizerArgumentList (Gee.List<PatternVisualizerArgument> items) {
			this.items = items;
		}

		/**
		 * Gets the number of arguments in the list.
		 *
		 * @return the count
		 */
		public int size () {
			return items.size;
		}

		/**
		 * Gets the argument at the given position.
		 *
		 * @param index zero-based position
		 * @return the argument
		 */
		public new PatternVisualizerArgument get (int index) {
			return items.get (index);
		}
	}

	/**
	 * An argument passed to a visualizer: a plain value, or a decoded
	 * pattern.
	 */
	public sealed class PatternVisualizerArgument : Object {
		/**
		 * Whether this is a value or a pattern.
		 */
		public PatternVisualizerArgumentKind kind {
			get;
			construct;
		}

		/**
		 * The value, or the pattern's own value when it has one.
		 */
		public Variant? value {
			get;
			construct;
		}

		/**
		 * The id of the pattern's PatternValue, or 0 when it is not part of
		 * the decoded tree.
		 */
		public uint pattern {
			get;
			construct;
		}

		/**
		 * The pattern's address.
		 */
		public uint64 address {
			get;
			construct;
		}

		/**
		 * The pattern's size in bytes, or -1 when it could not be determined.
		 */
		public int64 size {
			get;
			construct;
		}

		/**
		 * The pattern's bytes, or null when its size could not be determined.
		 */
		public Bytes? data {
			get;
			construct;
		}

		internal PatternVisualizerArgument (PatternVisualizerArgumentKind kind, Variant? value, uint pattern, uint64 address,
				int64 size, Bytes? data) {
			Object (kind: kind, value: value, pattern: pattern, address: address, size: size, data: data);
		}

		/**
		 * Serializes the argument as a dictionary.
		 *
		 * @return the argument as a variant of type a{sv}
		 */
		public Variant to_variant () {
			var dict = new VariantDict ();
			dict.insert_value ("kind", kind.to_nick ());
			if (value != null)
				dict.insert_value ("value", value);
			if (kind == PATTERN) {
				if (pattern != 0)
					dict.insert_value ("pattern", pattern);
				dict.insert_value ("address", address);
				dict.insert_value ("size", size);
				if (data != null)
					dict.insert_value ("data", Variant.new_from_data (new VariantType ("ay"), data.get_data (), true, data));
			}
			return dict.end ();
		}
	}

	public enum PatternVisualizerArgumentKind {
		VALUE,
		PATTERN;

		public static PatternVisualizerArgumentKind from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<PatternVisualizerArgumentKind> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<PatternVisualizerArgumentKind> (this);
		}
	}


	namespace PatternJson {
		private PatternModule parse_module (string json, PatternCompiler compiler, string source, string platform, string arch)
				throws Error {
			var reader = make_reader (json);

			var types = new Gee.ArrayList<PatternType> ();
			reader.read_member ("types");
			int n = reader.count_elements ();
			for (int i = 0; i != n; i++) {
				reader.read_element (i);
				types.add (parse_type (reader));
				reader.end_element ();
			}
			reader.end_member ();

			var diagnostics = new Gee.ArrayList<PatternDiagnostic> ();
			reader.read_member ("diagnostics");
			n = reader.count_elements ();
			for (int i = 0; i != n; i++) {
				reader.read_element (i);
				diagnostics.add (new PatternDiagnostic (
					(uint) read_int (reader, "line"),
					(uint) read_int (reader, "character"),
					read_string (reader, "message")));
				reader.end_element ();
			}
			reader.end_member ();

			var inputs = new Gee.ArrayList<PatternInput> ();
			if (reader.read_member ("inputs")) {
				n = reader.count_elements ();
				for (int i = 0; i != n; i++) {
					reader.read_element (i);
					PatternTypeRef? type_ref = null;
					if (reader.read_member ("type"))
						type_ref = parse_type_ref (reader);
					reader.end_member ();
					inputs.add (new PatternInput (read_string (reader, "name"), type_ref));
					reader.end_element ();
				}
			}
			reader.end_member ();

			return new PatternModule (compiler, source, platform, arch, new PatternTypeList (types),
				read_optional_string (reader, "root"), new PatternInputList (inputs), new PatternDiagnosticList (diagnostics));
		}

		internal string? serialize_inputs (PatternDecodeOptions? options) {
			if (options == null || options.inputs.size () == 0)
				return null;

			var builder = new Json.Builder ();
			builder.begin_object ();
			options.inputs.for_each ((name, value) => {
				builder.set_member_name (name);
				if (value.is_of_type (VariantType.INT64))
					builder.add_int_value (value.get_int64 ());
				else if (value.is_of_type (VariantType.UINT64))
					builder.add_int_value ((int64) value.get_uint64 ());
				else if (value.is_of_type (VariantType.INT32))
					builder.add_int_value (value.get_int32 ());
				else if (value.is_of_type (VariantType.UINT32))
					builder.add_int_value (value.get_uint32 ());
				else if (value.is_of_type (VariantType.DOUBLE))
					builder.add_double_value (value.get_double ());
				else if (value.is_of_type (VariantType.BOOLEAN))
					builder.add_boolean_value (value.get_boolean ());
				else if (value.is_of_type (VariantType.STRING))
					builder.add_string_value (value.get_string ());
				else
					builder.add_string_value (value.print (false));
			});
			builder.end_object ();
			return Json.to_string (builder.get_root (), false);
		}

		private PatternType parse_type (Json.Reader reader) throws Error {
			var kind = PatternTypeKind.from_nick (read_string (reader, "kind"));
			string name = read_string (reader, "name");
			string? doc = read_optional_string (reader, "doc");
			string? file = read_optional_string (reader, "file");
			uint line = (uint) read_int (reader, "line");
			uint character = (uint) read_int (reader, "character");
			int64 size = read_size (reader, "size");
			uint align = (uint) read_optional_int (reader, "align", 1);

			var fields = new Gee.ArrayList<PatternField> ();
			if (reader.read_member ("fields")) {
				int n = reader.count_elements ();
				for (int i = 0; i != n; i++) {
					reader.read_element (i);
					fields.add (parse_field (reader));
					reader.end_element ();
				}
			}
			reader.end_member ();

			PatternTypeRef? underlying = null;
			if (reader.read_member ("underlying"))
				underlying = parse_type_ref (reader);
			reader.end_member ();

			var values = new Gee.ArrayList<PatternEnumValue> ();
			if (reader.read_member ("values")) {
				int n = reader.count_elements ();
				for (int i = 0; i != n; i++) {
					reader.read_element (i);
					values.add (new PatternEnumValue (
						read_string (reader, "name"),
						read_optional_string (reader, "doc"),
						read_int (reader, "value"),
						read_int (reader, "last")));
					reader.end_element ();
				}
			}
			reader.end_member ();

			var bits = new Gee.ArrayList<PatternBit> ();
			if (reader.read_member ("bits")) {
				int n = reader.count_elements ();
				for (int i = 0; i != n; i++) {
					reader.read_element (i);
					bits.add (parse_bit (reader));
					reader.end_element ();
				}
			}
			reader.end_member ();

			PatternTypeRef? target = null;
			if (reader.read_member ("type"))
				target = parse_type_ref (reader);
			reader.end_member ();

			return new PatternType (kind, name, doc, file, line, character, size, align, new PatternFieldList (fields), underlying,
				new PatternEnumValueList (values), new PatternBitList (bits), target);
		}

		private PatternField parse_field (Json.Reader reader) throws Error {
			string name = read_string (reader, "name");
			string? doc = read_optional_string (reader, "doc");
			bool hidden = read_optional_bool (reader, "hidden");
			bool conditional = read_optional_bool (reader, "conditional");
			bool no_unique_address = read_optional_bool (reader, "no_unique_address");

			reader.read_member ("type");
			var type_ref = parse_type_ref (reader);
			reader.end_member ();

			return new PatternField (name, doc, hidden, conditional, no_unique_address, type_ref, read_size (reader, "offset"),
				read_size (reader, "size"));
		}

		private PatternTypeRef parse_type_ref (Json.Reader reader) throws Error {
			var kind = PatternTypeRefKind.from_nick (read_string (reader, "kind"));
			string display = read_string (reader, "display");
			string? name = read_optional_string (reader, "name");

			var order = PatternByteOrder.NATIVE;
			if (reader.read_member ("order"))
				order = PatternByteOrder.from_nick (read_current_string (reader));
			reader.end_member ();

			PatternTypeRef? target = null;
			if (reader.read_member ("target"))
				target = parse_type_ref (reader);
			reader.end_member ();

			PatternTypeRef? width = null;
			if (reader.read_member ("width"))
				width = parse_type_ref (reader);
			reader.end_member ();

			PatternTypeRef? element = null;
			if (reader.read_member ("element"))
				element = parse_type_ref (reader);
			reader.end_member ();

			int64 length = read_optional_int (reader, "length", -1);
			bool null_terminated = kind == ARRAY && !read_optional_bool (reader, "sized");
			int64 size = read_optional_int (reader, "size", 0);

			return new PatternTypeRef (kind, display, name, order, target, width, element, length, null_terminated, size);
		}

		private PatternBit parse_bit (Json.Reader reader) throws Error {
			string name = read_string (reader, "name");
			string? doc = read_optional_string (reader, "doc");
			uint offset = (uint) read_int (reader, "offset");
			uint bits = (uint) read_int (reader, "bits");
			string? enum_name = read_optional_string (reader, "enum");

			var kind = PatternBitKind.UNSIGNED;
			if (read_optional_bool (reader, "signed"))
				kind = SIGNED;
			else if (read_optional_bool (reader, "bool"))
				kind = BOOL;
			else if (enum_name != null)
				kind = ENUM;

			return new PatternBit (name, doc, kind, offset, bits, enum_name);
		}

		private PatternValue parse_value (string json) throws Error {
			return parse_value_node (make_reader (json));
		}

		private string parse_output (string json) throws Error {
			return read_string (make_reader (json), "output");
		}

		private PatternValue parse_value_node (Json.Reader reader) throws Error {
			uint id = (uint) read_int (reader, "id");
			string name = read_optional_string (reader, "name") ?? "";
			string type_name = read_string (reader, "type");
			uint64 address = uint64.parse (read_string (reader, "address"), 16);
			uint64 offset = (uint64) read_int (reader, "offset");
			int64 size = read_size (reader, "size");
			Variant? value = parse_scalar (reader);
			string? label = read_optional_string (reader, "label");
			string? display_name = read_optional_string (reader, "display_name");
			string? formatted = read_optional_string (reader, "formatted");
			string? comment = read_optional_string (reader, "comment");
			string? color = read_optional_string (reader, "color");
			bool hidden = read_optional_bool (reader, "hidden");
			bool inlined = read_optional_bool (reader, "inline");
			bool sealed = read_optional_bool (reader, "sealed");
			int bit_offset = (int) read_optional_int (reader, "bit_offset", -1);
			uint bits = (uint) read_optional_int (reader, "bits", 0);
			int64 count = read_optional_int (reader, "count", -1);
			var fields = parse_values (reader, "fields");
			var elements = parse_values (reader, "elements");
			bool truncated = read_optional_bool (reader, "truncated");
			uint64 section = (uint64) read_optional_int (reader, "section", 0);
			PatternVisualizer? visualizer = null;
			if (reader.read_member ("visualizer"))
				visualizer = parse_visualizer (reader);
			reader.end_member ();

			return new PatternValue (id, name, type_name, address, offset, size, value, label, display_name, formatted, comment, color,
				hidden, inlined, sealed, bit_offset, bits, count, fields, elements, truncated, section, visualizer);
		}

		private PatternVisualizer parse_visualizer (Json.Reader reader) throws Error {
			string name = read_string (reader, "name");
			var presentation = PatternVisualizerPresentation.from_nick (read_string (reader, "presentation"));
			var arguments = new Gee.ArrayList<PatternVisualizerArgument> ();
			reader.read_member ("arguments");
			int n = reader.count_elements ();
			for (int i = 0; i != n; i++) {
				reader.read_element (i);
				arguments.add (parse_visualizer_argument (reader));
				reader.end_element ();
			}
			reader.end_member ();
			return new PatternVisualizer (name, presentation, new PatternVisualizerArgumentList (arguments));
		}

		private PatternVisualizerArgument parse_visualizer_argument (Json.Reader reader) throws Error {
			var kind = PatternVisualizerArgumentKind.from_nick (read_string (reader, "kind"));
			Variant? value = parse_scalar (reader);
			if (kind == VALUE)
				return new PatternVisualizerArgument (kind, value, 0, 0, -1, null);
			uint pattern = (uint) read_optional_int (reader, "pattern", 0);
			uint64 address = uint64.parse (read_string (reader, "address"), 16);
			int64 size = read_size (reader, "size");
			string? encoded_data = read_optional_string (reader, "data");
			Bytes? data = (encoded_data != null) ? new Bytes.take (Base64.decode (encoded_data)) : null;
			return new PatternVisualizerArgument (kind, value, pattern, address, size, data);
		}

		private Variant? parse_scalar (Json.Reader reader) throws Error {
			string? kind = read_optional_string (reader, "value_kind");
			if (kind == null)
				return null;

			reader.read_member ("value");
			Variant? value;
			switch (kind) {
				case "int":
					value = new Variant.int64 (holds_string (reader)
						? int64.parse (reader.get_string_value ())
						: reader.get_int_value ());
					break;
				case "uint":
					value = new Variant.uint64 (holds_string (reader)
						? uint64.parse (reader.get_string_value ())
						: (uint64) reader.get_int_value ());
					break;
				case "float":
					value = new Variant.double (reader.get_double_value ());
					break;
				case "bool":
					value = new Variant.boolean (reader.get_boolean_value ());
					break;
				case "pointer":
					value = new Variant.uint64 (uint64.parse (reader.get_string_value (), 16));
					break;
				default:
					value = new Variant.string (reader.get_string_value ());
					break;
			}
			reader.end_member ();

			return value;
		}

		private bool holds_string (Json.Reader reader) {
			return reader.get_value ().get_value_type () == typeof (string);
		}

		private PatternValueList parse_values (Json.Reader reader, string member) throws Error {
			var values = new Gee.ArrayList<PatternValue> ();
			if (reader.read_member (member)) {
				int n = reader.count_elements ();
				for (int i = 0; i != n; i++) {
					reader.read_element (i);
					values.add (parse_value_node (reader));
					reader.end_element ();
				}
			}
			reader.end_member ();
			return new PatternValueList (values);
		}

		private Json.Reader make_reader (string json) throws Error {
			try {
				return make_json_reader (json);
			} catch (GLib.Error e) {
				throw new Error.PROTOCOL ("%s", e.message);
			}
		}

		private string read_string (Json.Reader reader, string member) throws Error {
			reader.read_member (member);
			string value = read_current_string (reader);
			reader.end_member ();
			return value;
		}

		private string read_current_string (Json.Reader reader) throws Error {
			unowned string? value = reader.get_string_value ();
			if (value == null)
				throw new Error.PROTOCOL ("Expected a string");
			return value;
		}

		private string? read_optional_string (Json.Reader reader, string member) {
			string? value = null;
			if (reader.read_member (member))
				value = reader.get_string_value ();
			reader.end_member ();
			return value;
		}

		private int64 read_int (Json.Reader reader, string member) {
			reader.read_member (member);
			int64 value = reader.get_int_value ();
			reader.end_member ();
			return value;
		}

		private int64 read_optional_int (Json.Reader reader, string member, int64 fallback) {
			int64 value = fallback;
			if (reader.read_member (member))
				value = reader.get_int_value ();
			reader.end_member ();
			return value;
		}

		private int64 read_size (Json.Reader reader, string member) {
			int64 value = -1;
			if (reader.read_member (member) && !reader.get_null_value ())
				value = reader.get_int_value ();
			reader.end_member ();
			return value;
		}

		private bool read_optional_bool (Json.Reader reader, string member) {
			bool value = false;
			if (reader.read_member (member))
				value = reader.get_boolean_value ();
			reader.end_member ();
			return value;
		}
	}

	namespace CompilerBackend {
		private void init () {
			if (initialized)
				return;
			initialized = true;

#if HAVE_COMPILER_BACKEND
#if COMPILER_BACKEND_LINKED
			_init_go_runtime ();
			build = (BuildFunc) _build;
			watch = (WatchFunc) _watch;
			WatchSession.dispose = (WatchSession.DisposeFunc) WatchSession._dispose;
			LanguageServer.open = (LanguageServer.OpenFunc) LanguageServer._open;
			LanguageServer.close = (LanguageServer.CloseFunc) LanguageServer._close;
			LanguageServer.post = (LanguageServer.PostFunc) LanguageServer._post;
			Patterns.describe = (Patterns.DescribeFunc) Patterns._describe;
			Patterns.decode = (Patterns.DecodeFunc) Patterns._decode;
			Patterns.call = (Patterns.CallFunc) Patterns._call;
#elif COMPILER_BACKEND_INSTALLED_LIBRARY
			Module? backend = null;
			try {
				backend = new Module (Frida.compiler_backend_path, LOCAL);
			} catch (ModuleError e) {
				return;
			}
			backend.make_resident ();

			build = resolve_symbol (backend, "_frida_compiler_backend_build");
			watch = resolve_symbol (backend, "_frida_compiler_backend_watch");
			WatchSession.dispose = resolve_symbol (backend, "_frida_compiler_backend_watch_session_dispose");
			LanguageServer.open = resolve_symbol (backend, "_frida_compiler_backend_language_server_open");
			LanguageServer.close = resolve_symbol (backend, "_frida_compiler_backend_language_server_close");
			LanguageServer.post = resolve_symbol (backend, "_frida_compiler_backend_language_server_post");
			Patterns.describe = resolve_symbol (backend, "_frida_compiler_backend_patterns_describe");
			Patterns.decode = resolve_symbol (backend, "_frida_compiler_backend_patterns_decode");
			Patterns.call = resolve_symbol (backend, "_frida_compiler_backend_patterns_call");
#elif COMPILER_BACKEND_EMBEDDED_LIBRARY
			unowned uint8[] backend_so = Frida.Data.Compiler.get_frida_compiler_backend_so_blob ().data;

			Module? backend = null;

			if (MemoryFileDescriptor.is_supported ()) {
				var fd = MemoryFileDescriptor.from_bytes ("frida-compiler-backend.so", new Bytes.static (backend_so));
				try {
					backend = new Module ("/proc/self/fd/%d".printf (fd.handle), LOCAL);
				} catch (ModuleError e) {
				}
			}

			if (backend == null) {
				try {
					string name_used;
					{
						var fd = new FileDescriptor (FileUtils.open_tmp ("frida-compiler-backend-XXXXXX.so", out name_used));
						fd.pwrite_all (backend_so, 0);
					}

					try {
						backend = new Module (name_used, LOCAL);
					} catch (ModuleError e) {
						assert_not_reached ();
					}

					FileUtils.unlink (name_used);
				} catch (GLib.Error e) {
					assert_not_reached ();
				}
			}
			backend.make_resident ();

			build = resolve_symbol (backend, "_frida_compiler_backend_build");
			watch = resolve_symbol (backend, "_frida_compiler_backend_watch");
			WatchSession.dispose = resolve_symbol (backend, "_frida_compiler_backend_watch_session_dispose");
			LanguageServer.open = resolve_symbol (backend, "_frida_compiler_backend_language_server_open");
			LanguageServer.close = resolve_symbol (backend, "_frida_compiler_backend_language_server_close");
			LanguageServer.post = resolve_symbol (backend, "_frida_compiler_backend_language_server_post");
			Patterns.describe = resolve_symbol (backend, "_frida_compiler_backend_patterns_describe");
			Patterns.decode = resolve_symbol (backend, "_frida_compiler_backend_patterns_decode");
			Patterns.call = resolve_symbol (backend, "_frida_compiler_backend_patterns_call");
#elif COMPILER_BACKEND_EMBEDDED_EXECUTABLE || COMPILER_BACKEND_INSTALLED_EXECUTABLE
			backend_process = new BackendProcess ();

			build = executable_build;
			watch = executable_watch;
			WatchSession.dispose = executable_watch_session_dispose;
			LanguageServer.open = executable_language_server_open;
			LanguageServer.close = executable_language_server_close;
			LanguageServer.post = executable_language_server_post;
			Patterns.describe = executable_patterns_describe;
			Patterns.decode = executable_patterns_decode;
			Patterns.call = executable_patterns_call;
#endif
#endif
		}

		private void check_available () throws Error {
			if (build == null) {
#if COMPILER_BACKEND_INSTALLED_LIBRARY || COMPILER_BACKEND_INSTALLED_EXECUTABLE
				throw new Error.NOT_SUPPORTED (
					"Compiler backend plugin not installed; expected at: %s",
					Frida.compiler_backend_path);
#else
				throw new Error.NOT_SUPPORTED ("Compiler backend disabled at build-time");
#endif
			}
		}

		private bool initialized = false;
		private BuildFunc? build;
		private WatchFunc? watch;

		[CCode (has_target = false)]
		private delegate void BuildFunc (string project_root, string entrypoint, OutputFormat output_format,
			BundleFormat bundle_format, size_t disable_type_check, size_t source_map, size_t compress,
			string platform, string[] externals, DiagnosticFunc on_diagnostic, owned BuildCompleteFunc on_complete);

		[CCode (has_target = false)]
		private delegate void WatchFunc (string project_root, string entrypoint, OutputFormat output_format,
			BundleFormat bundle_format, size_t disable_type_check, size_t source_map, size_t compress,
			string platform, string[] externals, StartingFunc on_starting, FinishedFunc on_finished,
			OutputFunc on_output, DiagnosticFunc on_diagnostic, owned WatchReadyFunc on_ready);

#if COMPILER_BACKEND_LINKED
		private extern void _init_go_runtime ();
		private extern void _build ();
		private extern void _watch ();
#endif

		namespace WatchSession {
			[CCode (has_target = false)]
			private delegate void DisposeFunc (size_t handle);

			private DisposeFunc? dispose;

#if COMPILER_BACKEND_LINKED
			private extern void _dispose ();
#endif
		}

		namespace LanguageServer {
			[CCode (has_target = false)]
			private delegate void OpenFunc (string project_root, LanguageServerMessageFunc on_message,
				owned LanguageServerReadyFunc on_ready);

			[CCode (has_target = false)]
			private delegate void CloseFunc (size_t handle);

			[CCode (has_target = false)]
			private delegate string? PostFunc (size_t handle, string json);

			private OpenFunc? open;
			private CloseFunc? close;
			private PostFunc? post;

#if COMPILER_BACKEND_LINKED
			private extern void _open ();
			private extern void _close ();
			private extern void _post ();
#endif
		}

		namespace Patterns {
			[CCode (has_target = false)]
			private delegate void DescribeFunc (string source, string platform, string arch, owned PatternResultFunc on_result);

			[CCode (has_target = false)]
			private delegate void DecodeFunc (string source, string type_name, uint8[] data, uint64 address, string platform,
				string arch, string? inputs, owned PatternResultFunc on_result);

			[CCode (has_target = false)]
			private delegate void CallFunc (string source, string type_name, uint8[] data, uint64 address, string platform,
				string arch, string? inputs, uint pattern, string function, owned PatternResultFunc on_result);

			private DescribeFunc? describe;
			private DecodeFunc? decode;
			private CallFunc? call;

#if COMPILER_BACKEND_LINKED
			private extern void _describe ();
			private extern void _decode ();
			private extern void _call ();
#endif
		}

		private delegate void BuildCompleteFunc (string? bundle, string? error_message);
		private delegate void WatchReadyFunc (size_t session_handle, string? error_message);
		private delegate void StartingFunc ();
		private delegate void FinishedFunc ();
		private delegate void OutputFunc (string bundle);
		private delegate void DiagnosticFunc (string category, int code, string? path, int line, int character,
			string text);
		private delegate void LanguageServerReadyFunc (size_t handle, string? error_message);
		private delegate void LanguageServerMessageFunc (string json);
		private delegate void PatternResultFunc (string? json, string? error_message);

#if HAVE_COMPILER_BACKEND && (COMPILER_BACKEND_EMBEDDED_LIBRARY || COMPILER_BACKEND_INSTALLED_LIBRARY)
		private T resolve_symbol<T> (Module m, string name) {
			void * address;
			if (!m.symbol (name, out address))
				assert_not_reached ();
			return (T) address;
		}
#endif

#if COMPILER_BACKEND_EMBEDDED_EXECUTABLE || COMPILER_BACKEND_INSTALLED_EXECUTABLE
		private BackendProcess? backend_process;

		private static void executable_build (string project_root, string entrypoint, OutputFormat output_format,
				BundleFormat bundle_format, size_t disable_type_check, size_t source_map, size_t compress,
				string platform, string[] externals, DiagnosticFunc on_diagnostic, owned BuildCompleteFunc on_complete) {
			backend_process.build (project_root, entrypoint, output_format, bundle_format, disable_type_check, source_map,
				compress, platform, externals, on_diagnostic, (owned) on_complete);
		}

		private static void executable_watch (string project_root, string entrypoint, OutputFormat output_format,
				BundleFormat bundle_format, size_t disable_type_check, size_t source_map, size_t compress,
				string platform, string[] externals, StartingFunc on_starting, FinishedFunc on_finished,
				OutputFunc on_output, DiagnosticFunc on_diagnostic, owned WatchReadyFunc on_ready) {
			backend_process.watch (project_root, entrypoint, output_format, bundle_format, disable_type_check, source_map,
				compress, platform, externals, on_starting, on_finished, on_output, on_diagnostic, (owned) on_ready);
		}

		private static void executable_watch_session_dispose (size_t handle) {
			backend_process.dispose_watch_session (handle);
		}

		private static void executable_language_server_open (string project_root, LanguageServerMessageFunc on_message,
				owned LanguageServerReadyFunc on_ready) {
			backend_process.open_language_server (project_root, on_message, (owned) on_ready);
		}

		private static void executable_language_server_close (size_t handle) {
			backend_process.close_language_server (handle);
		}

		private static string? executable_language_server_post (size_t handle, string json) {
			return backend_process.post_to_language_server (handle, json);
		}

		private static void executable_patterns_describe (string source, string platform, string arch,
				owned PatternResultFunc on_result) {
			backend_process.describe_patterns (source, platform, arch, (owned) on_result);
		}

		private static void executable_patterns_decode (string source, string type_name, uint8[] data, uint64 address,
				string platform, string arch, string? inputs, owned PatternResultFunc on_result) {
			backend_process.decode_pattern (source, type_name, data, address, platform, arch, inputs, (owned) on_result);
		}

		private static void executable_patterns_call (string source, string type_name, uint8[] data, uint64 address,
				string platform, string arch, string? inputs, uint pattern, string function, owned PatternResultFunc on_result) {
			backend_process.call_pattern_function (source, type_name, data, address, platform, arch, inputs, pattern, function,
				(owned) on_result);
		}

		private class BackendProcess : Object {
			private Subprocess? process;
			private BufferedInputStream? input;
			private OutputStream? output;
			private DataInputStream? errput;

			private ByteArray pending_output = new ByteArray ();
			private bool writing = false;

			private uint next_request_id = 1;
			private uint next_session_id = 1;

			private Gee.Map<uint, PendingBuild> pending_builds = new Gee.HashMap<uint, PendingBuild> ();
			private Gee.Map<uint, WatchEntry> watches = new Gee.HashMap<uint, WatchEntry> ();
			private Gee.Map<uint, LanguageServerEntry> language_servers = new Gee.HashMap<uint, LanguageServerEntry> ();
			private Gee.Map<uint, PendingPatternRequest> pending_pattern_requests = new Gee.HashMap<uint, PendingPatternRequest> ();

			private Cancellable io_cancellable = new Cancellable ();

			construct {
				try_start ();
			}

			private void try_start () {
				try {
					ensure_started ();
				} catch (GLib.Error e) {
				}
			}

			private void ensure_started () throws GLib.Error {
				if (process != null)
					return;

#if COMPILER_BACKEND_INSTALLED_EXECUTABLE
				unowned string path = Frida.compiler_backend_path;
				bool unlink_after = false;
#else
				string path = extract_backend_executable ();
				bool unlink_after = true;
#endif
				try {
					var p = new Subprocess (STDIN_PIPE | STDOUT_PIPE | STDERR_PIPE, path);
					process = p;

					input = (BufferedInputStream) Object.new (typeof (BufferedInputStream),
						"base-stream", p.get_stdout_pipe (),
						"close-base-stream", false,
						"buffer-size", 128 * 1024);
					output = p.get_stdin_pipe ();
					errput = new DataInputStream (p.get_stderr_pipe ());

					process_incoming_messages.begin ();
					process_stderr_stream.begin (errput);
				} finally {
					if (unlink_after)
						FileUtils.unlink (path);
				}
			}

#if COMPILER_BACKEND_EMBEDDED_EXECUTABLE
			private static string extract_backend_executable () throws GLib.Error {
				unowned uint8[] blob = Frida.Data.Compiler.get_frida_compiler_backend_blob ().data;

				string path;
				{
					var fd = new FileDescriptor (FileUtils.open_tmp ("frida-compiler-backend-XXXXXX", out path));
					fd.pwrite_all (blob, 0);
				}

				FileUtils.chmod (path, 0700);

				return path;
			}
#endif

			private void handle_process_failure (string message) {
				io_cancellable.cancel ();
				io_cancellable = new Cancellable ();

				if (process != null) {
					if (!process.get_if_exited ())
						process.force_exit ();
				}

				process = null;
				input = null;
				output = null;
				errput = null;

				foreach (var e in pending_builds.entries)
					e.value.on_complete (null, message);
				pending_builds.clear ();

				foreach (var e in watches.entries) {
					var entry = e.value;
					if (entry.on_ready != null)
						entry.on_ready (0, message);
				}
				watches.clear ();

				foreach (var e in language_servers.entries) {
					var entry = e.value;
					if (entry.on_ready != null)
						entry.on_ready (0, message);
				}
				language_servers.clear ();

				foreach (var e in pending_pattern_requests.entries)
					e.value.on_result (null, message);
				pending_pattern_requests.clear ();

				pending_output = new ByteArray ();
				writing = false;
			}

			public void build (string project_root, string entrypoint, OutputFormat output_format, BundleFormat bundle_format,
					size_t disable_type_check, size_t source_map, size_t compress, string platform, string[] externals,
					DiagnosticFunc on_diagnostic, owned BuildCompleteFunc on_complete) {
				try {
					ensure_started ();
				} catch (GLib.Error e) {
					on_complete (null, e.message);
					return;
				}

				uint request_id = allocate_request_id ();

				pending_builds[request_id] = new PendingBuild ((owned) on_complete, on_diagnostic);

				post_message (make_build_request (
					request_id,
					project_root,
					entrypoint,
					output_format,
					bundle_format,
					disable_type_check != 0,
					source_map != 0,
					compress != 0,
					platform,
					externals
				));
			}

			private class PendingBuild {
				public BuildCompleteFunc on_complete;
				public unowned DiagnosticFunc on_diagnostic;

				public PendingBuild (owned BuildCompleteFunc on_complete, DiagnosticFunc on_diagnostic) {
					this.on_complete = (owned) on_complete;
					this.on_diagnostic = on_diagnostic;
				}
			}

			public void watch (string project_root, string entrypoint, OutputFormat output_format, BundleFormat bundle_format,
					size_t disable_type_check, size_t source_map, size_t compress, string platform, string[] externals,
					StartingFunc on_starting, FinishedFunc on_finished, OutputFunc on_output,
					DiagnosticFunc on_diagnostic, owned WatchReadyFunc on_ready) {
				try {
					ensure_started ();
				} catch (GLib.Error e) {
					on_ready (0, e.message);
					return;
				}

				uint session_id = allocate_session_id ();

				watches[session_id] = new WatchEntry ((owned) on_ready, on_starting, on_finished, on_output, on_diagnostic);

				post_message (make_watch_request (
					session_id,
					project_root,
					entrypoint,
					output_format,
					bundle_format,
					disable_type_check != 0,
					source_map != 0,
					compress != 0,
					platform,
					externals
				));
			}

			private class WatchEntry {
				public WatchReadyFunc? on_ready;
				public unowned StartingFunc on_starting;
				public unowned FinishedFunc on_finished;
				public unowned OutputFunc on_output;
				public unowned DiagnosticFunc on_diagnostic;

				public WatchEntry (owned WatchReadyFunc on_ready, StartingFunc on_starting, FinishedFunc on_finished,
						OutputFunc on_output, DiagnosticFunc on_diagnostic) {
					this.on_ready = (owned) on_ready;
					this.on_starting = on_starting;
					this.on_finished = on_finished;
					this.on_output = on_output;
					this.on_diagnostic = on_diagnostic;
				}
			}

			public void dispose_watch_session (size_t handle) {
				uint session_id = (uint) handle;

				WatchEntry entry;
				if (!watches.unset (session_id, out entry))
					return;

				if (process != null)
					post_message (make_dispose_request (session_id));
			}

			public void open_language_server (string project_root, LanguageServerMessageFunc on_message,
					owned LanguageServerReadyFunc on_ready) {
				try {
					ensure_started ();
				} catch (GLib.Error e) {
					on_ready (0, e.message);
					return;
				}

				uint session_id = allocate_session_id ();

				language_servers[session_id] = new LanguageServerEntry ((owned) on_ready, on_message);

				post_message (make_language_server_open_request (session_id, project_root));
			}

			private class LanguageServerEntry {
				public LanguageServerReadyFunc? on_ready;
				public unowned LanguageServerMessageFunc on_message;

				public LanguageServerEntry (owned LanguageServerReadyFunc on_ready, LanguageServerMessageFunc on_message) {
					this.on_ready = (owned) on_ready;
					this.on_message = on_message;
				}
			}

			public void close_language_server (size_t handle) {
				uint session_id = (uint) handle;

				LanguageServerEntry entry;
				if (!language_servers.unset (session_id, out entry))
					return;

				if (process != null)
					post_message (make_language_server_close_request (session_id));
			}

			public string? post_to_language_server (size_t handle, string json) {
				uint session_id = (uint) handle;

				if (!language_servers.has_key (session_id) || process == null)
					return "Language server not running";

				post_message (make_language_server_post_request (session_id, json));

				return null;
			}

			public void describe_patterns (string source, string platform, string arch, owned PatternResultFunc on_result) {
				try {
					ensure_started ();
				} catch (GLib.Error e) {
					on_result (null, e.message);
					return;
				}

				uint request_id = allocate_request_id ();

				pending_pattern_requests[request_id] = new PendingPatternRequest ((owned) on_result);

				post_message (make_patterns_describe_request (request_id, source, platform, arch));
			}

			public void decode_pattern (string source, string type_name, uint8[] data, uint64 address, string platform,
					string arch, string? inputs, owned PatternResultFunc on_result) {
				try {
					ensure_started ();
				} catch (GLib.Error e) {
					on_result (null, e.message);
					return;
				}

				uint request_id = allocate_request_id ();

				pending_pattern_requests[request_id] = new PendingPatternRequest ((owned) on_result);

				post_message (make_patterns_decode_request (request_id, source, type_name, data, address, platform, arch, inputs));
			}

			public void call_pattern_function (string source, string type_name, uint8[] data, uint64 address, string platform,
					string arch, string? inputs, uint pattern, string function, owned PatternResultFunc on_result) {
				try {
					ensure_started ();
				} catch (GLib.Error e) {
					on_result (null, e.message);
					return;
				}

				uint request_id = allocate_request_id ();

				pending_pattern_requests[request_id] = new PendingPatternRequest ((owned) on_result);

				post_message (make_patterns_call_request (request_id, source, type_name, data, address, platform, arch, inputs,
					pattern, function));
			}

			private class PendingPatternRequest {
				public PatternResultFunc on_result;

				public PendingPatternRequest (owned PatternResultFunc on_result) {
					this.on_result = (owned) on_result;
				}
			}

			private static string make_build_request (uint id, string project_root, string entrypoint,
					OutputFormat output_format, BundleFormat bundle_format, bool disable_type_check,
					bool source_map, bool compress, string platform, string[] externals) {
				return make_request ("build", "id", id, project_root, entrypoint, output_format, bundle_format,
					disable_type_check, source_map, compress, platform, externals);
			}

			private static string make_watch_request (uint session_id, string project_root, string entrypoint,
					OutputFormat output_format, BundleFormat bundle_format, bool disable_type_check,
					bool source_map, bool compress, string platform, string[] externals) {
				return make_request ("watch", "session_id", session_id, project_root, entrypoint, output_format,
					bundle_format, disable_type_check, source_map, compress, platform, externals);
			}

			private static string make_request (string type, string id_name, uint id, string project_root, string entrypoint,
					OutputFormat output_format, BundleFormat bundle_format, bool disable_type_check,
					bool source_map, bool compress, string platform, string[] externals) {
				var builder = new Json.Builder ();

				builder
					.begin_object ()
						.set_member_name ("type")
						.add_string_value (type)
						.set_member_name (id_name)
						.add_int_value (id)
						.set_member_name ("project_root")
						.add_string_value (project_root)
						.set_member_name ("entrypoint")
						.add_string_value (entrypoint)
						.set_member_name ("output_format")
						.add_string_value (output_format.to_nick ())
						.set_member_name ("bundle_format")
						.add_string_value (bundle_format.to_nick ())
						.set_member_name ("disable_type_check")
						.add_boolean_value (disable_type_check)
						.set_member_name ("source_map")
						.add_boolean_value (source_map)
						.set_member_name ("compress")
						.add_boolean_value (compress)
						.set_member_name ("platform")
						.add_string_value (platform)
						.set_member_name ("externals")
						.begin_array ();

				foreach (unowned string e in externals)
					builder.add_string_value (e);

				builder
						.end_array ()
					.end_object ();

				return Json.to_string (builder.get_root (), false);
			}

			private static string make_language_server_open_request (uint session_id, string project_root) {
				var builder = new Json.Builder ();

				builder
					.begin_object ()
						.set_member_name ("type")
						.add_string_value ("language-server:open")
						.set_member_name ("session_id")
						.add_int_value (session_id)
						.set_member_name ("project_root")
						.add_string_value (project_root)
					.end_object ();

				return Json.to_string (builder.get_root (), false);
			}

			private static string make_language_server_close_request (uint session_id) {
				var builder = new Json.Builder ();

				builder
					.begin_object ()
						.set_member_name ("type")
						.add_string_value ("language-server:close")
						.set_member_name ("session_id")
						.add_int_value (session_id)
					.end_object ();

				return Json.to_string (builder.get_root (), false);
			}

			private static string make_language_server_post_request (uint session_id, string json) {
				var builder = new Json.Builder ();

				builder
					.begin_object ()
						.set_member_name ("type")
						.add_string_value ("language-server:post")
						.set_member_name ("session_id")
						.add_int_value (session_id)
						.set_member_name ("text")
						.add_string_value (json)
					.end_object ();

				return Json.to_string (builder.get_root (), false);
			}

			private static string make_patterns_describe_request (uint id, string source, string platform, string arch) {
				var builder = new Json.Builder ();

				builder
					.begin_object ()
						.set_member_name ("type")
						.add_string_value ("patterns:describe")
						.set_member_name ("id")
						.add_int_value (id)
						.set_member_name ("text")
						.add_string_value (source)
						.set_member_name ("platform")
						.add_string_value (platform)
						.set_member_name ("arch")
						.add_string_value (arch)
					.end_object ();

				return Json.to_string (builder.get_root (), false);
			}

			private static string make_patterns_decode_request (uint id, string source, string type_name, uint8[] data,
					uint64 address, string platform, string arch, string? inputs) {
				var builder = begin_patterns_data_request ("patterns:decode", id, source, type_name, data, address, platform, arch,
					inputs);
				builder.end_object ();

				return Json.to_string (builder.get_root (), false);
			}

			private static string make_patterns_call_request (uint id, string source, string type_name, uint8[] data,
					uint64 address, string platform, string arch, string? inputs, uint pattern, string function) {
				var builder = begin_patterns_data_request ("patterns:call", id, source, type_name, data, address, platform, arch,
					inputs);
				builder
					.set_member_name ("pattern")
					.add_int_value (pattern)
					.set_member_name ("function")
					.add_string_value (function)
					.end_object ();

				return Json.to_string (builder.get_root (), false);
			}

			private static Json.Builder begin_patterns_data_request (string type, uint id, string source, string type_name,
					uint8[] data, uint64 address, string platform, string arch, string? inputs) {
				var builder = new Json.Builder ();

				builder
					.begin_object ()
						.set_member_name ("type")
						.add_string_value (type)
						.set_member_name ("id")
						.add_int_value (id)
						.set_member_name ("text")
						.add_string_value (source)
						.set_member_name ("type_name")
						.add_string_value (type_name)
						.set_member_name ("data")
						.add_string_value (Base64.encode (data))
						.set_member_name ("address")
						.add_string_value (("0x%" + uint64.FORMAT_MODIFIER + "x").printf (address))
						.set_member_name ("platform")
						.add_string_value (platform)
						.set_member_name ("arch")
						.add_string_value (arch);
				if (inputs != null) {
					try {
						builder
							.set_member_name ("inputs")
							.add_value (Json.from_string (inputs));
					} catch (GLib.Error e) {
					}
				}

				return builder;
			}

			private static string make_dispose_request (uint session_id) {
				var builder = new Json.Builder ();

				builder
					.begin_object ()
						.set_member_name ("type")
						.add_string_value ("dispose")
						.set_member_name ("session_id")
						.add_int_value (session_id)
					.end_object ();

				return Json.to_string (builder.get_root (), false);
			}

			private uint allocate_request_id () {
				uint start = next_request_id;

				do {
					uint id = next_request_id++;
					if (next_request_id == 0)
						next_request_id = 1;

					if (!pending_builds.has_key (id) && !pending_pattern_requests.has_key (id))
						return id;
				} while (next_request_id != start);

				assert_not_reached ();
			}

			private uint allocate_session_id () {
				uint start = next_session_id;

				do {
					uint id = next_session_id++;
					if (next_session_id == 0)
						next_session_id = 1;

					if (!watches.has_key (id) && !language_servers.has_key (id))
						return id;
				} while (next_session_id != start);

				assert_not_reached ();
			}

			private void post_message (string json) {
				unowned uint8[] raw_json = json.data;

				uint32 size = ((uint32) raw_json.length).to_big_endian ();
				pending_output.append ((uint8[]) &size);
				pending_output.append (raw_json);

				if (!writing) {
					writing = true;

					var source = new IdleSource ();
					source.set_callback (() => {
						process_pending_output.begin ();
						return false;
					});
					source.attach (MainContext.get_thread_default ());
				}
			}

			private async void process_pending_output () {
				while (pending_output.len > 0) {
					uint8[] batch = pending_output.steal ();

					size_t bytes_written;
					try {
						yield output.write_all_async (batch, Priority.DEFAULT, io_cancellable, out bytes_written);
					} catch (GLib.Error e) {
						handle_process_failure ("Compiler backend process terminated unexpectedly");
						return;
					}
				}

				writing = false;
			}

			private async void process_incoming_messages () {
				try {
					while (true) {
						size_t header_size = 4;
						if (input.get_available () < header_size)
							yield fill_until_n_bytes_available (header_size);

						uint32 body_size = 0;
						unowned uint8[] size_buf = ((uint8[]) &body_size)[:4];
						input.peek (size_buf);
						body_size = uint32.from_big_endian (body_size);

						size_t full_size = header_size + body_size;
						if (input.get_available () < full_size)
							yield fill_until_n_bytes_available (full_size);

						var raw_json = new uint8[body_size + 1];
						input.peek (raw_json[:body_size], header_size);

						unowned string json = (string) raw_json;

						handle_message (json);

						input.skip (full_size, io_cancellable);
					}
				} catch (GLib.Error e) {
					handle_process_failure (e.message);
				}
			}

			private void handle_message (string json) throws Error {
				Json.Reader reader;
				try {
					reader = make_json_reader (json);
				} catch (GLib.Error e) {
					throw new Error.PROTOCOL ("%s", e.message);
				}

				reader.read_member ("type");
				unowned string? type = reader.get_string_value ();
				if (type == null)
					throw new Error.PROTOCOL ("Missing or invalid 'type' value");
				reader.end_member ();

				var tokens = type.split (":", 2);
				if (tokens.length != 2)
					throw new Error.PROTOCOL ("Invalid 'type' value");

				unowned string scope = tokens[0];
				unowned string subtype = tokens[1];

				if (scope == "build")
					handle_build_message (subtype, reader);
				else if (scope == "watch")
					handle_watch_message (subtype, reader);
				else if (scope == "language-server")
					handle_language_server_message (subtype, reader);
				else if (scope == "patterns")
					handle_patterns_message (subtype, reader);
				else
					throw new Error.PROTOCOL ("Unknown 'type' scope");
			}

			private void handle_build_message (string type, Json.Reader reader) throws Error {
				if (type == "complete")
					handle_build_complete_message (reader);
				else if (type == "diagnostic")
					handle_build_diagnostic_message (reader);
				else
					throw new Error.PROTOCOL ("Unknown build message type: %s", type);
			}

			private void handle_watch_message (string type, Json.Reader reader) throws Error {
				if (type == "ready")
					handle_watch_ready_message (reader);
				else if (type == "starting" || type == "finished" || type == "output" || type == "diagnostic")
					handle_watch_event_message (reader, type);
				else
					throw new Error.PROTOCOL ("Unknown watch message type: %s", type);
			}

			private void handle_language_server_message (string type, Json.Reader reader) throws Error {
				reader.read_member ("session_id");
				uint session_id = (uint) reader.get_int_value ();
				reader.end_member ();

				var server = language_servers[session_id];
				if (server == null)
					throw new Error.PROTOCOL ("Invalid language server session ID: %u", session_id);

				if (type == "ready") {
					if (reader.read_member ("error")) {
						unowned string? error = reader.get_string_value ();
						if (error == null)
							throw new Error.PROTOCOL ("Missing or invalid 'error' value");
						reader.end_member ();

						language_servers.unset (session_id);
						server.on_ready (0, error);
						return;
					}
					reader.end_member ();

					var on_ready = (owned) server.on_ready;
					if (on_ready == null)
						throw new Error.PROTOCOL ("Duplicate language-server:ready for session ID: %u", session_id);

					server.on_ready = null;
					on_ready (session_id, null);
					return;
				}

				if (type == "message") {
					reader.read_member ("text");
					unowned string? text = reader.get_string_value ();
					if (text == null)
						throw new Error.PROTOCOL ("Missing or invalid 'text' value");
					reader.end_member ();

					server.on_message (text);
					return;
				}

				if (type == "error") {
					reader.read_member ("error");
					unowned string? error = reader.get_string_value ();
					if (error == null)
						throw new Error.PROTOCOL ("Missing or invalid 'error' value");
					reader.end_member ();

					printerr ("[frida-compiler-backend] Language server: %s\n", error);
					return;
				}

				throw new Error.PROTOCOL ("Unknown language-server message type: %s", type);
			}

			private void handle_patterns_message (string type, Json.Reader reader) throws Error {
				if (type != "result")
					throw new Error.PROTOCOL ("Unknown patterns message type: %s", type);

				reader.read_member ("id");
				uint id = (uint) reader.get_int_value ();
				reader.end_member ();

				PendingPatternRequest request;
				if (!pending_pattern_requests.unset (id, out request))
					throw new Error.PROTOCOL ("Invalid pending pattern request ID: %u", id);
				unowned PatternResultFunc on_result = request.on_result;

				if (reader.read_member ("error")) {
					unowned string? error = reader.get_string_value ();
					if (error == null)
						throw new Error.PROTOCOL ("Missing or invalid 'error' value");
					reader.end_member ();

					on_result (null, error);
					return;
				}
				reader.end_member ();

				reader.read_member ("text");
				unowned string? text = reader.get_string_value ();
				if (text == null)
					throw new Error.PROTOCOL ("Missing or invalid 'text' value");
				reader.end_member ();

				on_result (text, null);
			}

			private void handle_build_complete_message (Json.Reader reader) throws Error {
				reader.read_member ("id");
				uint id = (uint) reader.get_int_value ();
				reader.end_member ();

				PendingBuild pending;
				if (!pending_builds.unset (id, out pending))
					throw new Error.PROTOCOL ("Invalid pending build ID: %u", id);

				if (reader.read_member ("error")) {
					unowned string? error = reader.get_string_value ();
					if (error == null)
						throw new Error.PROTOCOL ("Missing or invalid 'error' value");
					reader.end_member ();

					pending.on_complete (null, error);
					return;
				}
				reader.end_member ();

				reader.read_member ("bundle");
				unowned string? bundle = reader.get_string_value ();
				if (bundle == null)
					throw new Error.PROTOCOL ("Missing or invalid 'bundle' value");
				reader.end_member ();

				pending.on_complete (bundle, null);
			}

			private void handle_build_diagnostic_message (Json.Reader reader) throws Error {
				reader.read_member ("id");
				uint id = (uint) reader.get_int_value ();
				reader.end_member ();

				var pending = pending_builds[id];
				if (pending == null)
					throw new Error.PROTOCOL ("Invalid pending build ID: %u", id);

				emit_diagnostic_from_json (reader, pending.on_diagnostic);
			}

			private void handle_watch_ready_message (Json.Reader reader) throws Error {
				reader.read_member ("session_id");
				uint session_id = (uint) reader.get_int_value ();
				reader.end_member ();

				var watch = watches[session_id];
				if (watch == null)
					throw new Error.PROTOCOL ("Invalid watch session ID: %u", session_id);

				if (reader.read_member ("error")) {
					unowned string? error = reader.get_string_value ();
					if (error == null)
						throw new Error.PROTOCOL ("Missing or invalid 'error' value");
					reader.end_member ();

					watches.unset (session_id);
					watch.on_ready (0, error);
					return;
				}
				reader.end_member ();

				var on_ready = (owned) watch.on_ready;
				if (on_ready == null)
					throw new Error.PROTOCOL ("Duplicate watch:ready for session ID: %u", session_id);

				watch.on_ready = null;
				on_ready (session_id, null);
			}

			private void handle_watch_event_message (Json.Reader reader, string type) throws Error {
				reader.read_member ("session_id");
				var session_id = (uint) reader.get_int_value ();
				reader.end_member ();

				var watch = watches[session_id];
				if (watch == null)
					throw new Error.PROTOCOL ("Invalid watch session ID: %u", session_id);

				if (type == "starting") {
					watch.on_starting ();
					return;
				}

				if (type == "finished") {
					watch.on_finished ();
					return;
				}

				if (type == "output") {
					reader.read_member ("bundle");
					unowned string? bundle = reader.get_string_value ();
					if (bundle == null)
						throw new Error.PROTOCOL ("Missing or invalid 'bundle' value");
					reader.end_member ();

					watch.on_output (bundle);
					return;
				}

				emit_diagnostic_from_json (reader, watch.on_diagnostic);
			}

			private static void emit_diagnostic_from_json (Json.Reader reader, DiagnosticFunc on_diagnostic) throws Error {
				reader.read_member ("category");
				unowned string? category = reader.get_string_value ();
				if (category == null)
					throw new Error.PROTOCOL ("Missing or invalid 'category' value");
				reader.end_member ();

				reader.read_member ("code");
				int code = (int) reader.get_int_value ();
				reader.end_member ();

				string? path = null;
				int line = 0;
				int character = 0;

				if (reader.read_member ("path")) {
					path = reader.get_string_value ();
					reader.end_member ();

					reader.read_member ("line");
					line = (int) reader.get_int_value ();
					reader.end_member ();

					reader.read_member ("character");
					character = (int) reader.get_int_value ();
					reader.end_member ();
				} else {
					reader.end_member ();
				}

				reader.read_member ("text");
				unowned string? text = reader.get_string_value ();
				if (text == null)
					throw new Error.PROTOCOL ("Missing or invalid 'text' value");
				reader.end_member ();

				on_diagnostic (category, code, path, line, character, text);
			}

			private async void process_stderr_stream (DataInputStream stream) {
				try {
					while (true) {
						string? line = yield stream.read_line_utf8_async (Priority.DEFAULT, io_cancellable);
						if (line == null)
							break;
						printerr ("[frida-compiler-backend stderr] %s\n", line);
					}
				} catch (GLib.Error e) {
				}
			}

			private async void fill_until_n_bytes_available (size_t minimum) throws Error, IOError {
				size_t available = input.get_available ();
				while (available < minimum) {
					if (input.get_buffer_size () < minimum)
						input.set_buffer_size (minimum);

					ssize_t n;
					try {
						n = yield input.fill_async ((ssize_t) (input.get_buffer_size () - available),
							Priority.DEFAULT, io_cancellable);
					} catch (GLib.Error e) {
						throw new Error.TRANSPORT ("Compiler backend process terminated unexpectedly");
					}

					if (n == 0)
						throw new Error.TRANSPORT ("Compiler backend process terminated unexpectedly");

					available += n;
				}
			}
		}
#endif
	}

	private string compute_project_root (string entrypoint, CompilerOptions options) {
		string? project_root = options.project_root;

		if (project_root != null)
			return project_root;

		if (Path.is_absolute (entrypoint))
			return Path.get_dirname (entrypoint);

		return Environment.get_current_dir ();
	}

	/**
	 * Options shared by {@link Compiler.build} and {@link Compiler.watch}.
	 */
	public class CompilerOptions : Object {
		/**
		 * The project root directory, or null to infer it from the entrypoint.
		 */
		public string? project_root {
			get;
			set;
		}

		/**
		 * How the resulting bundle's bytes are encoded.
		 */
		public OutputFormat output_format {
			get;
			set;
			default = UNESCAPED;
		}

		/**
		 * The module format of the bundle.
		 */
		public BundleFormat bundle_format {
			get;
			set;
			default = ESM;
		}

		/**
		 * Whether to type-check the project.
		 */
		public TypeCheckMode type_check {
			get;
			set;
			default = FULL;
		}

		/**
		 * Whether to include source maps in the bundle.
		 */
		public SourceMaps source_maps {
			get;
			set;
			default = INCLUDED;
		}

		/**
		 * Which compressor to run the output through, if any.
		 */
		public JsCompression compression {
			get;
			set;
			default = NONE;
		}

		/**
		 * Which platform the bundle targets.
		 */
		public JsPlatform platform {
			get;
			set;
			default = GUM;
		}

		internal Gee.List<string> externals = new Gee.ArrayList<string> ();

		/**
		 * Removes all configured externals.
		 */
		public void clear_externals () {
			externals.clear ();
		}

		/**
		 * Marks a module as external, leaving it out of the bundle.
		 *
		 * @param external the module specifier to treat as external
		 */
		public void add_external (string external) {
			externals.add (external);
		}

		/**
		 * Invokes @func for each configured external.
		 *
		 * @param func function called with each external
		 */
		public void enumerate_externals (Func<string> func) {
			foreach (var external in externals)
				func (external);
		}
	}

	/**
	 * Options for {@link Compiler.build}.
	 */
	public sealed class BuildOptions : CompilerOptions {
	}

	/**
	 * Options for {@link Compiler.watch}.
	 */
	public sealed class WatchOptions : CompilerOptions {
	}

	/**
	 * How a compiled bundle's bytes are encoded.
	 */
	public enum OutputFormat {
		/**
		 * Raw, unescaped JavaScript.
		 */
		UNESCAPED,
		/**
		 * A hex-encoded byte string.
		 */
		HEX_BYTES,
		/**
		 * A C string literal.
		 */
		C_STRING;

		public static OutputFormat from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<OutputFormat> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<OutputFormat> (this);
		}
	}

	/**
	 * The module format of a compiled bundle.
	 */
	public enum BundleFormat {
		/**
		 * An ECMAScript module.
		 */
		ESM,
		/**
		 * An immediately-invoked function expression.
		 */
		IIFE;

		public static BundleFormat from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<BundleFormat> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<BundleFormat> (this);
		}
	}

	/**
	 * Whether the compiler type-checks the project.
	 */
	public enum TypeCheckMode {
		/**
		 * Perform full type checking.
		 */
		FULL,
		/**
		 * Skip type checking.
		 */
		NONE;

		public static TypeCheckMode from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<TypeCheckMode> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<TypeCheckMode> (this);
		}
	}

	/**
	 * Whether source maps are included in a compiled bundle.
	 */
	public enum SourceMaps {
		/**
		 * Include source maps.
		 */
		INCLUDED,
		/**
		 * Omit source maps.
		 */
		OMITTED;

		public static SourceMaps from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<SourceMaps> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<SourceMaps> (this);
		}
	}

	/**
	 * Which compressor the compiled JavaScript is run through.
	 */
	public enum JsCompression {
		/**
		 * No compression.
		 */
		NONE,
		/**
		 * Compress with Terser.
		 */
		TERSER;

		public static JsCompression from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<JsCompression> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<JsCompression> (this);
		}
	}

	/**
	 * The platform a compiled bundle targets.
	 */
	public enum JsPlatform {
		/**
		 * Frida's Gum runtime inside a target process.
		 */
		GUM,
		/**
		 * A web browser.
		 */
		BROWSER,
		/**
		 * A platform-neutral environment.
		 */
		NEUTRAL;

		public static JsPlatform from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<JsPlatform> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<JsPlatform> (this);
		}
	}
}
