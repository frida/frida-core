namespace Frida {
	public sealed class PackageManager : Object {
		public signal void progress (string text, double fraction);

		public string registry {
			get;
			set;
			default = "registry.npmjs.org";
		}

		private Soup.Session session;

		public PackageManager () {
			string cache_dir = Path.build_filename (Environment.get_user_cache_dir (), "frida", "package-manager");
			var cache = new Soup.Cache (cache_dir, Soup.CacheType.SINGLE_USER);
			session = new Soup.Session ();
			session.add_feature (cache);
		}

		public async PackageSearchResult search (string query, PackageSearchOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			var opts = (options != null) ? options : new PackageSearchOptions ();

			var text = string.join (" ", query, "keywords:frida-gum");
			Json.Reader reader = yield fetch ("https://%s/-/v1/search?text=%s&from=%u&size=%u"
				.printf (registry, Uri.escape_string (text), opts.offset, opts.limit), session, cancellable);

			var packages = new Gee.ArrayList<Package> ();
			reader.read_member ("objects");
			int count = reader.count_elements ();
			if (count == -1)
				throw new Error.PROTOCOL ("Unexpected JSON format: 'objects' array missing");
			for (uint i = 0; i != (uint) count; i++) {
				reader.read_element (i);

				reader.read_member ("package");

				reader.read_member ("name");
				string? name = reader.get_string_value ();
				reader.end_member ();

				reader.read_member ("version");
				string? version = reader.get_string_value ();
				reader.end_member ();

				reader.read_member ("description");
				string? description = reader.get_string_value ();
				reader.end_member ();

				reader.end_member ();

				if (name == null || version == null)
					throw new Error.PROTOCOL ("Unexpected JSON format: missing package details");
				packages.add (new Package (name, version, description));

				reader.end_element ();
			}
			reader.end_member ();

			reader.read_member ("total");
			int64 total_count = reader.get_int_value ();
			if (total_count == -1)
				throw new Error.PROTOCOL ("Unexpected JSON format: 'total' missing");

			return new PackageSearchResult (new PackageList (packages), (uint) total_count);
		}

		public PackageSearchResult search_sync (string query, PackageSearchOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			var task = create<SearchTask> ();
			task.query = query;
			task.options = options;
			return task.execute (cancellable);
		}

		private class SearchTask : PackageManagerTask<PackageSearchResult> {
			public string query;
			public PackageSearchOptions? options;

			protected override async PackageSearchResult perform_operation () throws Error, IOError {
				return yield parent.search (query, options, cancellable);
			}
		}

		public async PackageInstallResult install (PackageInstallOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			var opts = (options != null) ? options : new PackageInstallOptions ();

			File project_root = compute_project_root (opts);
			File pkg_json_f = project_root.get_child ("package.json");
			File lock_f = project_root.get_child ("package-lock.json");

			Manifest manifest = yield load_manifest (pkg_json_f, lock_f, cancellable);

			var wanted = new Gee.HashMap<string, PackageDependency> ();
			wanted.set_all (manifest.dependencies.all);
			foreach (string spec in opts.specs) {
				string name, version;
				int at = spec.last_index_of ("@");
				if (at != -1) {
					name = spec[:at];
					version = spec[at + 1:];
				} else {
					name = spec;
					version = "latest";
				}
				wanted[name] = new PackageDependency () {
					name = name,
					version = new PackageVersion (version),
					role = RUNTIME,
				};
			}

			File install_root = project_root.get_child ("node_modules");
			FS.mkdirp (install_root, cancellable);

			var all_installs = new Gee.HashMap<string, Promise<PackageLockEntry>> ();
			foreach (PackageDependency dep in wanted.values)
				all_installs[dep.name] = new Promise<PackageLockEntry> ();

			var toplevel_installs = new Gee.HashMap<string, Promise<PackageLockEntry>> ();
			toplevel_installs.set_all (all_installs);
			foreach (var e in toplevel_installs.entries) {
				PackageDependency dep = wanted[e.key];
				perform_install.begin (dep.name, dep.version, dep, install_root, cancellable, e.value, all_installs);
			}

			var finished_installs = new Gee.HashMap<string, PackageLockEntry> ();
			while (finished_installs.size != all_installs.size) {
				PackageLockEntry? entry = null;
				foreach (var e in all_installs.entries) {
					unowned string name = e.key;
					if (finished_installs.has_key (name))
						continue;
					entry = yield e.value.future.wait_async (cancellable);
					finished_installs[name] = entry;
					break;
				}

				PackageDependency? dep = wanted[entry.name];
				if (dep != null) {
					manifest.dependencies.add (new PackageDependency () {
						name = entry.name,
						version = dep.derive_version (entry.version),
						role = dep.role,
					});
				}
			}

			yield write_back_manifests (manifest, finished_installs, pkg_json_f, lock_f, cancellable);

			var pkgs = new Gee.ArrayList<Package> ();
			foreach (PackageLockEntry e in finished_installs.values) {
				if (e.name == e.toplevel_dep.name)
					pkgs.add (new Package (e.name, e.version, e.description));
			}

			return new PackageInstallResult (new PackageList (pkgs));
		}

		private class Manifest {
			public PackageDependencies dependencies = new PackageDependencies ();
		}

		private class PackageLockEntry {
			public string name;
			public string version;
			public string resolved;
			public string integrity;
			public string? description;
			public string? license;
			public PackageDependencies dependencies;
			public PackageDependency toplevel_dep;
		}

		private class PackageDependencies {
			public Gee.Map<string, PackageDependency> all = new Gee.HashMap<string, PackageDependency> ();

			public Gee.Map<string, PackageDependency> runtime {
				get {
					if (_runtime == null)
						_runtime = compute_subset_with_role (RUNTIME);
					return _runtime;
				}
			}

			public Gee.Map<string, PackageDependency> development {
				get {
					if (_development == null)
						_development = compute_subset_with_role (DEVELOPMENT);
					return _development;
				}
			}

			private Gee.Map<string, PackageDependency> _runtime;
			private Gee.Map<string, PackageDependency> _development;

			public void add (PackageDependency d) {
				all[d.name] = d;
			}

			private Gee.Map<string, PackageDependency> compute_subset_with_role (PackageRole role) {
				var result = new Gee.HashMap<string, PackageDependency> ();
				foreach (PackageDependency d in all.values) {
					if (d.role == role)
						result[d.name] = d;
				}
				return result;
			}
		}

		private class PackageDependency {
			public string name;
			public PackageVersion version;
			public PackageRole role;

			public PackageVersion derive_version (string installed_version) {
				if (version.is_pinned)
					return version;
				return new PackageVersion ("^" + installed_version);
			}
		}

		private class PackageVersion {
			public string spec;

			public bool is_pinned {
				get {
					return spec[0].isdigit ();
				}
			}

			public PackageVersion (string spec) {
				this.spec = spec;
			}
		}

		private enum PackageRole {
			RUNTIME,
			DEVELOPMENT
		}

		private async Manifest load_manifest (File pkg_json_f, File lock_f, Cancellable? cancellable) throws Error, IOError {
			var m = new Manifest ();
			if (!pkg_json_f.query_exists (cancellable))
				return m;

			Json.Reader r = yield load_json (pkg_json_f, cancellable);

			m.dependencies = read_dependencies (r);

			return m;
		}

		private static PackageDependencies read_dependencies (Json.Reader r) throws Error {
			var deps = new PackageDependencies ();

			string section_names[2] = {"dependencies", "devDependencies"};
			for (uint i = 0; i != section_names.length; i++) {
				unowned string section = section_names[i];

				if (!r.read_member (section)) {
					r.end_member ();
					continue;
				}

				string[]? names = r.list_members ();
				if (names == null)
					throw new Error.PROTOCOL ("Bad shape of %s section", section);

				PackageRole role = (i == 0) ? PackageRole.RUNTIME : PackageRole.DEVELOPMENT;

				foreach (unowned string name in names) {
					r.read_member (name);

					string? version = r.get_string_value ();
					if (version == null)
						throw new Error.PROTOCOL ("Bad type of %s entry for %s", section, name);

					deps.add (new PackageDependency () {
						name = name,
						version = new PackageVersion (version),
						role = role,
					});

					r.end_member ();
				}

				r.end_member ();
			}

			return deps;
		}

		private async void write_back_manifests (Manifest manifest, Gee.Map<string, PackageLockEntry> installed, File pkg_json_f,
				File lock_f, Cancellable? cancellable) throws Error, IOError {
			string? name = null;
			Json.Node? root = null;
			string? old_pkg_json = null;
			uint indent_level = 2;
			unichar indent_char = ' ';
			if (pkg_json_f.query_exists (cancellable)) {
				old_pkg_json = yield FS.read_all_text (pkg_json_f, cancellable);
				try {
					root = Json.from_string (old_pkg_json);
				} catch (GLib.Error e) {
					throw new Error.PROTOCOL ("%s is invalid: %s", pkg_json_f.get_parse_name (), e.message);
				}
				if (root.get_node_type () != OBJECT)
					throw new Error.PROTOCOL ("%s is invalid, root must be an object", pkg_json_f.get_parse_name ());
				detect_indent (old_pkg_json, out indent_level, out indent_char);

				var r = new Json.Reader (root);
				r.read_member ("name");
				name = r.get_string_value ();
			} else {
				root = new Json.Node (OBJECT);
				root.init_object (new Json.Object ());
			}
			if (name == null) {
				try {
					var info = yield pkg_json_f.get_parent ().query_info_async (FileAttribute.STANDARD_DISPLAY_NAME,
						FileQueryInfoFlags.NONE, Priority.DEFAULT, cancellable);
					name = info.get_display_name ();
					printerr ("Computed fallback name: \"%s\"\n", name);
				} catch (GLib.Error e) {
					throw new Error.PERMISSION_DENIED ("%s", e.message);
				}
			}

			Json.Object obj = root.get_object ();
			Json.Object deps;
			Json.Node? deps_node = obj.get_member ("dependencies");
			if (deps_node != null) {
				if (root.get_node_type () != OBJECT) {
					throw new Error.PROTOCOL ("%s is invalid, 'dependencies' must be an object",
						pkg_json_f.get_parse_name ());
				}
				deps = deps_node.get_object ();
			} else {
				deps = new Json.Object ();
				obj.set_object_member ("dependencies", deps);
			}
			foreach (PackageLockEntry e in installed.values) {
				PackageDependency toplevel_dep = e.toplevel_dep;
				if (e.name == toplevel_dep.name)
					deps.set_string_member (e.name, toplevel_dep.derive_version (e.version).spec);
			}

			var gen = new Json.Generator ();
			gen.set_pretty (true);
			gen.set_indent (indent_level);
			gen.set_indent_char (indent_char);
			gen.set_root (root);
			string new_pkg_json = gen.to_data (null);

			bool pkg_json_changed = old_pkg_json == null || new_pkg_json != old_pkg_json;
			if (pkg_json_changed)
				yield FS.write_all_text (pkg_json_f, new_pkg_json, cancellable);

			var b = new Json.Builder ();
			b.begin_object ()
				.set_member_name ("name")
				.add_string_value (name)
				.set_member_name ("lockfileVersion")
				.add_int_value (3)
				.set_member_name ("requires")
				.add_boolean_value (true)
				.set_member_name ("packages")
				.begin_object ();

			b
				.set_member_name ("")
				.begin_object ()
				.set_member_name ("dependencies")
				.begin_object ();
			add_dependencies (b, manifest.dependencies);
			b
				.end_object ()
				.end_object ();
			foreach (PackageLockEntry e in installed.values) {
				b
					.set_member_name (e.name)
					.begin_object ()
					.set_member_name ("version")
					.add_string_value (e.version)
					.set_member_name ("resolved")
					.add_string_value (e.resolved)
					.set_member_name ("integrity")
					.add_string_value (e.integrity);
				if (e.license != null) {
					b
						.set_member_name ("license")
						.add_string_value (e.license);
				}
				if (e.toplevel_dep.role == DEVELOPMENT) {
					b
						.set_member_name ("dev")
						.add_boolean_value (true);
				}
				b
					.end_object ();
			}
			b
				.end_object ()
				.end_object ();

			gen = new Json.Generator ();
			gen.set_pretty (true);
			gen.set_indent (indent_level);
			gen.set_indent_char (indent_char);
			gen.set_root (b.get_root ());
			string lock_json = gen.to_data (null);
			yield FS.write_all_text (lock_f, lock_json, cancellable);
		}

		private static void add_dependencies (Json.Builder b, PackageDependencies deps) {
			add_dependencies_in_section (b, "dependencies", deps.runtime.values);
			add_dependencies_in_section (b, "devDependencies", deps.development.values);
		}

		private static void add_dependencies_in_section (Json.Builder b, string section, Gee.Collection<PackageDependency> deps) {
			if (deps.is_empty)
				return;
			b
				.set_member_name (section)
				.begin_object ();
			foreach (var dep in deps) {
				b
					.set_member_name (dep.name)
					.add_string_value (dep.version.spec);
			}
			b
				.end_object ();
		}

		private async void perform_install (string name, PackageVersion version, PackageDependency toplevel_dep, File install_root,
				Cancellable? cancellable, Promise<PackageLockEntry> request,
				Gee.Map<string, Promise<PackageLockEntry>> all_installs) {
			try {
				Json.Reader r = yield fetch ("https://%s/%s/%s"
					.printf (registry, Uri.escape_string (name), Uri.escape_string (version.spec)),
					session, cancellable);
				r.read_member ("version");
				string? effective_version = r.get_string_value ();
				r.end_member ();
				r.read_member ("description");
				string? description = r.get_string_value ();
				r.end_member ();
				r.read_member ("license");
				string? license = r.get_string_value ();
				r.end_member ();
				r.read_member ("dist");
				r.read_member ("tarball");
				string? tarball_url = r.get_string_value ();
				r.end_member ();
				r.read_member ("integrity");
				string? integrity = r.get_string_value ();
				r.end_member ();
				r.read_member ("shasum");
				string? shasum = r.get_string_value ();
				r.end_member ();
				r.end_member ();
				var deps = read_dependencies (r);

				if (tarball_url == null)
					throw new Error.PROTOCOL ("No tarball URL for %s", name);

				bool is_toplevel = name != toplevel_dep.name;
				foreach (PackageDependency d in deps.all.values) {
					if (d.role == DEVELOPMENT && !is_toplevel)
						continue;
					if (all_installs.has_key (d.name))
						continue;
					var req = new Promise<PackageLockEntry> ();
					all_installs[d.name] = req;
					perform_install.begin (d.name, d.version, toplevel_dep, install_root, cancellable, req,
						all_installs);
				}

				File dest_root = install_root;
				foreach (string part in name.split ("/"))
					dest_root = dest_root.get_child (part);

				yield download_and_unpack (name, tarball_url, dest_root, integrity, shasum, cancellable);

				// TODO: handle missing 'integrity'

				request.resolve (new PackageLockEntry () {
					name = name,
					version = effective_version,
					resolved = tarball_url,
					integrity = integrity,
					description = description,
					license = license,
					dependencies = deps,
					toplevel_dep = toplevel_dep,
				});
			} catch (GLib.Error e) {
				request.reject (e);
			}
		}

		private async void download_and_unpack (string name, string tarball_url, File dest_root, string? integrity, string? shasum,
				Cancellable? cancellable) throws Error, IOError {
			int io_priority = Priority.DEFAULT;

			var tar_msg = new Soup.Message ("GET", tarball_url);
			InputStream http_stream;
			try {
				http_stream = yield session.send_async (tar_msg, io_priority, cancellable);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("Failed to GET %s: %s", tarball_url, e.message);
			}
			if (tar_msg.status_code != 200)
				throw new Error.PROTOCOL ("Failed to GET %s: HTTP %u", tarball_url, tar_msg.status_code);

			ChecksumType algo = SHA1;
			string? integrity_algo = null;
			uint8[]? integrity_digest = null;
			if (integrity != null) {
				string[] tokens = integrity.split ("-", 2);
				if (tokens.length != 2)
					throw new Error.PROTOCOL ("Invalid integrity encoding");
				integrity_algo = tokens[0];
				switch (integrity_algo) {
					case "md5":	algo = MD5;	break;
					case "sha1":	algo = SHA1;	break;
					case "sha256":	algo = SHA256;	break;
					case "sha384":	algo = SHA384;	break;
					case "sha512":	algo = SHA512;	break;
					default:
						throw new Error.PROTOCOL ("Unsupported integrity algorithm %s", integrity_algo);
				}
				integrity_digest = Base64.decode (tokens[1]);
			}
			var checksum_converter = new ChecksumConverter (algo);
			var checksum_input = new ConverterInputStream (http_stream, checksum_converter);

			var gunzip_input = new ConverterInputStream (checksum_input, new ZlibDecompressor (GZIP));
			File temp_dest_root = dest_root.get_parent ().get_child (".fpm_" + dest_root.get_basename ());
			yield FS.rmtree_async (temp_dest_root, cancellable);
			var tar_reader = new TarStreamReader (temp_dest_root);

			uint8 buffer[32 * 1024];
			size_t read_total = 0;
			size_t report_bucket = 0;
			int64 content_len = tar_msg.get_response_headers ().get_content_length ();

			while (true) {
				ssize_t n = yield gunzip_input.read_async (buffer, io_priority, cancellable);
				if (n == 0)
					break;
				if (n < 0)
					throw new IOError.FAILED ("Stream read failed");

				yield tar_reader.feed (buffer, (size_t) n, cancellable);
				read_total += (size_t) n;
				report_bucket += (size_t) n;

				if (content_len > 0 && report_bucket >= (1 << 20)) {
					progress (name, (double) read_total / (double) content_len);
					report_bucket = 0;
				}
			}

			tar_reader.finish ();

			Error? checksum_error = null;
			if (integrity != null) {
				uint8[] actual = checksum_converter.collect_raw_digest ();
				if (actual.length != integrity_digest.length)
					checksum_error = new Error.PROTOCOL ("Bad %s digest length for %s", integrity_algo, tarball_url);
				else if (Memory.cmp (actual, integrity_digest, integrity_digest.length) != 0)
					checksum_error = new Error.PROTOCOL ("Detected %s mismatch for %s", integrity_algo, tarball_url);
			} else if (shasum != null) {
				if (checksum_converter.collect_hex_digest () != shasum.down ())
					checksum_error = new Error.PROTOCOL ("Detected shasum mismatch for %s", tarball_url);
			}
			if (checksum_error != null) {
				yield FS.rmtree_async (temp_dest_root);
				throw checksum_error;
			}

			yield FS.rmtree_async (dest_root, cancellable);
			try {
				yield temp_dest_root.move_async (dest_root, FileCopyFlags.NONE, io_priority, cancellable, null);
			} catch (GLib.Error e) {
				throw new Error.PERMISSION_DENIED ("%s", e.message);
			}
		}

		private static File compute_project_root (PackageInstallOptions options) {
			string? project_root = options.project_root;
			if (project_root != null)
				return File.new_for_path (project_root);

			return File.new_for_path (Environment.get_current_dir ());
		}

		public PackageInstallResult install_sync (PackageInstallOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			var task = create<InstallTask> ();
			task.options = options;
			return task.execute (cancellable);
		}

		private class InstallTask : PackageManagerTask<PackageInstallResult> {
			public PackageInstallOptions? options;

			protected override async PackageInstallResult perform_operation () throws Error, IOError {
				return yield parent.install (options, cancellable);
			}
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		private abstract class PackageManagerTask<T> : AsyncTask<T> {
			public weak PackageManager parent {
				get;
				construct;
			}
		}
	}

	public sealed class Package : Object {
		public string name {
			get;
			construct;
		}

		public string version {
			get;
			construct;
		}

		public string? description {
			get;
			construct;
		}

		internal Package (string name, string version, string? description) {
			Object (
				name: name,
				version: version,
				description: description
			);
		}
	}

	public sealed class PackageList : Object {
		private Gee.List<Package> items;

		internal PackageList (Gee.List<Package> items) {
			this.items = items;
		}

		public int size () {
			return items.size;
		}

		public new Package get (int index) {
			return items.get (index);
		}
	}

	public class PackageSearchOptions : Object {
		public uint offset {
			get;
			set;
			default = 0;
		}

		public uint limit {
			get;
			set;
			default = 20;
		}
	}

	public sealed class PackageSearchResult : Object {
		public PackageList packages {
			get;
			construct;
		}

		public uint total {
			get;
			construct;
		}

		internal PackageSearchResult (PackageList packages, uint total) {
			Object (packages: packages, total: total);
		}
	}

	public class PackageInstallOptions : Object {
		internal Gee.List<string> specs = new Gee.ArrayList<string> ();

		public string? project_root {
			get;
			set;
		}

		public void clear_specs () {
			specs.clear ();
		}

		public void add_spec (string spec) {
			specs.add (spec);
		}
	}

	public sealed class PackageInstallResult : Object {
		public PackageList packages {
			get;
			construct;
		}

		internal PackageInstallResult (PackageList packages) {
			Object (packages: packages);
		}
	}

	private class ChecksumConverter : Object, Converter {
		private ChecksumType algo;
		private Checksum? checksum;

		public ChecksumConverter (ChecksumType algo) {
			this.algo = algo;
			reset ();
		}

		public ConverterResult convert (uint8[] inbuf, uint8[] outbuf, ConverterFlags flags, out size_t bytes_read,
				out size_t bytes_written) throws GLib.Error {
			var n = size_t.min (inbuf.length, outbuf.length);
			bytes_read = n;
			bytes_written = n;

			if (n == 0)
				return FINISHED;

			Memory.copy (outbuf, inbuf, n);
			checksum.update (inbuf, n);

			return CONVERTED;
		}

		public void reset () {
			checksum = new Checksum (algo);
		}

		public uint8[] collect_raw_digest () {
			uint8 digest[64];
			size_t len = digest.length;
			checksum.get_digest (digest, ref len);

			reset ();

			return digest[:len];
		}

		public string collect_hex_digest () {
			string digest = checksum.get_string ();
			reset ();
			return digest;
		}
	}

	private void detect_indent (string src, out uint indent_level, out unichar indent_char) {
		indent_level = 2;
		indent_char  = ' ';

		Regex indents_before_first_key = /^([ \t]+)"/m;
		MatchInfo? m;
		if (indents_before_first_key.match (src, 0, out m)) {
			string seq = m.fetch (1);
			indent_level = seq.length;
			indent_char = seq.get_char (0);
		}
	}

	private async Json.Reader fetch (string url, Soup.Session session, Cancellable? cancellable) throws Error, IOError {
		Bytes bytes;
		var msg = new Soup.Message ("GET", url);
		try {
			bytes = yield session.send_and_read_async (msg, Priority.DEFAULT, cancellable);
		} catch (GLib.Error e) {
			throw new Error.TRANSPORT ("Unable to GET %s: %s", url, e.message);
		}
		if (msg.status_code != 200)
			throw new Error.PROTOCOL ("Unable to GET %s: HTTP %u", url, msg.status_code);

		printerr ("Fetched %s: %s\n", url, (string) bytes.get_data ());

		var parser = new Json.Parser ();
		try {
			parser.load_from_data ((string) bytes.get_data (), (ssize_t) bytes.get_size ());
		} catch (GLib.Error e) {
			throw new Error.PROTOCOL ("Unable to parse response from %s: %s", url, e.message);
		}

		return new Json.Reader (parser.get_root ());
	}

	private async Json.Reader load_json (File f, Cancellable? cancellable) throws Error, IOError {
		Bytes b = yield FS.read_all_bytes (f, cancellable);
		return parse_json (b);
	}

	private Json.Reader parse_json (Bytes b) throws Error {
		var p = new Json.Parser ();
		try {
			p.load_from_data ((string) b.get_data (), (ssize_t) b.get_size ());
		} catch (GLib.Error e) {
			throw new Error.PROTOCOL ("%s", e.message);
		}
		return new Json.Reader (p.get_root ());
	}

	private class SemverVersion {
		public uint major;
		public uint minor;
		public uint patch;
		public string? prerelease;
		public string? metadata;

		public SemverVersion (uint major, uint minor, uint patch, string? prerelease, string? metadata) {
			this.major = major;
			this.minor = minor;
			this.patch = patch;
			this.prerelease = prerelease;
			this.metadata = metadata;
		}
	}

	namespace Semver {
		private static SemverVersion parse_version (string version) throws Error {
			string v = version;
			string? meta = null;
			int plus = version.index_of_char ('+');
			if (plus != -1) {
				v = version[:plus];
				meta = version[plus + 1:];
			}

			string core;
			string? pre = null;
			int dash = v.index_of_char ('-');
			if (dash != -1) {
				core = v[:dash];
				pre  = v[dash + 1:];
			} else {
				core = v;
			}

			string[] nums = core.split (".");
			if (nums.length == 0 || nums.length > 3)
				throw new Error.PROTOCOL ("Invalid semver version: %s", v);

			uint major = 0;
			uint minor = 0;
			uint patch = 0;

			major = parse_uint (nums[0]);

			if (nums.length > 1)
				minor = parse_uint (nums[1]);

			if (nums.length > 2)
				patch = parse_uint (nums[2]);

			return new SemverVersion (major, minor, patch, pre, meta);
		}

		private static int compare_version (SemverVersion a, SemverVersion b) {
			if (a.major != b.major)
				return a.major > b.major ? 1 : -1;

			if (a.minor != b.minor)
				return a.minor > b.minor ? 1 : -1;

			if (a.patch != b.patch)
				return a.patch > b.patch ? 1 : -1;

			if (a.prerelease == null && b.prerelease == null)
				return 0;

			if (a.prerelease == null)
				return 1;

			if (b.prerelease == null)
				return -1;

			return strcmp (a.prerelease, b.prerelease);
		}

		private static bool is_precise_spec (string spec) throws Error {
			if (spec.strip () == "")
				throw new Error.PROTOCOL ("Invalid version spec: '%s'", spec);

			if (spec.index_of_char (' ') != -1  ||
					spec.index_of_char ('^') != -1 ||
					spec.index_of_char ('~') != -1 ||
					spec.index_of_char ('>') != -1 ||
					spec.index_of_char ('<') != -1 ||
					spec.index_of_char ('|') != -1 ||
					spec.index_of_char ('*') != -1 ||
					spec.down ().index_of_char ('x') != -1) {
				return false;
			}

			try {
				parse_version (spec);
				return true;
			} catch (Error e) {
			}

			if (!spec[0].isalpha ())
				return false;

			foreach (unichar c in spec) {
				if (!(c == '.' || c == '_' || c == '-' || c.isalnum ()))
					return false;
			}
			return true;
		}

		private static string? max_satisfying (Gee.Collection<string> versions, string range) throws Error {
			string? best_str = null;
			SemverVersion? best_ver = null;

			foreach (string v in versions) {
				SemverVersion cand = parse_version (v);

				if (!satisfies_range (cand, range))
					continue;

				if (best_ver == null || compare_version (cand, best_ver) > 0) {
					best_ver = cand;
					best_str = v;
				}
			}

			return best_str;
		}

		private static bool satisfies_range (SemverVersion cand, string range) throws Error {
			string r = range.strip ();
			if (r == "")
				throw new Error.PROTOCOL ("Invalid version range: '%s'", range);

			string[] ors = r.split ("||");

			foreach (string clause in ors) {
				string part = clause.strip ();

				if (part.index_of (" - ") != -1) {
					if (check_comparator (cand, part))
						return true;
					continue;
				}

				string[] comps = part.split (" ");
				bool ok = true;

				foreach (string comp in comps) {
					string c = comp.strip ();
					if (c == "")
						continue;

					if (!check_comparator (cand, c)) {
						ok = false;
						break;
					}
				}

				if (ok)
					return true;
			}

			return false;
		}

		private static bool check_comparator (SemverVersion cand, string comparator) throws Error {
			string comp = comparator.strip ();

			if (comp.index_of (" - ") != -1) {
				string[] parts = comp.split (" - ", 2);
				string lo = parts[0].strip ();
				string hi = parts[1].strip ();

				return satisfies_range (cand, ">=" + lo) && satisfies_range (cand, "<=" + hi);
			}

			if (comp == "*" || comp == "x" || comp == "X")
				return true;

			string op = "";
			string ver = comp;

			if (comp.has_prefix (">=") || comp.has_prefix ("<=")) {
				op = comp[:2];
				ver = comp[2:];
			} else if (comp.has_prefix (">") || comp.has_prefix ("<")) {
				op = comp[:1];
				ver = comp[1:];
			}

			if (op != "") {
				SemverVersion rv = parse_version (ver);
				int cmp = compare_version (cand, rv);

				switch (op) {
					case ">":
						return cmp > 0;
					case ">=":
						return cmp >= 0;
					case "<":
						return cmp < 0;
					case "<=":
						return cmp <= 0;
				}
			}

			if (comp.has_prefix ("~")) {
				SemverVersion lower = parse_version (comp[1:]);
				SemverVersion upper;

				if (lower.major == 0 && lower.minor == 0)
					upper = new SemverVersion (0, 0, lower.patch + 1, null);
				else if (lower.major == 0)
					upper = new SemverVersion (0, lower.minor + 1, 0, null);
				else
					upper = new SemverVersion (lower.major, lower.minor + 1, 0, null);

				return compare_version (cand, lower) >= 0 && compare_version (cand, upper) < 0;
			}

			if (comp.has_prefix ("^")) {
				SemverVersion lower = parse_version (comp[1:]);
				SemverVersion upper;

				if (lower.major != 0) {
					upper = new SemverVersion (lower.major + 1, 0, 0, null);
				} else if (lower.minor != 0) {
					upper = new SemverVersion (0, lower.minor + 1, 0, null);
				} else {
					upper = new SemverVersion (0, 0, lower.patch + 1, null);
				}

				return compare_version (cand, lower) >= 0 && compare_version (cand, upper) < 0;
			}

			if (comp.index_of_char ('*') != -1 ||
					comp.index_of_char ('x') != -1 ||
					comp.index_of_char ('X') != -1 ||
					count_char (comp, '.') < 2) {
				return wildcard_match (cand, comp);
			}

			SemverVersion ev = parse_version (comp);
			return compare_version (cand, ev) == 0;
		}

		private static bool wildcard_match (SemverVersion cand, string pat) throws Error {
			string norm = pat.replace ("*", "x").replace ("X", "x");
			string[] parts = norm.split (".");

			bool major_wild = false;
			bool minor_wild = false;
			bool patch_wild = false;

			uint major = 0;
			uint minor = 0;
			uint patch = 0;

			if (parts.length > 0) {
				if (parts[0] == "x" || parts[0] == "")
					major_wild = true;
				else
					major = parse_uint (parts[0]);
			}

			if (parts.length > 1) {
				if (parts[1] == "x" || parts[1] == "")
					minor_wild = true;
				else
					minor = parse_uint (parts[1]);
			} else {
				minor_wild = true;
			}

			if (parts.length > 2) {
				if (parts[2] == "x" || parts[2] == "")
					patch_wild = true;
				else
					patch = parse_uint (parts[2]);
			} else {
				patch_wild = true;
			}

			if (major_wild)
				return true;

			SemverVersion lower = new SemverVersion (major,
					minor_wild ? 0 : minor,
					patch_wild ? 0 : patch,
					null);

			SemverVersion upper;

			if (minor_wild)
				upper = new SemverVersion (major + 1, 0, 0, null);
			else if (patch_wild)
				upper = new SemverVersion (major, minor + 1, 0, null);
			else
				return compare_version (cand, lower) == 0;

			return compare_version (cand, lower) >= 0 && compare_version (cand, upper) < 0;
		}
	}

	private uint parse_uint (string s) throws Error {
		uint u;
		if (!uint.try_parse (s, out u))
			throw new Error.PROTOCOL ("Invalid uint: '%s'", s);
		return u;
	}

	private int count_char (string s, char ch) {
		int n = 0;
		foreach (unichar c in s) {
			if (c == ch)
				n++;
		}
		return n;
	}

	private class TarStreamReader : Object {
		private const size_t BLOCK_SIZE = 512;

		private File root;
		private BufferBuilder header_builder = new BufferBuilder ();
		private File? current_file = null;
		private OutputStream? out_stream = null;
		private uint64 remaining = 0;
		private size_t pad = 0;

		public TarStreamReader (File root) {
			this.root = root;
		}

		public async void feed (uint8[] data, size_t len, Cancellable? cancellable) throws Error, IOError {
			int io_priority = Priority.DEFAULT;

			size_t off = 0;
			while (off < len) {
				if (remaining != 0) {
					size_t chunk_size = size_t.min ((size_t) remaining, len - off);
					if (out_stream != null) {
						try {
							yield out_stream.write_all_async (data[off:off + chunk_size], io_priority,
								cancellable, null);
						} catch (GLib.Error e) {
							throw new Error.TRANSPORT ("%s", e.message);
						}
					}
					remaining -= chunk_size;
					off += chunk_size;

					if (remaining == 0) {
						if (out_stream != null) {
							try {
								yield out_stream.close_async (io_priority, cancellable);
							} catch (GLib.Error e) {
								throw new Error.TRANSPORT ("%s", e.message);
							}
							current_file = null;
							out_stream = null;
						}
					}

					continue;
				}

				if (pad != 0) {
					size_t skip = size_t.min (pad, len - off);
					pad -= skip;
					off += skip;
					continue;
				}

				size_t n_header_bytes_missing = BLOCK_SIZE - header_builder.offset;
				size_t chunk_size = size_t.min (n_header_bytes_missing, len - off);
				header_builder.append_data (data[off:off + chunk_size]);
				off += chunk_size;
				if (chunk_size != n_header_bytes_missing)
					return;

				var header = new Buffer (header_builder.build ());

				string name = header.read_fixed_string (0, 100);
				if (name.length == 0) {
					off = len;
					break;
				}
				string safe_entry = sanitize_entry (name, root);

				string size_field = header.read_fixed_string (124, 12);
				uint64 file_size = 0;
				if (!uint64.try_parse (size_field.strip (), out file_size, null, 8))
					throw new Error.PROTOCOL ("Invalid tarball size (file '%s' corrupt)", safe_entry);

				var typeflag = (char) header.read_uint8 (156);

				header_builder = new BufferBuilder ();

				if (typeflag == '0' || typeflag == '\0') {
					current_file = root.get_child (safe_entry);
					FS.mkdirp (current_file.get_parent (), cancellable);
					try {
						out_stream = yield current_file.replace_async (null, false, FileCreateFlags.NONE,
							io_priority, cancellable);
					} catch (GLib.Error e) {
						throw new Error.TRANSPORT ("%s", e.message);
					}
				} else {
					current_file = null;
					out_stream = null;
				}
				remaining = file_size;

				pad = (size_t) ((BLOCK_SIZE - (file_size % BLOCK_SIZE)) % BLOCK_SIZE);
			}
		}

		public void finish () throws Error {
			if (current_file != null && remaining != 0)
				throw new Error.PROTOCOL ("Truncated tarball (file '%s' incomplete)", current_file.get_path ());
		}

		private static string sanitize_entry (string name, File root) throws Error {
			int slash = name.index_of ("/");
			string entry = (slash == -1) ? name : name[slash + 1:];
			if (entry.length == 0)
				throw new Error.PROTOCOL ("Empty tar entry name: %s", name);

			entry = entry.replace ("/", Path.DIR_SEPARATOR_S);

			if (entry[0] == Path.DIR_SEPARATOR || (entry.length >= 2 && entry[1] == ':'))
				throw new Error.PROTOCOL ("Absolute path in tar: %s", name);

			foreach (string part in entry.split (Path.DIR_SEPARATOR_S)) {
				if (part == "..")
					throw new Error.PROTOCOL ("Path traversal in tar: %s", name);
			}

			string final_path = root.resolve_relative_path (entry).get_path ();
			if (!final_path.has_prefix (root.get_path () + Path.DIR_SEPARATOR_S))
				throw new Error.PROTOCOL ("Escapes extraction root: %s".printf (name));
			return entry;
		}
	}
}
