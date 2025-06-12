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

			File toplevel_node_modules_root = project_root.get_child ("node_modules");
			FS.mkdirp (toplevel_node_modules_root, cancellable);

			var wanted = new Gee.HashMap<string, PackageDependency> ();
			foreach (var e in manifest.dependencies.all.entries) {
				string lockfile_key = lockfile_key_for_dependency (e.key, toplevel_node_modules_root, project_root);
				wanted[lockfile_key] = e.value;
			}
			wanted.set_all (manifest.dependencies.all);
			foreach (string spec in opts.specs) {
				string name, version_spec;
				int at = spec.last_index_of ("@");
				if (at != -1) {
					name = spec[:at];
					version_spec = spec[at + 1:];
				} else {
					name = spec;
					version_spec = "latest";
				}

				string lockfile_key = lockfile_key_for_dependency (name, toplevel_node_modules_root, project_root);

				wanted[lockfile_key] = new PackageDependency () {
					name = name,
					version = new PackageVersion (version_spec),
					role = RUNTIME,
				};
			}

			var all_installs = new Gee.HashMap<string, Promise<PackageLockEntry>> ();
			foreach (string lockfile_key in wanted.keys)
				all_installs[lockfile_key] = new Promise<PackageLockEntry> ();

			var toplevel_installs = new Gee.HashMap<string, Promise<PackageLockEntry>> ();
			toplevel_installs.set_all (all_installs);

			foreach (var e in toplevel_installs.entries) {
				PackageDependency original_dep = wanted[e.key];
				perform_install.begin (
					original_dep.name,
					original_dep.version,
					original_dep,
					toplevel_node_modules_root,
					project_root,
					manifest,
					cancellable,
					e.value,
					all_installs
				);
			}

			var finished_installs = new Gee.HashMap<string, PackageLockEntry> ();
			while (finished_installs.size != all_installs.size) {
				PackageLockEntry? entry = null;
				foreach (var e in all_installs.entries) {
					unowned string key = e.key;
					if (finished_installs.has_key (key))
						continue;
					entry = yield e.value.future.wait_async (cancellable);
					finished_installs[key] = entry;
					break;
				}

				if (entry.name == entry.toplevel_dep.name) {
					manifest.dependencies.add (new PackageDependency () {
						name = entry.name,
						version = entry.toplevel_dep.derive_version (entry.version),
						role = entry.toplevel_dep.role,
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

		private static string lockfile_key_for_dependency (string name, File node_modules_root, File project_root) {
			return install_dir_for_dependency (name, node_modules_root).get_relative_path (project_root);
		}

		private static File install_dir_for_dependency (string name, File node_modules_root) {
			File location = node_modules_root;
			foreach (unowned string part in name.split ("/"))
				location = location.get_child (part);
			return location;
		}

		private class Manifest {
			public string? name;
			public string? version;
			public PackageDependencies dependencies = new PackageDependencies ();
			public Gee.Map<string, PackageLockPackageInfo> locked_packages = new Gee.HashMap<string, PackageLockPackageInfo> ();
		}

		private class PackageLockPackageInfo {
			public string path_key;
			public string? name;
			public string? version;
			public string? resolved;
			public string? integrity;
			public PackageDependencies dependencies = new PackageDependencies ();
			public bool is_dev = false;
			public bool is_optional = false;
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
			DEVELOPMENT,
			OPTIONAL
		}

		private async Manifest load_manifest (File pkg_json_f, File lock_f, Cancellable? cancellable) throws Error, IOError {
			var m = new Manifest ();

			if (pkg_json_f.query_exists (cancellable)) {
				Json.Reader r = yield load_json (pkg_json_f, cancellable);

				r.read_member ("name");
				m.name = r.get_string_value ();
				r.end_member ();

				r.read_member ("version");
				m.version = r.get_string_value ();
				r.end_member ();

				m.dependencies = read_dependencies (r);
			}

			if (lock_f.query_exists (cancellable)) {
				Json.Reader lock_r = yield load_json (lock_f, cancellable);

				lock_r.read_member ("packages");
				string[]? pkg_paths = lock_r.list_members ();
				if (pkg_paths == null)
					throw new Error.PROTOCOL ("package-lock.json 'packages' member is missing or not an object");

				foreach (unowned string path_key in pkg_paths) {
					lock_r.read_member (path_key);
					if (lock_r.get_null_value ()) {
						lock_r.end_member ();
						continue;
					}

					var pli = new PackageLockPackageInfo ();
					pli.path_key = path_key;

					lock_r.read_member ("name");
					pli.name = lock_r.get_string_value ();
					lock_r.end_member ();

					lock_r.read_member ("version");
					pli.version = lock_r.get_string_value ();
					lock_r.end_member ();

					lock_r.read_member ("resolved");
					pli.resolved = lock_r.get_string_value ();
					lock_r.end_member ();

					lock_r.read_member ("integrity");
					pli.integrity = lock_r.get_string_value ();
					lock_r.end_member ();

					pli.dependencies = read_dependencies_from_lock_entry (lock_r, path_key);

					lock_r.read_member ("dev");
					pli.is_dev = lock_r.get_boolean_value ();
					lock_r.end_member ();

					lock_r.read_member ("optional");
					pli.is_optional = lock_r.get_boolean_value ();
					lock_r.end_member ();

					m.locked_packages[path_key] = pli;

					lock_r.end_member ();
				}

				lock_r.end_member ();
			}

			return m;
		}

		private static PackageDependencies read_dependencies (Json.Reader r) throws Error {
			var deps = new PackageDependencies ();

			string[] section_keys = {"dependencies", "devDependencies"};
			for (uint i = 0; i != section_keys.length; i++) {
				unowned string section_key = section_keys[i];

				if (!r.read_member (section_key)) {
					r.end_member ();
					continue;
				}

				string[]? names = r.list_members ();
				if (names == null)
					throw new Error.PROTOCOL ("Invalid package.json section for '%s'", section_key);

				PackageRole role = (i == 0) ? PackageRole.RUNTIME : PackageRole.DEVELOPMENT;
				foreach (unowned string name in names) {
					r.read_member (name);

					string? version = r.get_string_value ();
					if (version == null) {
						throw new Error.PROTOCOL ("Bad type of %s entry for %s, expected string value",
							section_key, name);
					}

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

		private static PackageDependencies read_dependencies_from_lock_entry (Json.Reader r, string parent_path_key) throws Error {
			var deps = new PackageDependencies ();

			string[] section_keys = { "dependencies", "optionalDependencies" };
			for (uint i = 0; i != section_keys.length; i++) {
				unowned string section_key = section_keys[i];

				if (!r.read_member (section_key)) {
					r.end_member ();
					continue;
				}

				string[]? dep_names = r.list_members ();
				if (dep_names == null) {
					throw new Error.PROTOCOL ("Lockfile section for '%s' is invalid for package '%s'",
						section_key, parent_path_key);
				}

				PackageRole role = (i == 1) ? PackageRole.OPTIONAL : PackageRole.RUNTIME;

				foreach (unowned string dep_name in dep_names) {
					r.read_member (dep_name);

					string? version_spec = r.get_string_value ();
					if (version_spec == null) {
						throw new Error.PROTOCOL ("Lockfile dependency '%s' in section '%s' for package '%s' " +
							"must have a string value", dep_name, section_key, parent_path_key);
					}

					deps.add (new PackageDependency () {
						name = dep_name,
						version = new PackageVersion (version_spec),
						role = role
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
				} catch (GLib.Error e) {
					throw new Error.PERMISSION_DENIED ("%s", e.message);
				}
			}

			Json.Object obj = root.get_object ();
			var deps_obj = new Json.Object ();
			obj.set_object_member ("dependencies", deps_obj);
			foreach (PackageLockEntry e in installed.values) {
				PackageDependency toplevel_dep = e.toplevel_dep;
				if (e.name == toplevel_dep.name)
					deps_obj.set_string_member (e.name, toplevel_dep.derive_version (e.version).spec);
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

			b.set_member_name ("")
				.begin_object ();
			if (manifest.name != null)
				b.set_member_name ("name").add_string_value (manifest.name);
			if (manifest.version != null)
				b.set_member_name ("version").add_string_value (manifest.version);
			b.set_member_name ("dependencies").begin_object ();
			foreach (var entry in installed.entries) {
				PackageLockEntry resolved_entry = entry.value;
				if (resolved_entry.name == resolved_entry.toplevel_dep.name) {
					b
						.set_member_name (resolved_entry.name)
						.add_string_value (resolved_entry.version);
				}
			}
			b
				.end_object ()
				.end_object ();

			foreach (var entry in installed.entries) {
				string lockfile_key = entry.key;
				PackageLockEntry e = entry.value;

				b.set_member_name (lockfile_key)
					.begin_object ()
					.set_member_name ("name")
					.add_string_value (e.name)
					.set_member_name ("version")
					.add_string_value (e.version)
					.set_member_name ("resolved")
					.add_string_value (e.resolved)
					.set_member_name ("integrity")
					.add_string_value (e.integrity);

				if (e.license != null)
					b.set_member_name ("license").add_string_value (e.license);

				if (e.toplevel_dep.role == DEVELOPMENT && e.name == e.toplevel_dep.name) {
					b
						.set_member_name ("dev")
						.add_boolean_value (true);
				}

				if (!e.dependencies.runtime.is_empty) {
					b.set_member_name ("dependencies").begin_object ();
					foreach (PackageDependency dep_info in e.dependencies.runtime.values) {
						b
							.set_member_name (dep_info.name)
							.add_string_value (dep_info.version.spec);
					}
					b.end_object ();
				}

				if (!e.dependencies.all.is_empty) {
					bool has_optional = false;
					foreach (PackageDependency dep_info in e.dependencies.all.values) {
						if (dep_info.role == OPTIONAL) {
							has_optional = true;
							break;
						}
					}
					if (has_optional) {
						b.set_member_name ("optionalDependencies").begin_object ();
						foreach (PackageDependency dep_info in e.dependencies.all.values) {
							if (dep_info.role == OPTIONAL) {
								b
									.set_member_name (dep_info.name)
									.add_string_value (dep_info.version.spec);
							}
						}
						b.end_object ();
					}
				}

				b.end_object ();
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

		private async void perform_install (string name, PackageVersion version_spec, PackageDependency toplevel_dep,
				File install_root, File project_root, Manifest manifest, Cancellable? cancellable,
				Promise<PackageLockEntry> request, Gee.Map<string, Promise<PackageLockEntry>> all_installs) {
			try {
				File dest_dir = install_dir_for_dependency (name, install_root);
				string lockfile_key = dest_dir.get_relative_path (project_root);
				PackageLockPackageInfo? locked_info = manifest.locked_packages[lockfile_key];

				string effective_version;
				string? description = null;
				string? license = null;
				string resolved_url;
				string? integrity_from_lock_or_registry = null;
				string? shasum_from_registry = null;
				PackageDependencies deps_to_install;

				bool use_lockfile_entry = false;
				if (locked_info != null) {
					// If version_spec is "latest", we might want to ignore lockfile or verify.
					// For now, if "latest" is specified, we bypass strict lockfile version matching.
					// Otherwise, the locked version must satisfy the requested spec.
					if (version_spec.spec != "latest" &&
						Semver.satisfies_range (Semver.parse_version (locked_info.version), version_spec.spec)) {
						use_lockfile_entry = true;
					} else if (version_spec.spec == "latest" && locked_info.version != null) {
						// If @latest is requested, but we have a lockfile entry,
						// a more advanced system might check if locked_info.version IS the latest.
						// For now, requesting @latest will mean fetching from registry to ensure latest.
						// If the spec was *derived* from a package.json that had "latest",
						// then we should prefer the lockfile if it exists. This distinction is subtle.
						// Let's assume if version_spec.spec is literally "latest", it's an explicit user request to get latest.
					}
				}

				if (use_lockfile_entry && locked_info != null) {
					effective_version = locked_info.version;
					resolved_url = locked_info.resolved;
					integrity_from_lock_or_registry = locked_info.integrity;
					deps_to_install = locked_info.dependencies;
					if (resolved_url == null) {
						throw new Error.PROTOCOL ("Lockfile entry for '%s' is missing 'resolved' URL.",
							lockfile_key);
					}
				} else {
					Json.Reader r = yield fetch ("https://%s/%s/%s"
						.printf (registry, Uri.escape_string (name), Uri.escape_string (version_spec.spec)),
						session, cancellable);

					r.read_member ("version");
					effective_version = r.get_string_value ();
					r.end_member ();
					if (effective_version == null) throw new Error.PROTOCOL("Registry response for '%s' missing 'version'", name);

					r.read_member ("description");
					description = r.get_string_value ();
					r.end_member ();

					r.read_member ("license");
					license = r.get_string_value ();
					r.end_member ();

					r.read_member ("dist");
					r.read_member ("tarball");
					resolved_url = r.get_string_value ();
					r.end_member ();
					r.read_member ("integrity");
					integrity_from_lock_or_registry = r.get_string_value ();
					r.end_member ();
					r.read_member ("shasum");
					shasum_from_registry = r.get_string_value ();
					r.end_member ();
					r.end_member ();

					deps_to_install = read_dependencies (r);

					if (resolved_url == null) {
						throw new Error.PROTOCOL ("No tarball URL for %s", name);
					}
				}

				foreach (PackageDependency d in deps_to_install.runtime.values) {
					File sub_install_root = dest_dir.get_child ("node_modules");
					string sub_lockfile_key = lockfile_key_for_dependency (d.name, sub_install_root, project_root);
					if (all_installs.has_key (sub_lockfile_key))
						continue;
					var sub_req = new Promise<PackageLockEntry> ();
					all_installs[sub_lockfile_key] = sub_req;
					perform_install.begin (
						d.name,
						d.version,
						toplevel_dep,
						sub_install_root,
						project_root,
						manifest,
						cancellable,
						sub_req,
						all_installs
					);
				}

				yield download_and_unpack (name, resolved_url, dest_dir, integrity_from_lock_or_registry,
					shasum_from_registry, cancellable);

				request.resolve (new PackageLockEntry () {
					name = name,
					version = effective_version,
					resolved = resolved_url,
					integrity = integrity_from_lock_or_registry,
					description = description,
					license = license,
					dependencies = deps_to_install,
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

		public SemverVersion (uint major, uint minor = 0, uint patch = 0, string? prerelease = null, string? metadata = null) {
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
			if (nums.length == 0 || nums.length > 3) {
				throw new Error.PROTOCOL ("Invalid semver version '%s': core part must have 1 to 3 segments, found %d",
					version, nums.length);
			}

			uint major = 0;
			uint minor = 0;
			uint patch = 0;

			try {
				major = parse_uint (nums[0]);
			} catch (Error e) {
				throw new Error.PROTOCOL ("Invalid major version in '%s': %s", version, e.message);
			}

			if (nums.length > 1) {
				try {
					minor = parse_uint (nums[1]);
				} catch (Error e) {
					throw new Error.PROTOCOL ("Invalid minor version in '%s': %s", version, e.message);
				}
			}

			if (nums.length > 2) {
				try {
					patch = parse_uint (nums[2]);
				} catch (Error e) {
					throw new Error.PROTOCOL ("Invalid patch version in '%s': %s", version, e.message);
				}
			}

			if (pre != null) {
				if (pre.length == 0) {
					throw new Error.PROTOCOL ("Pre-release part of '%s' cannot be empty if specified by a hyphen",
						version);
				}

				string[] pre_ids = pre.split (".");
				foreach (string id in pre_ids) {
					if (id.length == 0) {
						throw new Error.PROTOCOL ("Pre-release identifier in '%s' cannot be empty (found in '%s')",
							version, pre);
					}

					bool is_potentially_numeric = true;
					foreach (unichar c in id) {
						if (!c.isalnum () && c != '-') {
							throw new Error.PROTOCOL (
								"Pre-release identifier '%s' in '%s' contains invalid character '%s'",
								id, version, c.to_string ());
						}
						if (!c.isdigit ())
							is_potentially_numeric = false;
					}

					if (is_potentially_numeric) {
						try {
							parse_uint (id);
						} catch (Error e) {
							throw new Error.PROTOCOL ("Invalid numeric pre-release identifier '%s' in '%s': %s",
								id, version, e.message);
						}
					}
				}
			}

			if (meta != null) {
				if (meta.length == 0) {
					throw new Error.PROTOCOL ("Build metadata part of '%s' cannot be empty if specified by a plus",
						version);
				}

				string[] meta_ids = meta.split (".");
				foreach (string id in meta_ids) {
					if (id.length == 0) {
						throw new Error.PROTOCOL (
							"Build metadata identifier in '%s' cannot be empty (found in '%s')", version, meta);
					}
					foreach (unichar c_char in id) {
						if (!c_char.isalnum () && c_char != '-') {
							throw new Error.PROTOCOL (
								"Build metadata identifier '%s' in '%s' contains invalid character '%s'",
								id, version, c_char.to_string ());
						}
					}
				}
			}

			return new SemverVersion (major, minor, patch, pre, meta);
		}

		private static int compare_version (SemverVersion a, SemverVersion b) {
			if (a.major != b.major)
				return a.major > b.major ? 1 : -1;

			if (a.minor != b.minor)
				return a.minor > b.minor ? 1 : -1;

			if (a.patch != b.patch)
				return a.patch > b.patch ? 1 : -1;

			bool a_has_prerelease = a.prerelease != null;
			bool b_has_prerelease = b.prerelease != null;

			if (!a_has_prerelease && !b_has_prerelease)
				return 0;
			if (!a_has_prerelease)
				return 1;
			if (!b_has_prerelease)
				return -1;

			string[] a_ids = a.prerelease.split (".");
			string[] b_ids = b.prerelease.split (".");

			uint min_len = uint.min (a_ids.length, b_ids.length);
			for (uint i = 0; i != min_len; i++) {
				string id_a = a_ids[i];
				string id_b = b_ids[i];

				bool a_is_num = is_numeric_identifier (id_a);
				bool b_is_num = is_numeric_identifier (id_b);

				if (a_is_num && b_is_num) {
					var val_a = uint.parse (id_a);
					var val_b = uint.parse (id_b);
					if (val_a != val_b)
						return val_a > val_b ? 1 : -1;
				} else if (a_is_num) {
					return -1;
				} else if (b_is_num) {
					return 1;
				} else {
					int cmp = strcmp (id_a, id_b);
					if (cmp != 0)
						return cmp;
				}
			}

			if (a_ids.length != b_ids.length)
				return a_ids.length > b_ids.length ? 1 : -1;

			return 0;
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
					upper = new SemverVersion (0, 0, lower.patch + 1);
				else if (lower.major == 0)
					upper = new SemverVersion (0, lower.minor + 1);
				else
					upper = new SemverVersion (lower.major, lower.minor + 1);

				return compare_version (cand, lower) >= 0 && compare_version (cand, upper) < 0;
			}

			if (comp.has_prefix ("^")) {
				SemverVersion lower = parse_version (comp[1:]);
				SemverVersion upper;

				if (lower.major != 0) {
					upper = new SemverVersion (lower.major + 1);
				} else if (lower.minor != 0) {
					upper = new SemverVersion (0, lower.minor + 1);
				} else {
					upper = new SemverVersion (0, 0, lower.patch + 1);
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
					patch_wild ? 0 : patch);

			SemverVersion upper;

			if (minor_wild)
				upper = new SemverVersion (major + 1);
			else if (patch_wild)
				upper = new SemverVersion (major, minor + 1);
			else
				return compare_version (cand, lower) == 0;

			return compare_version (cand, lower) >= 0 && compare_version (cand, upper) < 0;
		}

		private uint parse_uint (string s) throws Error {
			if (s.length == 0)
				throw new Error.PROTOCOL ("Numeric component cannot be empty");

			if (s.length > 1 && s[0] == '0')
				throw new Error.PROTOCOL ("Numeric component '%s' has leading zeros", s);

			uint result_val;
			string unparsed_str;
			if (uint.try_parse (s, out result_val, out unparsed_str)) {
				if (unparsed_str.length == 0)
					return result_val;
				throw new Error.PROTOCOL ("Numeric component '%s' contains trailing non-digit characters: \"%s\"",
					s, unparsed_str);
			} else {
				if (unparsed_str.length == 0) {
					throw new Error.PROTOCOL ("Numeric component '%s' is too large or invalid", s);
				} else {
					throw new Error.PROTOCOL ("Invalid characters in numeric component '%s': problem starts at \"%s\"",
						s, unparsed_str);
				}
			}
		}

		private static bool is_numeric_identifier (string s) {
			if (s.length == 0)
				return false;
			foreach (unichar c in s) {
				if (!c.isdigit ())
					return false;
			}
			return true;
		}

		private int count_char (string s, char ch) {
			int n = 0;
			foreach (unichar c in s) {
				if (c == ch)
					n++;
			}
			return n;
		}
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
