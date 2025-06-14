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
			session = (Soup.Session) Object.new (typeof (Soup.Session),
				"max-conns-per-host", 15);
			session.add_feature (cache);
		}

		public async PackageSearchResult search (string query, PackageSearchOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			var opts = (options != null) ? options : new PackageSearchOptions ();

			var text = string.join (" ", query, "keywords:frida-gum");
			Json.Reader reader = yield fetch ("/-/v1/search?text=%s&from=%u&size=%u"
				.printf (Uri.escape_string (text), opts.offset, opts.limit), cancellable);

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
			File pkg_json_file = project_root.get_child ("package.json");
			File lock_file = project_root.get_child ("package-lock.json");

			Manifest manifest = yield load_manifest (pkg_json_file, lock_file, cancellable);

			File toplevel_node_modules_root = project_root.get_child ("node_modules");
			FS.mkdirp (toplevel_node_modules_root, cancellable);

			var wanted_deps_list = new Gee.ArrayList<PackageDependency> ();
			foreach (var dep_entry in manifest.dependencies.all.values) {
				wanted_deps_list.add (dep_entry);
			}
			foreach (string spec_str in opts.specs) {
				string name, version_spec_val;
				int at = spec_str.last_index_of ("@");
				if (at != -1) {
					name = spec_str.substring (0, at);
					version_spec_val = spec_str.substring (at + 1);
				} else {
					name = spec_str;
					version_spec_val = "latest";
				}
				PackageDependency? existing_wanted = null;
				foreach (var wd in wanted_deps_list) {
					if (wd.name == name) {
						existing_wanted = wd;
						break;
					}
				}
				if (existing_wanted != null)
					wanted_deps_list.remove (existing_wanted);
				wanted_deps_list.add (new PackageDependency () {
					name = name,
					version = new PackageVersion (version_spec_val),
					role = RUNTIME,
				});
			}

			var all_physical_installs = new Gee.HashMap<string, Promise<PackageLockEntry>> ();
			var resolution_cache = new Gee.HashMap<string, Promise<ResolvedPackageData>> ();
			var packument_cache = new Gee.HashMap<string, Promise<Json.Node>> ();
			var top_level_placements = new Gee.HashMap<string, string> ();

			var initial_dep_link_promises = new Gee.ArrayList<Future<PackageLockEntry>> ();

			foreach (PackageDependency original_dep in wanted_deps_list) {
				var dep_link_promise = new Promise<PackageLockEntry> ();
				initial_dep_link_promises.add (dep_link_promise.future);

				perform_install.begin (
					original_dep.name,
					original_dep.version,
					original_dep,
					toplevel_node_modules_root,
					project_root,
					manifest,
					cancellable,
					dep_link_promise,
					all_physical_installs,
					resolution_cache,
					packument_cache,
					top_level_placements
				);
			}

			if (!initial_dep_link_promises.is_empty)
				yield Future.all_void (initial_dep_link_promises);

			var all_installation_futures = new Gee.ArrayList<Future<PackageLockEntry>> ();
			foreach (var promise in all_physical_installs.values) {
				all_installation_futures.add (promise.future);
			}
			if (!all_installation_futures.is_empty)
				yield Future.all_void (all_installation_futures);

			var finished_installs = new Gee.HashMap<string, PackageLockEntry> ();
			foreach (var entry in all_physical_installs.entries)
				finished_installs[entry.key] = entry.value.future.get_value ();

			var new_manifest_dependencies = new PackageDependencies ();
			foreach (var future_ple in initial_dep_link_promises) {
				PackageLockEntry ple = future_ple.get_value ();
				PackageDependency? original_wanted_dep = null;
				foreach (var wd in wanted_deps_list) {
					if (wd == ple.toplevel_dep) {
						original_wanted_dep = wd;
						break;
					}
				}
				if (original_wanted_dep != null) {
					new_manifest_dependencies.add (new PackageDependency () {
						name = ple.name,
						version = original_wanted_dep.derive_version (ple.version),
						role = original_wanted_dep.role,
					});
				}
			}
			manifest.dependencies = new_manifest_dependencies;

			yield write_back_manifests (manifest, finished_installs, pkg_json_file, lock_file, cancellable);

			var pkgs = new Gee.ArrayList<Package> ();
			foreach (var future_ple in initial_dep_link_promises) {
				PackageLockEntry e = future_ple.get_value ();
				bool already_added = false;
				foreach (var p_ in pkgs) {
					if (p_.name == e.name && p_.version == e.version) {
						already_added = true;
						break;
					}
				}
				if (!already_added)
					pkgs.add (new Package (e.name, e.version, e.description));
			}

			return new PackageInstallResult (new PackageList (pkgs));
		}

		private static string lockfile_key_for_dependency (string name, File node_modules_root, File project_root) {
			return project_root.get_relative_path (install_dir_for_dependency (name, node_modules_root));
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

		private async Manifest load_manifest (File pkg_json_file, File lock_file, Cancellable? cancellable) throws Error, IOError {
			var m = new Manifest ();

			if (pkg_json_file.query_exists (cancellable)) {
				Json.Reader r = yield load_json (pkg_json_file, cancellable);

				r.read_member ("name");
				m.name = r.get_string_value ();
				r.end_member ();

				r.read_member ("version");
				m.version = r.get_string_value ();
				r.end_member ();

				m.dependencies = read_dependencies (r);
			}

			if (lock_file.query_exists (cancellable)) {
				Json.Reader lock_r = yield load_json (lock_file, cancellable);

				lock_r.read_member ("packages");
				string[]? path_keys = lock_r.list_members ();
				if (path_keys == null)
					throw new Error.PROTOCOL ("Lockfile 'packages' member missing or not an object");

				foreach (unowned string path_key in path_keys) {
					lock_r.read_member (path_key);

					if (lock_r.get_null_value ()) {
						lock_r.end_member ();
						continue;
					}

					var pli = new PackageLockPackageInfo ();
					pli.path_key = path_key;

					lock_r.read_member ("name");
					pli.name = lock_r.get_string_value ();
					if (pli.name == null)
						throw new Error.PROTOCOL ("Lockfile 'name' for '%s' missing or invalid", path_key);
					lock_r.end_member ();

					lock_r.read_member ("version");
					pli.version = lock_r.get_string_value ();
					if (pli.version == null)
						throw new Error.PROTOCOL ("Lockfile 'version' for '%s' missing or invalid", path_key);
					lock_r.end_member ();

					lock_r.read_member ("resolved");
					pli.resolved = lock_r.get_string_value ();
					if (pli.resolved == null)
						throw new Error.PROTOCOL ("Lockfile 'resolved' for '%s' missing or invalid", path_key);
					lock_r.end_member ();

					lock_r.read_member ("integrity");
					pli.integrity = lock_r.get_string_value ();
					if (pli.integrity == null)
						throw new Error.PROTOCOL ("Lockfile 'integrity' for '%s' missing or invalid", path_key);
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

		private async void write_back_manifests (Manifest manifest, Gee.Map<string, PackageLockEntry> installed, File pkg_json_file,
				File lock_file, Cancellable? cancellable) throws Error, IOError {
			string? name = null;
			Json.Node? root = null;
			string? old_pkg_json = null;
			uint indent_level = 2;
			unichar indent_char = ' ';
			if (pkg_json_file.query_exists (cancellable)) {
				old_pkg_json = yield FS.read_all_text (pkg_json_file, cancellable);
				try {
					root = Json.from_string (old_pkg_json);
				} catch (GLib.Error e) {
					throw new Error.PROTOCOL ("%s is invalid: %s", pkg_json_file.get_parse_name (), e.message);
				}
				if (root.get_node_type () != OBJECT)
					throw new Error.PROTOCOL ("%s is invalid, root must be an object", pkg_json_file.get_parse_name ());
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
					var info = yield pkg_json_file.get_parent ().query_info_async (FileAttribute.STANDARD_DISPLAY_NAME,
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
				yield FS.write_all_text (pkg_json_file, new_pkg_json, cancellable);

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
			yield FS.write_all_text (lock_file, lock_json, cancellable);
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

		private async void perform_install (
				string name,
				PackageVersion version_spec,
				PackageDependency toplevel_dep,
				File parent_node_modules_dir,
				File project_root,
				Manifest manifest,
				Cancellable? cancellable,
				Promise<PackageLockEntry> dep_link_promise,
				Gee.Map<string, Promise<PackageLockEntry>> all_physical_installs,
				Gee.Map<string, Promise<ResolvedPackageData>> resolution_cache,
				Gee.Map<string, Promise<Json.Node>> packument_cache,
				Gee.Map<string, string> top_level_placements) {
			try {
				// 1. Resolve package metadata (name@spec -> name@effective_version, tarball, deps)
				string resolution_id = name + "@" + version_spec.spec;
				Promise<ResolvedPackageData>? rpd_promise = resolution_cache[resolution_id];
				if (rpd_promise == null) {
					rpd_promise = new Promise<ResolvedPackageData> ();
					resolution_cache[resolution_id] = rpd_promise;
					_fetch_and_resolve_package_data_async.begin (name, version_spec, rpd_promise, packument_cache, cancellable);
				}
				ResolvedPackageData rpd = yield rpd_promise.future.wait_async (cancellable);

				// 2. Determine target installation directory (hoisting logic)
				File target_dir;
				File toplevel_nm_root = project_root.get_child ("node_modules");
				File potential_toplevel_dir = install_dir_for_dependency (rpd.name, toplevel_nm_root);

				string? placed_toplevel_version = top_level_placements[rpd.name];
				if (placed_toplevel_version == null) {
					target_dir = potential_toplevel_dir;
					top_level_placements[rpd.name] = rpd.effective_version;
				} else if (placed_toplevel_version == rpd.effective_version) {
					target_dir = potential_toplevel_dir;
				} else {
					target_dir = install_dir_for_dependency (rpd.name, parent_node_modules_dir);
				}

				string actual_install_lockfile_key = target_dir.get_relative_path (project_root);
				if (actual_install_lockfile_key == null) {
					actual_install_lockfile_key = target_dir.get_path (); // Fallback
				}

				// 3. Check if this physical installation is already happening or done (by another concurrent request)
				Promise<PackageLockEntry>? physical_install_promise = all_physical_installs[actual_install_lockfile_key];

				if (physical_install_promise != null) {
					PackageLockEntry existing_ple = yield physical_install_promise.future.wait_async (cancellable);
					dep_link_promise.resolve (new PackageLockEntry () {
						name = existing_ple.name,
						version = existing_ple.version,
						resolved = existing_ple.resolved,
						integrity = existing_ple.integrity,
						description = existing_ple.description,
						license = existing_ple.license,
						dependencies = existing_ple.dependencies,
						toplevel_dep = toplevel_dep
					});
					return;
				}

				// 4. This is the first request to physically install rpd.name@rpd.effective_version at target_dir.
				//	The dep_link_promise will drive this physical installation.
				all_physical_installs[actual_install_lockfile_key] = dep_link_promise;

				// 5. Check if package is already correctly installed at target_dir
				bool already_correctly_installed = false;
				if (target_dir.query_exists (cancellable)) {
					File installed_pkg_json_file = target_dir.get_child ("package.json");
					if (installed_pkg_json_file.query_exists (cancellable)) {
						try {
							Json.Reader installed_pkg_reader = yield load_json (installed_pkg_json_file, cancellable);
							if (installed_pkg_reader.read_member ("version")) {
								string? installed_version = installed_pkg_reader.get_string_value ();
								installed_pkg_reader.end_member ();
								if (installed_version == rpd.effective_version) {
									already_correctly_installed = true;
									// printerr ("Skipping download for %s@%s at %s (already installed)\n", rpd.name, rpd.effective_version, target_dir.get_path());
								} else {
									// printerr ("Version mismatch for %s at %s: expected %s, found %s. Re-installing.\n", rpd.name, target_dir.get_path(), rpd.effective_version, installed_version);
								}
							}
						} catch (Error e) {
							// printerr ("Error reading package.json from %s: %s. Re-installing.\n", target_dir.get_path(), e.message);
						}
					} else {
						// printerr ("Directory %s exists but missing package.json. Re-installing.\n", target_dir.get_path());
					}
				}

				// 6. Recursively process dependencies of rpd.name@rpd.effective_version
				//	This must happen even if already_correctly_installed is true, to ensure sub-dependencies are hoisted/placed.
				var sub_dep_futures = new Gee.ArrayList<Future<PackageLockEntry>> ();
				File sub_deps_parent_node_modules_dir = target_dir.get_child ("node_modules");
				PackageDependencies dependencies_to_recurse = rpd.dependencies;

				if (!dependencies_to_recurse.all.is_empty) {
					FS.mkdirp (sub_deps_parent_node_modules_dir, cancellable);
				}

				foreach (PackageDependency d in dependencies_to_recurse.all.values) {
					bool install_this_sub_dep = false;
					if (d.role == RUNTIME) {
						install_this_sub_dep = true;
					} else if (d.role == DEVELOPMENT) {
						// Install devDependencies only if the current package (rpd.name) is a direct project dependency
						bool is_rpd_direct_project_dep = false;
						if (toplevel_dep.name == rpd.name && parent_node_modules_dir.get_path() == project_root.get_child("node_modules").get_path()) {
							is_rpd_direct_project_dep = true;
						}
						if (is_rpd_direct_project_dep) {
							install_this_sub_dep = true;
						}
					}
					// TODO: Handle OPTIONAL role based on some policy

					if (!install_this_sub_dep) {
						continue;
					}

					var sub_dep_link_promise = new Promise<PackageLockEntry> ();
					sub_dep_futures.add (sub_dep_link_promise.future);
					perform_install.begin (
						d.name,
						d.version,
						toplevel_dep, 
						sub_deps_parent_node_modules_dir,
						project_root,
						manifest,
						cancellable,
						sub_dep_link_promise,
						all_physical_installs,
						resolution_cache,
						packument_cache,
						top_level_placements
					);
				}
				if (!sub_dep_futures.is_empty) {
					yield Future.all_void (sub_dep_futures);
				}

				// 7. Download and unpack the current package if not already correctly installed
				if (!already_correctly_installed) {
					// download_and_unpack already handles cleaning dest_root if it exists
					yield download_and_unpack (rpd.name, rpd.resolved_url, target_dir, rpd.integrity, rpd.shasum, cancellable);
				}

				// 8. Resolve the promise for this dependency link
				dep_link_promise.resolve (new PackageLockEntry () {
					name = rpd.name,
					version = rpd.effective_version,
					resolved = rpd.resolved_url,
					integrity = rpd.integrity,
					description = rpd.description,
					license = rpd.license,
					dependencies = rpd.dependencies, // Dependencies declared by *this* package
					toplevel_dep = toplevel_dep
				});

			} catch (GLib.Error e) {
				dep_link_promise.reject (e);
			}
		}

		private class ResolvedPackageData {
			public string name;
			public string effective_version;
			public string resolved_url;
			public string? integrity;
			public string? shasum;
			public string? description;
			public string? license;
			public PackageDependencies dependencies;
		}

		private async void _fetch_and_resolve_package_data_async (string name, PackageVersion version_spec,
				Promise<ResolvedPackageData> promise_to_fulfill, Gee.Map<string, Promise<Json.Node>> packument_cache,
				Cancellable? cancellable) {
			try {
				string effective_version_local;
				Json.Reader meta_reader;
				bool used_packument_reader_for_meta = false;

				if (Semver.is_precise_spec (version_spec.spec)) {
					meta_reader = yield fetch (
						"/%s/%s".printf (Uri.escape_string (name), Uri.escape_string (version_spec.spec)),
						cancellable);

					meta_reader.read_member ("version");
					var ver_val = meta_reader.get_string_value ();
					if (ver_val == null) {
						throw new Error.PROTOCOL ("Registry 'version' for '%s@%s' missing or invalid",
							name, version_spec.spec);
					}
					effective_version_local = ver_val;
					meta_reader.end_member ();
				} else {
					Promise<Json.Node>? packument_promise = packument_cache[name];
					if (packument_promise == null) {
						packument_promise = _fetch_packument_for_cache (this, name, cancellable);
						packument_cache[name] = packument_promise;
					}
					Json.Node packument_root_node = yield packument_promise.future.wait_async (cancellable);
					var packument_reader = new Json.Reader (packument_root_node);

					string? version_from_dist_tag = null;
					packument_reader.read_member ("dist-tags");
					packument_reader.read_member (version_spec.spec);
					version_from_dist_tag = packument_reader.get_string_value ();
					packument_reader.end_member ();
					packument_reader.end_member ();

					if (version_from_dist_tag != null) {
						effective_version_local = version_from_dist_tag;
					} else {
						packument_reader.read_member ("versions");
						string[]? available_version_strings = packument_reader.list_members ();
						if (available_version_strings == null) {
							throw new Error.PROTOCOL (
								"Packument 'versions' missing, not an object, or empty for '%s'", name);
						}
						packument_reader.end_member ();

						string? target_version_str = Semver.max_satisfying (
							new Gee.ArrayList<string>.wrap (available_version_strings),
							version_spec.spec);
						if (target_version_str == null)
							throw new Error.PROTOCOL ("No version satisfying '%s' for '%s'", version_spec.spec, name);
						effective_version_local = target_version_str;
					}

					if (!Semver.is_precise_spec(version_spec.spec) || version_from_dist_tag != null) {
						packument_reader.read_member("versions");
						packument_reader.read_member(effective_version_local);
						meta_reader = packument_reader;
						used_packument_reader_for_meta = true;
					} else {
						meta_reader = yield fetch (
							"/%s/%s".printf (Uri.escape_string (name), Uri.escape_string (effective_version_local)),
							cancellable);
					}

					meta_reader.read_member ("version");
					string? actual_fetched_version = meta_reader.get_string_value ();
					meta_reader.end_member ();
					if (actual_fetched_version != effective_version_local) {
						throw new Error.PROTOCOL (
							"Fetched version '%s' differs from expected '%s'",
							actual_fetched_version,
							effective_version_local);
					}
				}

				meta_reader.read_member ("description");
				string? description_local = meta_reader.get_string_value ();
				meta_reader.end_member ();

				string? license_local = null;
				meta_reader.read_member ("license");
				if (meta_reader.is_object ()) {
					meta_reader.read_member ("type");
					license_local = meta_reader.get_string_value ();
					meta_reader.end_member ();
				} else {
					license_local = meta_reader.get_string_value ();
				}
				meta_reader.end_member ();

				meta_reader.read_member ("dist");

				meta_reader.read_member ("tarball");
				string? resolved_url_local = meta_reader.get_string_value ();
				if (resolved_url_local == null)
					throw new Error.PROTOCOL ("'dist.tarball' for '%s@%s' missing or invalid", name, effective_version_local);
				meta_reader.end_member ();

				meta_reader.read_member ("integrity");
				string? integrity_local = meta_reader.get_string_value ();
				meta_reader.end_member ();

				meta_reader.read_member ("shasum");
				string? shasum_local = meta_reader.get_string_value ();
				meta_reader.end_member ();

				meta_reader.end_member ();

				PackageDependencies deps_from_pkg_json = read_dependencies (meta_reader);

				if (used_packument_reader_for_meta)
					meta_reader.end_member ();

				promise_to_fulfill.resolve (new ResolvedPackageData () {
					name = name,
					effective_version = effective_version_local,
					resolved_url = resolved_url_local,
					integrity = integrity_local,
					shasum = shasum_local,
					description = description_local,
					license = license_local,
					dependencies = deps_from_pkg_json
				});
			} catch (GLib.Error e) {
				promise_to_fulfill.reject (e);
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

		private async Json.Reader fetch (string resource, Cancellable? cancellable) throws Error, IOError {
			string url = "https://%s%s".printf (registry, resource);
			printerr ("Fetching %s\n", url);

			Bytes bytes;
			var msg = new Soup.Message ("GET", url);
			msg.request_headers.append ("Accept", "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*");
			try {
				bytes = yield session.send_and_read_async (msg, Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("Unable to GET %s: %s", url, e.message);
			}
			if (msg.status_code != 200)
				throw new Error.PROTOCOL ("Unable to GET %s: HTTP %u", url, msg.status_code);

			// printerr ("Fetched %s: %s\n", url, (string) bytes.get_data ());

			var parser = new Json.Parser ();
			try {
				parser.load_from_data ((string) bytes.get_data (), (ssize_t) bytes.get_size ());
			} catch (GLib.Error e) {
				throw new Error.PROTOCOL ("Unable to parse response from %s: %s", url, e.message);
			}

			return new Json.Reader (parser.get_root ());
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
			string stripped_spec = spec.strip ();
			if (stripped_spec == "")
				throw new Error.PROTOCOL ("Invalid version spec: '%s'", spec);

			if (stripped_spec == "latest")
				return true;

			if (stripped_spec.index_of_char (' ') != -1 ||
					stripped_spec.index_of_char ('^') != -1 ||
					stripped_spec.index_of_char ('~') != -1 ||
					stripped_spec.index_of_char ('>') != -1 ||
					stripped_spec.index_of_char ('<') != -1 ||
					stripped_spec.index_of_char ('*') != -1 ||
					stripped_spec.down ().index_of_char ('x') != -1) {
				return false;
			}

			try {
				parse_version (stripped_spec);

				string core_part_of_spec = stripped_spec;
				int plus_idx = core_part_of_spec.index_of_char ('+');
				if (plus_idx != -1)
					core_part_of_spec = core_part_of_spec.substring (0, plus_idx);
				int dash_idx = core_part_of_spec.index_of_char ('-');
				if (dash_idx != -1)
					core_part_of_spec = core_part_of_spec.substring (0, dash_idx);

				return count_char (core_part_of_spec, '.') == 2;
			} catch (Error e) {
				return false;
			}
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
