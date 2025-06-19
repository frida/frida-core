namespace Frida {
	public sealed class PackageManager : Object {
		public signal void install_progress (PackageInstallPhase phase, double fraction, string? details = null);

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

				reader.read_member ("links");
				reader.read_member ("npm");
				string? url = reader.get_string_value ();
				reader.end_member ();
				reader.end_member ();

				reader.end_member ();

				if (name == null || version == null || url == null)
					throw new Error.PROTOCOL ("Unexpected JSON format: missing package details");
				packages.add (new Package (name, version, description, url));

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
			install_progress (INITIALIZING, 0.0);

			var opts = (options != null) ? options : new PackageInstallOptions ();

			File project_root = compute_project_root (opts);
			File pkg_json_file = project_root.get_child ("package.json");
			File lock_file = project_root.get_child ("package-lock.json");

			Manifest manifest = yield load_manifest (pkg_json_file, lock_file, cancellable);

			File toplevel_node_modules_root = project_root.get_child ("node_modules");
			FS.mkdirp (toplevel_node_modules_root, cancellable);

			var specs = new Gee.HashMap<string, string> ();
			foreach (string spec_str in opts.specs) {
				string name, version_spec_val;
				int at = spec_str.last_index_of ("@");
				if (at != -1) {
					name = spec_str[:at];
					version_spec_val = spec_str[at + 1:];
				} else {
					name = spec_str;
					version_spec_val = "latest";
				}
				specs[name] = version_spec_val;
			}

			install_progress (PREPARING_DEPENDENCIES, 0.05);
			var wanted_deps_list = new Gee.ArrayList<PackageDependency> ();
			foreach (var dep_entry in manifest.dependencies.all.values)
				wanted_deps_list.add (dep_entry);
			foreach (var e in specs.entries) {
				string name = e.key;
				string version_spec_val = e.value;

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

			var initial_dep_link_futures = new Gee.ArrayList<Future<PackageLockEntry>> ();

			foreach (PackageDependency original_dep in wanted_deps_list) {
				var dep_link_promise = new Promise<PackageLockEntry> ();
				initial_dep_link_futures.add (dep_link_promise.future);

				bool prefer_lockfile_for_this_dep = !specs.has_key (original_dep.name);

				perform_install.begin (
					original_dep.name,
					original_dep.version,
					original_dep,
					toplevel_node_modules_root,
					project_root,
					manifest,
					prefer_lockfile_for_this_dep,
					cancellable,
					dep_link_promise,
					all_physical_installs,
					resolution_cache,
					packument_cache,
					top_level_placements
				);
			}

			double dep_processing_start_fraction = 0.1;
			double dep_processing_span = 0.7;
			int completed_top_level_deps = 0;
			int num_wanted_deps = wanted_deps_list.size;
			if (num_wanted_deps == 0) {
				install_progress (RESOLVING_AND_INSTALLING_ALL, dep_processing_start_fraction + dep_processing_span, null);
			} else {
				foreach (var f in initial_dep_link_futures) {
					PackageLockEntry ple = yield f.wait_async (cancellable);
					completed_top_level_deps++;
					double current_fraction = dep_processing_start_fraction +
						((double) completed_top_level_deps / num_wanted_deps) * dep_processing_span;
					install_progress (RESOLVING_AND_INSTALLING_ALL, current_fraction, ple.toplevel_dep.name);
				}
			}

			double physical_completion_start_fraction = dep_processing_start_fraction + dep_processing_span;
			double physical_completion_span = 0.05;

			var finished_installs = new Gee.HashMap<string, PackageLockEntry> ();
			install_progress (AWAITING_COMPLETION, physical_completion_start_fraction);
			foreach (var entry in all_physical_installs.entries)
				finished_installs[entry.key] = yield entry.value.future.wait_async (cancellable);
			install_progress (DEPENDENCIES_PROCESSED, physical_completion_start_fraction + physical_completion_span);

			var pkgs = new Gee.ArrayList<Package> ();
			var new_manifest_dependencies = new PackageDependencies ();
			foreach (var future_ple in initial_dep_link_futures) {
				PackageLockEntry ple = yield future_ple.wait_async (cancellable);

				if (ple.newly_installed)
					pkgs.add (new Package (ple.name, ple.version, ple.description));

				var original_dep = ple.toplevel_dep;
				new_manifest_dependencies.add (new PackageDependency () {
					name = ple.name,
					version = original_dep.derive_version (ple.version),
					role = original_dep.role,
				});
			}
			manifest.dependencies = new_manifest_dependencies;

			double finalizing_manifests_start_fraction = physical_completion_start_fraction + physical_completion_span;
			install_progress (FINALIZING_MANIFESTS, finalizing_manifests_start_fraction);
			yield write_back_manifests (manifest, finished_installs, pkg_json_file, lock_file, cancellable);

			install_progress (COMPLETE, 1.0);

			return new PackageInstallResult (new PackageList (pkgs));
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
			public bool newly_installed;
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
					bool is_root_package = path_key == "";

					lock_r.read_member (path_key);

					if (lock_r.get_null_value ()) {
						lock_r.end_member ();
						continue;
					}

					var pli = new PackageLockPackageInfo ();
					pli.path_key = path_key;

					if (is_root_package) {
						lock_r.read_member ("name");
						pli.name = lock_r.get_string_value ();
						lock_r.end_member ();
					} else {
						int last_start = path_key.last_index_of ("/node_modules/");
						pli.name = (last_start != -1)
							? path_key[last_start + 14:]
							: path_key[13:];
					}

					lock_r.read_member ("version");
					pli.version = lock_r.get_string_value ();
					if (!is_root_package && pli.version == null)
						throw new Error.PROTOCOL ("Lockfile 'version' for '%s' missing or invalid", path_key);
					lock_r.end_member ();

					if (!is_root_package) {
						lock_r.read_member ("resolved");
						pli.resolved = lock_r.get_string_value ();
						if (pli.resolved == null) {
							throw new Error.PROTOCOL ("Lockfile 'resolved' for '%s' missing or invalid",
								path_key);
						}
						lock_r.end_member ();

						lock_r.read_member ("integrity");
						pli.integrity = lock_r.get_string_value ();
						if (pli.integrity == null) {
							throw new Error.PROTOCOL ("Lockfile 'integrity' for '%s' missing or invalid",
								path_key);
						}
						lock_r.end_member ();
					}

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

			string new_pkg_json = generate_npm_style_json (root, indent_level, indent_char);
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
			foreach (PackageLockEntry e in installed.values) {
				PackageDependency toplevel_dep = e.toplevel_dep;
				if (e.name == toplevel_dep.name) {
					b
						.set_member_name (e.name)
						.add_string_value (toplevel_dep.derive_version (e.version).spec);
				}
			}
			b
				.end_object ()
				.end_object ();

			foreach (var entry in installed.entries) {
				string lockfile_key = entry.key;
				PackageLockEntry e = entry.value;
				bool is_root_package = lockfile_key == "";

				b
					.set_member_name (lockfile_key)
					.begin_object ();

				if (is_root_package) {
					b
						.set_member_name ("name")
						.add_string_value (e.name);
				}

				b
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

			string lock_json = generate_npm_style_json (b.get_root (), indent_level, indent_char);
			yield FS.write_all_text (lock_file, lock_json, cancellable);
		}

		private async void perform_install (
				string name,
				PackageVersion version_spec,
				PackageDependency toplevel_dep,
				File parent_node_modules_dir,
				File project_root,
				Manifest manifest,
				bool prefer_lockfile_for_this_dep,
				Cancellable? cancellable,
				Promise<PackageLockEntry> dep_link_promise,
				Gee.Map<string, Promise<PackageLockEntry>> all_physical_installs,
				Gee.Map<string, Promise<ResolvedPackageData>> resolution_cache,
				Gee.Map<string, Promise<Json.Node>> packument_cache,
				Gee.Map<string, string> top_level_placements) {
			try {
				install_progress (RESOLVING_PACKAGE, -1.0, "%s@%s".printf (name, version_spec.spec));
				string resolution_id = name + "@" + version_spec.spec;
				ResolvedPackageData? rpd = null;
				bool rpd_came_from_lockfile = false;

				Promise<ResolvedPackageData>? rpd_promise = resolution_cache[resolution_id];

				if (rpd_promise != null && rpd_promise.future.ready) {
					rpd = yield rpd_promise.future.wait_async (cancellable);
				} else if (prefer_lockfile_for_this_dep) {
					foreach (var lp_entry in manifest.locked_packages.entries) {
						PackageLockPackageInfo li = lp_entry.value;
						if (li.name == name) {
							try {
								if (Semver.satisfies_range (Semver.parse_version (li.version),
										version_spec.spec)) {
									rpd = new ResolvedPackageData () {
										name = li.name,
										effective_version = li.version,
										resolved_url = li.resolved,
										integrity = li.integrity,
										shasum = null,
										description = null,
										license = null,
										dependencies = li.dependencies
									};
									rpd_came_from_lockfile = true;
									install_progress (USING_LOCKFILE_DATA, -1.0,
										"%s@%s (%s)".printf (rpd.name, rpd.effective_version,
											lp_entry.key));

									if (rpd_promise == null) {
										rpd_promise = new Promise<ResolvedPackageData> ();
										resolution_cache[resolution_id] = rpd_promise;
									}
									if (!rpd_promise.future.ready)
										rpd_promise.resolve (rpd);
									break;
								}
							} catch (Error e) {
							}
						}
					}
				}

				if (rpd == null) {
					bool was_new_promise = false;
					if (rpd_promise == null) {
						rpd_promise = new Promise<ResolvedPackageData> ();
						resolution_cache[resolution_id] = rpd_promise;
						fetch_and_resolve_package_data.begin (name, version_spec, rpd_promise, packument_cache,
							cancellable);
						was_new_promise = true;
					}
					rpd = yield rpd_promise.future.wait_async (cancellable);
					if (was_new_promise) {
						install_progress (METADATA_FETCHED, -1.0, "%s@%s".printf (rpd.name, rpd.effective_version));
					}
					rpd_came_from_lockfile = false;
				}

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

				string actual_install_lockfile_key = project_root.get_relative_path (target_dir);

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
						toplevel_dep = toplevel_dep,
						newly_installed = existing_ple.newly_installed
					});
					return;
				}

				all_physical_installs[actual_install_lockfile_key] = dep_link_promise;

				bool already_correctly_installed = false;
				if (target_dir.query_exists (cancellable)) {
					File installed_pkg_json_file = target_dir.get_child ("package.json");
					if (installed_pkg_json_file.query_exists (cancellable)) {
						try {
							Json.Reader installed_pkg_reader =
								yield load_json (installed_pkg_json_file, cancellable);
							if (installed_pkg_reader.read_member ("version")) {
								string? installed_version = installed_pkg_reader.get_string_value ();
								installed_pkg_reader.end_member ();
								if (installed_version == rpd.effective_version) {
									already_correctly_installed = true;
									install_progress (PACKAGE_ALREADY_INSTALLED, -1.0,
										"%s@%s".printf (rpd.name, rpd.effective_version));
								}
							}
						} catch (Error e) { }
					}
				}

				var sub_dep_futures = new Gee.ArrayList<Future<PackageLockEntry>> ();
				File sub_deps_parent_node_modules_dir = target_dir.get_child ("node_modules");
				PackageDependencies dependencies_to_recurse = rpd.dependencies;

				if (!dependencies_to_recurse.all.is_empty) {
					FS.mkdirp (sub_deps_parent_node_modules_dir, cancellable);
				}

				foreach (PackageDependency d in dependencies_to_recurse.all.values) {
					bool install_this_sub_dep = d.role == RUNTIME || d.role == OPTIONAL;
					if (!install_this_sub_dep)
						continue;

					var sub_dep_link_promise = new Promise<PackageLockEntry> ();
					sub_dep_futures.add (sub_dep_link_promise.future);
					perform_install.begin (
						d.name,
						d.version,
						toplevel_dep,
						sub_deps_parent_node_modules_dir,
						project_root,
						manifest,
						true,
						cancellable,
						sub_dep_link_promise,
						all_physical_installs,
						resolution_cache,
						packument_cache,
						top_level_placements
					);
				}
				foreach (var f in sub_dep_futures)
					yield f.wait_async (cancellable);

				if (!already_correctly_installed) {
					yield download_and_unpack (rpd.name, rpd.effective_version, rpd.resolved_url, target_dir,
						rpd.integrity, rpd.shasum, cancellable);
					install_progress (PACKAGE_INSTALLED, -1.0, "%s@%s".printf (rpd.name, rpd.effective_version));
				}

				if (rpd.description == null || rpd.license == null) {
					Json.Reader reader = yield load_json (target_dir.get_child ("package.json"), cancellable);
					update_rpd_description_license_from_reader (reader, rpd);
				}

				dep_link_promise.resolve (new PackageLockEntry () {
					name = rpd.name,
					version = rpd.effective_version,
					resolved = rpd.resolved_url,
					integrity = rpd.integrity,
					description = rpd.description,
					license = rpd.license,
					dependencies = rpd.dependencies,
					toplevel_dep = toplevel_dep,
					newly_installed = !already_correctly_installed
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

		private async void fetch_and_resolve_package_data (string name, PackageVersion version_spec,
				Promise<ResolvedPackageData> promise_to_fulfill, Gee.Map<string, Promise<Json.Node>> packument_cache,
				Cancellable? cancellable) {
			try {
				string effective_version_local;
				Json.Reader meta_reader;

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
						packument_promise = new Promise<Json.Node> ();
						fetch_packument_for_cache.begin (name, packument_promise, cancellable);
						packument_cache[name] = packument_promise;
					}
					var packument_node = yield packument_promise.future.wait_async (cancellable);
					var packument_reader = new Json.Reader (packument_node);

					string? version_from_dist_tag = null;
					packument_reader.read_member ("dist-tags");
					packument_reader.read_member (version_spec.spec);
					version_from_dist_tag = packument_reader.get_string_value ();
					packument_reader.end_member ();
					packument_reader.end_member ();

					packument_reader.read_member ("versions");

					if (version_from_dist_tag != null) {
						effective_version_local = version_from_dist_tag;
					} else {
						string[]? available_version_strings = packument_reader.list_members ();
						if (available_version_strings == null || available_version_strings.length == 0) {
							throw new Error.PROTOCOL (
								"Packument 'versions' missing, not an object, or empty for '%s'", name);
						}

						string? target_version_str = Semver.max_satisfying (
							new Gee.ArrayList<string>.wrap (available_version_strings),
							version_spec.spec);
						if (target_version_str == null) {
							throw new Error.PROTOCOL ("No version satisfying '%s' for '%s'",
								version_spec.spec, name);
						}
						effective_version_local = target_version_str;
					}

					packument_reader.read_member (effective_version_local);
					meta_reader = packument_reader;

					meta_reader.read_member ("version");
					string? actual_fetched_version = meta_reader.get_string_value ();
					if (actual_fetched_version == null || actual_fetched_version != effective_version_local) {
						throw new Error.PROTOCOL ("Version object for '%s@%s' missing, invalid, or its 'version' " +
							"field is incorrect/missing. Fetched: '%s', Expected: '%s'",
							name,
							effective_version_local,
							(actual_fetched_version != null) ? actual_fetched_version : "null",
							effective_version_local);
					}
					meta_reader.end_member ();
				}

				var rpd = new ResolvedPackageData () {
					name = name,
					effective_version = effective_version_local
				};

				read_package_version_metadata (meta_reader, rpd);

				promise_to_fulfill.resolve (rpd);
			} catch (GLib.Error e) {
				promise_to_fulfill.reject (e);
			}
		}

		private async void fetch_packument_for_cache (string name, Promise<Json.Node> request, Cancellable? cancellable)
				throws Error, IOError {
			try {
				Json.Node root = yield fetch_node ("/" + Uri.escape_string (name), cancellable);
				request.resolve (root);
			} catch (GLib.Error e) {
				request.reject (e);
			}
		}

		private static void read_package_version_metadata (Json.Reader reader, ResolvedPackageData rpd) throws Error {
			rpd.description = read_description (reader);
			rpd.license = read_license (reader);

			reader.read_member ("dist");

			reader.read_member ("tarball");
			rpd.resolved_url = reader.get_string_value ();
			if (rpd.resolved_url == null) {
				throw new Error.PROTOCOL ("'dist.tarball' for '%s@%s' missing or invalid, or 'dist' not an object",
					rpd.name, rpd.effective_version);
			}
			reader.end_member ();

			reader.read_member ("integrity");
			rpd.integrity = reader.get_string_value ();
			reader.end_member ();

			reader.read_member ("shasum");
			rpd.shasum = reader.get_string_value ();
			reader.end_member ();

			reader.end_member ();

			rpd.dependencies = read_dependencies (reader);
		}

		private static void update_rpd_description_license_from_reader (Json.Reader reader, ResolvedPackageData rpd) {
			if (rpd.description == null)
				rpd.description = read_description (reader);

			if (rpd.license == null)
				rpd.license = read_license (reader);
		}

		private static string? read_description (Json.Reader reader) {
			reader.read_member ("description");
			string? description = reader.get_string_value ();
			reader.end_member ();
			return description;
		}

		private static string? read_license (Json.Reader reader) {
			string? license;

			reader.read_member ("license");
			if (reader.is_object ()) {
				reader.read_member ("type");
				license = reader.get_string_value ();
				reader.end_member ();
			} else {
				license = reader.get_string_value ();
			}
			reader.end_member ();

			return license;
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

		private async void download_and_unpack (string name, string version, string tarball_url, File dest_root, string? integrity,
				string? shasum, Cancellable? cancellable) throws Error, IOError {
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
			string progress_details = "%s@%s".printf (name, version);

			install_progress (DOWNLOADING_PACKAGE, 0.0, progress_details);

			while (true) {
				ssize_t n = yield gunzip_input.read_async (buffer, io_priority, cancellable);
				if (n == 0)
					break;
				if (n < 0)
					throw new IOError.FAILED ("Stream read failed");

				try {
					yield tar_reader.feed (buffer[:n], cancellable);
				} catch (Error e) {
					throw new Error.PROTOCOL ("Unable to extract tarball at %s: %s", tarball_url, e.message);
				}
				read_total += (size_t) n;
				report_bucket += (size_t) n;

				if (content_len > 0 && report_bucket >= (1 << 20)) {
					install_progress (DOWNLOADING_PACKAGE, (double) read_total / (double) content_len,
						progress_details);
					report_bucket = 0;
				}
			}

			install_progress (DOWNLOADING_PACKAGE, (content_len > 0) ? 1.0 : -1.0, progress_details);

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
			var root = yield fetch_node (resource, cancellable);
			return new Json.Reader (root);
		}

		private async Json.Node fetch_node (string resource, Cancellable? cancellable) throws Error, IOError {
			string url = "https://%s%s".printf (registry, resource);
			install_progress (FETCHING_RESOURCE, -1.0, url);

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

			var parser = new Json.Parser ();
			try {
				parser.load_from_data ((string) bytes.get_data (), (ssize_t) bytes.get_size ());
			} catch (GLib.Error e) {
				throw new Error.PROTOCOL ("Unable to parse response from %s: %s", url, e.message);
			}

			return parser.get_root ();
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

	public enum PackageInstallPhase {
		INITIALIZING,
		PREPARING_DEPENDENCIES,
		RESOLVING_PACKAGE,
		USING_LOCKFILE_DATA,
		METADATA_FETCHED,
		FETCHING_RESOURCE,
		PACKAGE_ALREADY_INSTALLED,
		DOWNLOADING_PACKAGE,
		PACKAGE_INSTALLED,
		RESOLVING_AND_INSTALLING_ALL,
		AWAITING_COMPLETION,
		DEPENDENCIES_PROCESSED,
		FINALIZING_MANIFESTS,
		COMPLETE,
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

		public string? url {
			get;
			construct;
		}

		internal Package (string name, string version, string? description, string? url = null) {
			Object (
				name: name,
				version: version,
				description: description,
				url: prettify_url (url)
			);
		}

		private static string? prettify_url (string? url) {
			if (url == null)
				return null;
			if (url.has_prefix ("https://www.npmjs.com/package/"))
				return "https://npm.im/" + url[30:];
			return url;
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
		indent_char = ' ';

		Regex indents_before_first_key = /^([ \t]+)"/m;
		MatchInfo? m;
		if (indents_before_first_key.match (src, 0, out m)) {
			string seq = m.fetch (1);
			indent_level = seq.length;
			indent_char = seq.get_char (0);
		}
	}

	private string generate_npm_style_json (Json.Node root_node, uint indent_level, unichar indent_char) {
		var gen = new Json.Generator ();
		gen.set_pretty (true);
		gen.set_indent (indent_level);
		gen.set_indent_char (indent_char);
		gen.set_root (root_node);
		string pretty_json = gen.to_data (null);

		string[] lines = pretty_json.split ("\n");
		var modified_lines = new Gee.ArrayList<string> ();
		foreach (string line in lines) {
			int idx = line.index_of (" : ");
			if (idx != -1 && line[idx - 1] == '"') {
					string part1 = line[:idx];
					string part2 = line[idx + 3:];
					modified_lines.add (part1 + ": " + part2);
			} else {
				modified_lines.add (line);
			}
		}

		return string.joinv ("\n", modified_lines.to_array ()) + "\n";
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
				pre = v[dash + 1:];
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
					core_part_of_spec = core_part_of_spec[:plus_idx];
				int dash_idx = core_part_of_spec.index_of_char ('-');
				if (dash_idx != -1)
					core_part_of_spec = core_part_of_spec[:dash_idx];

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

		public async void feed (uint8[] data, Cancellable? cancellable) throws Error, IOError {
			int io_priority = Priority.DEFAULT;

			size_t off = 0;
			size_t len = data.length;
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
				if (n_header_bytes_missing != 0) {
					size_t chunk_size = size_t.min (n_header_bytes_missing, len - off);
					header_builder.append_data (data[off:off + chunk_size]);
					off += chunk_size;
					if (chunk_size != n_header_bytes_missing)
						return;
				}

				var header = new Buffer (header_builder.build ());
				header_builder = new BufferBuilder ();

				string name = header.read_fixed_string (0, 100);
				if (name.length == 0) {
					off = len;
					break;
				}
				string safe_entry = sanitize_entry (name, root);

				string size_field = header.read_fixed_string (124, 12).split (" ")[0];
				uint64 file_size = 0;
				if (!uint64.try_parse (size_field, out file_size, null, 8))
					throw new Error.PROTOCOL ("Invalid tarball size (file '%s' corrupt)", safe_entry);

				var typeflag = (char) header.read_uint8 (156);

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
