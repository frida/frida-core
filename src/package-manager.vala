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

			var specs = parse_mutation_specs (ADD, opts.specs, RUNTIME);
			var manifest = yield load_manifest (pkg_json_file, cancellable);
			bool dirty = apply_specs_to_manifest (specs, manifest);

			install_progress (PREPARING_DEPENDENCIES, 0.05);

			Gee.Map<string, PackageLockPackageInfo>? locked = yield read_lockfile (lock_file, cancellable);

			bool lock_clean = !dirty && locked != null && deps_match (manifest, locked[""].dependencies);

			if (lock_clean && locked != null) {
				var root = lock_to_graph (locked);
				// TODO: validate_peers (root);
				yield reify_graph (root, project_root, cancellable);
			} else {
				var cache = new PackageDataCache (this, cancellable);

				PackageNode? base_graph = null;
				if (locked != null)
					base_graph = lock_to_graph (locked);

				var root = yield resolve_with_selective_unlock (manifest, base_graph, cache, cancellable);

				// TODO: validate_peers (root);
				yield reify_graph (root, project_root, cancellable);

				// TODO: manifest.save ("package.json");
				yield write_lockfile (root, manifest, lock_file, cancellable);
			}

			install_progress (DEPENDENCIES_PROCESSED, 0.98);
			install_progress (FINALIZING_MANIFESTS, 0.99);
			install_progress (COMPLETE, 1.0);

			return new PackageInstallResult (new PackageList (new Gee.ArrayList<Package> ()));
		}

		private static async PackageNode resolve_with_selective_unlock (Manifest manifest, PackageNode? base_node,
				PackageDataCache cache, Cancellable? cancellable) throws Error, IOError {
			if (base_node == null)
				return yield build_full_tree (manifest, cache, cancellable);

			var to_uninstall = collect_outdated_nodes (manifest, base_node);
			var anchors = yank_nodes_and_collect_parents (to_uninstall);
			yield patch_holes (anchors, manifest, cache, cancellable);

			hoist_graph (base_node);

			return base_node;
		}

		private static Gee.Queue<PackageNode> collect_outdated_nodes (Manifest manifest, PackageNode base_node) throws Error {
			var queue = new Gee.ArrayQueue<PackageNode> ();
			foreach (PackageDependency dep in manifest.dependencies.all.values) {
				var node = base_node.lookup (dep.name);
				bool ok = node != null && Semver.satisfies_range (node.version, dep.version.range);
				if (!ok)
					queue.offer ((node != null) ? node : base_node);
			}
			return queue;
		}

		private static Gee.List<PackageNode> yank_nodes_and_collect_parents (Gee.Queue<PackageNode> queue) {
			var anchors = new Gee.ArrayList<PackageNode> ();
			PackageNode? n;
			while ((n = queue.poll ()) != null) {
				if (n.parent != null) {
					var p = n.parent;
					p.children.unset (n.name);
					anchors.add (p);
				}
				foreach (PackageNode ch in n.children.values)
					queue.offer (ch);
			}
			return anchors;
		}

		private static async void patch_holes (Gee.List<PackageNode> anchors, Manifest manifest, PackageDataCache cache,
				Cancellable? cancellable) throws Error, IOError {
			foreach (PackageNode anchor in anchors) {
				var needed = anchor.find_missing_ranges (manifest);
				foreach (var kv in needed) {
					var sub = yield build_ideal_subtree (kv.key, kv.value, cache, cancellable);
					anchor.children[kv.key] = sub;
					sub.parent = anchor;
				}
			}
		}

		private static async PackageNode build_full_tree (Manifest manifest, PackageDataCache cache, Cancellable? cancellable)
				throws Error, IOError {
			var root = yield build_ideal_graph (manifest, cache, cancellable);
			hoist_graph (root);
			return root;
		}

		private static async PackageNode build_ideal_graph (Manifest manifest, PackageDataCache cache, Cancellable? cancellable)
				throws Error, IOError {
			var root = new PackageNode ();

			var q = new Gee.ArrayQueue<DepQueueItem> ();
			foreach (PackageDependency d in manifest.dependencies.all.values) {
				var future = cache.fetch (d.name, d.version);
				q.offer (new DepQueueItem (root, d, future));
			}

			var expanded = new Gee.HashSet<string> ();

			DepQueueItem? item;
			while ((item = q.poll ()) != null) {
				var host = item.host;
				var dep = item.dep;
				var pdata = yield item.data_future.wait_async (cancellable);

				var node = ensure_child_node (host, dep, pdata);

				string key = pdata.name + "@" + pdata.effective_version.str;
				if (expanded.add (key)) {
					foreach (PackageDependency cd in pdata.dependencies.all.values) {
						if (cd.role == DEVELOPMENT)
							continue;
						var future = cache.fetch (cd.name, cd.version);
						q.offer (new DepQueueItem (node, cd, future));
					}
				}
			}

			return root;
		}

		private static async PackageNode build_ideal_subtree (string name, string spec, PackageDataCache cache,
				Cancellable? cancellable) throws Error, IOError {
			ResolvedPackageData pdata = yield cache.fetch (name, new PackageVersion (spec)).wait_async (cancellable);

			var root = new PackageNode (pdata.name, pdata.effective_version);
			root.resolved = pdata.resolved_url;
			root.integrity = pdata.integrity;

			var q = new Gee.ArrayQueue<DepQueueItem> ();
			foreach (PackageDependency d in pdata.dependencies.runtime.values) {
				var future = cache.fetch (d.name, d.version);
				q.offer (new DepQueueItem (root, d, future));
			}

			var expanded = new Gee.HashSet<string> ();

			DepQueueItem? item;
			while ((item = q.poll ()) != null) {
				var host = item.host;
				var dep = item.dep;
				var ddata = yield item.data_future.wait_async (cancellable);

				var node = ensure_child_node (host, dep, pdata);

				string key = pdata.name + "@" + ddata.effective_version.str;
				if (expanded.add (key)) {
					foreach (PackageDependency cd in ddata.dependencies.all.values) {
						if (cd.role == DEVELOPMENT)
							continue;
						var future = cache.fetch (cd.name, cd.version);
						q.offer (new DepQueueItem (node, cd, future));
					}
				}
			}

			return root;
		}

		private static PackageNode ensure_child_node (PackageNode host, PackageDependency dep, ResolvedPackageData data)
				throws Error {
			PackageNode? reuse = find_ancestor (host, dep);
			if (reuse != null)
				return reuse;

			var n = new PackageNode (data.name, data.effective_version);
			n.resolved = data.resolved_url;
			n.integrity = data.integrity;

			host.children[data.name] = n;
			n.parent = host;
			return n;
		}

		private static PackageNode? find_ancestor (PackageNode start, PackageDependency dep) throws Error {
			for (PackageNode? n = start; n != null; n = n.parent) {
				var maybe = n.children[dep.name];
				if (maybe != null && Semver.satisfies_range (maybe.version, dep.version.range))
					return maybe;
			}
			return null;
		}

		private class DepQueueItem {
			public PackageNode host;
			public PackageDependency dep;
			public Future<ResolvedPackageData> data_future;

			public DepQueueItem (PackageNode host, PackageDependency dep, Future<ResolvedPackageData> data_future) {
				this.host = host;
				this.dep = dep;
				this.data_future = data_future;
			}
		}

		private static void hoist_graph (PackageNode root) {
			var bfs = new Gee.ArrayQueue<PackageNode> ();
			bfs.offer (root);

			PackageNode? n;
			while ((n = bfs.poll ()) != null) {
				foreach (PackageNode child in n.children.values.to_array ()) {
					try_hoist (child);
					if (child.parent != null)
						bfs.offer (child);
				}
			}
		}

		private static void try_hoist (PackageNode node) {
			while (true) {
				var parent = node.parent;
				bool already_at_top = parent == null || parent.parent == null;
				if (already_at_top)
					return;

				PackageNode? pkg_above = parent.parent.children[node.name];
				if (pkg_above != null) {
					bool versions_collide = pkg_above.version.str != node.version.str;
					if (versions_collide)
						return;

					foreach (PackageNode gc in node.children.values) {
						if (!pkg_above.children.has_key (gc.name)) {
							pkg_above.children[gc.name] = gc;
							gc.parent = pkg_above;
						}
					}

					parent.children.unset (node.name);
					node.parent = null;
					return;
				}

				foreach (var peer in node.peer_ranges.keys) {
					bool peer_missing_in_parent = !parent.peer_ranges.has_key (peer) && !parent.children.has_key (peer);
					if (peer_missing_in_parent)
						return;
				}

				parent.children.unset (node.name);
				parent.parent.children[node.name] = node;
				node.parent = parent.parent;
			}
		}

		private static Gee.List<MutationSpec> parse_mutation_specs (MutationKind kind, Gee.List<string> raw_specs,
				PackageRole role) {
			var specs = new Gee.ArrayList<MutationSpec> ();
			foreach (string raw_spec in raw_specs) {
				string name, range;
				if (raw_spec.contains ("@")) {
					var parts = raw_spec.split ("@", 2);
					name = parts[0];
					range = parts[1];
				} else {
					name = raw_spec;
					range = "";
				}
				specs.add (new MutationSpec () {
					kind = kind,
					name = name,
					range = range,
					role = role,
				});
			}
			return specs;
		}

		private static bool apply_specs_to_manifest (Gee.List<MutationSpec> specs, Manifest m) {
			bool dirty = false;
			foreach (var s in specs) {
				switch (s.kind) {
					case ADD:
					case UPGRADE:
						string new_range = s.range == "" ? "*" : s.range;
						PackageDependency? dep = m.dependencies.all[s.name];
						if (dep == null || new_range != dep.version.range) {
							m.dependencies.all[s.name] = new PackageDependency () {
								name = s.name,
								version = new PackageVersion (new_range),
								role = s.role,
							};
							dirty = true;
						}
						break;
					case REMOVE:
						dirty |= m.dependencies.all.unset (s.name);
						break;
				}
			}
			return dirty;
		}

		private static async Manifest load_manifest (File pkg_json_file, Cancellable? cancellable) throws Error, IOError {
			var m = new Manifest ();

			if (pkg_json_file.query_exists (cancellable)) {
				var pkg_json = yield FS.read_all_text (pkg_json_file, cancellable);
				detect_indent (pkg_json, out m.indent_level, out m.indent_char);

				Json.Reader r = parse_json (new Bytes.static (pkg_json.data));

				r.read_member ("name");
				m.name = r.get_string_value ();
				r.end_member ();

				r.read_member ("version");
				m.version = r.get_string_value ();
				r.end_member ();

				m.license = read_license (r);
				m.funding = read_funding (r);
				m.engines = read_engines (r);
				m.dependencies = read_dependencies (r);
			}

			return m;
		}

		private static async Gee.Map<string, PackageLockPackageInfo>? read_lockfile (File lock_file, Cancellable? cancellable)
				throws Error, IOError {
			if (!lock_file.query_exists (cancellable))
				return null;

			var packages = new Gee.HashMap<string, PackageLockPackageInfo> ();

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
				string? raw_version = lock_r.get_string_value ();
				if (!is_root_package && raw_version == null)
					throw new Error.PROTOCOL ("Lockfile 'version' for '%s' missing or invalid", path_key);
				pli.version = (raw_version != null) ? Semver.parse_version (raw_version) : null;
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

				pli.license = read_license (lock_r);
				pli.funding = read_funding (lock_r);
				pli.engines = read_engines (lock_r);
				pli.dependencies = read_dependencies_from_lock_entry (lock_r, path_key);

				lock_r.read_member ("dev");
				pli.is_dev = lock_r.get_boolean_value ();
				lock_r.end_member ();

				lock_r.read_member ("optional");
				pli.is_optional = lock_r.get_boolean_value ();
				lock_r.end_member ();

				packages[path_key] = pli;

				lock_r.end_member ();
			}

			lock_r.end_member ();

			return packages;
		}

		private async void write_lockfile (PackageNode root, Manifest manifest, File lock_file, Cancellable? cancellable)
				throws Error, IOError {
			var path_map = new Gee.HashMap<string, PackageNode> ();

			var node_stack = new Gee.LinkedList<PackageNode> ();
			var key_stack = new Gee.LinkedList<string> ();

			node_stack.offer_head (root);
			key_stack.offer_head ("");

			while (!node_stack.is_empty) {
				var node = node_stack.poll_head ();
				string key = key_stack.poll_head ();
				path_map[key] = node;

				foreach (PackageNode ch in node.children.values) {
					string child_key = (key == "") ? "" : key + "/";
					child_key += "node_modules/" + ch.name;
					node_stack.offer_head (ch);
					key_stack.offer_head (child_key);
				}
			}

			var b = new Json.Builder ();
			b.begin_object ();
			write_name (manifest.name, b);
			write_version (manifest.version, b);
			b.set_member_name ("lockfileVersion").add_int_value (3);
			b.set_member_name ("requires").add_boolean_value (true);
			b.set_member_name ("packages").begin_object ();

			b.set_member_name ("").begin_object ();
			write_name (manifest.name, b);
			write_version (manifest.version, b);
			write_license (manifest.license, b);
			write_funding (manifest.funding, b);
			write_dependencies_section ("dependencies", manifest.dependencies.runtime, b);
			write_dependencies_section ("devDependencies", manifest.dependencies.development, b);
			write_engines (manifest.engines, b);
			b.end_object ();

			var runtime_reach = compute_runtime_reach (manifest.dependencies.runtime.values, path_map);

			foreach (string k in path_map.keys) {
				if (k == "")
					continue;

				PackageNode pn = path_map[k];
				b.set_member_name (k).begin_object ();
				write_version (pn.version.str, b);
				b
					.set_member_name ("resolved")
					.add_string_value (pn.resolved)
					.set_member_name ("integrity")
					.add_string_value (pn.integrity);

				if (!runtime_reach.contains (k))
					b.set_member_name ("dev").add_boolean_value (true);

				write_dependencies_section ("dependencies", collect_direct_deps (pn), b);

				b.end_object ();
			}

			b
				.end_object ()
				.end_object ();

			string txt = generate_npm_style_json (b.get_root (), manifest.indent_level, manifest.indent_char);
			yield FS.write_all_text (lock_file, txt, cancellable);
		}

		private Gee.Map<string, PackageDependency> collect_direct_deps (PackageNode node) {
			var m = new Gee.TreeMap<string, PackageDependency> ();

			foreach (PackageNode ch in node.children.values.to_array ()) {
				var d = new PackageDependency ();
				d.name = ch.name;
				d.version = new PackageVersion (ch.version.str);
				d.role = PackageRole.RUNTIME;
				m[d.name] = d;
			}

			return m;
		}

		private static PackageNode lock_to_graph (Gee.Map<string, PackageLockPackageInfo> packages) throws Error {
			var root = new PackageNode ();

			foreach (var e in packages.entries) {
				string key = e.key;
				PackageLockPackageInfo pkg = e.value;

				if (key == "")
					continue;

				string[] segs = key.split ("/");
				PackageNode cur = root;
				for (int i = 0; i != segs.length; ) {
					if (segs[i] != "node_modules")
						throw new Error.PROTOCOL ("Invalid lockfile");
					i++;
					if (i >= segs.length)
						throw new Error.PROTOCOL ("Invalid lockfile");

					string name;
					if (segs[i].has_prefix ("@")) {
						if (i + 1 == segs.length)
							throw new Error.PROTOCOL ("Invalid lockfile");
						name = segs[i] + "/" + segs[i + 1];
						i += 2;
					} else {
						name = segs[i];
						i += 1;
					}

					PackageNode? next = cur.children[name];
					if (next == null) {
						next = new PackageNode (name);
						cur.children[name] = next;
					}
					cur = next;
				}

				cur.version = pkg.version;
				cur.resolved = pkg.resolved;
				cur.integrity = pkg.integrity;

				// TODO: peer_ranges
			}

			return root;
		}

		private async void reify_graph (PackageNode root, File target, Cancellable? cancellable) throws Error, IOError {
			var inner = new Cancellable ();

			var source = new CancellableSource (cancellable);
			source.set_callback (() => {
				inner.cancel ();
				return Source.REMOVE;
			});
			source.attach (MainContext.get_thread_default ());

			var futures = new Gee.ArrayList<Future<bool>> ();
			uint completed = 0;
			Error? first_error = null;

			perform_reify_graph (root, target, null, futures, inner);

			foreach (var f in futures) {
				f.then (fut => {
					try {
						fut.get_result ();
					} catch (GLib.Error e) {
						if (!(e is IOError.CANCELLED) && first_error == null)
							first_error = (Error) e;
						inner.cancel ();
					}

					completed++;

					double dep_processing_start_fraction = 0.1;
					double dep_processing_span = 0.88;
					double current_fraction = dep_processing_start_fraction
						+ ((double) completed / futures.size) * dep_processing_span;

					install_progress (RESOLVING_AND_INSTALLING_ALL, current_fraction);

					if (completed == futures.size)
						reify_graph.callback ();
				});
			}
			yield;
			if (first_error != null)
				throw first_error;
		}

		private void perform_reify_graph (PackageNode node, File base_dir, Promise<bool>? prereq, Gee.List<Future<bool>> futures,
				Cancellable inner) {
			Promise<bool>? my_job = prereq;

			if (!node.is_root) {
				my_job = new Promise<bool> ();
				futures.add (my_job.future);

				var dir = install_dir_for_dependency (node.name, base_dir);

				perform_download_and_unpack.begin (node, dir, my_job, prereq, inner);

				base_dir = dir;
			}

			foreach (var child in node.children.values)
				perform_reify_graph (child, base_dir, my_job, futures, inner);
		}

		private async void perform_download_and_unpack (PackageNode node, File dir, Promise<bool> job, Promise<bool>? prereq,
				Cancellable inner) {
			try {
				if (prereq != null)
					yield prereq.future.wait_async (inner);

				string progress_details = "%s@%s".printf (node.name, node.version.str);

				if (yield package_is_already_installed (node, dir, inner)) {
					install_progress (PackageInstallPhase.PACKAGE_ALREADY_INSTALLED, 1.0, progress_details);
					job.resolve (true);
					return;
				}

				yield download_and_unpack (node.name, node.version.str, node.resolved, dir, node.integrity, node.shasum, inner);

				install_progress (PackageInstallPhase.PACKAGE_INSTALLED, 1.0, progress_details);
				job.resolve (true);
			} catch (GLib.Error e) {
				job.reject (e);
			}
		}

		private static async bool package_is_already_installed (PackageNode node, File dir, Cancellable? cancellable)
				throws IOError {
			try {
				Json.Reader r = yield load_json (dir.get_child ("package.json"), cancellable);

				r.read_member ("name");
				string? name = r.get_string_value ();
				r.end_member ();

				r.read_member ("version");
				string? version = r.get_string_value ();
				r.end_member ();

				return name != null && version != null && name == node.name && version == node.version.str;
			} catch (Error e) {
				return false;
			}
		}

		private static bool deps_match (Manifest manifest, PackageDependencies deps) {
			// TODO
			return true;
		}

		private class MutationSpec {
			public MutationKind kind;
			public string name;
			public string range;
			public PackageRole role = RUNTIME;
		}

		private enum MutationKind {
			ADD,
			UPGRADE,
			REMOVE,
		}

		private class PackageNode {
			public string? name;
			public SemverVersion? version;
			public string? resolved;
			public string? integrity;
			public string? shasum;
			public weak PackageNode? parent;
			public Gee.Map<string, PackageNode> children = new Gee.HashMap<string, PackageNode> ();
			public Gee.Map<string, string> peer_ranges = new Gee.HashMap<string, string> ();

			public bool is_root {
				get {
					return name == null;
				}
			}

			public PackageNode (string? name = null, SemverVersion? version = null) {
				this.name = name;
				this.version = version;
			}

			~PackageNode () {
				foreach (var child in children.values)
					child.parent = null;
			}

			public PackageNode? lookup (string pkg_name) {
				if (name == pkg_name)
					return this;
				foreach (var child in children.values) {
					PackageNode? found = child.lookup (pkg_name);
					if (found != null)
						return found;
				}
				return null;
			}

			public Gee.Map<string, string> find_missing_ranges (Manifest manifest) {
				var missing = new Gee.HashMap<string, string> ();
				foreach (var dep in manifest.dependencies.all.values) {
					if (!children.has_key (dep.name))
						missing[dep.name] = dep.version.range;
				}
				return missing;
			}
		}

		private class Manifest {
			public string? name;
			public string? version;
			public string? license;
			public Gee.List<FundingSource>? funding;
			public Gee.Map<string, string>? engines;
			public PackageDependencies dependencies = new PackageDependencies ();

			public uint indent_level = 2;
			public unichar indent_char = ' ';
		}

		private class PackageVersion {
			public string range;

			public bool is_pinned {
				get {
					return range[0].isdigit ();
				}
			}

			public PackageVersion (string range) {
				this.range = range;
			}
		}

		private enum PackageRole {
			RUNTIME,
			DEVELOPMENT,
			OPTIONAL,
			PEER
		}

		private class PackageDependencies {
			public Gee.Map<string, PackageDependency> all = new Gee.TreeMap<string, PackageDependency> ();

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

			public Gee.Map<string, PackageDependency> optional {
				get {
					if (_optional == null)
						_optional = compute_subset_with_role (OPTIONAL);
					return _optional;
				}
			}

			public Gee.Map<string, PackageDependency> peer {
				get {
					if (_peer == null)
						_peer = compute_subset_with_role (PEER);
					return _peer;
				}
			}

			private Gee.Map<string, PackageDependency> _runtime;
			private Gee.Map<string, PackageDependency> _development;
			private Gee.Map<string, PackageDependency> _optional;
			private Gee.Map<string, PackageDependency> _peer;

			public void add (PackageDependency d) {
				all[d.name] = d;
			}

			private Gee.Map<string, PackageDependency> compute_subset_with_role (PackageRole role) {
				var result = new Gee.TreeMap<string, PackageDependency> ();
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

		private class FundingSource {
			public string? as_string;
			public string? type;
			public string? url;
		}

		private class PackageLockPackageInfo {
			public string path_key;
			public string? name;
			public SemverVersion? version;
			public string? resolved;
			public string? integrity;
			public string? license;
			public Gee.List<FundingSource>? funding;
			public Gee.Map<string, string>? engines;
			public PackageDependencies dependencies = new PackageDependencies ();
			public bool is_dev = false;
			public bool is_optional = false;
		}

		private class PackageLockEntry {
			public string id;
			public string name;
			public string version;
			public string resolved;
			public string integrity;
			public string? description;
			public string? license;
			public Gee.List<FundingSource>? funding;
			public Gee.Map<string, string>? engines;
			public PackageDependencies dependencies;
			public PackageDependency toplevel_dep;
			public bool newly_installed;
			public Gee.List<PackageLockEntry> children = new Gee.ArrayList<PackageLockEntry> ();
		}

		private static Gee.Set<string> compute_runtime_reach (Gee.Collection<PackageDependency> runtime_deps,
				Gee.Map<string, PackageNode> path_map) {
			var reach = new Gee.HashSet<string> ();

			var stack = new Gee.LinkedList<string> ();

			foreach (PackageDependency dep in runtime_deps) {
				string key = "node_modules/" + dep.name;
				stack.offer_head (key);
			}

			string? k;
			while ((k = stack.poll_head ()) != null) {
				if (!reach.add (k))
					continue;

				PackageNode node = path_map[k];
				foreach (PackageNode ch in node.children.values.to_array ()) {
					string child_key = (k == "") ? "" : k + "/";
					child_key += "node_modules/" + ch.name;
					stack.offer_head (child_key);
				}
			}

			return reach;
		}

		private class InstallProgressTracker {
			public int total_physical = 0;
			public int completed_physical = 0;
		}

		private static File install_dir_for_dependency (string name, File package_root) {
			File location = package_root.get_child ("node_modules");
			foreach (unowned string part in name.split ("/"))
				location = location.get_child (part);
			return location;
		}

		private class PackageDataCache {
			public Gee.Map<string, Promise<ResolvedPackageData>> data =
				new Gee.HashMap<string, Promise<ResolvedPackageData>> ();
			public Gee.Map<string, Promise<Json.Node>> packument =
				new Gee.HashMap<string, Promise<Json.Node>> ();

			private PackageManager manager;
			private Cancellable? cancellable;

			public PackageDataCache (PackageManager manager, Cancellable? cancellable) {
				this.manager = manager;
				this.cancellable = cancellable;
			}

			public Future<ResolvedPackageData> fetch (string name, PackageVersion ver) {
				string key = name + "@" + ver.range;
				Promise<ResolvedPackageData> p = data[key];
				if (p == null) {
					p = new Promise<ResolvedPackageData> ();
					data[key] = p;
					manager.fetch_and_resolve_package_data.begin (name, ver, p, packument, cancellable);
				}
				return p.future;
			}
		}

		private async void fetch_and_resolve_package_data (string name, PackageVersion version,
				Promise<ResolvedPackageData> promise_to_fulfill, Gee.Map<string, Promise<Json.Node>> packument_cache,
				Cancellable? cancellable) {
			try {
				string effective_version_local;
				Json.Reader meta_reader;

				if (Semver.is_precise_spec (version.range)) {
					meta_reader = yield fetch (
						"/%s/%s".printf (Uri.escape_string (name), Uri.escape_string (version.range)),
						cancellable);

					meta_reader.read_member ("version");
					var ver_val = meta_reader.get_string_value ();
					if (ver_val == null) {
						throw new Error.PROTOCOL ("Registry 'version' for '%s@%s' missing or invalid",
							name, version.range);
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
					packument_reader.read_member (version.range);
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
							version.range);
						if (target_version_str == null) {
							throw new Error.PROTOCOL ("No version satisfying '%s' for '%s'",
								version.range, name);
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
					effective_version = Semver.parse_version (effective_version_local)
				};

				read_package_version_metadata (meta_reader, rpd);

				promise_to_fulfill.resolve (rpd);
			} catch (GLib.Error e) {
				promise_to_fulfill.reject (e);
			}
		}

		private class ResolvedPackageData {
			public string name;
			public SemverVersion effective_version;
			public string resolved_url;
			public string? integrity;
			public string? shasum;
			public string? description;
			public string? license;
			public Gee.List<FundingSource>? funding;
			public Gee.Map<string, string>? engines;
			public PackageDependencies dependencies;
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
			rpd.funding = read_funding (reader);
			rpd.engines = read_engines (reader);

			reader.read_member ("dist");

			reader.read_member ("tarball");
			rpd.resolved_url = reader.get_string_value ();
			if (rpd.resolved_url == null) {
				throw new Error.PROTOCOL ("'dist.tarball' for '%s@%s' missing or invalid, or 'dist' not an object",
					rpd.name, rpd.effective_version.str);
			}
			reader.end_member ();

			reader.read_member ("integrity");
			rpd.integrity = reader.get_string_value ();
			reader.end_member ();

			reader.read_member ("shasum");
			rpd.shasum = reader.get_string_value ();
			reader.end_member ();

			reader.end_member ();

			rpd.license = read_license (reader);
			rpd.funding = read_funding (reader);
			rpd.engines = read_engines (reader);
			rpd.dependencies = read_dependencies (reader);
		}

		private static void write_name (string? name, Json.Builder b) {
			if (name != null)
				b.set_member_name ("name").add_string_value (name);
		}

		private static void write_version (string? version, Json.Builder b) {
			if (version != null)
				b.set_member_name ("version").add_string_value (version);
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

		private static void write_license (string? license, Json.Builder b) {
			if (license != null)
				b.set_member_name ("license").add_string_value (license);
		}

		private static Gee.List<FundingSource>? read_funding (Json.Reader reader) throws Error {
			if (!reader.read_member ("funding")) {
				reader.end_member ();
				return null;
			}

			var result = new Gee.ArrayList<FundingSource> ();

			if (reader.is_array ()) {
				int n = reader.count_elements ();
				for (int i = 0; i < n; i++) {
					reader.read_element (i);
					read_funding_source (reader, result);
					reader.end_element ();
				}
			} else {
				read_funding_source (reader, result);
			}

			reader.end_member ();

			return result.is_empty ? null : result;
		}

		private static void write_funding (Gee.List<FundingSource>? funding, Json.Builder b) {
			if (funding == null)
				return;
			b.set_member_name ("funding");
			if (funding.size == 1) {
				write_funding_source (funding.get (0), b);
			} else {
				b.begin_array ();
				foreach (var s in funding)
					write_funding_source (s, b);
				b.end_array ();
			}
		}

		private static void read_funding_source (Json.Reader r, Gee.List<FundingSource> list) throws Error {
			if (r.is_object ()) {
				var source = new FundingSource ();
				r.read_member ("type");
				source.type = r.get_string_value ();
				r.end_member ();
				r.read_member ("url");
				source.url = r.get_string_value ();
				r.end_member ();
				list.add (source);
			} else {
				var val = r.get_string_value ();
				if (val == null)
					throw new Error.PROTOCOL ("Invalid 'funding' field");
				list.add (new FundingSource () { as_string = val });
			}
		}

		private static void write_funding_source (FundingSource s, Json.Builder b) {
			if (s.as_string != null) {
				b.add_string_value (s.as_string);
			} else {
				b.begin_object ();
				if (s.type != null)
					b.set_member_name ("type").add_string_value (s.type);
				if (s.url != null)
					b.set_member_name ("url").add_string_value (s.url);
				b.end_object ();
			}
		}

		private static Gee.Map<string, string>? read_engines (Json.Reader reader) throws Error {
			if (!reader.read_member ("engines")) {
				reader.end_member ();
				return null;
			}

			var result = new Gee.TreeMap<string, string> ();
			string[]? members = reader.list_members ();
			if (members == null)
				throw new Error.PROTOCOL ("Invalid 'engines' field");
			foreach (unowned string name in members) {
				reader.read_member (name);
				string? val = reader.get_string_value ();
				if (val == null)
					throw new Error.PROTOCOL ("Invalid 'engines' value");
				result[name] = val;
				reader.end_member ();
			}

			reader.end_member ();

			return result;
		}

		private static void write_engines (Gee.Map<string, string>? engines, Json.Builder b) {
			if (engines == null)
				return;
			b.set_member_name ("engines").begin_object ();
			foreach (var e in engines.entries)
				b.set_member_name (e.key).add_string_value (e.value);
			b.end_object ();
		}

		private static PackageDependencies read_dependencies (Json.Reader r) throws Error {
			var deps = new PackageDependencies ();

			string[] section_keys = { "dependencies", "devDependencies", "optionalDependencies", "peerDependencies" };
			PackageRole[] section_roles = { RUNTIME, DEVELOPMENT, OPTIONAL, PEER };
			for (uint i = 0; i != section_keys.length; i++) {
				unowned string section_key = section_keys[i];

				if (!r.read_member (section_key)) {
					r.end_member ();
					continue;
				}

				string[]? names = r.list_members ();
				if (names == null)
					throw new Error.PROTOCOL ("Invalid package.json section for '%s'", section_key);

				PackageRole role = section_roles[i];
				foreach (unowned string name in names) {
					r.read_member (name);

					string? range = r.get_string_value ();
					if (range == null) {
						throw new Error.PROTOCOL ("Bad type of %s entry for %s, expected string value",
							section_key, name);
					}

					deps.add (new PackageDependency () {
						name = name,
						version = new PackageVersion (range),
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

			string[] section_keys = { "dependencies", "optionalDependencies", "peerDependencies" };
			PackageRole[] section_roles = { RUNTIME, OPTIONAL, PEER };
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

				PackageRole role = section_roles[i];

				foreach (unowned string dep_name in dep_names) {
					r.read_member (dep_name);

					string? range = r.get_string_value ();
					if (range == null) {
						throw new Error.PROTOCOL ("Lockfile dependency '%s' in section '%s' for package '%s' " +
							"must have a string value", dep_name, section_key, parent_path_key);
					}

					deps.add (new PackageDependency () {
						name = dep_name,
						version = new PackageVersion (range),
						role = role
					});

					r.end_member ();
				}

				r.end_member ();
			}

			return deps;
		}

		private static void write_dependencies_section (string section, Gee.Map<string, PackageDependency> deps, Json.Builder b) {
			if (deps.is_empty)
				return;
			b.set_member_name (section).begin_object ();
			foreach (PackageDependency dep in deps.values)
				b.set_member_name (dep.name).add_string_value (dep.version.range);
			b.end_object ();
		}

		private async void download_and_unpack (string name, string version, string tarball_url, File dest_root, string? integrity,
				string? shasum, Cancellable? cancellable) throws Error, IOError {
			string progress_details = "%s@%s".printf (name, version);
			install_progress (DOWNLOADING_PACKAGE, 0.0, progress_details);

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

		public string str {
			get {
				if (_str == null) {
					var s = new StringBuilder.sized (8);
					s.append_printf ("%u.%u.%u", major, minor, patch);
					if (prerelease != null)
						s.append_c ('-').append (prerelease);
					if (metadata != null)
						s.append_c ('+').append (metadata);
					_str = s.str;
				}
				return _str;
			}
		}

		private string? _str;

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
					throw new Error.PROTOCOL ("Invalid tarball size (file '%s' corrupt)", name);

				var typeflag = (char) header.read_uint8 (156);

				if ((typeflag == '0' || typeflag == '\0') && safe_entry != "") {
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
			string entry = (slash == -1) ? "" : name[slash + 1:];
			if (entry == "")
				return entry;

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
