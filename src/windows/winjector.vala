namespace Frida {
	public class Winjector : Object, Injector {
		public WindowsHelper helper {
			get;
			construct;
		}

		public bool close_helper {
			get;
			construct;
		}

		public TemporaryDirectory tempdir {
			get;
			construct;
		}

		private Gee.HashMap<uint, uint> pid_by_id = new Gee.HashMap<uint, uint> ();
		private Gee.HashMap<uint, TemporaryFile> blob_file_by_id = new Gee.HashMap<uint, TemporaryFile> ();
		private uint next_injectee_id = 1;
		private uint next_blob_id = 1;

		public Winjector (WindowsHelper helper, bool close_helper, TemporaryDirectory tempdir) {
			Object (helper: helper, close_helper: close_helper, tempdir: tempdir);
		}

		construct {
			helper.uninjected.connect (on_uninjected);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			helper.uninjected.disconnect (on_uninjected);

			if (close_helper) {
				yield helper.close (cancellable);

				tempdir.destroy ();
			}
		}

		public async uint inject_library_file (uint pid, string path, string entrypoint, string data, Cancellable? cancellable)
				throws Error, IOError {
			return yield inject_library_file_with_template (pid, PathTemplate (path), entrypoint, data, cancellable);
		}

		private async uint inject_library_file_with_template (uint pid, PathTemplate path_template, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			uint id = next_injectee_id++;
			yield helper.inject_library_file (pid, path_template, entrypoint, data, id, cancellable);
			pid_by_id[id] = pid;
			return id;
		}

		public async uint inject_library_blob (uint pid, Bytes blob, string entrypoint, string data, Cancellable? cancellable)
				throws Error, IOError {
			var name = "blob%u.dll".printf (next_blob_id++);
			var file = new TemporaryFile.from_stream (name, new MemoryInputStream.from_bytes (blob), tempdir);

			var id = yield inject_library_file (pid, file.path, entrypoint, data, cancellable);

			blob_file_by_id[id] = file;

			return id;
		}

		public async uint inject_library_resource (uint pid, AgentDescriptor agent, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			return yield inject_library_file_with_template (pid, agent.get_path_template (), entrypoint, data, cancellable);
		}

		public async uint demonitor_and_clone_state (uint id, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not supported on this OS");
		}

		public async void recreate_thread (uint pid, uint id, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not supported on this OS");
		}

		public bool any_still_injected () {
			return !pid_by_id.is_empty;
		}

		public bool is_still_injected (uint id) {
			return pid_by_id.has_key (id);
		}

		private void on_uninjected (uint id) {
			pid_by_id.unset (id);
			blob_file_by_id.unset (id);

			uninjected (id);
		}
	}

	public class AgentDescriptor : Object {
		public PathTemplate name_template {
			get;
			construct;
		}

		public Gee.Collection<AgentResource> resources {
			get;
			construct;
		}

		public TemporaryDirectory? tempdir {
			get;
			construct;
		}

		private PathTemplate? cached_path_template;

		public AgentDescriptor (PathTemplate name_template, Bytes dll32, Bytes dll64, AgentResource[] resources,
				TemporaryDirectory? tempdir = null) {
			var all_resources = new Gee.ArrayList<AgentResource> ();
			all_resources.add (new AgentResource (name_template.expand ("32"), dll32, tempdir));
			all_resources.add (new AgentResource (name_template.expand ("64"), dll64, tempdir));

			foreach (var r in resources)
				all_resources.add (r);

			Object (name_template: name_template, resources: all_resources, tempdir: tempdir);
		}

		public PathTemplate get_path_template () throws Error {
			if (cached_path_template == null) {
				TemporaryDirectory? first_tempdir = null;
				foreach (AgentResource r in resources) {
					TemporaryFile f = r.get_file ();
					if (first_tempdir == null)
						first_tempdir = f.parent;
				}

				if (first_tempdir.is_ours)
					set_acls_as_needed (first_tempdir.path);

				cached_path_template = PathTemplate (first_tempdir.path + "\\" + name_template.str);
			}

			return cached_path_template;
		}

		protected extern static void set_acls_as_needed (string path) throws Error;
	}

	public class AgentResource : Object {
		public string name {
			get;
			construct;
		}

		public Bytes blob {
			get;
			construct;
		}

		public TemporaryDirectory? tempdir {
			get;
			construct;
		}

		private TemporaryFile _file;

		public AgentResource (string name, Bytes blob, TemporaryDirectory? tempdir = null) {
			Object (name: name, blob: blob, tempdir: tempdir);
		}

		public TemporaryFile get_file () throws Error {
			if (_file == null) {
				var stream = new MemoryInputStream.from_bytes (blob);
				_file = new TemporaryFile.from_stream (name, stream, tempdir);
			}
			return _file;
		}
	}
}
