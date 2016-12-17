#if DARWIN
using Gee;

namespace Frida {
	public class Fruitjector : Object, Injector {
		private HelperProcess helper;
		private bool close_helper;
		private HashMap<uint, uint> pid_by_id = new HashMap<uint, uint> ();
		private HashMap<uint, TemporaryFile> blob_file_by_id = new HashMap<uint, TemporaryFile> ();
		private uint next_blob_id = 1;

		public Fruitjector () {
			close_helper = true;
		}

		internal Fruitjector.with_helper (HelperProcess helper) {
			close_helper = false;

			this.helper = helper;
			this.helper.uninjected.connect (on_uninjected);
		}

		private HelperProcess get_helper () {
			if (helper == null) {
				helper = new HelperProcess ();
				helper.uninjected.connect (on_uninjected);
			}
			return helper;
		}

		public async void close () {
			if (helper != null) {
				helper.uninjected.disconnect (on_uninjected);
				if (close_helper)
					yield helper.close ();
			}
		}

		public async uint inject_library_file (uint pid, string path, string entrypoint, string data) throws Error {
			var id = yield get_helper ().inject_library_file (pid, path, entrypoint, data);
			pid_by_id[id] = pid;
			return id;
		}

		public async uint inject_library_blob (uint pid, Bytes blob, string entrypoint, string data) throws Error {
			// We can optimize this later when our mapper is always used instead of dyld
			var name = "blob%u.dylib".printf (next_blob_id++);
			var file = new TemporaryFile.from_stream (name, new MemoryInputStream.from_bytes (blob), get_helper ().tempdir);

			var id = yield inject_library_file (pid, file.path, entrypoint, data);

			blob_file_by_id[id] = file;

			return id;
		}

		public async uint inject_library_resource (uint pid, AgentResource resource, string entrypoint, string data) throws Error {
			var helper = get_helper ();

			var blob = yield helper.try_mmap (resource.blob);
			if (blob == null)
				return yield inject_library_file (pid, resource.file.path, entrypoint, data);

			var id = yield helper.inject_library_blob (pid, resource.name, blob, entrypoint, data);
			pid_by_id[id] = pid;
			return id;
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

		public TemporaryFile file {
			get {
				if (_file == null) {
					try {
						var stream = new MemoryInputStream.from_bytes (blob);
						_file = new TemporaryFile.from_stream (name, stream, tempdir);
					} catch (Error e) {
						assert_not_reached ();
					}
					FileUtils.chmod (_file.path, 0755);
				}
				return _file;
			}
		}
		private TemporaryFile _file;

		public AgentResource (string name, Bytes blob, TemporaryDirectory? tempdir = null) {
			Object (name: name, blob: blob, tempdir: tempdir);
		}

		public void ensure_written_to_disk () {
			(void) file;
		}
	}
}
#endif
