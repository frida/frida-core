using Gee;

namespace Frida {
	public class Fruitjector : Object, Injector {
		public signal void injected (uint id, uint pid, bool has_mapped_module, DarwinModuleDetails mapped_module);

		public DarwinHelper helper {
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

		private HashMap<uint, uint> pid_by_id = new HashMap<uint, uint> ();
		private HashMap<uint, TemporaryFile> blob_file_by_id = new HashMap<uint, TemporaryFile> ();
		private uint next_blob_id = 1;

		public Fruitjector (DarwinHelper helper, bool close_helper, TemporaryDirectory tempdir) {
			Object (helper: helper, close_helper: close_helper, tempdir: tempdir);
		}

		construct {
			helper.injected.connect (on_injected);
			helper.uninjected.connect (on_uninjected);
		}

		~Fruitjector () {
			helper.injected.disconnect (on_injected);
			helper.uninjected.disconnect (on_uninjected);
			if (close_helper) {
				helper.close.begin ();

				tempdir.destroy ();
			}
		}

		public async void close () {
			helper.injected.disconnect (on_injected);
			helper.uninjected.disconnect (on_uninjected);
			if (close_helper) {
				yield helper.close ();

				tempdir.destroy ();
			}
		}

		public async uint inject_library_file (uint pid, string path, string entrypoint, string data) throws Error {
			var id = yield helper.inject_library_file (pid, path, entrypoint, data);
			pid_by_id[id] = pid;
			return id;
		}

		public async uint inject_library_blob (uint pid, Bytes blob, string entrypoint, string data) throws Error {
			// We can optimize this later when our mapper is always used instead of dyld
			FileUtils.chmod (tempdir.path, 0755);

			var name = "blob%u.dylib".printf (next_blob_id++);
			var file = new TemporaryFile.from_stream (name, new MemoryInputStream.from_bytes (blob), tempdir);

			var id = yield inject_library_file (pid, file.path, entrypoint, data);

			blob_file_by_id[id] = file;

			return id;
		}

		public async uint inject_library_resource (uint pid, AgentResource resource, string entrypoint, string data) throws Error {
			var blob = yield helper.try_mmap (resource.blob);
			if (blob == null)
				return yield inject_library_file (pid, resource.get_file ().path, entrypoint, data);

			var id = yield helper.inject_library_blob (pid, resource.name, blob, entrypoint, data);
			pid_by_id[id] = pid;
			return id;
		}

		public async uint demonitor_and_clone_state (uint id) throws Error {
			return yield helper.demonitor_and_clone_injectee_state (id);
		}

		public async void recreate_thread (uint pid, uint id) throws Error {
			yield helper.recreate_injectee_thread (pid, id);
		}

		public bool any_still_injected () {
			return !pid_by_id.is_empty;
		}

		public bool is_still_injected (uint id) {
			return pid_by_id.has_key (id);
		}

		private void on_injected (uint id, uint pid, bool has_mapped_module, DarwinModuleDetails mapped_module) {
			injected (id, pid, has_mapped_module, mapped_module);
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

		private TemporaryFile _file;

		public AgentResource (string name, Bytes blob, TemporaryDirectory? tempdir = null) {
			Object (name: name, blob: blob, tempdir: tempdir);
		}

		public TemporaryFile get_file () throws Error {
			if (_file == null) {
				var stream = new MemoryInputStream.from_bytes (blob);
				_file = new TemporaryFile.from_stream (name, stream, tempdir);
				FileUtils.chmod (_file.path, 0755);
			}
			return _file;
		}
	}
}
