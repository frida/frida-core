using Gee;

namespace Frida {
	public class Linjector : Object, Injector {
		private HelperProcess helper;
		private bool close_helper;

		private HashMap<uint, uint> pid_by_id = new HashMap<uint, uint> ();
		private HashMap<uint, TemporaryFile> blob_file_by_id = new HashMap<uint, TemporaryFile> ();
		private uint next_blob_id = 1;

		public Linjector () {
			close_helper = true;
		}

		internal Linjector.with_helper (HelperProcess helper) {
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
			var name = "blob%u.so".printf (next_blob_id++);
			var file = new TemporaryFile.from_stream (name, new MemoryInputStream.from_bytes (blob), get_helper ().tempdir);
			var path = file.path;
			FileUtils.chmod (path, 0755);
#if ANDROID
			SELinux.setfilecon (path, "u:object_r:frida_file:s0");
#endif

			var id = yield inject_library_file (pid, path, entrypoint, data);

			blob_file_by_id[id] = file;

			return id;
		}

		public async uint inject_library_resource (uint pid, AgentResource resource, string entrypoint, string data) throws Error {
			yield resource.ensure_written_to_disk ();
			return yield inject_library_file (pid, resource.path_template, entrypoint, data);
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

		private void on_uninjected (uint id) {
			pid_by_id.unset (id);
			blob_file_by_id.unset (id);

			uninjected (id);
		}
	}

	public enum AgentMode {
		INSTANCED,
		SINGLETON
	}

	public class AgentResource : Object {
		public string name_template {
			get;
			construct;
		}

		public InputStream so32 {
			get;
			construct;
		}

		public InputStream so64 {
			get;
			construct;
		}

		public AgentMode mode {
			get;
			construct;
		}

		public TemporaryDirectory tempdir {
			get;
			construct;
		}

		public string path_template {
			get {
				if (_path_template == null) {
					_path_template = Path.build_filename (tempdir.path, name_template);
				}

				return _path_template;
			}
		}
		private string _path_template;

		private Gee.Promise<bool> ensure_request;
		private TemporaryFile file32;
		private TemporaryFile file64;

		public AgentResource (string name_template, InputStream stream32, InputStream stream64, AgentMode mode = AgentMode.INSTANCED, TemporaryDirectory? tempdir = null) {
			Object (
				name_template: name_template,
				so32: stream32,
				so64: stream64,
				mode: mode,
				tempdir: (tempdir != null) ? tempdir : new TemporaryDirectory ()
			);
		}

		public async void ensure_written_to_disk () throws Error {
			if (ensure_request != null) {
				var future = ensure_request.future;
				try {
					yield future.wait_async ();
				} catch (Gee.FutureError e) {
					throw (Error) future.exception;
				}
				return;
			}
			ensure_request = new Gee.Promise<bool> ();

			try {
				file32 = yield write_agent (name_template.printf (32), so32);
				file64 = yield write_agent (name_template.printf (64), so64);

				ensure_request.set_value (true);
			} catch (Error e) {
				file32 = null;
				file64 = null;

				ensure_request.set_exception (e);
				ensure_request = null;
				throw e;
			}
		}

		private async TemporaryFile write_agent (string name, InputStream input) throws Error {
			try {
				var file = File.new_for_path (Path.build_filename (tempdir.path, name));
				var output = yield file.create_async (FileCreateFlags.REPLACE_DESTINATION);

				var temp_agent = new TemporaryFile (file, tempdir);

				yield output.splice_async (input, CLOSE_TARGET);

				FileUtils.chmod (temp_agent.path, 0755);
#if ANDROID
				SELinux.setfilecon (temp_agent.path, "u:object_r:frida_file:s0");
#endif

				return temp_agent;
			} catch (GLib.Error e) {
				reset_input_stream (input);

				throw new Error.PERMISSION_DENIED ("%s", e.message);
			}
		}

		private void reset_input_stream (InputStream stream) {
			Seekable seekable = null;
			if (stream is Seekable) {
				seekable = stream as Seekable;
			} else if (stream is FilterInputStream) {
				seekable = (stream as FilterInputStream).base_stream as Seekable;
			} else {
				assert_not_reached ();
			}

			try {
				seekable.seek (0, SeekType.SET);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
		}
	}
}
