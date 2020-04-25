namespace Frida {
	public class Linjector : Object, Injector {
		private LinuxHelperProcess? helper;
		private bool close_helper;

		private Gee.HashMap<uint, uint> pid_by_id = new Gee.HashMap<uint, uint> ();
		private Gee.HashMap<uint, TemporaryFile> blob_file_by_id = new Gee.HashMap<uint, TemporaryFile> ();
		private uint next_blob_id = 1;

		public Linjector () {
			close_helper = true;
		}

		internal Linjector.with_helper (LinuxHelperProcess helper) {
			close_helper = false;

			this.helper = helper;
			this.helper.uninjected.connect (on_uninjected);
		}

		private LinuxHelperProcess get_helper () {
			if (helper == null) {
				helper = new LinuxHelperProcess ();
				helper.uninjected.connect (on_uninjected);
			}
			return helper;
		}

		public async void close (Cancellable? cancellable) throws IOError {
			if (helper == null)
				return;

			helper.uninjected.disconnect (on_uninjected);

			if (close_helper)
				yield helper.close (cancellable);
		}

		public async uint inject_library_file (uint pid, string path, string entrypoint, string data, Cancellable? cancellable)
				throws Error, IOError {
			var id = yield get_helper ().inject_library_file (pid, path, entrypoint, data, cancellable);
			pid_by_id[id] = pid;
			return id;
		}

		public async uint inject_library_blob (uint pid, Bytes blob, string entrypoint, string data, Cancellable? cancellable)
				throws Error, IOError {
			var name = "blob%u.so".printf (next_blob_id++);
			var file = new TemporaryFile.from_stream (name, new MemoryInputStream.from_bytes (blob),
				get_helper ().get_tempdir ());
			var path = file.path;
			FileUtils.chmod (path, 0755);
#if ANDROID
			SELinux.setfilecon (path, "u:object_r:frida_file:s0");
#endif

			var id = yield inject_library_file (pid, path, entrypoint, data, cancellable);

			blob_file_by_id[id] = file;

			return id;
		}

		public async uint inject_library_resource (uint pid, AgentResource resource, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			return yield inject_library_file (pid, resource.get_path_template (), entrypoint, data, cancellable);
		}

		public async uint demonitor_and_clone_state (uint id, Cancellable? cancellable) throws Error, IOError {
			return yield helper.demonitor_and_clone_injectee_state (id, cancellable);
		}

		public async void recreate_thread (uint pid, uint id, Cancellable? cancellable) throws Error, IOError {
			yield helper.recreate_injectee_thread (pid, id, cancellable);
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

		public InputStream? so32 {
			get {
				if (_so32 != null)
					reset_stream (_so32);
				return _so32;
			}
			construct {
				_so32 = value;
			}
		}
		private InputStream? _so32;

		public InputStream? so64 {
			get {
				if (_so64 != null)
					reset_stream (_so64);
				return _so64;
			}
			construct {
				_so64 = value;
			}
		}
		private InputStream? _so64;

		public AgentMode mode {
			get;
			construct;
		}

		public TemporaryDirectory tempdir {
			get;
			construct;
		}

		private string? _path_template;
		private TemporaryFile _file32;
		private TemporaryFile _file64;

		public AgentResource (string name_template, InputStream stream32, InputStream stream64, AgentMode mode = AgentMode.INSTANCED, TemporaryDirectory? tempdir = null) {
			Object (
				name_template: name_template,
				so32: byte_size (stream32) > 0 ? stream32 : null,
				so64: byte_size (stream64) > 0 ? stream64 : null,
				mode: mode,
				tempdir: (tempdir != null) ? tempdir : new TemporaryDirectory ()
			);
		}

		public string get_path_template () throws Error {
			if (_path_template == null) {
				var name32 = name_template.printf (32);
				var name64 = name_template.printf (64);

				if (so32 != null) {
					var so = (mode == AgentMode.INSTANCED) ? _clone_so (so32) : so32;
					var temp_agent = new TemporaryFile.from_stream (name32, so, tempdir);
					FileUtils.chmod (temp_agent.path, 0755);
#if ANDROID
					SELinux.setfilecon (temp_agent.path, "u:object_r:frida_file:s0");
#endif
					_file32 = temp_agent;
				}

				if (so64 != null) {
					var so = (mode == AgentMode.INSTANCED) ? _clone_so (so64) : so64;
					var temp_agent = new TemporaryFile.from_stream (name64, so, tempdir);
					FileUtils.chmod (temp_agent.path, 0755);
#if ANDROID
					SELinux.setfilecon (temp_agent.path, "u:object_r:frida_file:s0");
#endif
					_file64 = temp_agent;
				}

				_path_template = Path.build_filename (tempdir.path, name_template);
			}

			return _path_template;
		}

		private void reset_stream (InputStream stream) {
			try {
				((Seekable) stream).seek (0, SeekType.SET);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
		}

		private static int64 byte_size (InputStream stream) {
			assert (stream is Seekable);
			var seekable = (Seekable) stream;
			try {
				var previous_offset = seekable.tell ();
				seekable.seek (0, SeekType.END);
				var size = seekable.tell ();
				seekable.seek (previous_offset, SeekType.SET);
				return size;
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
		}

		public extern static InputStream _clone_so (InputStream dylib);
	}
}
