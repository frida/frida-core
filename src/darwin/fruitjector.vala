#if DARWIN
using Gee;

namespace Frida {
	public class Fruitjector : Object {
		public signal void uninjected (uint id);

		private HelperProcess helper;
		private bool close_helper;
		private HashMap<uint, uint> pid_by_id = new HashMap<uint, uint> ();

		public Fruitjector () {
			helper = new HelperProcess ();
			close_helper = true;
			helper.uninjected.connect (on_uninjected);
		}

		internal Fruitjector.with_helper (HelperProcess helper) {
			this.helper = helper;
			close_helper = false;
			this.helper.uninjected.connect (on_uninjected);
		}

		public async void close () {
			helper.uninjected.disconnect (on_uninjected);
			if (close_helper)
				yield helper.close ();
		}

		public async uint inject (uint pid, AgentResource resource, string data_string) throws Error {
			var id = yield helper.inject (pid, resource.file.path, data_string);
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
			uninjected (id);
		}
	}

	public class AgentResource : Object {
		public string name {
			get;
			construct;
		}

		public InputStream dylib {
			get {
				reset_stream (_dylib);
				return _dylib;
			}

			construct {
				_dylib = value;
			}
		}
		private InputStream _dylib;

		public TemporaryDirectory? tempdir {
			get;
			construct;
		}

		public TemporaryFile file {
			get {
				if (_file == null) {
					try {
						_file = new TemporaryFile.from_stream (name, _clone_dylib (dylib), tempdir);
					} catch (Error e) {
						assert_not_reached ();
					}
					FileUtils.chmod (_file.path, 0755);
				}
				return _file;
			}
		}
		private TemporaryFile _file;

		public AgentResource (string name, InputStream dylib, TemporaryDirectory? tempdir = null) {
			Object (name: name, dylib: dylib, tempdir: tempdir);

			assert (dylib is Seekable);
		}

		public void ensure_written_to_disk () {
			(void) file;
		}

		private void reset_stream (InputStream stream) {
			try {
				(stream as Seekable).seek (0, SeekType.SET);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
		}

		public static extern InputStream _clone_dylib (InputStream dylib);
	}
}
#endif
