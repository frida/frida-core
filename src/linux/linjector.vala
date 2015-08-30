#if LINUX
using Gee;

namespace Frida {
	public class Linjector : Object {
		public signal void uninjected (uint id);

		private HelperProcess helper;
		private bool close_helper;
		private HashMap<uint, uint> pid_by_id = new HashMap<uint, uint> ();

		public Linjector () {
			helper = new HelperProcess ();
			close_helper = true;
			helper.uninjected.connect (on_uninjected);
		}

		internal Linjector.with_helper (HelperProcess helper) {
			this.helper = helper;
			close_helper = false;
			this.helper.uninjected.connect (on_uninjected);
		}

		public async void close () {
			helper.uninjected.disconnect (on_uninjected);
			if (close_helper)
				yield helper.close ();
		}

		public async uint inject (uint pid, AgentResource agent, string data_string) throws Error {
			var id = yield helper.inject (pid, agent.path_template, data_string);
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

		public string path_template {
			get {
				if (_path_template == null) {
					try {
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
					} catch (Error e) {
						assert_not_reached ();
					}

					_path_template = Path.build_filename (tempdir.path, name_template);
				}

				return _path_template;
			}
		}
		private string _path_template;
		private TemporaryFile _file32;
		private TemporaryFile _file64;

		public AgentResource (string name_template, InputStream stream32, InputStream stream64, AgentMode mode = AgentMode.INSTANCED, TemporaryDirectory? tempdir = null) {
			/* FIXME: we use a new variable to work around a Vala compiler bug */
			TemporaryDirectory? dir;
			if (tempdir != null) {
				dir = tempdir;
			} else {
				try {
					dir = new TemporaryDirectory ();
				} catch (Error e) {
					assert_not_reached ();
				}
			}

			Object (
				name_template: name_template,
				so32: byte_size (stream32) > 0 ? stream32 : null,
				so64: byte_size (stream64) > 0 ? stream64 : null,
				mode: mode,
				tempdir: dir
			);
		}

		public void ensure_written_to_disk () {
			(void) path_template;
		}

		private void reset_stream (InputStream stream) {
			try {
				(stream as Seekable).seek (0, SeekType.SET);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
		}

		private static int64 byte_size (InputStream stream) {
			assert (stream is Seekable);
			var seekable = stream as Seekable;
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

		public static extern InputStream _clone_so (InputStream dylib);
	}
}
#endif
