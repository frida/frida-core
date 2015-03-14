#if LINUX
using Gee;

namespace Frida {
	public class Linjector : Object {
		public signal void uninjected (uint id);

		private HelperProcess helper;
		private bool close_helper;
		private HashMap<string, TemporaryFile> agents = new HashMap<string, TemporaryFile> ();
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

			foreach (var tempfile in agents.values)
				tempfile.destroy ();
			agents.clear ();
		}

		public async uint inject (uint pid, AgentDescriptor desc, string data_string) throws IOError {
			var filename_template = ensure_copy_of (desc);
			var id = yield helper.inject (pid, filename_template, data_string);
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

		private string ensure_copy_of (AgentDescriptor desc) throws IOError {
			var name32 = desc.name_template.printf (32);
			var temp_agent = agents[name32];
			if (temp_agent == null) {
				var so32 = _clone_so (desc.so32);
				temp_agent = new TemporaryFile.from_stream (name32, so32, helper.tempdir);
				FileUtils.chmod (temp_agent.path, 0755);
				agents[name32] = temp_agent;

				var name64 = desc.name_template.printf (64);
				var so64 = _clone_so (desc.so64);
				temp_agent = new TemporaryFile.from_stream (name64, so64, helper.tempdir);
				FileUtils.chmod (temp_agent.path, 0755);
				agents[name64] = temp_agent;
			}
			return Path.build_filename (helper.tempdir.path, desc.name_template);
		}

		public static extern InputStream _clone_so (InputStream dylib);
	}

	public class AgentDescriptor : Object {
		public string name_template {
			get;
			construct;
		}

		public InputStream so32 {
			get {
				reset_stream (_so32);
				return _so32;
			}

			construct {
				_so32 = value;
			}
		}
		private InputStream _so32;

		public InputStream so64 {
			get {
				reset_stream (_so64);
				return _so64;
			}

			construct {
				_so64 = value;
			}
		}
		private InputStream _so64;

		public AgentDescriptor (string name_template, InputStream so32, InputStream so64) {
			Object (name_template: name_template, so32: so32, so64: so64);

			assert (so32 is Seekable);
			assert (so64 is Seekable);
		}

		private void reset_stream (InputStream stream) {
			try {
				(stream as Seekable).seek (0, SeekType.SET);
			} catch (Error e) {
				assert_not_reached ();
			}
		}
	}
}
#endif
