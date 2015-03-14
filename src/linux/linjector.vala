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
			var filename = ensure_copy_of (desc);
			var id = yield helper.inject (pid, filename, data_string);
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
			var temp_agent = agents[desc.name];
			if (temp_agent == null) {
				var dylib = _clone_so (desc.sofile);
				temp_agent = new TemporaryFile.from_stream (desc.name, dylib, helper.tempdir);
				FileUtils.chmod (temp_agent.path, 0755);
				agents[desc.name] = temp_agent;
			}
			return temp_agent.path;
		}

		public static extern InputStream _clone_so (InputStream dylib);
	}

	public class AgentDescriptor : Object {
		public string name {
			get;
			construct;
		}

		public InputStream sofile {
			get {
				reset_stream (_sofile);
				return _sofile;
			}

			construct {
				_sofile = value;
			}
		}
		private InputStream _sofile;

		public AgentDescriptor (string name, InputStream sofile) {
			Object (name: name, sofile: sofile);

			assert (sofile is Seekable);
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
