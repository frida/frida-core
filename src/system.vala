namespace Frida {
	namespace System {
		public static extern Frida.HostProcessInfo[] enumerate_processes ();
		public static extern void kill (uint pid);
	}

	public class ProcessEnumerator {
		private MainContext current_main_context;
		private Gee.ArrayList<EnumerateRequest> pending_requests = new Gee.ArrayList<EnumerateRequest> ();

		public async HostProcessInfo[] enumerate_processes () {
			bool is_first_request = pending_requests.is_empty;

			var request = new EnumerateRequest (() => enumerate_processes.callback ());
			if (is_first_request) {
				current_main_context = MainContext.get_thread_default ();
				new Thread<bool> ("frida-enumerate-processes", enumerate_processes_worker);
			}
			pending_requests.add (request);
			yield;

			return request.result;
		}

		private bool enumerate_processes_worker () {
			var processes = System.enumerate_processes ();

			var source = new IdleSource ();
			source.set_callback (() => {
				current_main_context = null;
				var requests = pending_requests;
				pending_requests = new Gee.ArrayList<EnumerateRequest> ();

				foreach (var request in requests)
					request.complete (processes);

				return false;
			});
			source.attach (current_main_context);

			return true;
		}

		private class EnumerateRequest {
			public delegate void CompletionHandler ();
			private CompletionHandler handler;

			public HostProcessInfo[] result {
				get;
				private set;
			}

			public EnumerateRequest (owned CompletionHandler handler) {
				this.handler = (owned) handler;
			}

			public void complete (HostProcessInfo[] processes) {
				this.result = processes;
				handler ();
			}
		}
	}

	public class TemporaryDirectory {
		public string path {
			owned get {
				return file.get_path ();
			}
		}
		private File file;

		private bool remove_on_dispose;

		public static TemporaryDirectory system_default {
			owned get {
				return new TemporaryDirectory.with_file (File.new_for_path (get_system_tmp ()), false);
			}
		}

		public TemporaryDirectory () throws Error {
			this.file = File.new_for_path (Path.build_filename (get_system_tmp (), make_name ()));
			this.remove_on_dispose = true;
			try {
				this.file.make_directory ();
			} catch (GLib.Error e) {
				throw new Error.PERMISSION_DENIED (e.message);
			}
		}

		public TemporaryDirectory.with_file (File file, bool remove_on_dispose) {
			this.file = file;
			this.remove_on_dispose = remove_on_dispose;
		}

		~TemporaryDirectory () {
			destroy ();
		}

		public void destroy () {
			if (remove_on_dispose) {
				try {
					this.file.delete ();
				} catch (GLib.Error e) {
				}
			}
		}

		public static string make_name () {
			var builder = new StringBuilder (".frida-");
			for (var i = 0; i != 16; i++)
				builder.append_printf ("%02x", Random.int_range (0, 256));
			return builder.str;
		}

		private static extern string get_system_tmp ();
	}

	public class TemporaryFile {
		public string path {
			owned get {
				return file.get_path ();
			}
		}
		private File file;
		private TemporaryDirectory directory;

		public TemporaryFile.from_stream (string name, InputStream istream, TemporaryDirectory? directory = null) throws Error {
			if (directory != null)
				this.directory = directory;
			else
				this.directory = TemporaryDirectory.system_default;
			this.file = File.new_for_path (Path.build_filename (this.directory.path, name));

			try {
				var ostream = file.create (FileCreateFlags.NONE, null);

				var buf_size = 128 * 1024;
				var buf = new uint8[buf_size];

				while (true) {
					var bytes_read = istream.read (buf);
					if (bytes_read == 0)
						break;
					buf.resize ((int) bytes_read);

					size_t bytes_written;
					ostream.write_all (buf, out bytes_written);
				}

				ostream.close (null);
			} catch (GLib.Error e) {
				throw new Error.PERMISSION_DENIED (e.message);
			}
		}

		public TemporaryFile (File file, TemporaryDirectory directory) {
			this.file = file;
			this.directory = directory;
		}

		~TemporaryFile () {
			destroy ();
		}

		public void destroy () {
			if (file != null) {
				try {
					file.delete (null);
				} catch (GLib.Error e) {
				}
				file = null;
			}
			directory = null;
		}
	}
}
