namespace Frida {
	namespace System {
		public extern static Frida.HostApplicationInfo get_frontmost_application () throws Error;
		public extern static Frida.HostApplicationInfo[] enumerate_applications ();
		public extern static Frida.HostProcessInfo[] enumerate_processes ();
		public extern static void kill (uint pid);

#if LINUX
		// memfd_create(2)
		[CCode (cprefix = "MFD_", has_type_id = false, cheader_filename = "sys/mman.h")]
		public enum MemfdFlags {
			CLOEXEC,
			ALLOW_SEALING,
			HUGETLB
		}

		[CCode (cheader_filename = "sys/mman.h", cname="memfd_create")]
		public extern static int memfd_create (string name, MemfdFlags flags);
#endif
	}

	public class ApplicationEnumerator {
		private MainContext current_main_context;
		private Gee.ArrayList<EnumerateRequest> pending_requests = new Gee.ArrayList<EnumerateRequest> ();

		public async HostApplicationInfo[] enumerate_applications () {
			bool is_first_request = pending_requests.is_empty;

			var request = new EnumerateRequest (enumerate_applications.callback);
			if (is_first_request) {
				current_main_context = MainContext.get_thread_default ();
				new Thread<bool> ("frida-enumerate-applications", enumerate_applications_worker);
			}
			pending_requests.add (request);
			yield;

			return request.result;
		}

		private bool enumerate_applications_worker () {
			var applications = System.enumerate_applications ();

			var source = new IdleSource ();
			source.set_callback (() => {
				current_main_context = null;
				var requests = pending_requests;
				pending_requests = new Gee.ArrayList<EnumerateRequest> ();

				foreach (var request in requests)
					request.complete (applications);

				return false;
			});
			source.attach (current_main_context);

			return true;
		}

		private class EnumerateRequest {
			private SourceFunc handler;

			public HostApplicationInfo[] result {
				get;
				private set;
			}

			public EnumerateRequest (owned SourceFunc handler) {
				this.handler = (owned) handler;
			}

			public void complete (HostApplicationInfo[] applications) {
				this.result = applications;
				handler ();
			}
		}
	}

	public class ProcessEnumerator {
		private MainContext current_main_context;
		private Gee.ArrayList<EnumerateRequest> pending_requests = new Gee.ArrayList<EnumerateRequest> ();

		public async HostProcessInfo[] enumerate_processes () {
			bool is_first_request = pending_requests.is_empty;

			var request = new EnumerateRequest (enumerate_processes.callback);
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
			private SourceFunc handler;

			public HostProcessInfo[] result {
				get;
				private set;
			}

			public EnumerateRequest (owned SourceFunc handler) {
				this.handler = (owned) handler;
			}

			public void complete (HostProcessInfo[] processes) {
				this.result = processes;
				handler ();
			}
		}
	}

	public class TemporaryDirectory {
		private string name;

		public string path {
			owned get {
				if (file == null) {
					file = File.new_for_path (Path.build_filename (get_system_tmp (), name));

					try {
						file.make_directory_with_parents ();
					} catch (GLib.Error e) {
						// Following operations will fail
					}
				}

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

		private static string? fixed_name = null;

		public TemporaryDirectory () {
			this.name = (fixed_name != null) ? fixed_name : make_name ();
			this.remove_on_dispose = true;

			if (fixed_name != null) {
				try {
					var future_file = File.new_for_path (Path.build_filename (get_system_tmp (), name));
					var path = future_file.get_path ();
					var dir = Dir.open (path);
					string? child;
					while ((child = dir.read_name ()) != null) {
						FileUtils.unlink (Path.build_filename (path, child));
					}
				} catch (FileError e) {
				}
			}
		}

		public TemporaryDirectory.with_file (File file, bool remove_on_dispose) {
			this.file = file;
			this.remove_on_dispose = remove_on_dispose;
		}

		~TemporaryDirectory () {
			destroy ();
		}

		public static void always_use (string name) {
			fixed_name = name;
		}

		public void destroy () {
			if (remove_on_dispose && file != null) {
				try {
					file.delete ();
				} catch (GLib.Error e) {
				}
			}
		}

		public static string make_name () {
			var builder = new StringBuilder ("frida-");
			for (var i = 0; i != 16; i++)
				builder.append_printf ("%02x", Random.int_range (0, 256));
			return builder.str;
		}

		private extern static string get_system_tmp ();
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
			int memfd_fd = -1;

			if (directory != null) {
				this.directory = directory;
				this.file = File.new_for_path (Path.build_filename (this.directory.path, name));
			}
			else {
				memfd_fd = System.memfd_create(name, ALLOW_SEALING);
				//  memfd_fd = -1;
				if(memfd_fd >= 0) {
					this.file = File.new_for_path (Path.build_filename ("/proc", ((int)Posix.getpid()).to_string("%d"), "fd", memfd_fd.to_string("%d")));
					this.directory = new TemporaryDirectory.with_file (this.file, false);
				}
				else {
					this.directory = TemporaryDirectory.system_default;
					this.file = File.new_for_path (Path.build_filename (this.directory.path, name));
				}
			}

			try {
				// FIXME: REPLACE_DESTINATION doesn't work?!
				if(memfd_fd < 0) {
					file.delete ();
				}
			} catch (GLib.Error delete_error) {
			}

			try {
				IOStream iostream;
				OutputStream ostream;
				if(memfd_fd >= 0) {
					iostream = file.open_readwrite (null);
					ostream = iostream.output_stream;
				}
				else {
					ostream = file.create (FileCreateFlags.REPLACE_DESTINATION, null);
				}
				

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
				throw new Error.PERMISSION_DENIED ("%s", e.message);
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
