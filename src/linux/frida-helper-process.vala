#if LINUX
namespace Frida {
	internal class HelperProcess {
		public signal void uninjected (uint id);

		public TemporaryDirectory tempdir {
			get {
				return resource_store.tempdir;
			}
		}

		private HelperFactory factory32;
		private HelperFactory factory64;

		private ResourceStore resource_store {
			get {
				if (_resource_store == null) {
					try {
						_resource_store = new ResourceStore ();
					} catch (Error e) {
						assert_not_reached ();
					}
				}
				return _resource_store;
			}
		}
		private ResourceStore _resource_store;

		private MainContext main_context;

		public HelperProcess () {
			this.main_context = MainContext.get_thread_default ();
		}

		public async void close () {
			if (factory32 != null) {
				yield factory32.close ();
				factory32 = null;
			}

			if (factory64 != null) {
				yield factory64.close ();
				factory64 = null;
			}

			_resource_store = null;
		}

		public async uint spawn (string path, string[] argv, string[] envp) throws Error {
			var helper = yield obtain_for_path (path);
			try {
				return yield helper.spawn (path, argv, envp);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async void resume (uint pid) throws Error {
			var helper = yield obtain_for_pid (pid);
			try {
				yield helper.resume (pid);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async void kill (uint pid) throws Error {
			var helper = yield obtain_for_pid (pid);
			try {
				yield helper.kill (pid);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async uint inject (uint pid, string filename_template, string data_string) throws Error {
			var cpu_type = cpu_type_from_pid (pid);

			string filename;
			switch (cpu_type) {
				case Gum.CpuType.IA32:
				case Gum.CpuType.ARM:
					filename = filename_template.printf (32);
					break;

				case Gum.CpuType.AMD64:
				case Gum.CpuType.ARM64:
					filename = filename_template.printf (64);
					break;

				default:
					assert_not_reached ();
			}

			var helper = yield obtain_for_cpu_type (cpu_type);
			try {
				return yield helper.inject (pid, filename, data_string, resource_store.tempdir.path);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		private async Helper obtain_for_path (string path) throws Error {
			return yield obtain_for_cpu_type (cpu_type_from_file (path));
		}

		private async Helper obtain_for_pid (uint pid) throws Error {
			return yield obtain_for_cpu_type (cpu_type_from_pid (pid));
		}

		private async Helper obtain_for_cpu_type (Gum.CpuType cpu_type) throws Error {
			HelperFactory factory = null;
			switch (cpu_type) {
				case Gum.CpuType.IA32:
				case Gum.CpuType.ARM:
					if (factory32 == null) {
						if (resource_store.helper32 == null)
							throw new Error.NOT_SUPPORTED ("Unable to handle 32-bit processes due to build configuration");
						factory32 = new HelperFactory (resource_store.helper32, resource_store, main_context);
						factory32.lost.connect (on_factory_lost);
						factory32.uninjected.connect (on_factory_uninjected);
					}
					factory = factory32;
					break;

				case Gum.CpuType.AMD64:
				case Gum.CpuType.ARM64:
					if (factory64 == null) {
						if (resource_store.helper64 == null)
							throw new Error.NOT_SUPPORTED ("Unable to handle 64-bit processes due to build configuration");
						factory64 = new HelperFactory (resource_store.helper64, resource_store, main_context);
						factory64.lost.connect (on_factory_lost);
						factory64.uninjected.connect (on_factory_uninjected);
					}
					factory = factory64;
					break;

				default:
					assert_not_reached ();
			}
			return yield factory.obtain ();
		}

		private static Gum.CpuType cpu_type_from_file (string path) throws Error {
			try {
				return Gum.Linux.cpu_type_from_file (path);
			} catch (GLib.Error e) {
				if (e is IOError.NOT_FOUND)
					throw new Error.EXECUTABLE_NOT_FOUND ("Unable to find executable at '%s'".printf (path));
				else if (e is IOError.NOT_SUPPORTED)
					throw new Error.EXECUTABLE_NOT_SUPPORTED ("Unable to spawn executable at '%s': unsupported file format".printf (path));
				else
					throw new Error.PERMISSION_DENIED (e.message);
			}
		}

		private static Gum.CpuType cpu_type_from_pid (uint pid) throws Error {
			try {
				return Gum.Linux.cpu_type_from_pid ((Posix.pid_t) pid);
			} catch (GLib.Error e) {
				if (e is FileError.NOENT)
					throw new Error.PROCESS_NOT_FOUND ("Unable to find process with pid %u".printf (pid));
				else if (e is FileError.ACCES)
					throw new Error.PERMISSION_DENIED ("Unable to access process with pid %u from the current user account".printf (pid));
				else
					throw new Error.NOT_SUPPORTED (e.message);
			}
		}

		private void on_factory_lost (HelperFactory factory) {
			factory.lost.disconnect (on_factory_lost);
			factory.uninjected.disconnect (on_factory_uninjected);
			if (factory == factory32) {
				factory32 = null;
			} else if (factory == factory64) {
				factory64 = null;
			}
		}

		private void on_factory_uninjected (uint id) {
			uninjected (id);
		}
	}

	private class HelperFactory {
		public signal void lost (HelperFactory factory);
		public signal void uninjected (uint id);

		private TemporaryFile helper_file;
		private ResourceStore resource_store;
		private MainContext? main_context;
		private Subprocess process;
		private DBusConnection connection;
		private Helper proxy;
		private Gee.Promise<Helper> obtain_request;

		public HelperFactory (TemporaryFile helper_file, ResourceStore resource_store, MainContext? main_context) {
			this.helper_file = helper_file;
			this.resource_store = resource_store;
			this.main_context = main_context;
		}

		public async void close () {
			if (proxy != null) {
				try {
					yield proxy.stop ();
				} catch (GLib.Error proxy_error) {
				}
				proxy.uninjected.disconnect (on_uninjected);
				proxy = null;
			}

			if (connection != null) {
				connection.closed.disconnect (on_connection_closed);
				try {
					yield connection.close ();
				} catch (GLib.Error connection_error) {
				}
				connection = null;
			}
		}

		public async Helper obtain () throws Error {
			if (obtain_request != null) {
				try {
					return yield obtain_request.future.wait_async ();
				} catch (Gee.FutureError future_error) {
					throw new Error.INVALID_OPERATION (future_error.message);
				}
			}
			obtain_request = new Gee.Promise<Helper> ();

			Subprocess pending_process = null;
			DBusConnection pending_connection = null;
			Helper pending_proxy = null;
			Error pending_error = null;

			try {
				string[] argv = { helper_file.path };
				pending_process = new Subprocess.newv (argv, SubprocessFlags.STDIN_PIPE | SubprocessFlags.STDOUT_PIPE);
				var stream = new SimpleIOStream (pending_process.get_stdout_pipe (), pending_process.get_stdin_pipe ());
				pending_connection = yield DBusConnection.new (stream, null, DBusConnectionFlags.NONE);
				pending_proxy = yield pending_connection.get_proxy (null, ObjectPath.HELPER);
			} catch (GLib.Error e) {
				pending_error = new Error.NOT_SUPPORTED ("Unexpected error while spawning helper process: " + e.message);
			}

			if (pending_error == null) {
				process = pending_process;
				connection = pending_connection;
				connection.closed.connect (on_connection_closed);
				proxy = pending_proxy;
				proxy.uninjected.connect (on_uninjected);

				obtain_request.set_value (proxy);
				return proxy;
			} else {
				if (pending_process != null)
					pending_process.force_exit ();
				obtain_request.set_exception (pending_error);
				obtain_request = null;
				throw pending_error;
			}
		}

		private void on_connection_closed (bool remote_peer_vanished, GLib.Error? error) {
			proxy.uninjected.disconnect (on_uninjected);
			connection.closed.disconnect (on_connection_closed);
			lost (this);
		}

		private void on_uninjected (uint id) {
			uninjected (id);
		}
	}

	private class ResourceStore {
		public TemporaryDirectory tempdir {
			get;
			private set;
		}

		public TemporaryFile? helper32 {
			get;
			private set;
		}

		public TemporaryFile? helper64 {
			get;
			private set;
		}

		private Gee.ArrayList<TemporaryFile> files = new Gee.ArrayList<TemporaryFile> ();

		public ResourceStore () throws Error {
#if ANDROID
			/*
			 * We used to write our temporary files to /data/local/tmp, but it turns out that this
			 * filesystem is mounted `noexec` on some devices. Because of this constraint we instead
			 * write to a .frida-<random-id> directory next to the application, which we know resides
			 * on a filesystem without `noexec`. The user or packager will have to guarantee that the
			 * enclosing directory is o+rx so apps can access the FIFOs.
			 */
			try {
				string exe_dir = Path.get_dirname (FileUtils.read_link ("/proc/self/exe"));
				File f = File.new_for_path (Path.build_filename (exe_dir, TemporaryDirectory.make_name ()));
				f.make_directory ();
				tempdir = new TemporaryDirectory.with_file (f, true);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
#else
			tempdir = new TemporaryDirectory ();
#endif
			FileUtils.chmod (tempdir.path, 0755);

			var blob32 = Frida.Data.Helper.get_frida_helper_32_blob ();
			if (blob32.data.length > 0) {
				helper32 = new TemporaryFile.from_stream ("frida-helper-32",
					new MemoryInputStream.from_data (blob32.data, null),
					tempdir);
				FileUtils.chmod (helper32.path, 0700);
			}

			var blob64 = Frida.Data.Helper.get_frida_helper_64_blob ();
			if (blob64.data.length > 0) {
				helper64 = new TemporaryFile.from_stream ("frida-helper-64",
					new MemoryInputStream.from_data (blob64.data, null),
					tempdir);
				FileUtils.chmod (helper64.path, 0700);
			}
		}

		~ResourceStore () {
			foreach (var file in files)
				file.destroy ();
			if (helper64 != null)
				helper64.destroy ();
			if (helper32 != null)
				helper32.destroy ();
			tempdir.destroy ();
		}
	}
}
#endif
