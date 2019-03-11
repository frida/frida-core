namespace Frida {
	internal class HelperProcess {
		public signal void output (uint pid, int fd, uint8[] data);
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

		public async uint spawn (string path, HostSpawnOptions options) throws Error {
			var helper = yield obtain_for_path (path);
			try {
				return yield helper.spawn (path, options);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async void prepare_exec_transition (uint pid) throws Error {
			var helper = yield obtain_for_pid (pid);
			try {
				yield helper.prepare_exec_transition (pid);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async void await_exec_transition (uint pid) throws Error {
			var helper = yield obtain_for_pid (pid);
			try {
				yield helper.await_exec_transition (pid);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async void cancel_exec_transition (uint pid) throws Error {
			var helper = yield obtain_for_pid (pid);
			try {
				yield helper.cancel_exec_transition (pid);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async void input (uint pid, uint8[] data) throws Error {
			var helper = yield obtain_for_pid (pid);
			try {
				yield helper.input (pid, data);
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

		public async uint inject_library_file (uint pid, string path_template, string entrypoint, string data) throws Error {
			var cpu_type = cpu_type_from_pid (pid);

			string path;
			switch (cpu_type) {
				case Gum.CpuType.IA32:
				case Gum.CpuType.ARM:
				case Gum.CpuType.MIPS:
					path = path_template.printf (32);
					break;

				case Gum.CpuType.AMD64:
				case Gum.CpuType.ARM64:
					path = path_template.printf (64);
					break;

				default:
					assert_not_reached ();
			}

			var helper = yield obtain_for_cpu_type (cpu_type);
			try {
				return yield helper.inject_library_file (pid, path, entrypoint, data, resource_store.tempdir.path);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async uint demonitor_and_clone_injectee_state (uint id) throws Error {
			var helper = yield obtain_for_injectee_id (id);
			try {
				return yield helper.demonitor_and_clone_injectee_state (id);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async void recreate_injectee_thread (uint pid, uint id) throws Error {
			var helper = yield obtain_for_injectee_id (id);
			try {
				yield helper.recreate_injectee_thread (pid, id);
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
			switch (cpu_type) {
				case Gum.CpuType.IA32:
				case Gum.CpuType.ARM:
				case Gum.CpuType.MIPS:
					return yield obtain_for_32bit ();

				case Gum.CpuType.AMD64:
				case Gum.CpuType.ARM64:
					return yield obtain_for_64bit ();

				default:
					assert_not_reached ();
			}
		}

		private async Helper obtain_for_injectee_id (uint id) throws Error {
			if (id % 2 != 0)
				return yield obtain_for_32bit ();
			else
				return yield obtain_for_64bit ();
		}

		private async Helper obtain_for_32bit () throws Error {
			if (factory32 == null) {
				if (resource_store.helper32 == null)
					throw new Error.NOT_SUPPORTED ("Unable to handle 32-bit processes due to build configuration");
				factory32 = new HelperFactory (resource_store.helper32, resource_store, main_context);
				factory32.output.connect (on_factory_output);
				factory32.uninjected.connect (on_factory_uninjected);
			}

			return yield factory32.obtain ();
		}

		private async Helper obtain_for_64bit () throws Error {
			if (factory64 == null) {
				if (resource_store.helper64 == null)
					throw new Error.NOT_SUPPORTED ("Unable to handle 64-bit processes due to build configuration");
				factory64 = new HelperFactory (resource_store.helper64, resource_store, main_context);
				factory64.output.connect (on_factory_output);
				factory64.uninjected.connect (on_factory_uninjected);
			}

			return yield factory64.obtain ();
		}

		private void on_factory_output (uint pid, int fd, uint8[] data) {
			output (pid, fd, data);
		}

		private void on_factory_uninjected (uint id) {
			uninjected (id);
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
	}

	private class HelperFactory {
		public signal void output (uint pid, int fd, uint8[] data);
		public signal void uninjected (uint id);

		private TemporaryFile helper_file;
		private ResourceStore resource_store;
		private MainContext? main_context;
		private Object process;
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
				} catch (GLib.Error e) {
				}
			}

			if (connection != null) {
				try {
					yield connection.close ();
				} catch (GLib.Error e) {
				}
			}

			process = null;
		}

		public async Helper obtain () throws Error {
			if (obtain_request != null) {
				var future = obtain_request.future;
				try {
					return yield future.wait_async ();
				} catch (Gee.FutureError future_error) {
					throw (Error) future.exception;
				}
			}
			obtain_request = new Gee.Promise<Helper> ();

			SuperSU.Process pending_superprocess = null;
			Subprocess pending_subprocess = null;
			DBusConnection pending_connection = null;
			Helper pending_proxy = null;
			Error pending_error = null;

			DBusServer server = null;
			TimeoutSource timeout_source = null;

			try {
				server = new DBusServer.sync ("unix:tmpdir=" + resource_store.tempdir.path, DBusServerFlags.AUTHENTICATION_ALLOW_ANONYMOUS, DBus.generate_guid ());
				server.start ();

				var tokens = server.client_address.split ("=", 2);

				resource_store.manage (new TemporaryFile (File.new_for_path (tokens[1]), resource_store.tempdir));

				var connection_handler = server.new_connection.connect ((c) => {
					pending_connection = c;
					obtain.callback ();
					return true;
				});

				timeout_source = new TimeoutSource.seconds (10);
				timeout_source.set_callback (() => {
					pending_error = new Error.TIMED_OUT ("Unexpectedly timed out while spawning helper process");
					obtain.callback ();
					return false;
				});
				timeout_source.attach (main_context);

				try {
					pending_superprocess = yield SuperSU.spawn ("/", new string[] { "su", "-c", helper_file.path, server.client_address });
				} catch (Error e) {
					string[] argv = { helper_file.path, server.client_address };
					pending_subprocess = new Subprocess.newv (argv, SubprocessFlags.STDIN_INHERIT);
				}

				yield;

				server.disconnect (connection_handler);
				server.stop ();
				server = null;
				timeout_source.destroy ();
				timeout_source = null;

				if (pending_error == null) {
					pending_proxy = yield pending_connection.get_proxy (null, ObjectPath.HELPER);
				}
			} catch (GLib.Error e) {
				if (timeout_source != null)
					timeout_source.destroy ();
				if (server != null)
					server.stop ();
				pending_error = new Error.PERMISSION_DENIED (e.message);
			}

			if (pending_error == null) {
				if (pending_superprocess != null)
					process = pending_superprocess;
				else
					process = pending_subprocess;

				connection = pending_connection;
				connection.on_closed.connect (on_connection_closed);

				proxy = pending_proxy;
				proxy.output.connect (on_output);
				proxy.uninjected.connect (on_uninjected);

				obtain_request.set_value (proxy);
				return proxy;
			} else {
				if (pending_subprocess != null)
					pending_subprocess.force_exit ();
				obtain_request.set_exception (pending_error);
				obtain_request = null;
				throw pending_error;
			}
		}

		private void on_connection_closed (bool remote_peer_vanished, GLib.Error? error) {
			obtain_request = null;

			proxy.output.disconnect (on_output);
			proxy.uninjected.disconnect (on_uninjected);
			proxy = null;

			connection.on_closed.disconnect (on_connection_closed);
			connection = null;

			process = null;
		}

		private void on_output (uint pid, int fd, uint8[] data) {
			output (pid, fd, data);
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
			tempdir = new TemporaryDirectory ();
			FileUtils.chmod (tempdir.path, 0755);
#if ANDROID
			SELinux.setfilecon (tempdir.path, "u:object_r:frida_file:s0");
#endif

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

		public void manage (TemporaryFile file) {
			files.add (file);
		}
	}
}
