namespace Frida {
	public class LinuxHelperProcess : Object, LinuxHelper {
		public TemporaryDirectory tempdir {
			get;
			construct;
		}

		private ResourceStore? _resource_store;

		private MainContext main_context;
		private HelperFactory? factory32;
		private HelperFactory? factory64;
		private Gee.Map<uint, LinuxHelper> injectee_ids = new Gee.HashMap<uint, LinuxHelper> ();

		public LinuxHelperProcess (TemporaryDirectory tempdir) {
			Object (tempdir: tempdir);
		}

		construct {
			main_context = MainContext.get_thread_default ();
		}

		public async void close (Cancellable? cancellable) throws IOError {
			injectee_ids.clear ();

			if (factory32 != null) {
				yield factory32.close (cancellable);
				factory32 = null;
			}

			if (factory64 != null) {
				yield factory64.close (cancellable);
				factory64 = null;
			}

			_resource_store = null;
		}

		private ResourceStore get_resource_store () throws Error {
			if (_resource_store == null)
				_resource_store = new ResourceStore (tempdir);
			return _resource_store;
		}

		public async uint spawn (string path, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain_for_path (path, cancellable);
			return yield helper.spawn (path, options, cancellable);
		}

		public async void prepare_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain_for_pid (pid, cancellable);
			yield helper.prepare_exec_transition (pid, cancellable);
		}

		public async void await_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain_for_pid (pid, cancellable);
			yield helper.await_exec_transition (pid, cancellable);
		}

		public async void cancel_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain_for_pid (pid, cancellable);
			yield helper.cancel_exec_transition (pid, cancellable);
		}

		public async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain_for_pid (pid, cancellable);
			yield helper.input (pid, data, cancellable);
		}

		public async void resume (uint pid, Cancellable? cancellable) throws Error, IOError {
			var cpu_type = cpu_type_from_pid (pid);
			var helper = yield obtain_for_cpu_type (cpu_type, cancellable);
			try {
				yield helper.resume (pid, cancellable);
			} catch (Error e) {
				if (!(e is Error.INVALID_ARGUMENT))
					throw e;
				if (cpu_type == Gum.CpuType.AMD64 || cpu_type == Gum.CpuType.ARM64)
					helper = yield obtain_for_32bit (cancellable);
				else
					helper = yield obtain_for_64bit (cancellable);
				yield helper.resume (pid, cancellable);
			}
		}

		public async void kill (uint pid, Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain_for_pid (pid, cancellable);
			try {
				yield helper.kill (pid, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void inject_library_file (uint pid, PathTemplate path_template, string entrypoint, string data,
				string temp_path, uint id, Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain_for_cpu_type (cpu_type_from_pid (pid), cancellable);
			try {
				yield helper.inject_library_file (pid, path_template, entrypoint, data, temp_path, id, cancellable);
				injectee_ids[id] = helper;
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void demonitor_and_clone_injectee_state (uint id, uint clone_id, Cancellable? cancellable)
				throws Error, IOError {
			var helper = obtain_for_injectee_id (id);
			try {
				yield helper.demonitor_and_clone_injectee_state (id, clone_id, cancellable);
				injectee_ids[clone_id] = helper;
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void recreate_injectee_thread (uint pid, uint id, Cancellable? cancellable) throws Error, IOError {
			var helper = obtain_for_injectee_id (id);
			try {
				yield helper.recreate_injectee_thread (pid, id, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		private LinuxHelper obtain_for_injectee_id (uint id) throws Error, IOError {
			var helper = injectee_ids[id];
			if (helper == null)
				throw new Error.INVALID_ARGUMENT ("Invalid injectee ID");
			return helper;
		}

		private async LinuxHelper obtain_for_path (string path, Cancellable? cancellable) throws Error, IOError {
			return yield obtain_for_cpu_type (cpu_type_from_file (path), cancellable);
		}

		private async LinuxHelper obtain_for_pid (uint pid, Cancellable? cancellable) throws Error, IOError {
			return yield obtain_for_cpu_type (cpu_type_from_pid (pid), cancellable);
		}

		private async LinuxHelper obtain_for_cpu_type (Gum.CpuType cpu_type, Cancellable? cancellable) throws Error, IOError {
			switch (cpu_type) {
				case Gum.CpuType.IA32:
				case Gum.CpuType.ARM:
				case Gum.CpuType.MIPS:
					return yield obtain_for_32bit (cancellable);

				case Gum.CpuType.AMD64:
				case Gum.CpuType.ARM64:
					return yield obtain_for_64bit (cancellable);

				default:
					assert_not_reached ();
			}
		}

		private async LinuxHelper obtain_for_32bit (Cancellable? cancellable) throws Error, IOError {
			if (factory32 == null) {
				var store = get_resource_store ();
				if (sizeof (void *) != 4 && store.helper32 == null)
					throw new Error.NOT_SUPPORTED ("Unable to handle 32-bit processes due to build configuration");
				factory32 = new HelperFactory (store.helper32, store, main_context);
				factory32.lost.connect (on_factory_lost);
				factory32.output.connect (on_factory_output);
				factory32.uninjected.connect (on_factory_uninjected);
			}

			return yield factory32.obtain (cancellable);
		}

		private async LinuxHelper obtain_for_64bit (Cancellable? cancellable) throws Error, IOError {
			if (factory64 == null) {
				var store = get_resource_store ();
				if (sizeof (void *) != 8 && store.helper64 == null)
					throw new Error.NOT_SUPPORTED ("Unable to handle 64-bit processes due to build configuration");
				factory64 = new HelperFactory (store.helper64, store, main_context);
				factory64.lost.connect (on_factory_lost);
				factory64.output.connect (on_factory_output);
				factory64.uninjected.connect (on_factory_uninjected);
			}

			return yield factory64.obtain (cancellable);
		}

		private void on_factory_lost (LinuxHelper helper) {
			var dead_ids = new Gee.ArrayList<uint> ();
			foreach (var e in injectee_ids.entries) {
				if (e.value == helper)
					dead_ids.add (e.key);
			}

			foreach (var id in dead_ids) {
				injectee_ids.unset (id);

				uninjected (id);
			}
		}

		private void on_factory_output (uint pid, int fd, uint8[] data) {
			output (pid, fd, data);
		}

		private void on_factory_uninjected (uint id) {
			injectee_ids.unset (id);

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
					throw new Error.PERMISSION_DENIED ("%s", e.message);
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
					throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
		}
	}

	private class HelperFactory {
		public signal void lost (LinuxHelper helper);
		public signal void output (uint pid, int fd, uint8[] data);
		public signal void uninjected (uint id);

		private HelperFile? helper_file;
		private ResourceStore? resource_store;
		private MainContext? main_context;
		private SuperSU.Process superprocess;
		private Pid process_pid;
		private DBusConnection connection;
		private LinuxHelper helper;
		private Promise<LinuxHelper> obtain_request;

		public HelperFactory (HelperFile? helper_file, ResourceStore resource_store, MainContext? main_context) {
			this.helper_file = helper_file;
			this.resource_store = resource_store;
			this.main_context = main_context;
		}

		public async void close (Cancellable? cancellable) throws IOError {
			if (helper != null) {
				yield helper.close (cancellable);

				discard_helper ();
			}

			if (connection != null) {
				try {
					yield connection.close (cancellable);
				} catch (GLib.Error e) {
					if (e is IOError.CANCELLED)
						throw (IOError) e;
				}
			}

			if (superprocess != null) {
				yield superprocess.detach (cancellable);
				superprocess = null;
			}
			process_pid = 0;

			resource_store = null;
		}

		public async LinuxHelper obtain (Cancellable? cancellable) throws Error, IOError {
			while (obtain_request != null) {
				try {
					return yield obtain_request.future.wait_async (cancellable);
				} catch (Error e) {
					throw e;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}
			obtain_request = new Promise<LinuxHelper> ();

			if (helper_file == null) {
				assign_helper (new LinuxHelperBackend ());

				obtain_request.resolve (helper);
				return helper;
			}

			SuperSU.Process? pending_superprocess = null;
			Pid pending_pid = 0;
			IOStream? pending_stream = null;
			DBusConnection pending_connection = null;
			LinuxRemoteHelper? pending_proxy = null;
			GLib.Error? pending_error = null;

			SocketService? service = null;
			TimeoutSource? timeout_source = null;

			try {
				string socket_path = Path.build_filename (resource_store.tempdir.path, Uuid.string_random ());
				string socket_address = "unix:abstract=" + socket_path;

				service = new SocketService ();
				SocketAddress effective_address;
				service.add_address (new UnixSocketAddress.with_type (socket_path, -1, ABSTRACT),
					SocketType.STREAM, SocketProtocol.DEFAULT, null, out effective_address);
				service.start ();

				var idle_source = new IdleSource ();
				idle_source.set_callback (() => {
					obtain.callback ();
					return false;
				});
				idle_source.attach (main_context);

				yield;

				var incoming_handler = service.incoming.connect ((c) => {
					pending_stream = c;
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

				string[] envp = Environ.unset_variable (Environ.get (), "LD_LIBRARY_PATH");

				try {
					string cwd = "/";
					string[] argv = new string[] { "su", "-c", helper_file.path, socket_address };
					bool capture_output = false;
					pending_superprocess = yield SuperSU.spawn (cwd, argv, envp, capture_output, cancellable);
				} catch (Error e) {
					string[] argv = { helper_file.path, socket_address };

					GLib.SpawnFlags flags = GLib.SpawnFlags.LEAVE_DESCRIPTORS_OPEN | /* GLib.SpawnFlags.CLOEXEC_PIPES */ 256;
					GLib.Process.spawn_async (null, argv, envp, flags, null, out pending_pid);
				}

				yield;

				service.disconnect (incoming_handler);
				service.stop ();
				service = null;
				timeout_source.destroy ();
				timeout_source = null;

				if (pending_error == null) {
					pending_connection = yield new DBusConnection (pending_stream, null, DBusConnectionFlags.NONE, null,
						cancellable);
					pending_proxy = yield connection.get_proxy (null, ObjectPath.HELPER, DO_NOT_LOAD_PROPERTIES,
						cancellable);
					if (pending_connection.is_closed ())
						throw new Error.NOT_SUPPORTED ("Helper terminated prematurely");
				}
			} catch (GLib.Error e) {
				if (timeout_source != null)
					timeout_source.destroy ();

				if (service != null)
					service.stop ();

				if (e is Error || e is IOError.CANCELLED)
					pending_error = e;
				else
					pending_error = new Error.PERMISSION_DENIED ("%s", e.message);
			}

			if (pending_error == null) {
				superprocess = pending_superprocess;
				process_pid = pending_pid;

				connection = pending_connection;
				connection.on_closed.connect (on_connection_closed);

				assign_helper (new HelperSession (pending_proxy));

				obtain_request.resolve (helper);
				return helper;
			} else {
				if (pending_pid != 0)
					Posix.kill ((Posix.pid_t) pending_pid, Posix.Signal.KILL);

				obtain_request.reject (pending_error);
				obtain_request = null;

				throw_api_error (pending_error);
			}
		}

		private void on_connection_closed (bool remote_peer_vanished, GLib.Error? error) {
			obtain_request = null;

			discard_helper ();

			connection.on_closed.disconnect (on_connection_closed);
			connection = null;

			superprocess = null;
			process_pid = 0;
		}

		private void assign_helper (owned LinuxHelper h) {
			helper = h;
			helper.output.connect (on_helper_output);
			helper.uninjected.connect (on_helper_uninjected);
		}

		private void discard_helper () {
			if (helper == null)
				return;

			var h = helper;
			h.output.disconnect (on_helper_output);
			h.uninjected.disconnect (on_helper_uninjected);
			helper = null;

			lost (h);
		}

		private void on_helper_output (uint pid, int fd, uint8[] data) {
			output (pid, fd, data);
		}

		private void on_helper_uninjected (uint id) {
			uninjected (id);
		}
	}

	private class HelperSession : Object, LinuxHelper {
		public LinuxRemoteHelper proxy {
			get;
			construct;
		}

		public HelperSession (LinuxRemoteHelper proxy) {
			Object (proxy: proxy);
		}

		construct {
			proxy.output.connect (on_output);
			proxy.uninjected.connect (on_uninjected);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			try {
				yield proxy.stop (cancellable);
			} catch (GLib.Error e) {
			}

			proxy.output.disconnect (on_output);
			proxy.uninjected.disconnect (on_uninjected);
		}

		public async uint spawn (string path, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError {
			try {
				return yield proxy.spawn (path, options, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void prepare_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			try {
				yield proxy.prepare_exec_transition (pid, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void await_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			try {
				yield proxy.await_exec_transition (pid, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void cancel_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			try {
				yield proxy.cancel_exec_transition (pid, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError {
			try {
				yield proxy.input (pid, data, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void resume (uint pid, Cancellable? cancellable) throws Error, IOError {
			try {
				yield proxy.resume (pid, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void kill (uint pid, Cancellable? cancellable) throws Error, IOError {
			try {
				yield proxy.kill (pid, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void inject_library_file (uint pid, PathTemplate path_template, string entrypoint, string data,
				string temp_path, uint id, Cancellable? cancellable) throws Error, IOError {
			try {
				yield proxy.inject_library_file (pid, path_template, entrypoint, data, temp_path, id, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void demonitor_and_clone_injectee_state (uint id, uint clone_id, Cancellable? cancellable)
				throws Error, IOError {
			try {
				yield proxy.demonitor_and_clone_injectee_state (id, clone_id, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void recreate_injectee_thread (uint pid, uint id, Cancellable? cancellable) throws Error, IOError {
			try {
				yield proxy.recreate_injectee_thread (pid, id, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
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

		public HelperFile? helper32 {
			get;
			private set;
		}

		public HelperFile? helper64 {
			get;
			private set;
		}

		public ResourceStore (TemporaryDirectory tempdir) throws Error {
			this.tempdir = tempdir;

#if HAVE_EMBEDDED_ASSETS
			var blob32 = Frida.Data.Helper.get_frida_helper_32_blob ();
			if (blob32.data.length > 0) {
				helper32 = new TemporaryHelperFile (
					new TemporaryFile.from_stream ("frida-helper-32",
						new MemoryInputStream.from_data (blob32.data, null),
						tempdir));
				FileUtils.chmod (helper32.path, 0700);
			}

			var blob64 = Frida.Data.Helper.get_frida_helper_64_blob ();
			if (blob64.data.length > 0) {
				helper64 = new TemporaryHelperFile (
					new TemporaryFile.from_stream ("frida-helper-64",
						new MemoryInputStream.from_data (blob64.data, null),
						tempdir));
				FileUtils.chmod (helper64.path, 0700);
			}
#else
			HelperFile file = new InstalledHelperFile.for_path (Config.FRIDA_HELPER_PATH);
			if (sizeof (void *) == 8)
				helper64 = file;
			else
				helper32 = file;
#endif
		}
	}
}
