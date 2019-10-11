namespace Frida {
	public class DarwinHelperProcess : Object, DarwinHelper {
		public uint pid {
			get {
				if (process == null)
					return 0;

				return (uint) uint64.parse (process.get_identifier ());
			}
		}

		public TemporaryDirectory tempdir {
			get;
			construct;
		}

		private ResourceStore _resource_store;

		private MainContext main_context;
		private Subprocess process;
		private TaskPort task;
		private DBusConnection connection;
		private DarwinRemoteHelper proxy;
		private Promise<DarwinRemoteHelper> obtain_request;

		public DarwinHelperProcess (TemporaryDirectory tempdir) {
			Object (tempdir: tempdir);
		}

		construct {
			main_context = MainContext.get_thread_default ();
		}

		public async void close (Cancellable? cancellable) throws IOError {
			if (proxy != null) {
				try {
					yield proxy.stop (cancellable);
				} catch (GLib.Error e) {
					if (e is IOError.CANCELLED)
						throw (IOError) e;
				}
			}

			if (connection != null) {
				try {
					yield connection.close (cancellable);
				} catch (GLib.Error e) {
					if (e is IOError.CANCELLED)
						throw (IOError) e;
				}
			}

			process = null;

			_resource_store = null;
		}

		private ResourceStore get_resource_store () throws Error {
			if (_resource_store == null)
				_resource_store = new ResourceStore (tempdir);
			return _resource_store;
		}

		public async void preload (Cancellable? cancellable) throws Error, IOError {
			yield obtain (cancellable);
		}

		public async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain (cancellable);
			try {
				yield helper.enable_spawn_gating (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain (cancellable);
			try {
				yield helper.disable_spawn_gating (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain (cancellable);
			try {
				return yield helper.enumerate_pending_spawn (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async uint spawn (string path, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain (cancellable);
			try {
				return yield helper.spawn (path, options, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void launch (string identifier, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain (cancellable);
			try {
				yield helper.launch (identifier, options, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void notify_launch_completed (string identifier, uint pid, Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain (cancellable);
			try {
				yield helper.notify_launch_completed (identifier, pid, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void notify_exec_completed (uint pid, Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain (cancellable);
			try {
				yield helper.notify_exec_completed (pid, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void wait_until_suspended (uint pid, Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain (cancellable);
			try {
				yield helper.wait_until_suspended (pid, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void cancel_pending_waits (uint pid, Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain (cancellable);
			try {
				yield helper.cancel_pending_waits (pid, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain (cancellable);
			try {
				yield helper.input (pid, data, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void resume (uint pid, Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain (cancellable);
			try {
				yield helper.resume (pid, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void kill_process (uint pid, Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain (cancellable);
			try {
				yield helper.kill_process (pid, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void kill_application (string identifier, Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain (cancellable);
			try {
				yield helper.kill_application (identifier, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async uint inject_library_file (uint pid, string path, string entrypoint, string data, Cancellable? cancellable)
				throws Error, IOError {
			var helper = yield obtain (cancellable);
			try {
				return yield helper.inject_library_file (pid, path, entrypoint, data, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async uint inject_library_blob (uint pid, string name, MappedLibraryBlob blob, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain (cancellable);
			try {
				return yield helper.inject_library_blob (pid, name, blob, entrypoint, data, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async uint demonitor_and_clone_injectee_state (uint id, Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain (cancellable);
			try {
				return yield helper.demonitor_and_clone_injectee_state (id, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void recreate_injectee_thread (uint pid, uint id, Cancellable? cancellable) throws Error, IOError {
			var helper = yield obtain (cancellable);
			try {
				yield helper.recreate_injectee_thread (pid, id, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async Future<IOStream> open_pipe_stream (uint remote_pid, Cancellable? cancellable, out string remote_address)
				throws Error, IOError {
			var helper = yield obtain (cancellable);
			try {
				var endpoints = yield helper.make_pipe_endpoints (remote_pid, cancellable);

				remote_address = endpoints.remote_address;

				return Pipe.open (endpoints.local_address, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async MappedLibraryBlob? try_mmap (Bytes blob, Cancellable? cancellable) throws Error, IOError {
			if (!DarwinHelperBackend.is_mmap_available ())
				return null;

			yield obtain (cancellable);

			return DarwinHelperBackend.mmap (task.mach_port, blob);
		}

		private async DarwinRemoteHelper obtain (Cancellable? cancellable) throws Error, IOError {
			while (obtain_request != null) {
				try {
					return yield obtain_request.future.wait_async (cancellable);
				} catch (Error e) {
					throw e;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}
			obtain_request = new Promise<DarwinRemoteHelper> ();

			Subprocess pending_process = null;
			TaskPort pending_task_port = null;
			DBusConnection pending_connection = null;
			DarwinRemoteHelper pending_proxy = null;
			GLib.Error? pending_error = null;

			var service_name = make_service_name ();

			try {
				var handshake_port = new HandshakePort.local (service_name);

				string[] argv = { get_resource_store ().helper.path, service_name };
				pending_process = new Subprocess.newv (argv, SubprocessFlags.STDIN_INHERIT);

				var peer_pid = (uint) uint64.parse (pending_process.get_identifier ());
				IOStream stream;
				yield handshake_port.exchange (peer_pid, out pending_task_port, out stream);

				pending_connection = yield new DBusConnection (stream, null, NONE, null, cancellable);
				pending_proxy = yield pending_connection.get_proxy (null, ObjectPath.HELPER, DBusProxyFlags.NONE,
					cancellable);
			} catch (GLib.Error e) {
				if (e is IOError.CANCELLED)
					pending_error = e;
				else
					pending_error = new Error.PERMISSION_DENIED ("%s", e.message);
			}

			if (pending_error == null) {
				process = pending_process;
				task = pending_task_port;

				connection = pending_connection;
				connection.on_closed.connect (on_connection_closed);

				proxy = pending_proxy;
				proxy.output.connect (on_output);
				proxy.spawn_added.connect (on_spawn_added);
				proxy.spawn_removed.connect (on_spawn_removed);
				proxy.injected.connect (on_injected);
				proxy.uninjected.connect (on_uninjected);
				proxy.process_resumed.connect (on_process_resumed);
				proxy.process_killed.connect (on_process_killed);

				obtain_request.resolve (proxy);
				return proxy;
			} else {
				if (pending_process != null)
					pending_process.force_exit ();

				obtain_request.reject (pending_error);
				obtain_request = null;

				throw_api_error (pending_error);
			}
		}

		private static string make_service_name () {
			var builder = new StringBuilder ("re.frida.Helper");

			builder.append_printf (".%d.", Posix.getpid ());

			for (var i = 0; i != 16; i++)
				builder.append_printf ("%02x", Random.int_range (0, 256));

			return builder.str;
		}

		private void on_connection_closed (bool remote_peer_vanished, GLib.Error? error) {
			obtain_request = null;

			proxy.output.disconnect (on_output);
			proxy.spawn_added.disconnect (on_spawn_added);
			proxy.spawn_removed.disconnect (on_spawn_removed);
			proxy.injected.disconnect (on_injected);
			proxy.uninjected.disconnect (on_uninjected);
			proxy.process_resumed.disconnect (on_process_resumed);
			proxy.process_killed.disconnect (on_process_killed);
			proxy = null;

			connection.on_closed.disconnect (on_connection_closed);
			connection = null;

			process = null;
			task = null;
		}

		private void on_output (uint pid, int fd, uint8[] data) {
			output (pid, fd, data);
		}

		private void on_spawn_added (HostSpawnInfo info) {
			spawn_added (info);
		}

		private void on_spawn_removed (HostSpawnInfo info) {
			spawn_removed (info);
		}

		private void on_injected (uint id, uint pid, bool has_mapped_module, DarwinModuleDetails mapped_module) {
			injected (id, pid, has_mapped_module, mapped_module);
		}

		private void on_uninjected (uint id) {
			uninjected (id);
		}

		private void on_process_resumed (uint pid) {
			process_resumed (pid);
		}

		private void on_process_killed (uint pid) {
			process_killed (pid);
		}
	}

	private class ResourceStore {
		public TemporaryFile helper {
			get;
			private set;
		}

		public ResourceStore (TemporaryDirectory tempdir) throws Error {
			FileUtils.chmod (tempdir.path, 0755);

			var blob = Frida.Data.Helper.get_frida_helper_blob ();
			helper = new TemporaryFile.from_stream ("frida-helper",
				new MemoryInputStream.from_data (blob.data, null),
				tempdir);
			FileUtils.chmod (helper.path, 0700);
		}

		~ResourceStore () {
			helper.destroy ();
		}
	}
}
