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

		private ResourceStore resource_store {
			get {
				if (_resource_store == null) {
					try {
						_resource_store = new ResourceStore (tempdir);
					} catch (Error e) {
						assert_not_reached ();
					}
				}
				return _resource_store;
			}
		}
		private ResourceStore _resource_store;

		private MainContext main_context;
		private Subprocess process;
		private TaskPort task;
		private DBusConnection connection;
		private DarwinRemoteHelper proxy;
		private Gee.Promise<DarwinRemoteHelper> obtain_request;

		public DarwinHelperProcess (TemporaryDirectory tempdir) {
			Object (tempdir: tempdir);
		}

		construct {
			main_context = MainContext.get_thread_default ();
		}

		public async void close () {
			var proc = process;

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

			if (proc != null) {
				try {
					yield proc.wait_async ();
				} catch (GLib.Error e) {
				}
			}

			_resource_store = null;
		}

		public async void preload () throws Error {
			yield obtain ();
		}

		public async void enable_spawn_gating () throws Error {
			var helper = yield obtain ();
			try {
				yield helper.enable_spawn_gating ();
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async void disable_spawn_gating () throws Error {
			var helper = yield obtain ();
			try {
				yield helper.disable_spawn_gating ();
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async HostSpawnInfo[] enumerate_pending_spawn () throws Error {
			var helper = yield obtain ();
			try {
				return yield helper.enumerate_pending_spawn ();
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async uint spawn (string path, HostSpawnOptions options) throws Error {
			var helper = yield obtain ();
			try {
				return yield helper.spawn (path, options);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async void launch (string identifier, HostSpawnOptions options) throws Error {
			var helper = yield obtain ();
			try {
				yield helper.launch (identifier, options);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async void notify_launch_completed (string identifier, uint pid) throws Error {
			var helper = yield obtain ();
			try {
				yield helper.notify_launch_completed (identifier, pid);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async void wait_until_suspended (uint pid) throws Error {
			var helper = yield obtain ();
			try {
				yield helper.wait_until_suspended (pid);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async void cancel_pending_waits (uint pid) throws Error {
			var helper = yield obtain ();
			try {
				yield helper.cancel_pending_waits (pid);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async void input (uint pid, uint8[] data) throws Error {
			var helper = yield obtain ();
			try {
				yield helper.input (pid, data);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async void resume (uint pid) throws Error {
			var helper = yield obtain ();
			try {
				yield helper.resume (pid);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async void kill_process (uint pid) throws Error {
			var helper = yield obtain ();
			try {
				yield helper.kill_process (pid);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async void kill_application (string identifier) throws Error {
			var helper = yield obtain ();
			try {
				yield helper.kill_application (identifier);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async uint inject_library_file (uint pid, string path, string entrypoint, string data) throws Error {
			var helper = yield obtain ();
			try {
				return yield helper.inject_library_file (pid, path, entrypoint, data);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async uint inject_library_blob (uint pid, string name, MappedLibraryBlob blob, string entrypoint, string data) throws Error {
			var helper = yield obtain ();
			try {
				return yield helper.inject_library_blob (pid, name, blob, entrypoint, data);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async uint demonitor_and_clone_injectee_state (uint id) throws Error {
			var helper = yield obtain ();
			try {
				return yield helper.demonitor_and_clone_injectee_state (id);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async void recreate_injectee_thread (uint pid, uint id) throws Error {
			var helper = yield obtain ();
			try {
				yield helper.recreate_injectee_thread (pid, id);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async Gee.Promise<IOStream> open_pipe_stream (uint remote_pid, out string remote_address) throws Error {
			var helper = yield obtain ();
			try {
				var endpoints = yield helper.make_pipe_endpoints (remote_pid);

				remote_address = endpoints.remote_address;

				return Pipe.open (endpoints.local_address);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async MappedLibraryBlob? try_mmap (Bytes blob) throws Error {
			if (!DarwinHelperBackend.is_mmap_available ())
				return null;

			yield obtain ();

			return DarwinHelperBackend.mmap (task.mach_port, blob);
		}

		private async DarwinRemoteHelper obtain () throws Error {
			if (obtain_request != null) {
				try {
					return yield obtain_request.future.wait_async ();
				} catch (Gee.FutureError future_error) {
					throw new Error.INVALID_OPERATION (future_error.message);
				}
			}
			obtain_request = new Gee.Promise<DarwinRemoteHelper> ();

			Subprocess pending_process = null;
			TaskPort pending_task_port = null;
			DBusConnection pending_connection = null;
			DarwinRemoteHelper pending_proxy = null;
			Error pending_error = null;

			var service_name = make_service_name ();

			try {
				var handshake_port = new HandshakePort.local (service_name);

				string[] argv = { resource_store.helper.path, service_name };
				pending_process = new Subprocess.newv (argv, SubprocessFlags.STDIN_INHERIT);

				var peer_pid = (uint) uint64.parse (pending_process.get_identifier ());
				IOStream stream;
				yield handshake_port.exchange (peer_pid, out pending_task_port, out stream);

				pending_connection = yield new DBusConnection (stream, null, DBusConnectionFlags.NONE, null, null);
				pending_proxy = yield pending_connection.get_proxy (null, ObjectPath.HELPER);
			} catch (GLib.Error e) {
				pending_error = new Error.PERMISSION_DENIED (e.message);
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
			proxy.uninjected.disconnect (on_uninjected);
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

		private void on_uninjected (uint id) {
			uninjected (id);
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
