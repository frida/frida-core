namespace Frida {
	public class DarwinHelperProcess : Object, DarwinHelper {
		public uint pid {
			get {
				return (uint) process_pid;
			}
		}

		public TemporaryDirectory tempdir {
			get;
			construct;
		}

		private ResourceStore _resource_store;

		private MainContext main_context;
		private Pid process_pid;
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

			process_pid = 0;

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

			try {
				var proxy = yield launch_helper (cancellable);
				obtain_request.resolve (proxy);
				return proxy;
			} catch (GLib.Error e) {
				if (e is Error.PROCESS_NOT_FOUND && get_resource_store ().maybe_thin_helper_to_basic_abi ()) {
					try {
						var proxy = yield launch_helper (cancellable);
						obtain_request.resolve (proxy);
						return proxy;
					} catch (GLib.Error e) {
						obtain_request.reject (e);
						obtain_request = null;
						throw_api_error (e);
					}
				}

				obtain_request.reject (e);
				obtain_request = null;
				throw_api_error (e);
			}
		}

		private async DarwinRemoteHelper launch_helper (Cancellable? cancellable) throws Error, IOError {
			Pid pending_pid = 0;
			TaskPort pending_task_port = null;
			DBusConnection pending_connection = null;
			DarwinRemoteHelper pending_proxy = null;

			var service_name = make_service_name ();

			try {
				var handshake_port = new HandshakePort.local (service_name);

				string[] argv = { get_resource_store ().helper.path, service_name };

				GLib.SpawnFlags flags = GLib.SpawnFlags.LEAVE_DESCRIPTORS_OPEN | /* GLib.SpawnFlags.CLOEXEC_PIPES */ 256;
				GLib.Process.spawn_async (null, argv, null, flags, null, out pending_pid);

				IOStream stream;
				yield handshake_port.exchange (pending_pid, out pending_task_port, out stream);

				pending_connection = yield new DBusConnection (stream, null, NONE, null, cancellable);
				pending_proxy = yield pending_connection.get_proxy (null, ObjectPath.HELPER, DBusProxyFlags.NONE,
					cancellable);
			} catch (GLib.Error e) {
				if (e is Error.PROCESS_NOT_FOUND || e is IOError.CANCELLED)
					throw_api_error (e);

				if (pending_pid != 0)
					Posix.kill ((Posix.pid_t) pending_pid, Posix.Signal.KILL);

				throw new Error.PERMISSION_DENIED ("%s", e.message);
			}

			process_pid = pending_pid;
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

			return proxy;
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

			process_pid = 0;
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

#if MACOS && ARM64
		private bool thinned = false;
#endif

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

		public bool maybe_thin_helper_to_basic_abi () {
#if MACOS && ARM64
			if (thinned)
				return false;

			var blob = Frida.Data.Helper.get_frida_helper_blob ();

			var input = new DataInputStream (new MemoryInputStream.from_data (blob.data, null));
			input.byte_order = BIG_ENDIAN;

			try {
				const uint32 fat_magic = 0xcafebabeU;
				var magic = input.read_uint32 ();
				if (magic != fat_magic)
					return false;

				uint32 arm64e_offset = 0;

				uint32 arm64_offset = 0;
				uint32 arm64_size = 0;

				var nfat_arch = input.read_uint32 ();
				for (uint32 i = 0; i != nfat_arch; i++) {
					var cputype = input.read_uint32 ();
					var cpusubtype = input.read_uint32 ();
					var offset = input.read_uint32 ();
					var size = input.read_uint32 ();
					input.skip (4);

					bool is_arm64 = cputype == 0x0100000cU;
					bool is_arm64e = is_arm64 && (cpusubtype & 0x00ffffffU) == 2;
					if (is_arm64e) {
						arm64e_offset = offset;
					} else if (is_arm64) {
						arm64_offset = offset;
						arm64_size = size;
					}
				}

				if (arm64e_offset == 0 || arm64_offset == 0)
					return false;

				FileUtils.set_data (helper.path, blob.data[arm64_offset:arm64_offset + arm64_size]);
				FileUtils.chmod (helper.path, 0700);

				thinned = true;

				return true;
			} catch (GLib.Error e) {
			}
#endif

			return false;
		}
	}
}
