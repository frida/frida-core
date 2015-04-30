#if DARWIN
namespace Frida {
	internal class HelperProcess {
		public signal void uninjected (uint id);

		public TemporaryDirectory tempdir {
			get {
				return resource_store.tempdir;
			}
		}

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
		private Subprocess process;
		private DBusConnection connection;
		private Helper proxy;
		private Gee.Promise<Helper> obtain_request;

		public HelperProcess () {
			this.main_context = MainContext.get_thread_default ();
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

			_resource_store = null;
		}

		public async uint spawn (string path, string[] argv, string[] envp) throws Error {
			var helper = yield obtain ();
			try {
				return yield helper.spawn (path, argv, envp);
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

		public async uint inject (uint pid, string filename, string data_string) throws Error {
			var helper = yield obtain ();
			try {
				return yield helper.inject (pid, filename, data_string);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async PipeEndpoints make_pipe_endpoints (uint local_pid, uint remote_pid) throws Error {
			var helper = yield obtain ();
			try {
				return yield helper.make_pipe_endpoints (local_pid, remote_pid);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		private async Helper obtain () throws Error {
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
				string[] argv = { resource_store.helper.path };
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
				throw pending_error;
			}
		}

		private void on_connection_closed (bool remote_peer_vanished, GLib.Error? error) {
			proxy.uninjected.disconnect (on_uninjected);
			connection.closed.disconnect (on_connection_closed);
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

		public TemporaryFile helper {
			get;
			private set;
		}

		public TemporaryFile pipe {
			get;
			set;
		}

		public ResourceStore () throws Error {
			tempdir = new TemporaryDirectory ();
			FileUtils.chmod (tempdir.path, 0755);
			var blob = Frida.Data.Helper.get_frida_helper_blob ();
			helper = new TemporaryFile.from_stream ("frida-helper",
				new MemoryInputStream.from_data (blob.data, null),
				tempdir);
			FileUtils.chmod (helper.path, 0700);
		}

		~ResourceStore () {
			if (pipe != null)
				pipe.destroy ();
			helper.destroy ();
			tempdir.destroy ();
		}
	}
}
#endif
