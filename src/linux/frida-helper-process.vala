#if LINUX
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
					} catch (IOError e) {
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
			if (proxy != null) {
				try {
					yield proxy.stop ();
				} catch (IOError proxy_error) {
				}
				proxy.uninjected.disconnect (on_uninjected);
				proxy = null;
			}

			if (connection != null) {
				connection.closed.disconnect (on_connection_closed);
				try {
					yield connection.close ();
				} catch (Error connection_error) {
				}
				connection = null;
			}

			_resource_store = null;
		}

		public async uint spawn (string path, string[] argv, string[] envp) throws IOError {
			var helper = yield obtain_for_path (path);
			return yield helper.spawn (path, argv, envp);
		}

		public async void resume (uint pid) throws IOError {
			var helper = yield obtain_for_pid (pid);
			yield helper.resume (pid);
		}

		public async uint inject (uint pid, string filename, string data_string) throws IOError {
			var helper = yield obtain_for_pid (pid);
			return yield helper.inject (pid, filename, data_string);
		}

		private async Helper obtain_for_path (string path) throws IOError {
		}

		private async Helper obtain_for_pid (uint pid) throws IOError {
		}
	}

	private class HelperFactory {
		public signal void lost ();
		public signal void uninjected (uint id);

		private DBusConnection connection;
		private Helper proxy;
		private Gee.Promise<Helper> obtain_request;

		public async Helper obtain () throws IOError {
			if (obtain_request != null) {
				try {
					return yield obtain_request.future.wait_async ();
				} catch (Gee.FutureError future_error) {
					throw new IOError.FAILED (future_error.message);
				}
			}
			obtain_request = new Gee.Promise<Helper> ();

			DBusConnection pending_connection = null;
			Helper pending_proxy = null;
			IOError pending_error = null;

			DBusServer server = null;
			TimeoutSource timeout_source = null;

			try {
				server = new DBusServer.sync ("unix:tmpdir=" + resource_store.tempdir.path, DBusServerFlags.AUTHENTICATION_ALLOW_ANONYMOUS, DBus.generate_guid ());
				server.start ();
				var tokens = server.client_address.split ("=", 2);
				resource_store.pipe = new TemporaryFile (File.new_for_path (tokens[1]), resource_store.tempdir);
				var connection_handler = server.new_connection.connect ((c) => {
					pending_connection = c;
					obtain.callback ();
					return true;
				});
				timeout_source = new TimeoutSource.seconds (2);
				timeout_source.set_callback (() => {
					pending_error = new IOError.TIMED_OUT ("timed out");
					obtain.callback ();
					return false;
				});
				timeout_source.attach (main_context);
				string[] argv = { resource_store.helper.path, server.client_address };
				spawn_helper (resource_store.helper.path, argv);
				yield;
				server.disconnect (connection_handler);
				server.stop ();
				server = null;
				timeout_source.destroy ();

				if (pending_error == null) {
					pending_proxy = yield pending_connection.get_proxy (null, ObjectPath.HELPER);
				}
			} catch (Error e) {
				if (timeout_source != null)
					timeout_source.destroy ();
				if (server != null)
					server.stop ();
				pending_error = new IOError.FAILED (e.message);
			}

			if (pending_error == null) {
				connection = pending_connection;
				connection.closed.connect (on_connection_closed);
				proxy = pending_proxy;
				proxy.uninjected.connect (on_uninjected);

				obtain_request.set_value (proxy);
				return proxy;
			} else {
				obtain_request.set_exception (pending_error);
				throw new IOError.FAILED (pending_error.message);
			}
		}

		private void on_connection_closed (bool remote_peer_vanished, GLib.Error? error) {
			proxy.uninjected.disconnect (on_uninjected);
			connection.closed.disconnect (on_connection_closed);
			lost ();
		}

		private void on_uninjected (uint id) {
			uninjected (id);
		}

		private static extern uint spawn_helper (string path, string[] argv) throws IOError;
	}

	private class ResourceStore {
		public TemporaryDirectory tempdir {
			get;
			private set;
		}

		public TemporaryFile helper32 {
			get;
			private set;
		}

		public TemporaryFile helper64 {
			get;
			private set;
		}

		private Gee.ArrayList<TemporaryFile> files = new Gee.ArrayList<TemporaryFile> ();

		public ResourceStore () throws IOError {
			tempdir = new TemporaryDirectory ();
			FileUtils.chmod (tempdir.path, 0755);

			var blob32 = Frida.Data.Helper.get_frida_helper_32_blob ();
			helper32 = new TemporaryFile.from_stream ("frida-helper-32",
				new MemoryInputStream.from_data (blob32.data, null),
				tempdir);
			FileUtils.chmod (helper32.path, 0700);

			var blob64 = Frida.Data.Helper.get_frida_helper_64_blob ();
			helper64 = new TemporaryFile.from_stream ("frida-helper-64",
				new MemoryInputStream.from_data (blob64.data, null),
				tempdir);
			FileUtils.chmod (helper64.path, 0700);
		}

		~ResourceStore () {
			foreach (var file in files)
				file.destroy ();
			helper64.destroy ();
			helper32.destroy ();
			tempdir.destroy ();
		}

		public void manage (TemporaryFile file) {
			files.add (file);
		}
	}
}
#endif
