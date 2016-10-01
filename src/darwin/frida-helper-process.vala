#if DARWIN
namespace Frida {
	internal class HelperProcess {
		public signal void output (uint pid, int fd, uint8[] data);
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

		public async AgentSessionProvider create_system_session_provider (string agent_filename, out DBusConnection conn) throws Error {
			var helper = yield obtain ();
			try {
				var provider_path = yield helper.create_system_session_provider (agent_filename);
				AgentSessionProvider provider = yield connection.get_proxy (null, provider_path);
				conn = connection;
				return provider;
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async uint spawn (string path, string[] argv, string[] envp) throws Error {
			/* FIXME: workaround for Vala compiler bug */
			var argv_copy = argv;
			var envp_copy = envp;
			var helper = yield obtain ();
			try {
				return yield helper.spawn (path, argv_copy, envp_copy);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async void input (uint pid, uint8[] data) throws Error {
			/* FIXME: workaround for Vala compiler bug */
			var data_copy = data;
			var helper = yield obtain ();
			try {
				yield helper.input (pid, data_copy);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async void launch (string identifier, string? url) throws Error {
			var helper = yield obtain ();
			try {
				yield helper.launch (identifier, (url != null) ? url : "");
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

		public async uint inject (uint pid, string filename, string data_string) throws Error {
			var helper = yield obtain ();
			try {
				return yield helper.inject (pid, filename, data_string);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		public async IOStream make_pipe_stream (uint remote_pid, out string remote_address) throws Error {
			var helper = yield obtain ();
			try {
				var endpoints = yield helper.make_pipe_endpoints ((uint) Posix.getpid (), remote_pid);
				var local_address = endpoints.local_address;
				remote_address = endpoints.remote_address;
				if (local_address[0] == '/') {
					TunneledStream ts;
					ts = yield connection.get_proxy (null, local_address);
					return new SimpleIOStream (TunneledInputStream.create (ts), TunneledOutputStream.create (ts));
				} else {
					return new Pipe (local_address);
				}
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
					pending_error = new Error.TIMED_OUT ("Unexpectedly timed out while spawning helper process");
					obtain.callback ();
					return false;
				});
				timeout_source.attach (main_context);
				string[] argv = { resource_store.helper.path, server.client_address };
				pending_process = new Subprocess.newv (argv, SubprocessFlags.STDIN_INHERIT);
				yield;
				server.disconnect (connection_handler);
				server.stop ();
				server = null;
				timeout_source.destroy ();
				timeout_source = null;

				if (pending_error == null)
					pending_proxy = yield pending_connection.get_proxy (null, ObjectPath.HELPER);
			} catch (GLib.Error e) {
				if (timeout_source != null)
					timeout_source.destroy ();
				if (server != null)
					server.stop ();
				pending_error = new Error.PERMISSION_DENIED (e.message);
			}

			if (pending_error == null) {
				process = pending_process;

				connection = pending_connection;
				connection.closed.connect (on_connection_closed);

				proxy = pending_proxy;
				proxy.output.connect (on_output);
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
			obtain_request = null;

			proxy.output.disconnect (on_output);
			proxy.uninjected.disconnect (on_uninjected);
			proxy = null;

			connection.closed.disconnect (on_connection_closed);
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

	namespace TunneledInputStream {
		private InputStream create (TunneledStream stream) {
			var pipe = new LocalUnixPipe ();
			process.begin (stream, pipe);
			return pipe.input;
		}

		private async void process (TunneledStream stream, LocalUnixPipe pipe) {
			var output = pipe.output;

			while (true) {
				uint8[] chunk;
				try {
					chunk = yield stream.read ();
				} catch (GLib.Error e) {
					output.close_async.begin ();
					return;
				}
				if (chunk.length == 0) {
					output.close_async.begin ();
					return;
				}
				try {
					yield output.write_all_async (chunk, Priority.DEFAULT, null, null);
				} catch (GLib.Error e) {
					stream.close.begin ();
					return;
				}
			}
		}
	}

	namespace TunneledOutputStream {
		private OutputStream create (TunneledStream stream) {
			var pipe = new LocalUnixPipe ();
			process.begin (stream, pipe);
			return pipe.output;
		}

		private async void process (TunneledStream stream, LocalUnixPipe pipe) {
			var input = pipe.input;

			var buf = new uint8[4096];
			while (true) {
				ssize_t n;
				try {
					n = yield input.read_async (buf);
				} catch (GLib.Error e) {
					stream.close.begin ();
					return;
				}
				if (n == 0) {
					stream.close.begin ();
					return;
				}
				try {
					yield stream.write (buf[0:n]);
				} catch (GLib.Error e) {
					input.close_async.begin ();
					return;
				}
			}
		}
	}

	private class LocalUnixPipe {
		public UnixInputStream input {
			get;
			private set;
		}

		public UnixOutputStream output {
			get;
			private set;
		}

		public LocalUnixPipe () {
			var fds = new int[2];
			try {
				open_pipe (fds, 0);
				Unix.set_fd_nonblocking (fds[0], true);
				Unix.set_fd_nonblocking (fds[1], true);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			input = new UnixInputStream (fds[0], true);
			output = new UnixOutputStream (fds[1], true);
		}

		/* FIXME: working around vapi bug */
		[CCode (cheader_filename = "glib-unix.h", cname = "g_unix_open_pipe")]
		public static extern bool open_pipe (int * fds, int flags) throws GLib.Error;
	}
}
#endif
