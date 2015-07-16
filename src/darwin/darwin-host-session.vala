#if DARWIN
namespace Frida {
	public class DarwinHostSessionBackend : Object, HostSessionBackend {
		private DarwinHostSessionProvider local_provider;

		public async void start () {
			assert (local_provider == null);
			local_provider = new DarwinHostSessionProvider ();
			provider_available (local_provider);
		}

		public async void stop () {
			assert (local_provider != null);
			provider_unavailable (local_provider);
			yield local_provider.close ();
			local_provider = null;
		}
	}

	public class DarwinHostSessionProvider : Object, HostSessionProvider {
		public string name {
			get { return "Local System"; }
		}

		public ImageData? icon {
			get { return _icon; }
		}
		private ImageData? _icon;

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.LOCAL_SYSTEM; }
		}

		private DarwinHostSession host_session;

		construct {
			_icon = _extract_icon ();
		}

		public async void close () {
			if (host_session != null)
				yield host_session.close ();
			host_session = null;
		}

		public async HostSession create (string? location = null) throws Error {
			assert (location == null);
			if (host_session != null)
				throw new Error.INVALID_ARGUMENT ("Invalid location: already created");
			host_session = new DarwinHostSession ();
			host_session.agent_session_closed.connect (on_agent_session_closed);
			return host_session;
		}

		public async void destroy (HostSession session) throws Error {
			if (session != host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");
			host_session.agent_session_closed.disconnect (on_agent_session_closed);
			yield host_session.close ();
			host_session = null;
		}

		public async AgentSession obtain_agent_session (HostSession host_session, AgentSessionId agent_session_id) throws Error {
			if (host_session != this.host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");
			return yield this.host_session.obtain_agent_session (agent_session_id);
		}

		private void on_agent_session_closed (AgentSessionId id, AgentSession session) {
			agent_session_closed (id);
		}

		public static extern ImageData? _extract_icon ();
	}

	public class DarwinHostSession : BaseDBusHostSession {
		private HelperProcess helper;
		private Fruitjector injector;
		private AgentResource agent;
		private FruitLauncher fruit_launcher;

		private ApplicationEnumerator application_enumerator = new ApplicationEnumerator ();
		private ProcessEnumerator process_enumerator = new ProcessEnumerator ();

		construct {
			helper = new HelperProcess ();
			injector = new Fruitjector.with_helper (helper);

			var blob = Frida.Data.Agent.get_frida_agent_dylib_blob ();
			agent = new AgentResource (blob.name, new MemoryInputStream.from_data (blob.data, null), helper.tempdir);
		}

		public override async void close () {
			yield base.close ();

			if (fruit_launcher != null) {
				yield fruit_launcher.close ();
				fruit_launcher = null;
			}

			var uninjected_handler = injector.uninjected.connect ((id) => close.callback ());
			while (injector.any_still_injected ())
				yield;
			injector.disconnect (uninjected_handler);
			yield injector.close ();
			injector = null;

			agent = null;

			yield helper.close ();
			helper = null;
		}

		public override async HostApplicationInfo get_frontmost_application () throws Error {
			return System.get_frontmost_application ();
		}

		public override async HostApplicationInfo[] enumerate_applications () throws Error {
			return yield application_enumerator.enumerate_applications ();
		}

		public override async HostProcessInfo[] enumerate_processes () throws Error {
			return yield process_enumerator.enumerate_processes ();
		}

		public override async uint spawn (string path, string[] argv, string[] envp) throws Error {
			if (_is_running_on_ios () && !path.has_prefix ("/")) {
				string identifier = path;
				string? url = null;
				if (argv.length == 2)
					url = argv[1];
				else if (argv.length > 2)
					throw new Error.INVALID_ARGUMENT ("Too many arguments: expected identifier and optionally a URL to open");

				if (fruit_launcher == null)
					fruit_launcher = new FruitLauncher (this, helper, agent);
				return yield fruit_launcher.spawn (identifier, url);
			} else {
				return yield helper.spawn (path, argv, envp);
			}
		}

		public override async void resume (uint pid) throws Error {
			if (fruit_launcher != null) {
				if (yield fruit_launcher.resume (pid))
					return;
			}
			yield helper.resume (pid);
		}

		public override async void kill (uint pid) throws Error {
			System.kill (pid);
		}

		protected override async IOStream perform_attach_to (uint pid, out Object? transport) throws Error {
			transport = null;

			Pipe pipe;

			if (fruit_launcher != null) {
				pipe = fruit_launcher.get_pipe (pid);
				if (pipe != null)
					return pipe;
			}

			string local_address, remote_address;
			yield injector.make_pipe_endpoints (pid, out local_address, out remote_address);
			try {
				pipe = new Pipe (local_address);
			} catch (IOError pipe_error) {
				throw new Error.NOT_SUPPORTED (pipe_error.message);
			}
			yield injector.inject (pid, agent, remote_address);

			return pipe;
		}

		protected override async AgentSession obtain_kernel_session () throws Error {
			return yield helper.obtain_kernel_session ();
		}

		// TODO: use Vala's preprocessor when the build system has been fixed
		public static extern bool _is_running_on_ios ();
	}

	private class FruitLauncher {
		private const string LOADER_DATA_DIR_MAGIC = "3zPLi3BupiesaB9diyimME74fJw4jvj6";

		private DarwinHostSession host_session;
		private HelperProcess helper;
		private AgentResource agent;
		private UnixSocketAddress service_address;
		private SocketService service;

		private Gee.Promise<bool> spawn_request;
		private delegate void LaunchErrorHandler (Error e);
		private LaunchErrorHandler on_launch_error;
		private Gee.HashMap<uint, Loader> loader_by_pid = new Gee.HashMap<uint, Loader> ();

		internal FruitLauncher (DarwinHostSession host_session, HelperProcess helper, AgentResource agent) {
			this.host_session = host_session;
			this.helper = helper;
			this.agent = agent;

			this.service = new SocketService ();
			var address = new UnixSocketAddress (Path.build_filename (agent.tempdir.path, "callback"));
			SocketAddress effective_address;
			try {
				this.service.add_address (address, SocketType.STREAM, SocketProtocol.DEFAULT, null, out effective_address);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
			assert (effective_address is UnixSocketAddress);
			this.service_address = effective_address as UnixSocketAddress;
			FileUtils.chmod (this.service_address.path, 0777);
			this.service.start ();
		}

		public async void close () {
			service.stop ();
			service = null;

			FileUtils.unlink (service_address.path);

			agent = null;

			host_session = null;
		}

		public async uint spawn (string identifier, string? url) throws Error {
			while (spawn_request != null) {
				try {
					yield spawn_request.future.wait_async ();
				} catch (Gee.FutureError e) {
					assert_not_reached ();
				}
			}

			spawn_request = new Gee.Promise<bool> ();

			try {
				var plugin_directory = "/Library/MobileSubstrate/DynamicLibraries";
				if (!FileUtils.test (plugin_directory, FileTest.IS_DIR))
					throw new Error.NOT_SUPPORTED ("Cydia Substrate is required for launching iOS apps");

				yield helper.preload ();
				(void) agent.file; // Make sure it's written to disk

				check_identifier (identifier);

				var dylib_blob = Frida.Data.Loader.get_fridaloader_dylib_blob ();
				var plist_path = Path.build_filename (plugin_directory, dylib_blob.name.split (".", 2)[0] + ".plist");
				var dylib_path = Path.build_filename (plugin_directory, dylib_blob.name);
				try {
					FileUtils.set_data (dylib_path, generate_loader_dylib (dylib_blob, agent.tempdir.path));
					FileUtils.chmod (dylib_path, 0755);
					FileUtils.set_contents (plist_path, generate_loader_plist (identifier));
					FileUtils.chmod (plist_path, 0644);
				} catch (GLib.FileError e) {
					throw new Error.NOT_SUPPORTED ("Failed to write loader: " + e.message);
				}

				Loader loader = null;
				Error error = null;
				on_launch_error = (e) => {
					error = e;
					spawn.callback ();
				};
				var on_incoming = this.service.incoming.connect ((connection, source_object) => {
					loader = new Loader (connection);
					spawn.callback ();
					return true;
				});
				var timeout = Timeout.add_seconds (10, () => {
					spawn.callback ();
					return false;
				});
				kill (identifier);
				perform_launch.begin (identifier, url);
				yield;
				Source.remove (timeout);
				this.service.disconnect (on_incoming);
				on_launch_error = null;

				FileUtils.unlink (plist_path);
				FileUtils.unlink (dylib_path);

				if (loader == null) {
					if (error != null)
						throw error;
					else
						throw new Error.TIMED_OUT ("Unexpectedly timed out while waiting for app to launch");
				}

				string pid_message = yield loader.recv_string ();
				uint pid = (uint) uint64.parse (pid_message);

				var endpoints = yield helper.make_pipe_endpoints ((uint) Posix.getpid (), pid);
				try {
					loader.pipe = new Pipe (endpoints.local_address);
				} catch (IOError stream_error) {
					throw new Error.NOT_SUPPORTED (stream_error.message);
				}
				yield loader.send_string (endpoints.remote_address);

				loader_by_pid[pid] = loader;

				return pid;
			} finally {
				spawn_request.set_value (true);
				spawn_request = null;
			}
		}

		private async void perform_launch (string identifier, string? url) {
			try {
				yield helper.launch (identifier, url);
			} catch (Error e) {
				if (on_launch_error != null)
					on_launch_error (e);
			}
		}

		public Pipe? get_pipe (uint pid) {
			Loader loader = loader_by_pid[pid];
			if (loader == null)
				return null;
			return loader.pipe;
		}

		public async bool resume (uint pid) throws Error {
			Loader loader;
			if (!loader_by_pid.unset (pid, out loader))
				return false;
			yield loader.send_string ("go");
			return true;
		}

		private string generate_loader_plist (string identifier) {
			return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
				"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">" +
				"<plist version=\"1.0\">" +
				"<dict>" +
					"<key>Filter</key>" +
					"<dict>" +
						"<key>Bundles</key>" +
						"<array>" +
							"<string>" + identifier + "</string>" +
						"</array>" +
					"</dict>" +
				"</dict>" +
			"</plist>";
		}

		private uint8[] generate_loader_dylib (Frida.Data.Loader.Blob blob, string callback_path) {
			var result = blob.data[0:blob.data.length];
			uint8 first_byte = LOADER_DATA_DIR_MAGIC[0];
			for (var i = 0; i != result.length; i++) {
				if (result[i] == first_byte) {
					uint8 * p = &result[i];
					if (Memory.cmp (p, LOADER_DATA_DIR_MAGIC, LOADER_DATA_DIR_MAGIC.length) == 0) {
						Memory.copy (p, callback_path, callback_path.length + 1);
						i += callback_path.length;
						// We need to keep going due to universal binaries.
						// Note that we omit the `+ 1` as the for-loop does it for us.
					}
				}
			}
			return result;
		}

		private static extern void check_identifier (string identifier) throws Error;
		private static extern void kill (string identifier);

		private class Loader {
			private SocketConnection connection;
			private InputStream input;
			private OutputStream output;

			public Pipe pipe {
				get;
				set;
			}

			public Loader (SocketConnection connection) {
				this.connection = connection;
				this.input = connection.input_stream;
				this.output = connection.output_stream;
			}

			public async string recv_string () throws Error {
				try {
					var size_buf = new uint8[1];
					var n = yield input.read_async (size_buf);
					if (n == 0)
						throw new Error.TRANSPORT ("Unable to communicate with loader");
					var size = size_buf[0];

					var data_buf = new uint8[size];
					size_t bytes_read;
					yield input.read_all_async (data_buf, Priority.DEFAULT, null, out bytes_read);
					if (bytes_read != size)
						throw new Error.TRANSPORT ("Unable to communicate with loader");

					char * v = data_buf;
					return (string) v;
				} catch (GLib.Error e) {
					throw new Error.TRANSPORT ("Unable to communicate with loader");
				}
			}

			public async void send_string (string v) throws Error {
				var data_buf = new uint8[1 + v.length];
				data_buf[0] = (uint8) v.length;
				Memory.copy (data_buf + 1, v, v.length);
				size_t bytes_written;
				try {
					yield output.write_all_async (data_buf, Priority.DEFAULT, null, out bytes_written);
				} catch (GLib.Error e) {
					throw new Error.TRANSPORT ("Unable to communicate with loader");
				}
				if (bytes_written != data_buf.length)
					throw new Error.TRANSPORT ("Unable to communicate with loader");
			}
		}
	}
}
#endif
