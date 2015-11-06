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
		public string id {
			get { return "local"; }
		}

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

		public override async void enable_spawn_gating () throws Error {
			if (_is_running_on_ios ())
				yield get_fruit_launcher ().enable_spawn_gating ();
			else
				throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		public override async void disable_spawn_gating () throws Error {
			if (_is_running_on_ios ())
				yield get_fruit_launcher ().disable_spawn_gating ();
			else
				throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		public override async HostSpawnInfo[] enumerate_pending_spawns () throws Error {
			if (_is_running_on_ios ())
				return get_fruit_launcher ().enumerate_pending_spawns ();
			else
				throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		public override async uint spawn (string path, string[] argv, string[] envp) throws Error {
			if (_is_running_on_ios () && !path.has_prefix ("/")) {
				string identifier = path;
				string? url = null;
				if (argv.length == 2)
					url = argv[1];
				else if (argv.length > 2)
					throw new Error.INVALID_ARGUMENT ("Too many arguments: expected identifier and optionally a URL to open");

				return yield get_fruit_launcher ().spawn (identifier, url);
			} else {
				return yield helper.spawn (path, argv, envp);
			}
		}

		public override async void resume (uint pid) throws Error {
			if (fruit_launcher != null) {
				if (yield fruit_launcher.try_resume (pid))
					return;
			}
			yield helper.resume (pid);
		}

		public override async void kill (uint pid) throws Error {
			System.kill (pid);
		}

		protected override async IOStream perform_attach_to (uint pid, out Object? transport) throws Error {
			transport = null;

			string local_address, remote_address;
			yield injector.make_pipe_endpoints (pid, out local_address, out remote_address);
			Pipe pipe;
			try {
				pipe = new Pipe (local_address);
			} catch (IOError pipe_error) {
				throw new Error.NOT_SUPPORTED (pipe_error.message);
			}

			if (fruit_launcher != null) {
				if (yield fruit_launcher.try_establish (pid, remote_address))
					return pipe;
			}

			yield injector.inject (pid, agent, remote_address);

			return pipe;
		}

		protected override async AgentSession obtain_system_session () throws Error {
			return yield helper.obtain_system_session ();
		}

		private FruitLauncher get_fruit_launcher () {
			if (fruit_launcher == null) {
				fruit_launcher = new FruitLauncher (helper, agent);
				fruit_launcher.spawned.connect ((info) => { spawned (info); });
			}
			return fruit_launcher;
		}

		// TODO: use Vala's preprocessor when the build system has been fixed
		public static extern bool _is_running_on_ios ();
	}

	private class FruitLauncher {
		public signal void spawned (HostSpawnInfo info);

		private const string LOADER_DATA_DIR_MAGIC = "3zPLi3BupiesaB9diyimME74fJw4jvj6";

		private HelperProcess helper;
		private AgentResource agent;
		private UnixSocketAddress service_address;
		private SocketService service;

		private string plugin_directory;
		private string plist_path;
		private string dylib_path;

		private bool spawn_gating_enabled = false;
		private Gee.HashMap<string, SpawnRequest> spawn_request_by_identifier = new Gee.HashMap<string, SpawnRequest> ();
		private Gee.HashMap<uint, Loader> loader_by_pid = new Gee.HashMap<uint, Loader> ();

		internal FruitLauncher (HelperProcess helper, AgentResource agent) {
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
			this.service.incoming.connect (this.on_incoming_connection);

			this.plugin_directory = "/Library/MobileSubstrate/DynamicLibraries";
			var dylib_blob = Frida.Data.Loader.get_fridaloader_dylib_blob ();
			this.plist_path = Path.build_filename (this.plugin_directory, dylib_blob.name.split (".", 2)[0] + ".plist");
			this.dylib_path = Path.build_filename (this.plugin_directory, dylib_blob.name);

			this.service.start ();
		}

		public async void close () {
			service.stop ();
			service = null;

			FileUtils.unlink (plist_path);
			FileUtils.unlink (dylib_path);
			FileUtils.unlink (service_address.path);

			agent = null;
		}

		public async void enable_spawn_gating () throws Error {
			yield ensure_loader_deployed ();
			spawn_gating_enabled = true;
		}

		public async void disable_spawn_gating () throws Error {
			spawn_gating_enabled = false;
		}

		public HostSpawnInfo[] enumerate_pending_spawns () throws Error {
			var result = new HostSpawnInfo[0];
			var i = 0;
			foreach (var loader in loader_by_pid.values) {
				var info = loader.spawn_info;
				if (info != null) {
					result.resize (i + 1);
					result[i++] = info;
				}
			}
			return result;
		}

		public async uint spawn (string identifier, string? url) throws Error {
			check_identifier (identifier);

			yield ensure_loader_deployed ();

			var waiting = false;
			var timed_out = false;
			var request = new SpawnRequest (identifier, () => {
				if (waiting)
					spawn.callback ();
			});
			spawn_request_by_identifier[identifier] = request;

			try {
				kill (identifier);
				yield helper.launch (identifier, url);
			} catch (Error e) {
				spawn_request_by_identifier.unset (identifier);
				throw e;
			}

			if (request.result == null) {
				var timeout = Timeout.add_seconds (10, () => {
					timed_out = true;
					spawn.callback ();
					return false;
				});
				waiting = true;
				yield;
				waiting = false;
				if (timed_out) {
					spawn_request_by_identifier.unset (identifier);
					throw new Error.TIMED_OUT ("Unexpectedly timed out while waiting for app to launch");
				} else {
					Source.remove (timeout);
				}
			}

			return request.result.pid;
		}

		public async bool try_establish (uint pid, string remote_address) throws Error {
			Loader loader = loader_by_pid[pid];
			if (loader == null)
				return false;
			yield loader.establish (remote_address);
			return true;
		}

		public async bool try_resume (uint pid) throws Error {
			Loader loader;
			if (!loader_by_pid.unset (pid, out loader))
				return false;
			yield loader.resume ();
			return true;
		}

		private async void ensure_loader_deployed () throws Error {
			if (!FileUtils.test (plugin_directory, FileTest.IS_DIR))
				throw new Error.NOT_SUPPORTED ("Cydia Substrate is required for launching iOS apps");

			yield helper.preload ();
			agent.ensure_written_to_disk ();

			var dylib_blob = Frida.Data.Loader.get_fridaloader_dylib_blob ();
			try {
				FileUtils.set_data (plist_path, generate_loader_plist ());
				FileUtils.chmod (plist_path, 0644);
				FileUtils.set_data (dylib_path, generate_loader_dylib (dylib_blob, agent.tempdir.path));
				FileUtils.chmod (dylib_path, 0755);
			} catch (GLib.FileError e) {
				throw new Error.NOT_SUPPORTED ("Failed to write loader: " + e.message);
			}
		}

		private uint8[] generate_loader_plist () {
			/*
			 * {
			 *   "Filter": {
			 *     "Bundles": ["com.apple.UIKit"]
			 *   }
			 * }
			 */
			return new uint8[] {
				0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, 0xd1, 0x01, 0x02, 0x56, 0x46, 0x69, 0x6c, 0x74,
				0x65, 0x72, 0xd1, 0x03, 0x04, 0x57, 0x42, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x73, 0xa1, 0x05, 0x5f,
				0x10, 0x0f, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e, 0x55, 0x49, 0x4b, 0x69,
				0x74, 0x08, 0x0b, 0x12, 0x15, 0x1d, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31
			};
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

		private bool on_incoming_connection (SocketConnection connection, Object? source_object) {
			perform_handshake.begin (new Loader (connection));
			return true;
		}

		private async void perform_handshake (Loader loader) {
			try {
				var details = yield loader.recv_string ();
				var tokens = details.split (":", 2);
				if (tokens.length == 2) {
					var pid = (uint) uint64.parse (tokens[0]);
					var identifier = tokens[1];

					loader.pid = pid;
					loader.identifier = identifier;

					loader_by_pid[pid] = loader;

					SpawnRequest request;
					if (spawn_request_by_identifier.unset (loader.identifier, out request)) {
						request.complete (loader);
						return;
					}

					if (spawn_gating_enabled) {
						var info = HostSpawnInfo (pid, identifier);
						loader.spawn_info = info;
						spawned (info);
						return;
					}

					loader_by_pid.unset (pid);
				}

				loader.close ();
			} catch (Error e) {
			}
		}

		private class SpawnRequest : Object {
			public delegate void CompletionHandler ();

			public string identifier {
				get;
				construct;
			}

			private CompletionHandler handler;

			public Loader? result {
				get;
				private set;
			}

			public SpawnRequest (string identifier, owned CompletionHandler handler) {
				Object (identifier: identifier);

				this.handler = (owned) handler;
			}

			public void complete (Loader r) {
				result = r;
				handler ();
			}
		}

		private class Loader {
			private SocketConnection connection;
			private InputStream input;
			private OutputStream output;
			private bool established = false;

			public uint pid {
				get;
				set;
			}

			public string identifier {
				get;
				set;
			}

			public HostSpawnInfo? spawn_info {
				get;
				set;
			}

			public Loader (SocketConnection connection) {
				this.connection = connection;
				this.input = connection.input_stream;
				this.output = connection.output_stream;
			}

			public void close () {
				connection.close_async.begin ();
			}

			public async void establish (string remote_address) throws Error {
				yield send_string (remote_address);
				established = true;
			}

			public async void resume () throws Error {
				if (established)
					yield send_string ("go");
				else
					close ();
			}

			public async string recv_string () throws Error {
				try {
					var size_buf = new uint8[1];
					var n = yield input.read_async (size_buf);
					if (n == 0)
						throw new Error.TRANSPORT ("Unable to communicate with loader");
					var size = size_buf[0];

					var data_buf = new uint8[size + 1];
					size_t bytes_read;
					yield input.read_all_async (data_buf[0:size], Priority.DEFAULT, null, out bytes_read);
					if (bytes_read != size)
						throw new Error.TRANSPORT ("Unable to communicate with loader");
					data_buf[size] = 0;

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
