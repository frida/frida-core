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

		public override async Frida.HostProcessInfo[] enumerate_processes () throws Error {
			return System.enumerate_processes ();
		}

		public override async uint spawn (string path, string[] argv, string[] envp) throws Error {
			if (_is_running_on_ios () && !path.has_prefix ("/")) {
				if (fruit_launcher == null)
					fruit_launcher = new FruitLauncher (this, agent);
				return yield fruit_launcher.launch (path);
			} else {
				return yield helper.spawn (path, argv, envp);
			}
		}

		public override async void resume (uint pid) throws Error {
			yield helper.resume (pid);
		}

		public override async void kill (uint pid) throws Error {
			System.kill (pid);
		}

		protected override async IOStream perform_attach_to (uint pid, out Object? transport) throws Error {
			string local_address, remote_address;
			yield injector.make_pipe_endpoints (pid, out local_address, out remote_address);
			Pipe stream;
			try {
				stream = new Pipe (local_address);
			} catch (IOError stream_error) {
				throw new Error.NOT_SUPPORTED (stream_error.message);
			}
			yield injector.inject (pid, agent, remote_address);
			transport = null;
			return stream;
		}

		// TODO: use Vala's preprocessor when the build system has been fixed
		public static extern bool _is_running_on_ios ();
	}

	private class FruitLauncher {
		private const string LOADER_CALLBACK_PATH_MAGIC = "3zPLi3BupiesaB9diyimME74fJw4jvj6";

		private DarwinHostSession host_session;
		private AgentResource agent;
		private UnixSocketAddress service_address;
		private SocketService service;

		internal FruitLauncher (DarwinHostSession host_session, AgentResource agent) {
			this.host_session = host_session;
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
			this.service.incoming.connect (on_incoming_connection);
			this.service.start ();
		}

		public async void close () {
			service.stop ();
			service = null;

			agent = null;

			host_session = null;
		}

		public async uint launch (string name) throws Error {
			var plugin_directory = "/Library/MobileSubstrate/DynamicLibraries";
			if (!FileUtils.test (plugin_directory, FileTest.IS_DIR))
				throw new Error.NOT_SUPPORTED ("Cydia Substrate is required for launching iOS apps");

			var loader_blob = Frida.Data.Loader.get_fridaloader_dylib_blob ();
			var loader_path = Path.build_filename (plugin_directory, loader_blob.name);
			try {
				FileUtils.set_data (loader_path, generate_loader_dylib (loader_blob, service_address.path));
			} catch (GLib.FileError e) {
				throw new Error.NOT_SUPPORTED ("Failed to write loader: " + e.message);
			}

			// TODO: ask SpringBoard to launch this app
			yield;

			throw new Error.NOT_SUPPORTED ("DERPRRRR");
		}

		private uint8[] generate_loader_dylib (Frida.Data.Loader.Blob blob, string callback_path) {
			var result = blob.data[0:blob.data.length];
			uint8 first_byte = LOADER_CALLBACK_PATH_MAGIC[0];
			for (var i = 0; i != result.length; i++) {
				if (result[i] == first_byte) {
					uint8 * p = &result[i];
					if (Memory.cmp (p, LOADER_CALLBACK_PATH_MAGIC, LOADER_CALLBACK_PATH_MAGIC.length) == 0) {
						Memory.copy (p, callback_path, callback_path.length + 1);
						break;
					}
				}
			}
			return result;
		}

		private bool on_incoming_connection (SocketConnection connection, Object? source_object) {
			stderr.printf ("Incoming connection! %p\n", connection);
			return false;
		}
	}
}
#endif
