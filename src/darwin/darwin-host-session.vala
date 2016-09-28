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
		private Gee.HashMap<uint, uint> injectee_by_pid = new Gee.HashMap<uint, uint> ();

		construct {
			helper = new HelperProcess ();
			helper.stopped.connect (on_helper_stopped);
			helper.output.connect (on_output);
			injector = new Fruitjector.with_helper (helper);

			var blob = Frida.Data.Agent.get_frida_agent_dylib_blob ();
			agent = new AgentResource (blob.name, new MemoryInputStream.from_data (blob.data, null), helper.tempdir);

			injector.uninjected.connect (on_uninjected);
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
			injector.uninjected.disconnect (on_uninjected);
			yield injector.close ();
			injector = null;

			agent = null;

			yield helper.close ();
			helper.output.disconnect (on_output);
			helper.stopped.disconnect (on_helper_stopped);
			helper = null;
		}

		protected override async AgentSessionProvider create_system_session () throws Error {
			return yield helper.create_system_session (agent.file.path);
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

		public override async void input (uint pid, uint8[] data) throws Error {
			yield helper.input (pid, data);
		}

		public override async void resume (uint pid) throws Error {
			if (fruit_launcher != null) {
				if (yield fruit_launcher.try_resume (pid))
					return;
			}
			yield helper.resume (pid);
		}

		public override async void kill (uint pid) throws Error {
			yield helper.kill_process (pid);
		}

		protected override async IOStream perform_attach_to (uint pid, out Object? transport) throws Error {
			transport = null;

			string remote_address;
			var stream = yield helper.make_pipe_stream (pid, out remote_address);

			if (fruit_launcher != null) {
				if (yield fruit_launcher.try_establish (pid, remote_address))
					return stream;
			}

			var uninjected_handler = injector.uninjected.connect ((id) => perform_attach_to.callback ());
			while (injectee_by_pid.has_key (pid))
				yield;
			injector.disconnect (uninjected_handler);

			var id = yield injector.inject (pid, agent, remote_address);
			injectee_by_pid[pid] = id;

			return stream;
		}

		private FruitLauncher get_fruit_launcher () {
			if (fruit_launcher == null) {
				fruit_launcher = new FruitLauncher (helper, agent);
				fruit_launcher.spawned.connect ((info) => { spawned (info); });
			}
			return fruit_launcher;
		}

		private void on_helper_stopped () {
			release_system_session ();
		}

		private void on_output (uint pid, int fd, uint8[] data) {
			output (pid, fd, data);
		}

		private void on_uninjected (uint id) {
			foreach (var entry in injectee_by_pid.entries) {
				if (entry.value == id) {
					injectee_by_pid.unset (entry.key);
					return;
				}
			}
		}

		// TODO: use Vala's preprocessor when the build system has been fixed
		public static extern bool _is_running_on_ios ();
	}

	protected class FruitLauncher : Object {
		public signal void spawned (HostSpawnInfo info);

		private HelperProcess helper;
		private AgentResource agent;
		protected MainContext main_context;

		private string plugin_directory;
		private string plist_path;
		private string dylib_path;
		private string real_dylib_path;
		protected void * service;
		private Gee.Promise<bool> service_closed = new Gee.Promise<bool> ();
		private Gee.Promise<bool> close_request;
		private Gee.Promise<bool> ensure_request;

		private bool spawn_gating_enabled = false;
		private Gee.HashMap<string, Gee.Promise<uint>> spawn_request_by_identifier = new Gee.HashMap<string, Gee.Promise<uint>> ();
		private Gee.HashMap<uint, Loader> loader_by_pid = new Gee.HashMap<uint, Loader> ();

		internal FruitLauncher (HelperProcess helper, AgentResource agent) {
			this.helper = helper;
			this.agent = agent;
			this.main_context = MainContext.ref_thread_default ();

			var tempdir_path = agent.tempdir.path;

			this.plugin_directory = "/Library/MobileSubstrate/DynamicLibraries";
			var dylib_blob = Frida.Data.Loader.get_fridaloader_dylib_blob ();
			this.plist_path = Path.build_filename (this.plugin_directory, dylib_blob.name.split (".", 2)[0] + ".plist");
			this.dylib_path = Path.build_filename (this.plugin_directory, dylib_blob.name);
			this.real_dylib_path = Path.build_filename (tempdir_path, dylib_blob.name);

			open_xpc_service ();
		}

		public override void dispose () {
			if (close_request == null)
				close.begin ();
			else if (close_request.future.ready)
				base.dispose ();
		}

		private void check_open () throws Error {
			if (close_request != null)
				throw new Error.INVALID_OPERATION ("XPC server is closed; is frida-server running outside launchd?");
		}

		public async void close () {
			if (close_request != null) {
				try {
					yield close_request.future.wait_async ();
				} catch (Gee.FutureError e) {
					assert_not_reached ();
				}
				return;
			}
			close_request = new Gee.Promise<bool> ();

			close_xpc_service ();

			try {
				yield service_closed.future.wait_async ();
			} catch (Gee.FutureError e) {
				assert_not_reached ();
			}

			foreach (var loader in loader_by_pid.values)
				yield loader.close ();
			loader_by_pid.clear ();

			foreach (var request in spawn_request_by_identifier.values)
				request.set_exception (new Error.INVALID_OPERATION ("XPC server is closed; is frida-server running outside launchd?"));
			spawn_request_by_identifier.clear ();

			FileUtils.unlink (plist_path);
			FileUtils.unlink (dylib_path);
			FileUtils.unlink (real_dylib_path);

			agent = null;

			close_request.set_value (true);
		}

		protected void on_service_closed () {
			var source = new IdleSource ();
			source.set_callback (() => {
				service_closed.set_value (true);

				if (close_request == null)
					close.begin ();

				return false;
			});
			source.attach (main_context);
		}

		public async void enable_spawn_gating () throws Error {
			check_open ();

			yield ensure_loader_deployed ();
			spawn_gating_enabled = true;
		}

		public async void disable_spawn_gating () throws Error {
			check_open ();

			spawn_gating_enabled = false;
		}

		public HostSpawnInfo[] enumerate_pending_spawns () throws Error {
			check_open ();

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
			check_open ();

			yield ensure_loader_deployed ();

			if (spawn_request_by_identifier.has_key (identifier))
				throw new Error.INVALID_OPERATION ("Spawn already in progress for the specified identifier");

			var request = new Gee.Promise<uint> ();
			spawn_request_by_identifier[identifier] = request;

			try {
				yield helper.kill_application (identifier);
				yield helper.launch (identifier, url);
			} catch (Error e) {
				spawn_request_by_identifier.unset (identifier);
				throw e;
			}

			var timeout = new TimeoutSource.seconds (10);
			timeout.set_callback (() => {
				spawn_request_by_identifier.unset (identifier);
				request.set_exception (new Error.TIMED_OUT ("Unexpectedly timed out while waiting for app to launch"));
				return false;
			});
			timeout.attach (main_context);

			try {
				var future = request.future;
				try {
					return yield future.wait_async ();
				} catch (Gee.FutureError e) {
					throw (Error) future.exception;
				}
			} finally {
				timeout.destroy ();
			}
		}

		public async bool try_establish (uint pid, string remote_address) throws Error {
			Loader loader = loader_by_pid[pid];
			if (loader == null)
				return false;

			check_open ();

			yield loader.establish (remote_address);
			return true;
		}

		public async bool try_resume (uint pid) throws Error {
			Loader loader;
			if (!loader_by_pid.unset (pid, out loader))
				return false;

			check_open ();

			yield loader.resume ();
			return true;
		}

		private async void ensure_loader_deployed () throws Error {
			if (ensure_request != null) {
				var future = ensure_request.future;
				try {
					yield future.wait_async ();
					return;
				} catch (Gee.FutureError e) {
					throw (Error) future.exception;
				}
			}
			ensure_request = new Gee.Promise<bool> ();

			try {
				if (!FileUtils.test (plugin_directory, FileTest.IS_DIR))
					throw new Error.NOT_SUPPORTED ("Cydia Substrate is required for launching iOS apps");

				yield helper.preload ();
				agent.ensure_written_to_disk ();

				var dylib_blob = Frida.Data.Loader.get_fridaloader_dylib_blob ();
				try {
					FileUtils.set_data (plist_path, generate_loader_plist ());
					FileUtils.chmod (plist_path, 0644);
					FileUtils.set_data (real_dylib_path, dylib_blob.data);
					FileUtils.chmod (real_dylib_path, 0755);
					FileUtils.unlink (dylib_path);
					FileUtils.symlink (real_dylib_path, dylib_path);
				} catch (GLib.FileError e) {
					throw new Error.NOT_SUPPORTED ("Failed to write loader: " + e.message);
				}

				ensure_request.set_value (true);
			} catch (Error ensure_error) {
				ensure_request.set_exception (ensure_error);
				ensure_request = null;

				throw ensure_error;
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

		protected void on_incoming_connection (Loader loader) {
			var source = new IdleSource ();
			source.set_callback (() => {
				perform_handshake.begin (loader);
				return false;
			});
			source.attach (main_context);
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

					loader.check_open ();

					loader_by_pid[pid] = loader;
					loader.closed.connect (on_loader_closed);

					Gee.Promise<uint> request;
					if (spawn_request_by_identifier.unset (loader.identifier, out request)) {
						request.set_value (pid);
						return;
					}

					if (spawn_gating_enabled) {
						var info = HostSpawnInfo (pid, identifier);
						loader.spawn_info = info;
						spawned (info);
						return;
					}

					loader.closed.disconnect (on_loader_closed);
					loader_by_pid.unset (pid);
				}

				yield loader.close ();
			} catch (Error e) {
			}
		}

		private void on_loader_closed (Loader loader) {
			loader_by_pid.unset (loader.pid);
		}

		protected extern void open_xpc_service ();
		protected extern void close_xpc_service ();

		protected class Loader : Object {
			public signal void closed (Loader loader);

			protected void * connection;
			private Gee.Promise<bool> connection_closed = new Gee.Promise<bool> ();
			private Gee.Promise<bool> close_request;

			private MainContext main_context;
			private Gee.LinkedList<string> pending_messages = new Gee.LinkedList<string> ();
			private Gee.LinkedList<Gee.Promise<string>> pending_requests = new Gee.LinkedList<Gee.Promise<string>> ();
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

			public Loader (void * connection, MainContext main_context) {
				this.connection = connection;
				this.main_context = main_context;
			}

			public override void dispose () {
				if (close_request == null)
					close.begin ();
				else if (close_request.future.ready)
					base.dispose ();
			}

			public void check_open () throws Error {
				if (close_request != null)
					throw new Error.INVALID_OPERATION ("Connection is closed");
			}

			public async void close () {
				if (close_request != null) {
					try {
						yield close_request.future.wait_async ();
					} catch (Gee.FutureError e) {
						assert_not_reached ();
					}
					return;
				}
				close_request = new Gee.Promise<bool> ();

				close_connection ();

				try {
					yield connection_closed.future.wait_async ();
				} catch (Gee.FutureError e) {
					assert_not_reached ();
				}

				while (!pending_requests.is_empty) {
					var request = pending_requests.poll ();
					request.set_exception (new Error.INVALID_OPERATION ("Connection closed"));
				}

				closed (this);

				close_request.set_value (true);
			}

			protected void on_connection_closed () {
				var source = new IdleSource ();
				source.set_callback (() => {
					connection_closed.set_value (true);

					if (close_request == null)
						close.begin ();

					return false;
				});
				source.attach (main_context);
			}

			public async void establish (string remote_address) throws Error {
				send_string (remote_address);
				established = true;
			}

			public async void resume () throws Error {
				if (established)
					send_string ("go");
				else
					close.begin ();
			}

			public async string recv_string () throws Error {
				check_open ();

				var payload = pending_messages.poll ();
				if (payload == null) {
					var request = new Gee.Promise<string> ();

					pending_requests.offer (request);

					var future = request.future;
					try {
						return yield future.wait_async ();
					} catch (Gee.FutureError e) {
						throw (Error) future.exception;
					}
				}

				return payload;
			}

			public void send_string (string str) throws Error {
				check_open ();

				send_string_to_connection (str);
			}

			protected void on_message (string payload) {
				var source = new IdleSource ();
				source.set_callback (() => {
					handle_message (payload);
					return false;
				});
				source.attach (main_context);
			}

			private void handle_message (string payload) {
				var request = pending_requests.poll ();
				if (request != null)
					request.set_value (payload);
				else
					pending_messages.offer (payload);
			}

			protected extern void close_connection ();
			protected extern void send_string_to_connection (string str);
		}
	}
}
#endif
