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
			var tempdir = new TemporaryDirectory ();
			host_session = new DarwinHostSession (new DarwinHelperProcess (tempdir), tempdir);
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
		public DarwinHelper helper {
			get;
			construct;
		}

		public TemporaryDirectory tempdir {
			get;
			construct;
		}

		private AgentResource agent;
		private FruitLauncher fruit_launcher;

		private ApplicationEnumerator application_enumerator = new ApplicationEnumerator ();
		private ProcessEnumerator process_enumerator = new ProcessEnumerator ();

		private Gee.HashMap<uint, uint> injectee_by_pid = new Gee.HashMap<uint, uint> ();

		public DarwinHostSession (owned DarwinHelper helper, owned TemporaryDirectory tempdir) {
			Object (helper: helper, tempdir: tempdir);
		}

		construct {
			helper.output.connect (on_output);

			injector = new Fruitjector (helper, false, tempdir);
			injector.uninjected.connect (on_uninjected);

			var blob = Frida.Data.Agent.get_frida_agent_dylib_blob ();
			agent = new AgentResource (blob.name, new Bytes.static (blob.data), tempdir);
		}

		public override async void close () {
			yield base.close ();

			if (fruit_launcher != null) {
				yield fruit_launcher.close ();
				fruit_launcher = null;
			}

			var fruitjector = injector as Fruitjector;

			var uninjected_handler = injector.uninjected.connect ((id) => close.callback ());
			while (fruitjector.any_still_injected ())
				yield;
			injector.disconnect (uninjected_handler);

			agent = null;

			injector.uninjected.disconnect (on_uninjected);
			yield fruitjector.close ();
			injector = null;

			yield helper.close ();
			helper.output.disconnect (on_output);

			tempdir.destroy ();
		}

		protected override async AgentSessionProvider create_system_session_provider (out DBusConnection connection) throws Error {
			yield helper.preload ();

			var pid = helper.pid;

			string remote_address;
			var stream = yield helper.make_pipe_stream (pid, out remote_address);

			var fruitjector = injector as Fruitjector;
			var id = yield fruitjector.inject_library_resource (pid, agent, "frida_agent_main", remote_address);
			injectee_by_pid[pid] = id;

			DBusConnection conn;
			AgentSessionProvider provider;
			try {
				conn = yield DBusConnection.new (stream, null, DBusConnectionFlags.NONE);
				provider = yield conn.get_proxy (null, ObjectPath.AGENT_SESSION_PROVIDER);
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}

			connection = conn;

			return provider;
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

			var uninjected_handler = injector.uninjected.connect ((id) => perform_attach_to.callback ());
			while (injectee_by_pid.has_key (pid))
				yield;
			injector.disconnect (uninjected_handler);

			string remote_address;
			var stream = yield helper.make_pipe_stream (pid, out remote_address);

			var fruitjector = injector as Fruitjector;
			var id = yield fruitjector.inject_library_resource (pid, agent, "frida_agent_main", remote_address);
			injectee_by_pid[pid] = id;

			return stream;
		}

		private FruitLauncher get_fruit_launcher () {
			if (fruit_launcher == null) {
				fruit_launcher = new FruitLauncher (this, agent);
				fruit_launcher.spawned.connect ((info) => { spawned (info); });
			}
			return fruit_launcher;
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

			uninjected (InjectorPayloadId (id));
		}

		// TODO: use Vala's preprocessor when the build system has been fixed
		public static extern bool _is_running_on_ios ();
	}

	protected class FruitLauncher : Object {
		public signal void spawned (HostSpawnInfo info);

		private DarwinHelper helper;
		private AgentResource agent;
		protected MainContext main_context;

		private LaunchdAgent launchd_agent;
		private bool spawn_gating_enabled = false;
		private Gee.HashMap<string, Gee.Promise<uint>> spawn_request_by_identifier = new Gee.HashMap<string, Gee.Promise<uint>> ();
		private Gee.HashMap<uint, HostSpawnInfo?> pending_spawn_by_pid = new Gee.HashMap<uint, HostSpawnInfo?> ();

		internal FruitLauncher (DarwinHostSession host_session, AgentResource agent) {
			this.helper = host_session.helper;
			this.agent = agent;
			this.main_context = MainContext.ref_thread_default ();

			this.launchd_agent = new LaunchdAgent (host_session);
			this.launchd_agent.app_launch_completed.connect (on_app_launch_completed);
			this.launchd_agent.spawned.connect (on_spawned);
		}

		~FruitLauncher () {
			this.launchd_agent.spawned.disconnect (on_spawned);
			this.launchd_agent.app_launch_completed.disconnect (on_app_launch_completed);
		}

		public async void close () {
			if (spawn_gating_enabled) {
				try {
					yield disable_spawn_gating ();
				} catch (Error e) {
				}
			}

			yield launchd_agent.close ();
		}

		public async void enable_spawn_gating () throws Error {
			yield launchd_agent.enable_spawn_gating ();

			spawn_gating_enabled = true;
		}

		public async void disable_spawn_gating () throws Error {
			spawn_gating_enabled = false;

			yield launchd_agent.disable_spawn_gating ();

			foreach (var entry in pending_spawn_by_pid.entries)
				helper.resume.begin (entry.key);
			pending_spawn_by_pid.clear ();
		}

		public HostSpawnInfo[] enumerate_pending_spawns () throws Error {
			var result = new HostSpawnInfo[pending_spawn_by_pid.size];
			var index = 0;
			foreach (var spawn in pending_spawn_by_pid.values)
				result[index++] = spawn;
			return result;
		}

		public async uint spawn (string identifier, string? url) throws Error {
			if (spawn_request_by_identifier.has_key (identifier))
				throw new Error.INVALID_OPERATION ("Spawn already in progress for the specified identifier");

			var request = new Gee.Promise<uint> ();
			spawn_request_by_identifier[identifier] = request;

			yield launchd_agent.prepare_for_launch (identifier);

			try {
				yield helper.kill_application (identifier);
				yield helper.launch (identifier, url);
			} catch (Error e) {
				spawn_request_by_identifier.unset (identifier);
				throw e;
			}

			var timeout = new TimeoutSource.seconds (20);
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

		public async bool try_resume (uint pid) throws Error {
			HostSpawnInfo? info;
			if (!pending_spawn_by_pid.unset (pid, out info))
				return false;

			yield helper.resume (pid);
			return true;
		}

		private void on_app_launch_completed (string identifier, uint pid, Error? error) {
			Gee.Promise<uint> request;
			if (spawn_request_by_identifier.unset (identifier, out request)) {
				if (error == null)
					request.set_value (pid);
				else
					request.set_exception (error);
			}
		}

		private void on_spawned (HostSpawnInfo info) {
			pending_spawn_by_pid[info.pid] = info;

			spawned (info);
		}
	}

	private class LaunchdAgent : DarwinAgent {
		public signal void app_launch_completed (string identifier, uint pid, Error? error);
		public signal void spawned (HostSpawnInfo info);

		public LaunchdAgent (DarwinHostSession host_session) {
			string * source = Frida.Data.Darwin.get_launchd_js_blob ().data;
			Object (host_session: host_session, target_pid: 1, script_source: source);
		}

		public async void prepare_for_launch (string identifier) throws Error {
			yield call ("prepareForLaunch", new Json.Node[] { new Json.Node.alloc ().init_string (identifier) });
		}

		public async void enable_spawn_gating () throws Error {
			yield call ("enableSpawnGating", new Json.Node[] {});
		}

		public async void disable_spawn_gating () throws Error {
			yield call ("disableSpawnGating", new Json.Node[] {});
		}

		protected override void on_event (string type, Json.Array event) {
			var identifier = event.get_string_element (1);
			var pid = (uint) event.get_int_element (2);

			switch (type) {
				case "launch:app":
					prepare_app.begin (identifier, pid);
					break;
				case "spawn":
					prepare_xpcproxy.begin (identifier, pid);
					break;
				default:
					assert_not_reached ();
			}
		}

		private async void prepare_app (string identifier, uint pid) {
			try {
				var agent = new XpcProxyAgent (host_session, identifier, pid);
				yield agent.run_until_exec ();
				app_launch_completed (identifier, pid, null);
			} catch (Error e) {
				app_launch_completed (identifier, pid, e);
			}
		}

		private async void prepare_xpcproxy (string identifier, uint pid) {
			try {
				var agent = new XpcProxyAgent (host_session, identifier, pid);
				yield agent.run_until_exec ();
				spawned (HostSpawnInfo (pid, identifier));
			} catch (Error e) {
			}
		}
	}

	private class XpcProxyAgent : DarwinAgent {
		public string identifier {
			get;
			construct;
		}

		public XpcProxyAgent (DarwinHostSession host_session, string identifier, uint pid) {
			string * source = Frida.Data.Darwin.get_xpcproxy_js_blob ().data;
			Object (host_session: host_session, identifier: identifier, target_pid: pid, script_source: source);
		}

		public async void run_until_exec () throws Error {
			yield ensure_loaded ();
			yield host_session.helper.resume (target_pid);
			yield wait_for_unload ();
		}
	}

	private class DarwinAgent : Object {
		public DarwinHostSession host_session {
			get;
			construct;
		}

		public uint target_pid {
			get;
			construct;
		}

		public string script_source {
			get;
			construct;
		}

		protected MainContext main_context;
		private Gee.Promise<bool> ensure_request;
		private Gee.Promise<bool> unloaded;

		private AgentSession session;
		private AgentScriptId script;

		private Gee.HashMap<string, PendingResponse> pending = new Gee.HashMap<string, PendingResponse> ();
		private int64 next_request_id = 1;

		construct {
			main_context = MainContext.ref_thread_default ();

			host_session.agent_session_closed.connect (on_agent_session_closed);

			unloaded = new Gee.Promise<bool> ();
		}

		~DarwinAgent () {
			host_session.agent_session_closed.disconnect (on_agent_session_closed);
		}

		public async void close () {
			if (ensure_request != null) {
				try {
					yield ensure_loaded ();
				} catch (Error e) {
				}
			}

			if (script.handle != 0) {
				try {
					yield session.destroy_script (script);
				} catch (GLib.Error e) {
				}
				script = AgentScriptId (0);
			}

			if (session != null) {
				try {
					yield session.close ();
				} catch (GLib.Error e) {
				}
				session = null;
			}
		}

		protected virtual void on_event (string type, Json.Array event) {
		}

		protected async Json.Node call (string method, Json.Node[] args) throws Error {
			yield ensure_loaded ();

			var request_id = next_request_id++;

			var builder = new Json.Builder ();
			builder
			.begin_array ()
			.add_string_value ("frida:rpc")
			.add_int_value (request_id)
			.add_string_value ("call")
			.add_string_value (method)
			.begin_array ();
			foreach (var arg in args)
				builder.add_value (arg);
			builder
			.end_array ()
			.end_array ();

			var generator = new Json.Generator ();
			generator.set_root (builder.get_root ());
			size_t length;
			var request = generator.to_data (out length);

			var response = new PendingResponse (() => call.callback ());
			pending[request_id.to_string ()] = response;

			post_call_request.begin (request, response, session, script);

			yield;

			if (response.error != null)
				throw response.error;

			return response.result;
		}

		private async void post_call_request (string request, PendingResponse response, AgentSession session, AgentScriptId script) {
			try {
				yield session.post_to_script (script, request, false, new uint8[0]);
			} catch (GLib.Error e) {
				response.complete_with_error (Marshal.from_dbus (e));
			}
		}

		protected async void ensure_loaded () throws Error {
			if (ensure_request != null) {
				var future = ensure_request.future;
				try {
					yield future.wait_async ();
				} catch (Gee.FutureError e) {
					throw (Error) future.exception;
				}
				return;
			}
			ensure_request = new Gee.Promise<bool> ();

			try {
				var id = yield host_session.attach_to (target_pid);
				session = yield host_session.obtain_agent_session (id);

				script = yield session.create_script ("darwin-agent", script_source);
				session.message_from_script.connect (on_message_from_script);
				yield session.load_script (script);

				ensure_request.set_value (true);
			} catch (GLib.Error raw_error) {
				script = AgentScriptId (0);

				if (session != null) {
					session.message_from_script.disconnect (on_message_from_script);
					session = null;
				}

				var error = Marshal.from_dbus (raw_error);
				ensure_request.set_exception (error);
				ensure_request = null;

				throw error;
			}
		}

		protected async void wait_for_unload () {
			try {
				yield unloaded.future.wait_async ();
			} catch (Gee.FutureError e) {
				assert_not_reached ();
			}
		}

		private void on_agent_session_closed (AgentSessionId id, AgentSession session) {
			if (session != this.session)
				return;

			unloaded.set_value (true);
		}

		private void on_message_from_script (AgentScriptId sid, string raw_message, bool has_data, uint8[] data) {
			if (sid != script)
				return;

			var parser = new Json.Parser ();
			try {
				parser.load_from_data (raw_message);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
			var message = parser.get_root ().get_object ();
			var type = message.get_string_member ("type");
			if (type == "send") {
				var event = message.get_array_member ("payload");
				var event_type = event.get_string_element (0);
				if (event_type == "frida:rpc") {
					var request_id = event.get_int_element (1);
					PendingResponse response;
					pending.unset (request_id.to_string (), out response);
					var status = event.get_string_element (2);
					if (status == "ok")
						response.complete_with_result (event.get_element (3));
					else
						response.complete_with_error (new Error.NOT_SUPPORTED (event.get_string_element (3)));
				} else {
					on_event (event_type, event);
				}
			} else {
				stderr.printf ("%s\n", raw_message);
			}
		}

		private class PendingResponse {
			public delegate void CompletionHandler ();
			private CompletionHandler handler;

			public Json.Node? result {
				get;
				private set;
			}

			public Error? error {
				get;
				private set;
			}

			public PendingResponse (owned CompletionHandler handler) {
				this.handler = (owned) handler;
			}

			public void complete_with_result (Json.Node r) {
				result = r;
				handler ();
			}

			public void complete_with_error (Error e) {
				error = e;
				handler ();
			}
		}
	}
}
#endif
