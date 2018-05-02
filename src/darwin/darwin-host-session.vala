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

		public Image? icon {
			get { return _icon; }
		}
		private Image? _icon;

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.LOCAL_SYSTEM; }
		}

		private DarwinHostSession host_session;

		construct {
			_icon = Image.from_data (_try_extract_icon ());
		}

		public async void close () {
			if (host_session != null) {
				host_session.agent_session_closed.disconnect (on_agent_session_closed);
				yield host_session.close ();
				host_session = null;
			}
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

		private void on_agent_session_closed (AgentSessionId id, AgentSession session, SessionDetachReason reason) {
			agent_session_closed (id, reason);
		}

		public static extern ImageData? _try_extract_icon ();
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
#if IOS
		private FruitLauncher fruit_launcher;
#endif

		private ApplicationEnumerator application_enumerator = new ApplicationEnumerator ();
		private ProcessEnumerator process_enumerator = new ProcessEnumerator ();

		public DarwinHostSession (owned DarwinHelper helper, owned TemporaryDirectory tempdir) {
			Object (helper: helper, tempdir: tempdir);
		}

		construct {
			helper.output.connect (on_output);
			helper.spawn_added.connect (on_spawn_added);
			helper.spawn_removed.connect (on_spawn_removed);

			injector = new Fruitjector (helper, false, tempdir);
			injector.uninjected.connect (on_uninjected);

			var blob = Frida.Data.Agent.get_frida_agent_dylib_blob ();
			agent = new AgentResource (blob.name, new Bytes.static (blob.data), tempdir);
		}

		public override async void close () {
			yield base.close ();

#if IOS
			if (fruit_launcher != null) {
				yield fruit_launcher.close ();
				fruit_launcher.spawn_added.disconnect (on_spawn_added);
				fruit_launcher.spawn_removed.disconnect (on_spawn_removed);
				fruit_launcher = null;
			}
#endif

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
			helper.spawn_added.disconnect (on_spawn_added);
			helper.spawn_removed.disconnect (on_spawn_removed);

			tempdir.destroy ();
		}

		protected override async AgentSessionProvider create_system_session_provider (out DBusConnection connection) throws Error {
			yield helper.preload ();

			var pid = helper.pid;

			string remote_address;
			var stream_request = yield helper.open_pipe_stream (pid, out remote_address);

			var fruitjector = injector as Fruitjector;
			var id = yield fruitjector.inject_library_resource (pid, agent, "frida_agent_main", remote_address);
			injectee_by_pid[pid] = id;

			IOStream stream;
			try {
				stream = yield stream_request.future.wait_async ();
			} catch (Gee.FutureError e) {
				throw new Error.TRANSPORT (e.message);
			}

			DBusConnection conn;
			AgentSessionProvider provider;
			try {
				conn = yield new DBusConnection (stream, ServerGuid.HOST_SESSION_SERVICE, AUTHENTICATION_SERVER | AUTHENTICATION_ALLOW_ANONYMOUS);

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
#if IOS
			yield get_fruit_launcher ().enable_spawn_gating ();
#else
			yield helper.enable_spawn_gating ();
#endif
		}

		public override async void disable_spawn_gating () throws Error {
#if IOS
			yield get_fruit_launcher ().disable_spawn_gating ();
#else
			yield helper.disable_spawn_gating ();
#endif
		}

		public override async HostSpawnInfo[] enumerate_pending_spawn () throws Error {
#if IOS
			return get_fruit_launcher ().enumerate_pending_spawn ();
#else
			return yield helper.enumerate_pending_spawn ();
#endif
		}

		public override async uint spawn (string path, string[] argv, bool has_envp, string[] envp) throws Error {
#if IOS
			if (!path.has_prefix ("/")) {
				string identifier = path;
				string? url = null;
				if (argv.length == 2)
					url = argv[1];
				else if (argv.length > 2)
					throw new Error.INVALID_ARGUMENT ("Too many arguments: expected identifier and optionally a URL to open");

				return yield get_fruit_launcher ().spawn (identifier, url);
			}
#endif

			return yield helper.spawn (path, argv, has_envp, envp);
		}

		protected override async void await_exec_transition (uint pid) throws Error {
			yield helper.wait_until_suspended (pid);
		}

		protected override async void cancel_exec_transition (uint pid) throws Error {
			yield helper.cancel_pending_waits (pid);
		}

		protected override bool process_is_alive (uint pid) {
			return Posix.kill ((Posix.pid_t) pid, 0) == 0 || Posix.errno == Posix.EPERM;
		}

		public override async void input (uint pid, uint8[] data) throws Error {
			yield helper.input (pid, data);
		}

		protected override async void perform_resume (uint pid) throws Error {
#if IOS
			if (fruit_launcher != null) {
				if (yield fruit_launcher.try_resume (pid))
					return;
			}
#endif

			yield helper.resume (pid);
		}

		public override async void kill (uint pid) throws Error {
			yield helper.kill_process (pid);
		}

		protected override async Gee.Promise<IOStream> perform_attach_to (uint pid, out Object? transport) throws Error {
			transport = null;

			var uninjected_handler = injector.uninjected.connect ((id) => perform_attach_to.callback ());
			while (injectee_by_pid.has_key (pid))
				yield;
			injector.disconnect (uninjected_handler);

			string remote_address;
			var stream_request = yield helper.open_pipe_stream (pid, out remote_address);

			var fruitjector = injector as Fruitjector;
			var id = yield fruitjector.inject_library_resource (pid, agent, "frida_agent_main", remote_address);
			injectee_by_pid[pid] = id;

			return stream_request;
		}

#if IOS
		private FruitLauncher get_fruit_launcher () {
			if (fruit_launcher == null) {
				fruit_launcher = new FruitLauncher (this);
				fruit_launcher.spawn_added.connect (on_spawn_added);
				fruit_launcher.spawn_removed.connect (on_spawn_removed);
			}
			return fruit_launcher;
		}
#endif

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
			foreach (var entry in injectee_by_pid.entries) {
				if (entry.value == id) {
					injectee_by_pid.unset (entry.key);
					return;
				}
			}

			uninjected (InjectorPayloadId (id));
		}
	}

#if IOS
	private class FruitLauncher : Object {
		public signal void spawn_added (HostSpawnInfo info);
		public signal void spawn_removed (HostSpawnInfo info);

		public weak DarwinHostSession host_session {
			get;
			construct;
		}

		public DarwinHelper helper {
			get;
			construct;
		}

		private LaunchdAgent launchd_agent;
		private bool spawn_gating_enabled = false;
		private Gee.HashMap<string, Gee.Promise<uint>> spawn_requests = new Gee.HashMap<string, Gee.Promise<uint>> ();
		private Gee.HashMap<uint, HostSpawnInfo?> pending_spawn = new Gee.HashMap<uint, HostSpawnInfo?> ();

		public FruitLauncher (DarwinHostSession host_session) {
			Object (host_session: host_session, helper: host_session.helper);
		}

		construct {
			launchd_agent = new LaunchdAgent (host_session);
			launchd_agent.app_launch_completed.connect (on_app_launch_completed);
			launchd_agent.spawn_captured.connect (on_spawn_captured);
		}

		~FruitLauncher () {
			launchd_agent.spawn_captured.disconnect (on_spawn_captured);
			launchd_agent.app_launch_completed.disconnect (on_app_launch_completed);
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

			var pending = pending_spawn.values.to_array ();
			pending_spawn.clear ();
			foreach (var spawn in pending) {
				spawn_removed (spawn);

				helper.resume.begin (spawn.pid);
			}
		}

		public HostSpawnInfo[] enumerate_pending_spawn () throws Error {
			var result = new HostSpawnInfo[pending_spawn.size];
			var index = 0;
			foreach (var spawn in pending_spawn.values)
				result[index++] = spawn;
			return result;
		}

		public async uint spawn (string identifier, string? url) throws Error {
			if (spawn_requests.has_key (identifier))
				throw new Error.INVALID_OPERATION ("Spawn already in progress for the specified identifier");

			var request = new Gee.Promise<uint> ();
			spawn_requests[identifier] = request;

			yield launchd_agent.prepare_for_launch (identifier);

			try {
				yield helper.kill_application (identifier);
				yield helper.launch (identifier, url);
			} catch (Error e) {
				launchd_agent.cancel_launch.begin (identifier);
				if (!spawn_requests.unset (identifier)) {
					var pid = request.future.value;
					if (pid != 0)
						helper.resume.begin (pid);
				}
				throw e;
			}

			var timeout = new TimeoutSource.seconds (20);
			timeout.set_callback (() => {
				spawn_requests.unset (identifier);
				request.set_exception (new Error.TIMED_OUT ("Unexpectedly timed out while waiting for app to launch"));
				return false;
			});
			timeout.attach (MainContext.get_thread_default ());

			try {
				var future = request.future;
				try {
					return yield future.wait_async ();
				} catch (Gee.FutureError e) {
					throw (Error) future.exception;
				}
			} catch (Error e) {
				launchd_agent.cancel_launch.begin (identifier);
				throw e;
			} finally {
				timeout.destroy ();
			}
		}

		public async bool try_resume (uint pid) throws Error {
			HostSpawnInfo? info;
			if (!pending_spawn.unset (pid, out info))
				return false;
			spawn_removed (info);

			yield helper.resume (pid);

			return true;
		}

		private void on_app_launch_completed (string identifier, uint pid, Error? error) {
			Gee.Promise<uint> request;
			if (spawn_requests.unset (identifier, out request)) {
				if (error == null)
					request.set_value (pid);
				else
					request.set_exception (error);
			} else {
				if (error == null)
					helper.resume.begin (pid);
			}
		}

		private void on_spawn_captured (HostSpawnInfo info) {
			var pid = info.pid;

			if (!spawn_gating_enabled) {
				helper.resume.begin (pid);
				return;
			}

			pending_spawn[pid] = info;
			spawn_added (info);
		}
	}

	private class LaunchdAgent : InternalAgent {
		public signal void app_launch_completed (string identifier, uint pid, Error? error);
		public signal void spawn_captured (HostSpawnInfo info);

		public LaunchdAgent (DarwinHostSession host_session) {
			string * source = Frida.Data.Darwin.get_launchd_js_blob ().data;
			Object (host_session: host_session, script_source: source);
		}

		public async void prepare_for_launch (string identifier) throws Error {
			yield call ("prepareForLaunch", new Json.Node[] { new Json.Node.alloc ().init_string (identifier) });
		}

		public async void cancel_launch (string identifier) throws Error {
			yield call ("cancelLaunch", new Json.Node[] { new Json.Node.alloc ().init_string (identifier) });
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
				var agent = new XpcProxyAgent (host_session as DarwinHostSession, identifier, pid);
				yield agent.run_until_exec ();
				app_launch_completed (identifier, pid, null);
			} catch (Error e) {
				app_launch_completed (identifier, pid, e);
			}
		}

		private async void prepare_xpcproxy (string identifier, uint pid) {
			try {
				var agent = new XpcProxyAgent (host_session as DarwinHostSession, identifier, pid);
				yield agent.run_until_exec ();
				spawn_captured (HostSpawnInfo (pid, identifier));
			} catch (Error e) {
			}
		}

		protected override async uint get_target_pid () throws Error {
			return 1;
		}
	}

	private class XpcProxyAgent : InternalAgent {
		public string identifier {
			get;
			construct;
		}

		public uint pid {
			get;
			construct;
		}

		public XpcProxyAgent (DarwinHostSession host_session, string identifier, uint pid) {
			string * source = Frida.Data.Darwin.get_xpcproxy_js_blob ().data;
			Object (host_session: host_session, script_source: source, identifier: identifier, pid: pid);
		}

		public async void run_until_exec () throws Error {
			yield ensure_loaded ();

			var helper = (host_session as DarwinHostSession).helper;
			yield helper.resume (pid);

			yield wait_for_unload ();

			yield helper.wait_until_suspended (pid);
		}

		protected override async uint get_target_pid () throws Error {
			return pid;
		}
	}
#endif
}
