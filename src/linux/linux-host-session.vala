namespace Frida {
	public class LinuxHostSessionBackend : Object, HostSessionBackend {
		private LinuxHostSessionProvider local_provider;

		public async void start () {
			assert (local_provider == null);
			local_provider = new LinuxHostSessionProvider ();
			provider_available (local_provider);
		}

		public async void stop () {
			assert (local_provider != null);
			provider_unavailable (local_provider);
			yield local_provider.close ();
			local_provider = null;
		}
	}

	public class LinuxHostSessionProvider : Object, HostSessionProvider {
		public string id {
			get { return "local"; }
		}

		public string name {
			get { return "Local System"; }
		}

		public Image? icon {
			get { return null; }
		}

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.LOCAL_SYSTEM; }
		}

		private LinuxHostSession host_session;

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
			host_session = new LinuxHostSession ();
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
	}

	public class LinuxHostSession : BaseDBusHostSession {
		private AgentContainer system_session_container;

		private HelperProcess helper;
		private AgentResource agent;

#if ANDROID
		private RoboLauncher robo_launcher;
		private SystemUIAgent system_ui_agent;
#endif

		construct {
			helper = new HelperProcess ();
			helper.output.connect (on_output);

			injector = new Linjector.with_helper (helper);
			injector.uninjected.connect (on_uninjected);

			var blob32 = Frida.Data.Agent.get_frida_agent_32_so_blob ();
			var blob64 = Frida.Data.Agent.get_frida_agent_64_so_blob ();
			agent = new AgentResource ("frida-agent-%u.so",
				new MemoryInputStream.from_data (blob32.data, null),
				new MemoryInputStream.from_data (blob64.data, null),
				AgentMode.INSTANCED,
				helper.tempdir);

#if ANDROID
			system_ui_agent = new SystemUIAgent (this);
#endif
		}

		public override async void close () {
			yield base.close ();

#if ANDROID
			if (robo_launcher != null) {
				yield robo_launcher.close ();
				robo_launcher = null;
			}

			yield system_ui_agent.close ();
			system_ui_agent = null;
#endif

			var linjector = injector as Linjector;

			var uninjected_handler = injector.uninjected.connect ((id) => close.callback ());
			while (linjector.any_still_injected ())
				yield;
			injector.disconnect (uninjected_handler);

			injector.uninjected.disconnect (on_uninjected);
			yield linjector.close ();
			injector = null;

			yield helper.close ();
			helper.output.disconnect (on_output);
			helper = null;

			if (system_session_container != null) {
				yield system_session_container.destroy ();
				system_session_container = null;
			}
		}

		protected override async AgentSessionProvider create_system_session_provider (out DBusConnection connection) throws Error {
			PipeTransport.set_temp_directory (helper.tempdir.path);

			var agent_filename = agent.path_template.printf (sizeof (void *) == 8 ? 64 : 32);
			system_session_container = yield AgentContainer.create (agent_filename);

			connection = system_session_container.connection;

			return system_session_container;
		}

		public override async HostApplicationInfo get_frontmost_application () throws Error {
#if ANDROID
			return yield system_ui_agent.get_frontmost_application ();
#else
			return System.get_frontmost_application ();
#endif
		}

		public override async HostApplicationInfo[] enumerate_applications () throws Error {
#if ANDROID
			return yield system_ui_agent.enumerate_applications ();
#else
			return System.enumerate_applications ();
#endif
		}

		public override async HostProcessInfo[] enumerate_processes () throws Error {
			return System.enumerate_processes ();
		}

		public override async void enable_spawn_gating () throws Error {
#if ANDROID
			yield get_robo_launcher ().enable_spawn_gating ();
#else
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
#endif
		}

		public override async void disable_spawn_gating () throws Error {
#if ANDROID
			yield get_robo_launcher ().disable_spawn_gating ();
#else
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
#endif
		}

		public override async HostSpawnInfo[] enumerate_pending_spawns () throws Error {
#if ANDROID
			return get_robo_launcher ().enumerate_pending_spawns ();
#else
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
#endif
		}

		public override async uint spawn (string path, string[] argv, string[] envp) throws Error {
#if ANDROID
			if (!path.has_prefix ("/")) {
				string package_name = path;
				if (argv.length > 1)
					throw new Error.INVALID_ARGUMENT ("Too many arguments: expected package name only");
				return yield get_robo_launcher ().spawn (package_name);
			} else {
				return yield helper.spawn (path, argv, envp);
			}
#else
			return yield helper.spawn (path, argv, envp);
#endif
		}

		protected override bool try_handle_child (HostChildInfo info) {
#if ANDROID
			if (robo_launcher != null)
				return robo_launcher.try_handle_child (info);
#endif

			return false;
		}

		public override async void input (uint pid, uint8[] data) throws Error {
			yield helper.input (pid, data);
		}

		protected override async void perform_resume (uint pid) throws Error {
			yield helper.resume (pid);
		}

		public override async void kill (uint pid) throws Error {
			yield helper.kill (pid);
		}

		protected override async Gee.Promise<IOStream> perform_attach_to (uint pid, out Object? transport) throws Error {
			PipeTransport.set_temp_directory (helper.tempdir.path);

			PipeTransport t;
			try {
				t = new PipeTransport ();
			} catch (IOError e) {
				throw new Error.NOT_SUPPORTED (e.message);
			}

			var stream_request = Pipe.open (t.local_address);

			var uninjected_handler = injector.uninjected.connect ((id) => perform_attach_to.callback ());
			while (injectee_by_pid.has_key (pid))
				yield;
			injector.disconnect (uninjected_handler);

			var linjector = injector as Linjector;
			var id = yield linjector.inject_library_resource (pid, agent, "frida_agent_main", t.remote_address);
			injectee_by_pid[pid] = id;

			transport = t;

			return stream_request;
		}

#if ANDROID
		private RoboLauncher get_robo_launcher () {
			if (robo_launcher == null) {
				robo_launcher = new RoboLauncher (this, helper, system_ui_agent);
				robo_launcher.spawned.connect ((info) => { spawned (info); });
			}
			return robo_launcher;
		}
#endif

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
	}

#if ANDROID
	private class RoboLauncher : Object {
		public signal void spawned (HostSpawnInfo info);

		public weak LinuxHostSession host_session {
			get;
			construct;
		}

		public HelperProcess helper {
			get;
			construct;
		}

		public SystemUIAgent system_ui_agent {
			get;
			construct;
		}

		private Gee.Promise<bool> ensure_request;

		private Gee.HashMap<uint, ZygoteAgent> zygote_agent_by_pid = new Gee.HashMap<uint, ZygoteAgent> ();

		private bool spawn_gating_enabled = false;
		private Gee.HashMap<string, Gee.Promise<uint>> spawn_request_by_package_name = new Gee.HashMap<string, Gee.Promise<uint>> ();

		public RoboLauncher (LinuxHostSession host_session, HelperProcess helper, SystemUIAgent system_ui_agent) {
			Object (host_session: host_session, helper: helper, system_ui_agent: system_ui_agent);
		}

		public async void close () {
			foreach (var request in spawn_request_by_package_name.values)
				request.set_exception (new Error.INVALID_OPERATION ("Cancelled by shutdown"));
			spawn_request_by_package_name.clear ();
		}

		public async void enable_spawn_gating () throws Error {
			yield ensure_loaded ();
			spawn_gating_enabled = true;
		}

		public async void disable_spawn_gating () throws Error {
			spawn_gating_enabled = false;
		}

		public HostSpawnInfo[] enumerate_pending_spawns () throws Error {
			return new HostSpawnInfo[0];
		}

		public async uint spawn (string package_name) throws Error {
			yield ensure_loaded ();

			if (spawn_request_by_package_name.has_key (package_name))
				throw new Error.INVALID_OPERATION ("Spawn already in progress for the specified package name");

			var request = new Gee.Promise<uint> ();
			spawn_request_by_package_name[package_name] = request;

			try {
				yield system_ui_agent.stop_activity (package_name);
				yield system_ui_agent.start_activity (package_name);
			} catch (Error e) {
				spawn_request_by_package_name.unset (package_name);
				throw e;
			}

			var timeout = new TimeoutSource.seconds (10);
			timeout.set_callback (() => {
				spawn_request_by_package_name.unset (package_name);
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
			} finally {
				timeout.destroy ();
			}
		}

		public bool try_handle_child (HostChildInfo info) {
			if (!zygote_agent_by_pid.has_key (info.parent_pid))
				return false;

			Gee.Promise<uint> spawn_request;
			if (spawn_request_by_package_name.unset (info.identifier, out spawn_request)) {
				spawn_request.set_value (info.pid);
				return true;
			}

			if (spawn_gating_enabled) {
				spawned (HostSpawnInfo (info.pid, info.identifier));
				return true;
			}

			return false;
		}

		private async void ensure_loaded () throws Error {
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
				foreach (HostProcessInfo info in System.enumerate_processes ()) {
					var name = info.name;
					if (name == "zygote" || name == "zygote64") {
						var agent = new ZygoteAgent (host_session, info.pid);
						yield agent.load ();
						zygote_agent_by_pid[info.pid] = agent;
					}
				}

				ensure_request.set_value (true);
			} catch (Error e) {
				ensure_request.set_exception (e);
				ensure_request = null;

				throw e;
			}
		}
	}

	private class ZygoteAgent : InternalAgent {
		public uint pid {
			get;
			construct;
		}

		public ZygoteAgent (LinuxHostSession host_session, uint pid) {
			Object (host_session: host_session, script_source: null, pid: pid);
		}

		public async void load () throws Error {
			yield ensure_loaded ();

			try {
				yield session.enable_child_gating ();
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}
		}

		protected override async uint get_target_pid () throws Error {
			return pid;
		}
	}

	private class SystemUIAgent : InternalAgent {
		public SystemUIAgent (LinuxHostSession host_session) {
			string * source = Frida.Data.Android.get_systemui_js_blob ().data;
			Object (host_session: host_session, script_source: source);
		}

		public async HostApplicationInfo[] enumerate_applications () throws Error {
			var apps = yield call ("enumerateApplications", new Json.Node[] {});

			var items = apps.get_array ();
			var length = items.get_length ();

			var result = new HostApplicationInfo[length];
			var no_icon = ImageData (0, 0, 0, "");

			for (var i = 0; i != length; i++) {
				var item = items.get_array_element (i);
				var identifier = item.get_string_element (0);
				var name = item.get_string_element (1);
				var pid = (uint) item.get_int_element (2);
				result[i] = HostApplicationInfo (identifier, name, pid, no_icon, no_icon);
			}

			return result;
		}

		public async HostApplicationInfo get_frontmost_application () throws Error {
			var app = yield call ("getFrontmostApplication", new Json.Node[] {});
			var no_icon = ImageData (0, 0, 0, "");
			if (app != null) {
				var item = app.get_array ();
				var identifier = item.get_string_element (0);
				var name = item.get_string_element (1);
				var pid = (uint) item.get_int_element (2);
				return HostApplicationInfo (identifier, name, pid, no_icon, no_icon);
			} else {
				return HostApplicationInfo ("", "", 0, no_icon, no_icon);
			}
		}

		public async void start_activity (string package_name) throws Error {
			yield call ("startActivity", new Json.Node[] { new Json.Node.alloc ().init_string (package_name) });
		}

		public async void stop_activity (string package_name) throws Error {
			bool existing_app_killed = false;
			do {
				existing_app_killed = false;
				var installed_apps = yield enumerate_applications ();
				foreach (var installed_app in installed_apps) {
					if (installed_app.identifier == package_name) {
						var running_pid = installed_app.pid;
						if (running_pid != 0) {
							System.kill (running_pid);

							existing_app_killed = true;

							var source = new TimeoutSource (100);
							source.set_callback (() => {
								stop_activity.callback ();
								return false;
							});
							source.attach (MainContext.get_thread_default ());
							yield;
						}
						break;
					}
				}
			} while (existing_app_killed);
		}

		protected override async uint get_target_pid () throws Error {
			return LocalProcesses.get_pid ("com.android.systemui");
		}
	}

	namespace LocalProcesses {
		internal uint find_pid (string name) {
			foreach (HostProcessInfo info in System.enumerate_processes ()) {
				if (info.name == name)
					return info.pid;
			}
			return 0;
		}

		internal uint get_pid (string name) throws Error {
			var pid = find_pid (name);
			if (pid == 0)
				throw new Error.PROCESS_NOT_FOUND ("Unable to find process with name '%s'".printf (name));
			return pid;
		}
	}
#endif
}
