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
			get { return HostSessionProviderKind.LOCAL; }
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

		private void on_agent_session_closed (AgentSessionId id, AgentSession session, SessionDetachReason reason, CrashInfo? crash) {
			agent_session_closed (id, reason, crash);
		}
	}

	public class LinuxHostSession : BaseDBusHostSession {
		private AgentContainer system_session_container;

		private LinuxHelperProcess helper;
		private AgentResource? agent_resource;

#if ANDROID
		private RoboLauncher robo_launcher;
		private SystemServerAgent system_server_agent;
		private CrashMonitor crash_monitor;
#endif

		construct {
			helper = new LinuxHelperProcess ();
			helper.output.connect (on_output);

			injector = new Linjector.with_helper (helper);
			injector.uninjected.connect (on_uninjected);

#if ANDROID
			system_server_agent = new SystemServerAgent (this);

			robo_launcher = new RoboLauncher (this, system_server_agent);
			robo_launcher.spawn_added.connect (on_robo_launcher_spawn_added);
			robo_launcher.spawn_removed.connect (on_robo_launcher_spawn_removed);

			crash_monitor = new CrashMonitor ();
			crash_monitor.process_crashed.connect (on_process_crashed);
#endif
		}

		public override async void preload () throws Error {
#if ANDROID
			yield system_server_agent.preload ();

			yield robo_launcher.preload ();
#endif
		}

		public override async void close () {
			yield base.close ();

#if ANDROID
			yield robo_launcher.close ();
			robo_launcher.spawn_added.disconnect (on_robo_launcher_spawn_added);
			robo_launcher.spawn_removed.disconnect (on_robo_launcher_spawn_removed);
			robo_launcher = null;

			yield system_server_agent.close ();
			system_server_agent = null;

			crash_monitor.process_crashed.disconnect (on_process_crashed);
			yield crash_monitor.close ();
			crash_monitor = null;
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

			agent_resource = null;
		}

		protected override async AgentSessionProvider create_system_session_provider (out DBusConnection connection) throws Error {
			PipeTransport.set_temp_directory (helper.get_tempdir ().path);

			var agent_filename = get_agent_resource ().get_path_template ().printf (sizeof (void *) == 8 ? 64 : 32);
			system_session_container = yield AgentContainer.create (agent_filename);

			connection = system_session_container.connection;

			return system_session_container;
		}

		public override async HostApplicationInfo get_frontmost_application () throws Error {
#if ANDROID
			return yield system_server_agent.get_frontmost_application ();
#else
			return System.get_frontmost_application ();
#endif
		}

		public override async HostApplicationInfo[] enumerate_applications () throws Error {
#if ANDROID
			return yield system_server_agent.enumerate_applications ();
#else
			return System.enumerate_applications ();
#endif
		}

		public override async HostProcessInfo[] enumerate_processes () throws Error {
			return System.enumerate_processes ();
		}

		public override async void enable_spawn_gating () throws Error {
#if ANDROID
			yield robo_launcher.enable_spawn_gating ();
#else
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
#endif
		}

		public override async void disable_spawn_gating () throws Error {
#if ANDROID
			yield robo_launcher.disable_spawn_gating ();
#else
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
#endif
		}

		public override async HostSpawnInfo[] enumerate_pending_spawn () throws Error {
#if ANDROID
			return robo_launcher.enumerate_pending_spawn ();
#else
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
#endif
		}

		public override async uint spawn (string program, HostSpawnOptions options) throws Error {
#if ANDROID
			if (!program.has_prefix ("/")) {
				return yield robo_launcher.spawn (program, options);
			} else {
				return yield helper.spawn (program, options);
			}
#else
			return yield helper.spawn (program, options);
#endif
		}

		protected override bool try_handle_child (HostChildInfo info) {
#if ANDROID
			return robo_launcher.try_handle_child (info);
#else
			return false;
#endif
		}

		protected override void notify_child_resumed (uint pid) {
#if ANDROID
			robo_launcher.notify_child_resumed (pid);
#endif
		}

		protected override void notify_child_gating_changed (uint pid, uint subscriber_count) {
#if ANDROID
			robo_launcher.notify_child_gating_changed (pid, subscriber_count);
#endif
		}

		protected override async void prepare_exec_transition (uint pid) throws Error {
			yield helper.prepare_exec_transition (pid);
		}

		protected override async void await_exec_transition (uint pid) throws Error {
			yield helper.await_exec_transition (pid);
		}

		protected override async void cancel_exec_transition (uint pid) throws Error {
			yield helper.cancel_exec_transition (pid);
		}

		protected override bool process_is_alive (uint pid) {
			return Posix.kill ((Posix.pid_t) pid, 0) == 0 || Posix.errno == Posix.EPERM;
		}

		public override async void input (uint pid, uint8[] data) throws Error {
			yield helper.input (pid, data);
		}

		protected override async void perform_resume (uint pid) throws Error {
			yield helper.resume (pid);
		}

		public override async void kill (uint pid) throws Error {
#if ANDROID
			if (yield system_server_agent.try_stop_package_by_pid (pid))
				return;
#endif

			yield helper.kill (pid);
		}

		protected override async Gee.Promise<IOStream> perform_attach_to (uint pid, out Object? transport) throws Error {
			var agent_resource = get_agent_resource ();

			PipeTransport.set_temp_directory (helper.get_tempdir ().path);

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
			var id = yield linjector.inject_library_resource (pid, agent_resource, "frida_agent_main", t.remote_address);
			injectee_by_pid[pid] = id;

			transport = t;

			return stream_request;
		}

#if ANDROID
		private void on_robo_launcher_spawn_added (HostSpawnInfo info) {
			spawn_added (info);
		}

		private void on_robo_launcher_spawn_removed (HostSpawnInfo info) {
			spawn_removed (info);
		}

		protected override async CrashInfo? try_collect_crash (uint pid) {
			return yield crash_monitor.try_collect_crash (pid);
		}

		private void on_process_crashed (CrashInfo info) {
			process_crashed (info);

			if (still_attached_to (info.pid)) {
				/*
				 * May take a while as a Java fatal exception typically won't terminate the process until
				 * the user dismisses the dialog.
				 */
				crash_monitor.disable_crash_delivery_timeout (info.pid);
			}
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

		private AgentResource get_agent_resource () throws Error {
			if (agent_resource == null) {
				var blob32 = Frida.Data.Agent.get_frida_agent_32_so_blob ();
				var blob64 = Frida.Data.Agent.get_frida_agent_64_so_blob ();
				agent_resource = new AgentResource ("frida-agent-%u.so",
					new MemoryInputStream.from_data (blob32.data, null),
					new MemoryInputStream.from_data (blob64.data, null),
					AgentMode.INSTANCED,
					helper.get_tempdir ());
			}
			return agent_resource;
		}

	}

#if ANDROID
	private class RoboLauncher : Object {
		public signal void spawn_added (HostSpawnInfo info);
		public signal void spawn_removed (HostSpawnInfo info);

		public weak LinuxHostSession host_session {
			get;
			construct;
		}

		public SystemServerAgent system_server_agent {
			get;
			construct;
		}

		private Gee.Promise<bool> ensure_request;

		private Gee.HashMap<uint, ZygoteAgent> zygote_agents = new Gee.HashMap<uint, ZygoteAgent> ();

		private bool spawn_gating_enabled = false;
		private Gee.HashMap<string, Gee.Promise<uint>> spawn_requests = new Gee.HashMap<string, Gee.Promise<uint>> ();
		private Gee.HashMap<uint, HostSpawnInfo?> pending_spawn = new Gee.HashMap<uint, HostSpawnInfo?> ();

		public RoboLauncher (LinuxHostSession host_session, SystemServerAgent system_server_agent) {
			Object (host_session: host_session, system_server_agent: system_server_agent);
		}

		public async void preload () throws Error {
			yield ensure_loaded ();
		}

		public async void close () {
			if (ensure_request != null) {
				try {
					yield ensure_loaded ();
				} catch (Error e) {
				}
			}

			foreach (var request in spawn_requests.values)
				request.set_exception (new Error.INVALID_OPERATION ("Cancelled by shutdown"));
			spawn_requests.clear ();

			foreach (var agent in zygote_agents.values)
				yield agent.close ();
			zygote_agents.clear ();
		}

		public async void enable_spawn_gating () throws Error {
			yield ensure_loaded ();
			spawn_gating_enabled = true;
		}

		public async void disable_spawn_gating () throws Error {
			spawn_gating_enabled = false;

			var pending = pending_spawn.values.to_array ();
			pending_spawn.clear ();
			foreach (var spawn in pending) {
				spawn_removed (spawn);

				host_session.resume.begin (spawn.pid);
			}
		}

		public HostSpawnInfo[] enumerate_pending_spawn () throws Error {
			var result = new HostSpawnInfo[pending_spawn.size];
			var index = 0;
			foreach (var spawn in pending_spawn.values)
				result[index++] = spawn;
			return result;
		}

		public async uint spawn (string program, HostSpawnOptions options) throws Error {
			string package = program;

			if (options.has_argv)
				throw new Error.NOT_SUPPORTED ("The 'argv' option is not supported when spawning Android apps");

			if (options.has_envp)
				throw new Error.NOT_SUPPORTED ("The 'envp' option is not supported when spawning Android apps");

			if (options.has_env)
				throw new Error.NOT_SUPPORTED ("The 'env' option is not supported when spawning Android apps");

			if (options.cwd.length > 0)
				throw new Error.NOT_SUPPORTED ("The 'cwd' option is not supported when spawning Android apps");

			if (options.stdio != INHERIT)
				throw new Error.NOT_SUPPORTED ("Redirected stdio is not supported when spawning Android apps");

			PackageEntrypoint? entrypoint = null;

			var aux_options = options.load_aux ();

			if (aux_options.contains ("activity")) {
				string? activity = null;
				if (!aux_options.lookup ("activity", "s", out activity))
					throw new Error.INVALID_ARGUMENT ("The 'activity' option must be a string");
				activity = canonicalize_class_name (activity, package);

				if (aux_options.contains ("action"))
					throw new Error.INVALID_ARGUMENT ("The 'action' option should only be specified when a 'receiver' is specified");

				entrypoint = new ActivityEntrypoint (activity);
			}

			if (aux_options.contains ("receiver")) {
				if (entrypoint != null)
					throw new Error.INVALID_ARGUMENT ("Only one of 'activity' or 'receiver' (with 'action') may be specified");

				string? receiver = null;
				if (!aux_options.lookup ("receiver", "s", out receiver))
					throw new Error.INVALID_ARGUMENT ("The 'receiver' option must be a string");
				receiver = canonicalize_class_name (receiver, package);

				string? action = null;
				if (!aux_options.contains ("action"))
					throw new Error.INVALID_ARGUMENT ("The 'action' option is required when 'receiver' is specified");
				if (!aux_options.lookup ("action", "s", out action))
					throw new Error.INVALID_ARGUMENT ("The 'action' option must be a string");

				entrypoint = new BroadcastReceiverEntrypoint (receiver, action);
			}

			if (entrypoint == null)
				entrypoint = new DefaultActivityEntrypoint ();

			yield ensure_loaded ();

			var process_name = yield system_server_agent.get_process_name (package);
			if (spawn_requests.has_key (process_name))
				throw new Error.INVALID_OPERATION ("Spawn already in progress for the specified package name");

			var request = new Gee.Promise<uint> ();
			spawn_requests[process_name] = request;

			try {
				yield system_server_agent.stop_package (package);
				yield system_server_agent.start_package (package, entrypoint);
			} catch (Error e) {
				spawn_requests.unset (process_name);
				throw e;
			}

			var timeout = new TimeoutSource.seconds (20);
			timeout.set_callback (() => {
				spawn_requests.unset (process_name);
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
			var agent = zygote_agents[info.parent_pid];
			if (agent == null)
				return false;

			var pid = info.pid;

			Gee.Promise<uint> spawn_request;
			if (spawn_requests.unset (info.identifier, out spawn_request)) {
				spawn_request.set_value (pid);
				return true;
			}

			if (spawn_gating_enabled) {
				var spawn_info = HostSpawnInfo (pid, info.identifier);
				pending_spawn[pid] = spawn_info;
				spawn_added (spawn_info);
				return true;
			}

			if (agent.child_gating_only_used_by_us) {
				var source = new IdleSource ();
				var host_session = this.host_session;
				source.set_callback (() => {
					host_session.resume.begin (pid);
					return false;
				});
				source.attach (MainContext.get_thread_default ());
				return true;
			}

			return false;
		}

		public void notify_child_resumed (uint pid) {
			HostSpawnInfo? info;
			if (pending_spawn.unset (pid, out info))
				spawn_removed (info);
		}

		public void notify_child_gating_changed (uint pid, uint subscriber_count) {
			var agent = zygote_agents[pid];
			if (agent != null)
				agent.child_gating_only_used_by_us = subscriber_count == 1;
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
						var pid = info.pid;

						var agent = new ZygoteAgent (host_session, pid);
						zygote_agents[pid] = agent;

						try {
							yield agent.load ();
						} catch (Error e) {
							zygote_agents.unset (pid);

							if (e is Error.PERMISSION_DENIED) {
								throw new Error.NOT_SUPPORTED ("Unable to access %s while preparing for app launch;" +
									" try disabling Magisk Hide in case it is active", name);
							} else {
								throw e;
							}
						}
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

		public bool child_gating_only_used_by_us {
			get;
			set;
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

	private class SystemServerAgent : InternalAgent {
		public SystemServerAgent (LinuxHostSession host_session) {
			string * source = Frida.Data.Android.get_system_server_js_blob ().data;
			Object (
				host_session: host_session,
				script_source: source,
				enable_jit: true
			);
		}

		public async void preload () throws Error {
			yield enumerate_applications ();

			try {
				yield get_process_name ("");
			} catch (Error e) {
			}

			try {
				yield start_package ("", new DefaultActivityEntrypoint ());
			} catch (Error e) {
			}
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

		public async string get_process_name (string package) throws Error {
			var package_name_value = new Json.Node.alloc ().init_string (package);

			var process_name = yield call ("getProcessName", new Json.Node[] { package_name_value });

			return process_name.get_string ();
		}

		public async void start_package (string package, PackageEntrypoint entrypoint) throws Error {
			var package_value = new Json.Node.alloc ().init_string (package);

			if (entrypoint is DefaultActivityEntrypoint) {
				var activity_value = new Json.Node.alloc ();
				activity_value.init_null ();

				yield call ("startActivity", new Json.Node[] { package_value, activity_value });
			} else if (entrypoint is ActivityEntrypoint) {
				var e = entrypoint as ActivityEntrypoint;

				var activity_value = new Json.Node.alloc ();
				activity_value.init_string (e.activity);

				yield call ("startActivity", new Json.Node[] { package_value, activity_value });
			} else if (entrypoint is BroadcastReceiverEntrypoint) {
				var e = entrypoint as BroadcastReceiverEntrypoint;

				var receiver_value = new Json.Node.alloc ();
				receiver_value.init_string (e.receiver);

				var action_value = new Json.Node.alloc ();
				action_value.init_string (e.action);

				yield call ("sendBroadcast", new Json.Node[] { package_value, receiver_value, action_value });
			} else {
				assert_not_reached ();
			}
		}

		public async void stop_package (string package) throws Error {
			var package_value = new Json.Node.alloc ().init_string (package);

			yield call ("stopPackage", new Json.Node[] { package_value });
		}

		public async bool try_stop_package_by_pid (uint pid) throws Error {
			var pid_value = new Json.Node.alloc ().init_int (pid);

			var success = yield call ("tryStopPackageByPid", new Json.Node[] { pid_value });

			return success.get_boolean ();
		}

		protected override async uint get_target_pid () throws Error {
			return LocalProcesses.get_pid ("system_server");
		}
	}

	private class CrashMonitor : Object {
		public signal void process_crashed (CrashInfo crash);

		private Object logcat;
		private DataInputStream input;
		private Cancellable cancellable = new Cancellable ();
		private Gee.HashMap<uint, CrashDelivery> crash_deliveries = new Gee.HashMap<uint, CrashDelivery> ();
		private Gee.HashMap<uint, CrashBuilder> crash_builders = new Gee.HashMap<uint, CrashBuilder> ();
		private Timer since_start;

		construct {
			since_start = new Timer ();

			start_monitoring.begin ();
		}

		public async void close () {
			cancellable.cancel ();

			if (logcat != null) {
				if (logcat is Subprocess) {
					var process = logcat as Subprocess;
					process.send_signal (Posix.Signal.TERM);
				} else if (logcat is SuperSU.Process) {
					var process = logcat as SuperSU.Process;
					yield process.detach (); // TODO: Figure out how we can terminate it.
				}
				logcat = null;
			}
		}

		public async CrashInfo? try_collect_crash (uint pid) {
			var delivery = get_crash_delivery_for_pid (pid);
			try {
				return yield delivery.future.wait_async ();
			} catch (Gee.FutureError future_error) {
				return null;
			}
		}

		public void disable_crash_delivery_timeout (uint pid) {
			var delivery = crash_deliveries[pid];
			if (delivery != null)
				delivery.disable_timeout ();
		}

		private void on_crash_received (CrashInfo crash) {
			var delivery = get_crash_delivery_for_pid (crash.pid);
			delivery.complete (crash);

			process_crashed (crash);
		}

		private void on_log_entry (LogEntry entry) {
			if (since_start.elapsed () < 2.0)
				return;

			if (entry.tag == "libc") {
				var delivery = get_crash_delivery_for_pid (entry.pid);
				delivery.extend_timeout ();
				return;
			}

			bool is_java_crash = entry.message.has_prefix ("FATAL EXCEPTION: ");
			if (is_java_crash) {
				try {
					var crash = parse_java_report (entry.message);
					on_crash_received (crash);
				} catch (Error e) {
				}

				return;
			}

			var builder = get_crash_builder_for_reporter_pid (entry.pid);
			builder.append (entry.message);
		}

		private CrashDelivery get_crash_delivery_for_pid (uint pid) {
			var delivery = crash_deliveries[pid];
			if (delivery == null) {
				delivery = new CrashDelivery (pid);
				delivery.expired.connect (on_crash_delivery_expired);
				crash_deliveries[pid] = delivery;
			}
			return delivery;
		}

		private void on_crash_delivery_expired (CrashDelivery delivery) {
			crash_deliveries.unset (delivery.pid);
		}

		private CrashBuilder get_crash_builder_for_reporter_pid (uint pid) {
			var builder = crash_builders[pid];
			if (builder == null) {
				builder = new CrashBuilder (pid);
				builder.completed.connect (on_crash_builder_completed);
				crash_builders[pid] = builder;
			}
			return builder;
		}

		private void on_crash_builder_completed (CrashBuilder builder, string report) {
			crash_builders.unset (builder.reporter_pid);

			try {
				var crash = parse_native_report (report);
				on_crash_received (crash);
			} catch (Error e) {
			}
		}

		private static CrashInfo parse_java_report (string report) throws Error {
			MatchInfo info;
			if (!/^Process: (.+), PID: (\d+)$/m.match (report, 0, out info)) {
				throw new Error.INVALID_ARGUMENT ("Malformed Java crash report");
			}

			string process_name = info.fetch (1);

			string raw_pid = info.fetch (2);
			uint pid = (uint) uint64.parse (raw_pid);

			string summary = summarize_java_report (report);

			return CrashInfo (pid, process_name, summary, report);
		}

		private static CrashInfo parse_native_report (string report) throws Error {
			MatchInfo info;
			if (!/^pid: (\d+), tid: \d+, name: (\S+) +>>>/m.match (report, 0, out info)) {
				throw new Error.INVALID_ARGUMENT ("Malformed native crash report");
			}

			string raw_pid = info.fetch (1);
			uint pid = (uint) uint64.parse (raw_pid);

			string process_name = info.fetch (2);

			string summary = summarize_native_report (report);

			return CrashInfo (pid, process_name, summary, report);
		}

		private static string summarize_java_report (string report) throws Error {
			MatchInfo info;

			string? last_cause = null;
			try {
				var cause_pattern = /^Caused by: (.+)$/m;
				cause_pattern.match (report, 0, out info);
				while (info.matches ()) {
					last_cause = info.fetch (1);
					info.next ();
				}
			} catch (RegexError e) {
			}
			if (last_cause != null)
				return last_cause;

			var lines = report.split ("\n", 4);
			if (lines.length < 3)
				throw new Error.INVALID_ARGUMENT ("Malformed Java crash report");
			return lines[2];
		}

		private static string summarize_native_report (string report) throws Error {
			MatchInfo info;
			if (!/^signal \d+ \((\w+)\), code \S+ \((\w+)\)/m.match (report, 0, out info)) {
				return "Unknown error";
			}
			string signal_name = info.fetch (1);
			string code_name = info.fetch (2);

			if (signal_name == "SIGSEGV") {
				if (code_name == "SEGV_MAPERR")
					return "Bad access due to invalid address";
				if (code_name == "SEGV_ACCERR")
					return "Bad access due to protection failure";
			}

			if (signal_name == "SIGABRT")
				return "Trace/BPT trap";

			if (signal_name == "SIGILL")
				return "Illegal instruction";

			return "%s %s".printf (signal_name, code_name);
		}

		private async void start_monitoring () {
			InputStream stdout_pipe = null;

			try {
				var process = yield SuperSU.spawn ("/", new string[] { "su", "-c", "logcat", "-b", "crash", "-B" }, null, true);

				logcat = process;
				stdout_pipe = process.output;
			} catch (Error e) {
			}

			if (stdout_pipe == null) {
				try {
					var process = new Subprocess.newv ({ "logcat", "-b", "crash", "-B" }, STDIN_INHERIT | STDOUT_PIPE | STDERR_SILENCE);

					logcat = process;
					stdout_pipe = process.get_stdout_pipe ();
				} catch (GLib.Error e) {
				}
			}

			if (stdout_pipe == null)
				return;

			input = new DataInputStream (stdout_pipe);
			input.byte_order = HOST_ENDIAN;

			process_messages.begin ();
		}

		private async void process_messages () {
			try {
				while (true) {
					yield prepare_to_read (2 * sizeof (uint16));
					size_t payload_size = input.read_uint16 (cancellable);
					size_t header_size = input.read_uint16 (cancellable);
					if (header_size < 24)
						throw new Error.PROTOCOL ("Header too short");
					yield prepare_to_read (header_size + payload_size - 4);

					var entry = new LogEntry ();

					entry.pid = input.read_int32 (cancellable);
					entry.tid = input.read_uint32 (cancellable);
					entry.sec = input.read_uint32 (cancellable);
					entry.nsec = input.read_uint32 (cancellable);
					entry.lid = input.read_uint32 (cancellable);
					size_t ignored_size = header_size - 24;
					if (ignored_size > 0)
						input.skip (ignored_size, cancellable);

					var payload_buf = new uint8[payload_size + 1];
					input.read (payload_buf[0:payload_size], cancellable);
					payload_buf[payload_size] = 0;

					uint8 * payload_start = payload_buf;

					entry.priority = payload_start[0];
					unowned string tag = (string) (payload_start + 1);
					unowned string message = (string) (payload_start + 1 + tag.length + 1);
					entry.tag = tag;
					entry.message = message;

					on_log_entry (entry);
				}
			} catch (GLib.Error e) {
			}
		}

		private async void prepare_to_read (size_t required) throws GLib.Error {
			while (true) {
				size_t available = input.get_available ();
				if (available >= required)
					return;
				ssize_t n = yield input.fill_async ((ssize_t) (required - available));
				if (n == 0)
					throw new Error.TRANSPORT ("Disconnected");
			}
		}

		private class LogEntry {
			public int32 pid;
			public uint32 tid;
			public uint32 sec;
			public uint32 nsec;
			public uint32 lid;
			public uint priority;
			public string tag;
			public string message;
		}

		private class CrashDelivery : Object {
			public signal void expired ();

			public uint pid {
				get;
				construct;
			}

			public Gee.Future<CrashInfo?> future {
				get {
					return promise.future;
				}
			}

			private Gee.Promise<CrashInfo?> promise = new Gee.Promise <CrashInfo?> ();
			private TimeoutSource expiry_source;

			public CrashDelivery (uint pid) {
				Object (pid: pid);
			}

			construct {
				expiry_source = make_expiry_source (500);
			}

			public void disable_timeout () {
				expiry_source.destroy ();
				expiry_source = null;
			}

			private TimeoutSource make_expiry_source (uint timeout) {
				var source = new TimeoutSource (timeout);
				source.set_callback (on_timeout);
				source.attach (MainContext.get_thread_default ());
				return source;
			}

			public void extend_timeout () {
				if (future.ready)
					return;

				disable_timeout ();
				expiry_source = make_expiry_source (2000);
			}

			public void complete (CrashInfo? crash) {
				if (future.ready)
					return;

				promise.set_value (crash);

				expiry_source.destroy ();
				expiry_source = make_expiry_source (1000);
			}

			private bool on_timeout () {
				if (!future.ready)
					promise.set_exception (new Error.TIMED_OUT ("Crash delivery timed out"));

				expired ();

				return false;
			}
		}

		private class CrashBuilder : Object {
			public signal void completed (string report);

			public uint reporter_pid {
				get;
				construct;
			}

			private StringBuilder report = new StringBuilder ();
			private TimeoutSource completion_source = null;

			public CrashBuilder (uint reporter_pid) {
				Object (reporter_pid: reporter_pid);
			}

			construct {
				start_polling_reporter_pid ();
			}

			public void append (string chunk) {
				report.append (chunk);

				defer_completion ();
			}

			private void start_polling_reporter_pid () {
				var source = new TimeoutSource (50);
				source.set_callback (on_poll_tick);
				source.attach (MainContext.get_thread_default ());
			}

			private bool on_poll_tick () {
				bool reporter_still_alive = Posix.kill ((Posix.pid_t) reporter_pid, 0) == 0;
				if (!reporter_still_alive)
					schedule_completion ();

				return reporter_still_alive;
			}

			private void schedule_completion () {
				completion_source = new TimeoutSource (250);
				completion_source.set_callback (on_complete);
				completion_source.attach (MainContext.get_thread_default ());
			}

			private void defer_completion () {
				if (completion_source == null)
					return;

				completion_source.destroy ();
				completion_source = null;

				schedule_completion ();
			}

			private bool on_complete () {
				completed (report.str);

				completion_source = null;

				return false;
			}
		}
	}

	private static string canonicalize_class_name (string klass, string package) {
		var result = new StringBuilder (klass);

		if (klass.has_prefix (".")) {
			result.prepend (package);
		} else if (klass.index_of (".") == -1) {
			result.prepend_c ('.');
			result.prepend (package);
		}

		return result.str;
	}

	private class PackageEntrypoint : Object {
	}

	private class DefaultActivityEntrypoint : PackageEntrypoint {
		public DefaultActivityEntrypoint () {
			Object ();
		}
	}

	private class ActivityEntrypoint : PackageEntrypoint {
		public string activity {
			get;
			construct;
		}

		public ActivityEntrypoint (string activity) {
			Object (activity: activity);
		}
	}

	private class BroadcastReceiverEntrypoint : PackageEntrypoint {
		public string receiver {
			get;
			construct;
		}

		public string action {
			get;
			construct;
		}

		public BroadcastReceiverEntrypoint (string receiver, string action) {
			Object (receiver: receiver, action: action);
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
