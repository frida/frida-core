namespace Frida {
	public sealed class LinuxHostSessionBackend : LocalHostSessionBackend {
		protected override LocalHostSessionProvider make_provider () {
			return new LinuxHostSessionProvider ();
		}
	}

	public sealed class LinuxHostSessionProvider : LocalHostSessionProvider {
		protected override LocalHostSession make_host_session (HostSessionOptions? options) throws Error {
			var tempdir = new TemporaryDirectory ();
			return new LinuxHostSession (new LinuxHelperProcess (tempdir), tempdir);
		}
	}

	public sealed class LinuxHostSession : LocalHostSession {
		public LinuxHelper helper {
			get;
			construct;
		}

		public TemporaryDirectory tempdir {
			get;
			construct;
		}

		public bool report_crashes {
			get;
			construct;
		}

		private AgentContainer system_session_container;

		private AgentDescriptor? agent;

#if ANDROID
		private Promise<AndroidHelperClient>? android_helper_request;
		private Subprocess? android_helper_process;
		private RoboLauncher robo_launcher;
		private CrashMonitor? crash_monitor;
#else
		private Spawner? spawn_gater;
#endif

#if !ANDROID
		private ApplicationEnumerator application_enumerator = new ApplicationEnumerator ();
#endif
		private ProcessEnumerator process_enumerator = new ProcessEnumerator ();

		public LinuxHostSession (owned LinuxHelper helper, owned TemporaryDirectory tempdir, bool report_crashes = true) {
			Object (
				helper: helper,
				tempdir: tempdir,
				report_crashes: report_crashes
			);
		}

		construct {
			helper.output.connect (on_output);

			injector = new Linjector (helper, false, tempdir);
			injector.uninjected.connect (on_uninjected);

#if !ANDROID
	    		spawn_gater = Spawner.try_open ();
			if (spawn_gater != null) {
				spawn_gater.spawn_added.connect (on_spawn_gater_spawn_added);
				spawn_gater.spawn_removed.connect (on_spawn_gater_spawn_removed);
			}
#endif

#if HAVE_EMBEDDED_ASSETS
			var blob32 = Frida.Data.Agent.get_frida_agent_32_so_blob ();
			var blob64 = Frida.Data.Agent.get_frida_agent_64_so_blob ();
			var emulated_arm = Frida.Data.Agent.get_frida_agent_arm_so_blob ();
			var emulated_arm64 = Frida.Data.Agent.get_frida_agent_arm64_so_blob ();
			agent = new AgentDescriptor (PathTemplate ("frida-agent-<arch>.so"),
				new Bytes.static (blob32.data),
				new Bytes.static (blob64.data),
				new AgentResource[] {
					new AgentResource ("frida-agent-arm.so", new Bytes.static (emulated_arm.data), tempdir),
					new AgentResource ("frida-agent-arm64.so", new Bytes.static (emulated_arm64.data), tempdir),
				},
				AgentMode.INSTANCED,
				tempdir);
#endif

#if ANDROID
			robo_launcher = new RoboLauncher (this, io_cancellable);
			robo_launcher.spawn_added.connect (on_robo_launcher_spawn_added);
			robo_launcher.spawn_removed.connect (on_robo_launcher_spawn_removed);

			if (report_crashes) {
				crash_monitor = new CrashMonitor ();
				crash_monitor.process_crashed.connect (on_process_crashed);
			}
#endif
		}

		public override async void preload (Cancellable? cancellable) throws Error, IOError {
#if ANDROID
			yield get_android_helper_client (cancellable);
			yield robo_launcher.preload (cancellable);
#endif
		}

		public override async void close (Cancellable? cancellable) throws IOError {
#if ANDROID
			yield robo_launcher.close (cancellable);
			robo_launcher.spawn_added.disconnect (on_robo_launcher_spawn_added);
			robo_launcher.spawn_removed.disconnect (on_robo_launcher_spawn_removed);

			if (android_helper_request != null) {
				try {
					var client = yield get_android_helper_client (cancellable);
					client.closed.disconnect (on_android_helper_client_closed);
					yield client.close (cancellable);
				} catch (Error e) {
				}
			}

			android_helper_process = null;
#else
			if (spawn_gater != null) {
				spawn_gater.spawn_added.disconnect (on_spawn_gater_spawn_added);
				spawn_gater.spawn_removed.disconnect (on_spawn_gater_spawn_removed);
				yield spawn_gater.close (cancellable);
				spawn_gater = null;
			}
#endif

			yield base.close (cancellable);

#if ANDROID
			if (crash_monitor != null) {
				crash_monitor.process_crashed.disconnect (on_process_crashed);
				yield crash_monitor.close (cancellable);
			}
#endif

			var linjector = (Linjector) injector;

			yield wait_for_uninject (injector, cancellable, () => {
				return linjector.any_still_injected ();
			});

			injector.uninjected.disconnect (on_uninjected);
			yield injector.close (cancellable);

			if (system_session_container != null) {
				yield system_session_container.destroy (cancellable);
				system_session_container = null;
			}

			yield helper.close (cancellable);
			helper.output.disconnect (on_output);

			agent = null;

			tempdir.destroy ();
		}

		protected override async AgentSessionProvider create_system_session_provider (Cancellable? cancellable,
				out DBusConnection connection) throws Error, IOError {
			unowned string arch_name = (sizeof (void *) == 8) ? "64" : "32";

			string? path = null;
			PathTemplate? tpl = null;
#if HAVE_EMBEDDED_ASSETS
			if (MemoryFileDescriptor.is_supported ()) {
				string agent_name = agent.name_template.expand (arch_name);
				AgentResource resource = agent.resources.first_match (r => r.name == agent_name);
				path = "/proc/self/fd/%d".printf (resource.get_memfd ().fd);
			} else {
				tpl = agent.get_path_template ();
			}
#else
			tpl = PathTemplate (Config.FRIDA_AGENT_PATH);
#endif
			if (path == null)
				path = tpl.expand (arch_name);

#if HAVE_EMBEDDED_ASSETS
			try {
#endif
				system_session_container = yield AgentContainer.create (path, cancellable);
#if HAVE_EMBEDDED_ASSETS
			} catch (Error e) {
				if (MemoryFileDescriptor.is_supported ()) {
					path = agent.get_path_template ().expand (arch_name);
					system_session_container = yield AgentContainer.create (path, cancellable);
				} else {
					throw e;
				}
			}
#endif

			connection = system_session_container.connection;

			return system_session_container;
		}

		public override async HostApplicationInfo get_frontmost_application (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			var opts = FrontmostQueryOptions._deserialize (options);
#if ANDROID
			var client = yield get_android_helper_client (cancellable);

			var app = yield client.get_frontmost_application (opts, cancellable);
			if (app.pid == 0)
				return app;

			if (opts.scope != MINIMAL) {
				var process_opts = new ProcessQueryOptions ();
				process_opts.select_pid (app.pid);
				process_opts.scope = METADATA;

				var processes = yield process_enumerator.enumerate_processes (process_opts);
				if (processes.length == 0)
					return HostApplicationInfo.empty ();

				add_app_process_state (app, processes[0].parameters);
			}

			return app;
#else
			return System.get_frontmost_application (opts);
#endif
		}

		public override async HostApplicationInfo[] enumerate_applications (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			var opts = ApplicationQueryOptions._deserialize (options);
#if ANDROID
			var client = yield get_android_helper_client (cancellable);

			var apps = yield client.enumerate_applications (opts, cancellable);

			if (opts.scope != MINIMAL) {
				var app_index_by_pid = new Gee.HashMap<uint, uint> ();
				int i = 0;
				foreach (var app in apps) {
					if (app.pid != 0)
						app_index_by_pid[app.pid] = i;
					i++;
				}

				if (!app_index_by_pid.is_empty) {
					var process_opts = new ProcessQueryOptions ();
					foreach (uint pid in app_index_by_pid.keys)
						process_opts.select_pid (pid);
					process_opts.scope = METADATA;

					var processes = yield process_enumerator.enumerate_processes (process_opts);

					foreach (var process in processes) {
						add_app_process_state (apps[app_index_by_pid[process.pid]], process.parameters);
						app_index_by_pid.unset (process.pid);
					}

					foreach (uint index in app_index_by_pid.values)
						apps[index].pid = 0;
				}
			}

			return apps;
#else
			return yield application_enumerator.enumerate_applications (opts);
#endif
		}

#if ANDROID
		private void add_app_process_state (HostApplicationInfo app, HashTable<string, Variant> process_params) {
			var app_params = app.parameters;
			app_params["user"] = process_params["user"];
			app_params["ppid"] = process_params["ppid"];
			app_params["started"] = process_params["started"];
		}
#endif

		public override async HostProcessInfo[] enumerate_processes (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			var opts = ProcessQueryOptions._deserialize (options);
#if ANDROID
			var client = yield get_android_helper_client (cancellable);
			return yield client.enumerate_processes (opts, cancellable);
#else
			return yield process_enumerator.enumerate_processes (opts);
#endif
		}

		public override async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
#if ANDROID
			yield robo_launcher.enable_spawn_gating (cancellable);
#else
			var agent = get_spawn_gater_agent ();
			yield agent.enable_spawn_gating (cancellable);
#endif
		}

		public override async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
#if ANDROID
			yield robo_launcher.disable_spawn_gating (cancellable);
#else
			var agent = get_spawn_gater_agent ();
			yield agent.disable_spawn_gating (cancellable);
#endif
		}

#if !ANDROID
		private Spawner get_spawn_gater_agent () throws Error {
			if (spawn_gater == null)
				throw new Error.NOT_SUPPORTED ("Spawn gating requires additional privileges");
			return spawn_gater;
		}
#endif

		public override async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws Error, IOError {
#if ANDROID
			return robo_launcher.enumerate_pending_spawn ();
#else
			return spawn_gater.enumerate_pending_spawn();
#endif
		}

		public override async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable)
				throws Error, IOError {
#if ANDROID
			if (!program.has_prefix ("/"))
				return yield robo_launcher.spawn (program, options, cancellable);
#endif

			return yield helper.spawn (program, options, cancellable);
		}

		protected override async void prepare_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			yield helper.prepare_exec_transition (pid, cancellable);
		}

		protected override async void await_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			yield helper.await_exec_transition (pid, cancellable);
		}

		protected override async void cancel_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			yield helper.cancel_exec_transition (pid, cancellable);
		}

		protected override bool process_is_alive (uint pid) {
			return Posix.kill ((Posix.pid_t) pid, 0) == 0 || Posix.errno == Posix.EPERM;
		}

		public override async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError {
			yield helper.input (pid, data, cancellable);
		}

		protected override async void perform_resume (uint pid, Cancellable? cancellable) throws Error, IOError {
#if ANDROID
			if (robo_launcher.try_resume (pid))
				return;
#else
			if (spawn_gater.try_resume (pid))
				return;
#endif

			yield helper.resume (pid, cancellable);
		}

		public override async void kill (uint pid, Cancellable? cancellable) throws Error, IOError {
#if ANDROID
			var client = yield get_android_helper_client (cancellable);

			if (yield client.try_stop_package_by_pid (pid, cancellable))
				return;
#endif

			yield helper.kill (pid, cancellable);
		}

		protected override async Future<IOStream> perform_attach_to (uint pid, HashTable<string, Variant> options,
				Cancellable? cancellable, out Object? transport) throws Error, IOError {
			uint id;
			string entrypoint = "frida_agent_main";
			string parameters = make_agent_parameters (pid, "", options);
			AgentFeatures features = CONTROL_CHANNEL;
			var linjector = (Linjector) injector;
#if HAVE_EMBEDDED_ASSETS
			id = yield linjector.inject_library_resource (pid, agent, entrypoint, parameters, features, cancellable);
#else
			id = yield linjector.inject_library_file_with_template (pid, PathTemplate (Config.FRIDA_AGENT_PATH), entrypoint,
				parameters, features, cancellable);
#endif
			injectee_by_pid[pid] = id;

			var stream_request = new Promise<IOStream> ();
			IOStream stream = yield linjector.request_control_channel (id, cancellable);
			stream_request.resolve (stream);

			transport = null;

			return stream_request.future;
		}

		protected override string? get_emulated_agent_path (uint pid) throws Error {
			unowned string name;
			switch (cpu_type_from_pid (pid)) {
				case Gum.CpuType.IA32:
					name = "frida-agent-arm.so";
					break;
				case Gum.CpuType.AMD64:
					name = "frida-agent-arm64.so";
					break;
				default:
					throw new Error.NOT_SUPPORTED ("Emulated realm is not supported on this architecture");
			}

			AgentResource? resource = agent.resources.first_match (r => r.name == name);
			if (resource == null)
				throw new Error.NOT_SUPPORTED ("Unable to handle emulated processes due to build configuration");

			return resource.get_file ().path;
		}
#if !ANDROID
		private void on_spawn_gater_spawn_added (HostSpawnInfo info) {
			spawn_added (info);
		}

		private void on_spawn_gater_spawn_removed (HostSpawnInfo info) {
			spawn_removed (info);
		}
#else
		private void on_robo_launcher_gater_spawn_added (HostSpawnInfo info) {
			spawn_added (info);
		}

		private void on_robo_launcher_gater_spawn_removed (HostSpawnInfo info) {
			spawn_removed (info);
		}
#endif

#if ANDROID
		internal async AndroidHelperClient get_android_helper_client (Cancellable? cancellable) throws Error, IOError {
			while (android_helper_request != null) {
				try {
					return yield android_helper_request.future.wait_async (cancellable);
				} catch (Error e) {
					throw e;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}
			android_helper_request = new Promise<AndroidHelperClient> ();

			string? helper_path = null;
			Subprocess? process = null;
			try {
				string instance_id = Uuid.string_random ().replace ("-", "");
				helper_path = "/data/local/tmp/frida-helper-" + instance_id + ".dex";
				FileUtils.set_data (helper_path, Frida.Data.Android.get_helper_dex_blob ().data);
				Posix.chmod (helper_path, 0644);

				var helper_address = new UnixSocketAddress.with_type ("/frida-helper-" + instance_id, -1, ABSTRACT);

				var launcher = new SubprocessLauncher (STDIN_INHERIT | STDOUT_PIPE | STDERR_PIPE);
				launcher.setenv ("CLASSPATH", helper_path, true);
				process = launcher.spawn (
					"app_process",
					"/data/local/tmp",
					"--nice-name=re.frida.helper",
					"re.frida.Helper",
					instance_id
				);
				uint pid = uint.parse (process.get_identifier ());

				var output = new DataInputStream (process.get_stdout_pipe ());
				var errput = new DataInputStream (process.get_stderr_pipe ());

				string? line = yield output.read_line_utf8_async (Priority.DEFAULT, cancellable);
				if (line == null || line != "READY.") {
					string error_details = "";

					try {
						StringBuilder sb = new StringBuilder ();
						while (true) {
							string? l = yield errput.read_line_utf8_async (Priority.DEFAULT, cancellable);
							if (l == null)
								break;
							sb.append (l);
							sb.append_c ('\n');
						}
						error_details = sb.str;
					} catch (GLib.Error e) {
					}

					try {
						yield process.wait_check_async (cancellable);
					} catch (GLib.Error e) {
						if (error_details.length == 0)
							error_details = e.message;
						else
							error_details = error_details + "\n" + e.message;
					}

					string? logs = yield collect_logcat_for_pid (pid, cancellable);
					if (logs != null)
						error_details = error_details + "\n\n" + logs;

					if (line == null) {
						throw new Error.NOT_SUPPORTED ("Unable to spawn Android helper: %s", error_details);
					} else {
						throw new Error.PROTOCOL ("Unexpected output from Android helper: %s\nstderr:\n%s",
							line, error_details);
					}
				}

				process_android_helper_stream.begin (output, "stdout");
				process_android_helper_stream.begin (errput, "stderr");

				var sc = new SocketClient ();
				var stream = yield sc.connect_async (helper_address, cancellable);

				var helper = new AndroidHelperClient (stream);
				helper.closed.connect (on_android_helper_client_closed);

				android_helper_process = process;

				android_helper_request.resolve (helper);

				return helper;
			} catch (GLib.Error e) {
				if (helper_path != null)
					Posix.unlink (helper_path);

				if (process != null)
					process.force_exit ();

				var api_error = new Error.NOT_SUPPORTED ("%s", e.message);

				android_helper_request.reject (api_error);

				throw_api_error (api_error);
			}
		}

		private void on_android_helper_client_closed (AndroidHelperClient helper) {
			helper.closed.disconnect (on_android_helper_client_closed);
			android_helper_request = null;
			android_helper_process = null;
		}

		private async void process_android_helper_stream (DataInputStream stream, string label) {
			try {
				while (true) {
					string? line = yield stream.read_line_utf8_async (Priority.DEFAULT, io_cancellable);
					if (line == null)
						break;
					if (label == "stderr" && line.has_prefix ("WARNING: ") && " has text relocations" in line)
						continue;
					printerr ("[android-helper %s] %s\n", label, line);
				}
			} catch (GLib.Error e) {
			}
		}

		private async string? collect_logcat_for_pid (uint pid, Cancellable? cancellable) throws IOError {
			string output;

			string header = "[logcat output]\n";

			try {
				var p = new Subprocess (STDOUT_PIPE | STDERR_SILENCE, "logcat", "-d", "--pid=%u".printf (pid));

				yield p.communicate_utf8_async (null, cancellable, out output, null);

				if (p.get_exit_status () == 0) {
					output = output.chomp ();
					return (output.length != 0) ? header + output : null;
				}
			} catch (GLib.Error e) {
			}

			try {
				var p = new Subprocess (STDOUT_PIPE | STDERR_SILENCE, "logcat", "-d", "-v", "threadtime");

				yield p.communicate_utf8_async (null, cancellable, out output, null);

				if (p.get_exit_status () == 0) {
					string? filtered = filter_logcat_threadtime_by_pid (output, pid);
					if (filtered != null)
						return header + filtered;
				}
			} catch (GLib.Error e) {
			}

			return null;
		}

		private static string? filter_logcat_threadtime_by_pid (string log, uint pid) {
			var sb = new StringBuilder ();

			foreach (string line in log.split ("\n")) {
				if (line.length == 0)
					continue;

				string[] parts = line.split_set (" \t");
				if (parts.length < 5)
					continue;

				uint line_pid = uint.parse (parts[2]);
				if (line_pid != pid)
					continue;

				sb.append (line);
				sb.append_c ('\n');
			}

			var result = sb.str.chomp ();
			return (result.length != 0) ? result : null;
		}

		private void on_robo_launcher_spawn_added (HostSpawnInfo info) {
			spawn_added (info);
		}


		private void on_spawn_gater_spawn_removed (HostSpawnInfo info) {
			spawn_removed (info);
		}

		protected override async CrashInfo? try_collect_crash (uint pid, Cancellable? cancellable) throws IOError {
			if (crash_monitor == null)
				return null;
			return yield crash_monitor.try_collect_crash (pid, cancellable);
		}

		private void on_process_crashed (CrashInfo info) {
			process_crashed (info);

			if (crash_monitor != null && still_attached_to (info.pid)) {
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
	}

#if ANDROID
	private sealed class RoboLauncher : Object {
		public signal void spawn_added (HostSpawnInfo info);
		public signal void spawn_removed (HostSpawnInfo info);

		public weak LinuxHostSession host_session {
			get;
			construct;
		}

		public Cancellable io_cancellable {
			get;
			construct;
		}

		private Promise<bool> ensure_request;

		private string? server_name;
		private UnixSocketAddress? server_address;
		private Gee.Map<uint, ZymbiotePatches> zymbiote_patches = new Gee.HashMap<uint, ZymbiotePatches> ();
		private Gee.Map<uint, ZymbioteConnection> zymbiote_connections = new Gee.HashMap<uint, ZymbioteConnection> ();

		private bool spawn_gating_enabled = false;
		private Gee.HashMap<string, Promise<uint>> spawn_requests = new Gee.HashMap<string, Promise<uint>> ();
		private Gee.HashMap<uint, HostSpawnInfo?> pending_spawn = new Gee.HashMap<uint, HostSpawnInfo?> ();

		private delegate void CompletionNotify (GLib.Error? error);

		public RoboLauncher (LinuxHostSession host_session, Cancellable io_cancellable) {
			Object (
				host_session: host_session,
				io_cancellable: io_cancellable
			);
		}

		public async void preload (Cancellable? cancellable) throws Error, IOError {
			yield ensure_loaded (cancellable);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			if (ensure_request != null) {
				try {
					yield ensure_loaded (cancellable);
				} catch (GLib.Error e) {
				}
			}

			foreach (var request in spawn_requests.values.to_array ())
				request.reject (new Error.INVALID_OPERATION ("Cancelled by shutdown"));
			spawn_requests.clear ();

			foreach (var e in zymbiote_patches.entries) {
				uint pid = e.key;
				var patches = e.value;
				try {
					Posix.kill ((Posix.pid_t) pid, Posix.Signal.STOP);
					yield wait_until_stopped (pid, cancellable);
					try {
						var fd = open_process_memory (pid);
						patches.revert (fd);
					} finally {
						Posix.kill ((Posix.pid_t) pid, Posix.Signal.CONT);
					}
				} catch (Error e) {
				}
			}
			zymbiote_patches.clear ();
		}

		public async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			yield ensure_loaded (cancellable);

			spawn_gating_enabled = true;
		}

		public async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			spawn_gating_enabled = false;

			var pending = pending_spawn.values.to_array ();
			pending_spawn.clear ();
			foreach (var spawn in pending) {
				spawn_removed (spawn);

				host_session.resume.begin (spawn.pid, io_cancellable);
			}
		}

		public HostSpawnInfo[] enumerate_pending_spawn () {
			var result = new HostSpawnInfo[pending_spawn.size];
			var index = 0;
			foreach (var spawn in pending_spawn.values)
				result[index++] = spawn;
			return result;
		}

		public async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError {
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

			var entrypoint = PackageEntrypoint.parse (package, options);

			yield ensure_loaded (cancellable);

			var helper = yield host_session.get_android_helper_client (cancellable);

			var process_name = yield helper.get_process_name (package, entrypoint.uid, cancellable);

			if (spawn_requests.has_key (process_name))
				throw new Error.INVALID_OPERATION ("Spawn already in progress for the specified package name");

			var request = new Promise<uint> ();
			spawn_requests[process_name] = request;

			uint pid = 0;
			try {
				yield helper.stop_package (package, entrypoint.uid, cancellable);
				yield helper.start_package (package, entrypoint, cancellable);

				var timeout = new TimeoutSource.seconds (20);
				timeout.set_callback (() => {
					request.reject (new Error.TIMED_OUT ("Unexpectedly timed out while waiting for app to launch"));
					return false;
				});
				timeout.attach (MainContext.get_thread_default ());
				try {
					pid = yield request.future.wait_async (cancellable);
				} finally {
					timeout.destroy ();
				}
			} catch (GLib.Error e) {
				if (!spawn_requests.unset (process_name)) {
					var pending_pid = request.future.value;
					if (pending_pid != 0)
						host_session.resume.begin (pending_pid, io_cancellable);
				}

				throw_api_error (e);
			}

			return pid;
		}

		public bool try_resume (uint pid) {
			ZymbioteConnection? connection;
			if (!zymbiote_connections.unset (pid, out connection))
				return false;

            trace_syscalls.begin (pid);

			connection.resume.begin (io_cancellable);

			HostSpawnInfo? info;
			if (pending_spawn.unset (pid, out info))
				spawn_removed (info);

			return true;
		}

        private async void trace_syscalls (uint pid) {
            printerr ("=== Starting\n");
            var tracer = new SyscallTracer (pid);
            try {
                   tracer.start ();
            } catch (Error e) {
                   printerr ("=== Error: %s\n", e.message);
                   return;
            }
            printerr ("=== Started\n");

            var source = new TimeoutSource.seconds (2);
            source.set_callback (trace_syscalls.callback);
            source.attach (MainContext.get_thread_default ());

            yield;
            printerr ("=== Finished\n");
        }

		private async void ensure_loaded (Cancellable? cancellable) throws Error, IOError {
			while (ensure_request != null) {
				try {
					yield ensure_request.future.wait_async (cancellable);
					return;
				} catch (Error e) {
					throw e;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}
			ensure_request = new Promise<bool> ();

			if (server_name == null) {
				string name = "/frida-zymbiote-" + Uuid.string_random ().replace ("-", "");
				var address = new UnixSocketAddress.with_type (name, -1, UnixSocketAddressType.ABSTRACT);

				try {
					var socket = new Socket (SocketFamily.UNIX, SocketType.STREAM, SocketProtocol.DEFAULT);
					socket.bind (address, true);
					socket.listen ();

					server_name = name;
					server_address = address;

					handle_zymbiote_connections.begin (socket);
				} catch (GLib.Error raw_err) {
					var err = new Error.TRANSPORT ("%s", raw_err.message);
					ensure_request.reject (err);
					throw err;
				}
			}

			uint pending = 1;
			GLib.Error? first_error = null;

			CompletionNotify on_complete = error => {
				pending--;
				if (error != null && first_error == null)
					first_error = error;

				if (pending == 0) {
					var source = new IdleSource ();
					source.set_callback (ensure_loaded.callback);
					source.attach (MainContext.get_thread_default ());
				}
			};

			foreach (HostProcessInfo info in System.enumerate_processes (new ProcessQueryOptions ())) {
				var name = info.name;
				if (name == "zygote" || name == "zygote64" || name == "usap32" || name == "usap64") {
					uint pid = info.pid;
					if (zymbiote_patches.has_key (pid))
						continue;

					pending++;
					do_inject_zygote_agent.begin (pid, name, cancellable, on_complete);
				}
			}

			on_complete (null);

			yield;

			on_complete = null;

			if (first_error == null) {
				ensure_request.resolve (true);
			} else {
				ensure_request.reject (first_error);
				ensure_request = null;

				throw_api_error (first_error);
			}
		}

		private async void do_inject_zygote_agent (uint pid, string name, Cancellable? cancellable, CompletionNotify on_complete) {
			try {
				yield inject_zymbiote (pid, cancellable);

				on_complete (null);
			} catch (GLib.Error e) {
				on_complete (e);
			}
		}

		private async void inject_zymbiote (uint pid, Cancellable? cancellable) throws Error, IOError {
			var prep = yield prepare_zymbiote_injection (pid, cancellable);

			Posix.kill ((Posix.pid_t) pid, Posix.Signal.STOP);
			yield wait_until_stopped (pid, cancellable);
			try {
				var patches = new ZymbiotePatches ();

				unowned uint8[] payload = prep.payload.get_data ();
				if (prep.already_patched) {
					var handle = Posix.open (prep.payload_path, Posix.O_RDONLY);
					if (handle == -1) {
						throw new Error.PERMISSION_DENIED ("Unable to open payload backing file: %s",
							strerror (errno));
					}
					var backing_file = new FileDescriptor (handle);
					var original = new uint8[payload.length];
					backing_file.pread_all (original, prep.payload_file_offset);
					patches.apply (payload, prep.process_memory, prep.payload_base, new Bytes.take ((owned) original));
				} else {
					patches.apply (payload, prep.process_memory, prep.payload_base);
				}

				if (prep.already_patched) {
					patches.apply (prep.replaced_ptr, prep.process_memory, prep.art_method_slot,
						new Bytes (prep.original_ptr));
				} else {
					patches.apply (prep.replaced_ptr, prep.process_memory, prep.art_method_slot);
				}

				zymbiote_patches[pid] = patches;
			} finally {
				Posix.kill ((Posix.pid_t) pid, Posix.Signal.CONT);
			}
		}

		private class ZymbiotePrepResult : Object {
			public FileDescriptor process_memory;
			public bool already_patched;

			public uint64 art_method_slot;
			public uint8[] original_ptr;
			public uint8[] replaced_ptr;

			public Bytes payload;
			public uint64 payload_base;
			public string payload_path;
			public uint64 payload_file_offset;
		}

		private async ZymbiotePrepResult prepare_zymbiote_injection (uint pid, Cancellable? cancellable) throws Error, IOError {
			var task = new Task (this, cancellable, (obj, res) => {
				prepare_zymbiote_injection.callback ();
			});
			task.set_task_data ((void *) pid, null);
			task.run_in_thread ((t, source_object, task_data, c) => {
				unowned RoboLauncher launcher = (RoboLauncher) t.get_unowned_source_object ();
				uint pid_to_prep = (uint) task_data;
				try {
					var r = do_prepare_zymbiote_injection (pid_to_prep, launcher.server_name);
					t.return_pointer ((owned) r, Object.unref);
				} catch (GLib.Error e) {
					t.return_error ((owned) e);
				}
			});
			yield;

			try {
				return (ZymbiotePrepResult) (owned) task.propagate_pointer ();
			} catch (GLib.Error e) {
				throw_api_error (e);
			}
		}

		private static ZymbiotePrepResult do_prepare_zymbiote_injection (uint pid, string server_name) throws Error, IOError {
			uint64 payload_base = 0;
			string? payload_path = null;
			uint64 payload_file_offset = 0;
			string? libc_path = null;
			string? runtime_path = null;
			Gee.List<Gum.MemoryRange?> heap_candidates = new Gee.ArrayList<Gum.MemoryRange?> ();

			var iter = ProcMapsIter.for_pid (pid);
			while (iter.next ()) {
				string path = iter.path;
				string flags = iter.flags;
				if (path.has_suffix ("/libstagefright.so") && "x" in flags) {
					if (payload_base == 0) {
						payload_base = iter.end_address - Gum.query_page_size ();
						payload_path = path;
						payload_file_offset = iter.file_offset;
					}
				} else if (path.has_suffix ("/libc.so")) {
					if (libc_path == null)
						libc_path = path;
				} else if (path.has_suffix ("/libandroid_runtime.so")) {
					if (runtime_path == null)
						runtime_path = path;
				} else if (flags == "rw-p" && is_boot_heap (path)) {
					uint64 start = iter.start_address;
					uint64 end = iter.end_address;
					heap_candidates.add (Gum.MemoryRange () {
						base_address = start,
						size = (size_t) (end - start),
					});
				}
			}

			if (payload_base == 0)
				throw new Error.NOT_SUPPORTED ("Unable to pick a payload base");
			if (libc_path == null)
				throw new Error.NOT_SUPPORTED ("Unable to detect libc.so path");
			if (runtime_path == null)
				throw new Error.NOT_SUPPORTED ("Unable to detect libandroid_runtime.so path");
			if (heap_candidates.is_empty)
				throw new Error.NOT_SUPPORTED ("Unable to detect any VM heap candidates");

			var libc_entry = ProcMapsSoEntry.find_by_path (pid, libc_path);
			if (libc_entry == null)
				throw new Error.NOT_SUPPORTED ("Unable to detect libc.so entry");

			var runtime_entry = ProcMapsSoEntry.find_by_path (pid, runtime_path);
			if (runtime_entry == null)
				throw new Error.NOT_SUPPORTED ("Unable to detect libandroid_runtime.so entry");

			Gum.ElfModule libc;
			try {
				libc = new Gum.ElfModule.from_file (libc_path);
			} catch (Gum.Error e) {
				throw new Error.NOT_SUPPORTED ("Unable to parse libc.so: %s", e.message);
			}

			Gum.ElfModule runtime;
			try {
				runtime = new Gum.ElfModule.from_file (runtime_path);
			} catch (Gum.Error e) {
				throw new Error.NOT_SUPPORTED ("Unable to parse libandroid_runtime.so: %s", e.message);
			}

			uint64 set_argv0_address = 0;
			runtime.enumerate_exports (e => {
				if (e.name == "_Z27android_os_Process_setArgV0P7_JNIEnvP8_jobjectP8_jstring") {
					set_argv0_address = runtime_entry.base_address + e.address;
					return false;
				}
				return true;
			});
			if (set_argv0_address == 0)
				throw new Error.NOT_SUPPORTED ("Unable to locate android.os.Process.setArgV0(); please file a bug");

			uint pointer_size = ("/lib64/" in libc_path) ? 8 : 4;

			var original_ptr = new uint8[pointer_size];
			var replaced_ptr = new uint8[pointer_size];

			(new Buffer (new Bytes.static (original_ptr), ByteOrder.HOST, pointer_size)).write_pointer (0, set_argv0_address);
			(new Buffer (new Bytes.static (replaced_ptr), ByteOrder.HOST, pointer_size)).write_pointer (0, payload_base);

			var fd = open_process_memory (pid);

			uint64 art_method_slot = 0;
			bool already_patched = false;
			foreach (var candidate in heap_candidates) {
				var heap = new uint8[candidate.size];
				var n = fd.pread (heap, candidate.base_address);
				if (n != heap.length)
					throw new Error.NOT_SUPPORTED ("Short read");

				void * p = memmem (heap, original_ptr);
				if (p == null) {
					p = memmem (heap, replaced_ptr);
					already_patched = p != null;
				}

				if (p != null) {
					art_method_slot = candidate.base_address + ((uint8 *) p - (uint8 *) heap);
					break;
				}
			}
			if (art_method_slot == 0)
				throw new Error.NOT_SUPPORTED ("Unable to locate method slot; please file a bug");

			var blob = (pointer_size == 8)
#if ARM || ARM64
				? Frida.Data.Android.get_zymbiote_arm64_bin_blob ()
				: Frida.Data.Android.get_zymbiote_arm_bin_blob ();
#else
				? Frida.Data.Android.get_zymbiote_x86_64_bin_blob ()
				: Frida.Data.Android.get_zymbiote_x86_bin_blob ();
#endif

			unowned uint8[] payload_template = blob.data;
			void * p = memmem (payload_template, "/frida-zymbiote-00000000000000000000000000000000".data);
			assert (p != null);
			size_t data_offset = (uint8 *) p - (uint8 *) payload_template;

			var payload = new Buffer (new Bytes (payload_template), ByteOrder.HOST, pointer_size);

			size_t cursor = data_offset;
			payload.write_string (cursor, server_name);
			cursor += 64;

			payload.write_pointer (cursor, art_method_slot);
			cursor += pointer_size;

			payload.write_pointer (cursor, set_argv0_address);
			cursor += pointer_size;

			string[] wanted = {
				"socket",
				"connect",
				"__errno",
				"getpid",
				"getppid",
				"sendmsg",
				"recv",
				"close",
				"raise",
			};

			var index_of = new Gee.HashMap<string, int> ();
			for (int i = 0; i != wanted.length; i++)
				index_of[wanted[i]] = i;

			var addrs = new uint64[wanted.length];
			uint pending = wanted.length;
			libc.enumerate_exports (e => {
				if (index_of.has_key (e.name)) {
					int idx = index_of[e.name];
					addrs[idx] = libc_entry.base_address + e.address;
					pending--;
				}
				return pending != 0;
			});

			for (int i = 0; i != addrs.length; i++) {
				assert (addrs[i] != 0);
				payload.write_pointer (cursor, addrs[i]);
				cursor += pointer_size;
			}

			return new ZymbiotePrepResult () {
				process_memory = fd,
				already_patched = already_patched,

				art_method_slot = art_method_slot,
				original_ptr = original_ptr,
				replaced_ptr = replaced_ptr,

				payload = payload.bytes,
				payload_base = payload_base,
				payload_path = payload_path,
				payload_file_offset = payload_file_offset,
			};
		}

		private static bool is_boot_heap (string path) {
			return
				"boot.art" in path ||
				"boot-framework.art" in path ||
				"dalvik-LinearAlloc" in path;
		}

		[CCode (cname = "memmem", cheader_filename = "string.h")]
		private extern static void * memmem (uint8[] haystack, uint8[] needle);

		private async void handle_zymbiote_connections (Socket server_socket) {
			var listener = new SocketListener ();
			try {
				listener.add_socket (server_socket, null);

				while (true) {
					var raw_connection = (UnixConnection) yield listener.accept_async (io_cancellable);
					var connection = new ZymbioteConnection (raw_connection);
					handle_zymbiote_connection.begin (connection);
				}
			} catch (GLib.Error e) {
			} finally {
				listener.close ();
			}
		}

		private async void handle_zymbiote_connection (ZymbioteConnection connection) {
			try {
				var hello = yield connection.read_hello (io_cancellable);

				connection.patches_to_revert = zymbiote_patches[hello.ppid];

				bool needs_resume = false;

				Promise<uint> spawn_request;
				if (spawn_requests.unset (hello.package_name, out spawn_request)) {
					spawn_request.resolve (hello.pid);
					needs_resume = true;
				} else if (spawn_gating_enabled) {
					var spawn_info = HostSpawnInfo (hello.pid, hello.package_name);
					pending_spawn[hello.pid] = spawn_info;
					spawn_added (spawn_info);
					needs_resume = true;
				}

				if (needs_resume)
					zymbiote_connections[hello.pid] = connection;
				else
					connection.resume.begin (io_cancellable);
			} catch (GLib.Error e) {
			}
		}

		private class ZymbiotePatches {
			public Gee.Queue<Entry> entries = new Gee.ArrayQueue<Entry> ();

			public class Entry {
				public uint64 address;
				public Bytes original;
			}

			public void apply (uint8[] patch, FileDescriptor fd, uint64 address, Bytes? original = null) throws Error {
				Bytes? orig = original;

				if (orig == null) {
					var buf = new uint8[patch.length];
					fd.pread (buf, address);
					orig = new Bytes.take ((owned) buf);
				}

				fd.pwrite (patch, address);

				entries.offer (new Entry () {
					address = address,
					original = orig,
				});
			}

			public void revert (FileDescriptor fd) throws Error {
				foreach (var e in entries)
					fd.pwrite (e.original.get_data (), e.address);
			}
		}

		private class ZymbioteConnection : Object {
			public ZymbiotePatches? patches_to_revert = null;

			private UnixConnection connection;
			private DataInputStream input;

			private Hello? hello = null;

			public ZymbioteConnection (UnixConnection conn) {
				connection = conn;

				input = new DataInputStream (conn.get_input_stream ());
				input.byte_order = HOST_ENDIAN;
			}

			public async Hello read_hello (Cancellable? cancellable) throws Error, IOError {
				size_t header_size = 12;

				try {
					yield prepare_to_read (header_size, cancellable);

					uint32 package_name_len = 0;
					input.peek ((uint8[]) &package_name_len, 8);

					size_t message_size = header_size + package_name_len;

					yield prepare_to_read (message_size, cancellable);

					var r = new BufferReader (new Buffer (input.read_bytes (message_size, cancellable)));
					uint32 pid = r.read_uint32 ();
					uint32 ppid = r.read_uint32 ();
					r.skip (4);
					string package_name = r.read_fixed_string (package_name_len);

					hello = new Hello () {
						pid = pid,
						ppid = ppid,
						package_name = package_name,
					};

					return hello;
				} catch (GLib.Error e) {
					if (e is Error)
						throw (Error) e;
					throw new Error.TRANSPORT ("%s", e.message);
				}
			}

			public class Hello {
				public uint pid;
				public uint ppid;
				public string package_name;
			}

			public async void resume (Cancellable? cancellable) throws Error, IOError {
				var priority = Priority.DEFAULT;

				try {
					uint8 ack[1] = { 0x42 };
					yield connection.get_output_stream ().write_async (ack, priority, cancellable);

					uint8 bye[1];
					yield input.read_async (bye, priority, cancellable);
				} catch (GLib.Error e) {
					throw new Error.TRANSPORT ("%s", e.message);
				}

				yield wait_until_stopped (hello.pid, cancellable);

				if (patches_to_revert != null)
					patches_to_revert.revert (open_process_memory (hello.pid));

				Posix.kill ((Posix.pid_t) hello.pid, Posix.Signal.CONT);
			}

			private async void prepare_to_read (size_t required, Cancellable? cancellable) throws GLib.Error {
				while (true) {
					size_t available = input.get_available ();
					if (available >= required)
						return;
					ssize_t n = yield input.fill_async ((ssize_t) (required - available), Priority.DEFAULT,
						cancellable);
					if (n == 0)
						throw new Error.TRANSPORT ("Connection closed");
				}
			}
		}
	}

	private sealed class CrashMonitor : Object {
		public signal void process_crashed (CrashInfo crash);

		private Object logcat;

		private DataInputStream input;
		private Cancellable io_cancellable = new Cancellable ();

		private Gee.HashMap<uint, CrashDelivery> crash_deliveries = new Gee.HashMap<uint, CrashDelivery> ();
		private Gee.HashMap<uint, CrashBuilder> crash_builders = new Gee.HashMap<uint, CrashBuilder> ();

		private Timer since_start;

		construct {
			since_start = new Timer ();

			start_monitoring.begin ();
		}

		public async void close (Cancellable? cancellable) throws IOError {
			io_cancellable.cancel ();

			if (logcat != null) {
				if (logcat is Subprocess) {
					var process = logcat as Subprocess;
					process.send_signal (Posix.Signal.TERM);
				} else if (logcat is SuperSU.Process) {
					var process = logcat as SuperSU.Process;
					yield process.detach (cancellable); // TODO: Figure out how we can terminate it.
				}
				logcat = null;
			}
		}

		public async CrashInfo? try_collect_crash (uint pid, Cancellable? cancellable) throws IOError {
			var delivery = get_crash_delivery_for_pid (pid);
			try {
				return yield delivery.future.wait_async (cancellable);
			} catch (Error e) {
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
			string? last_cause = null;
			var cause_pattern = /^Caused by: (.+)$/m;
			try {
				MatchInfo info;
				for (cause_pattern.match (report, 0, out info); info.matches (); info.next ())
					last_cause = info.fetch (1);
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
			InputStream? stdout_pipe = null;

			try {
				string cwd = "/";
				string[] argv = new string[] { "su", "-c", "logcat", "-b", "crash", "-B" };
				string[]? envp = null;
				bool capture_output = true;
				var process = yield SuperSU.spawn (cwd, argv, envp, capture_output, io_cancellable);

				logcat = process;
				stdout_pipe = process.output;
			} catch (GLib.Error e) {
			}

			if (stdout_pipe == null) {
				try {
					var process = new Subprocess.newv ({ "logcat", "-b", "crash", "-B" },
						STDIN_INHERIT | STDOUT_PIPE | STDERR_SILENCE);

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
					size_t payload_size = input.read_uint16 (io_cancellable);
					size_t header_size = input.read_uint16 (io_cancellable);
					if (header_size < 24)
						throw new Error.PROTOCOL ("Header too short");
					yield prepare_to_read (header_size + payload_size - 4);

					var entry = new LogEntry ();

					entry.pid = input.read_int32 (io_cancellable);
					entry.tid = input.read_uint32 (io_cancellable);
					entry.sec = input.read_uint32 (io_cancellable);
					entry.nsec = input.read_uint32 (io_cancellable);
					entry.lid = input.read_uint32 (io_cancellable);
					size_t ignored_size = header_size - 24;
					if (ignored_size > 0)
						input.skip (ignored_size, io_cancellable);

					var payload_buf = new uint8[payload_size + 1];
					input.read (payload_buf[0:payload_size], io_cancellable);
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
				ssize_t n = yield input.fill_async ((ssize_t) (required - available), Priority.DEFAULT, io_cancellable);
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

			public Future<CrashInfo?> future {
				get {
					return promise.future;
				}
			}

			private Promise<CrashInfo?> promise = new Promise <CrashInfo?> ();
			private TimeoutSource expiry_source;

			public CrashDelivery (uint pid) {
				Object (pid: pid);
			}

			construct {
				expiry_source = make_expiry_source (500);
			}

			public void disable_timeout () {
				if (expiry_source != null) {
					expiry_source.destroy ();
					expiry_source = null;
				}
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

				promise.resolve (crash);

				expiry_source.destroy ();
				expiry_source = make_expiry_source (1000);
			}

			private bool on_timeout () {
				if (!future.ready)
					promise.reject (new Error.TIMED_OUT ("Crash delivery timed out"));

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

	private FileDescriptor open_process_memory (uint pid) throws Error {
		int handle = Posix.open ("/proc/%u/mem".printf (pid), Posix.O_RDWR);
		if (handle == -1)
			throw new Error.PERMISSION_DENIED ("%s", strerror (errno));
		return new FileDescriptor (handle);
	}

	private async void wait_until_stopped (uint pid, Cancellable? cancellable) throws Error, IOError {
		var main_context = MainContext.get_thread_default ();

		bool timed_out = false;
		var timeout_source = new TimeoutSource.seconds (5);
		timeout_source.set_callback (() => {
			timed_out = true;
			return Source.REMOVE;
		});
		timeout_source.attach (main_context);

		uint[] delays = { 0, 1, 2, 5, 10, 20, 50, 250 };

		try {
			for (uint i = 0; !timed_out && !cancellable.set_error_if_cancelled (); i++) {
				if (is_process_stopped (pid))
					break;

				uint delay_ms = (i < delays.length) ? delays[i] : delays[delays.length - 1];

				var delay_source = new TimeoutSource (delay_ms);
				delay_source.set_callback (wait_until_stopped.callback);
				delay_source.attach (main_context);

				var cancel_source = new CancellableSource (cancellable);
				cancel_source.set_callback (wait_until_stopped.callback);
				cancel_source.attach (main_context);

				yield;

				cancel_source.destroy ();
				delay_source.destroy ();
			}
		} finally {
			timeout_source.destroy ();
		}

		if (timed_out)
			throw new Error.TIMED_OUT ("Unexpectedly timed out while waiting for process with PID %u to stop", pid);
	}

	private bool is_process_stopped (uint pid) throws Error {
		string path = "/proc/%u/stat".printf (pid);

		string contents;
		size_t length;
		try {
			GLib.FileUtils.get_contents (path, out contents, out length);
		} catch (FileError e) {
			throw new Error.PROCESS_NOT_FOUND ("%s", e.message);
		}

		int rparen = contents.last_index_of (")");
		assert (rparen != -1 && rparen + 2 < contents.length);

		char state = contents.get (rparen + 2);

		return state == 'T';
	}
# else
    private sealed class Spawner : Object {
        public signal void spawn_added (HostSpawnInfo info);
        public signal void spawn_removed (HostSpawnInfo info);

        public weak LinuxHostSession host_session {
		get;
		construct;
        }

	public Cancellable io_cancellable {
		get;
		construct;
	}

	public static Spawner? try_open () {
		if (Posix.getuid () != 0)
			return null;
		return new Spawner ();
	}

	private SpawnGater gater = new SpawnGater();

        private Gee.HashMap<uint, HostSpawnInfo?> pending_spawn = new Gee.HashMap<uint, HostSpawnInfo?> ();

        public async void close (Cancellable? cancellable) throws IOError {
		if (gater != null) {
			try {
			    yield disable_spawn_gating (cancellable);
			} catch (Error e) {
			    assert_not_reached ();
			}
		}
        }

	public void spawn_callback(int pid, string command) {
		var info = HostSpawnInfo (pid, command);
		pending_spawn[pid] = info;
		spawn_added (info);
	}

        public async void enable_spawn_gating (Cancellable? cancellable) throws Error {
		gater.set_callback (spawn_callback);
		gater.start ();
        }

	public HostSpawnInfo[] enumerate_pending_spawn () {
		var result = new HostSpawnInfo[pending_spawn.size];
		var index = 0;
		foreach (var spawn in pending_spawn.values)
			result[index++] = spawn;
		return result;
	}

	public bool try_resume(uint pid) {
		Posix.kill ((Posix.pid_t) pid, Posix.Signal.CONT);
		return true;
	}

        public async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
		if (gater == null)
			throw new Error.INVALID_OPERATION ("Already disabled");


		var pending = pending_spawn.values.to_array ();
		pending_spawn.clear ();
		foreach (var spawn in pending) {
			spawn_removed (spawn);

			host_session.resume.begin (spawn.pid, io_cancellable);
		}

		gater.stop ();
		gater = null;

		io_cancellable.cancel ();
        }
    }
#endif
}
