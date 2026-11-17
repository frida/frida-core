[CCode (gir_namespace = "FridaDroidyInjector", gir_version = "1.0")]
namespace Frida.Droidy.Injector {
	public static async GadgetDetails spawn (InputStream gadget, string package, string device_serial, Cancellable? cancellable = null)
			throws Error, IOError {
		var session = new Session (gadget, device_serial);
		return yield session.spawn (package, cancellable);
	}

	public static async GadgetDetails attach (InputStream gadget, uint pid, string device_serial, Cancellable? cancellable = null)
			throws Error, IOError {
		var session = new Session (gadget, device_serial);
		return yield session.attach (pid, cancellable);
	}

	public sealed class GadgetDetails : Object {
		public uint pid {
			get;
			construct;
		}

		public string unix_socket_path {
			get;
			construct;
		}

		public JDWP.Client? jdwp {
			get;
			construct;
		}

		public GadgetDetails (uint pid, string unix_socket_path, JDWP.Client? jdwp) {
			Object (
				pid: pid,
				unix_socket_path: unix_socket_path,
				jdwp: jdwp
			);
		}
	}

	private sealed class Session : Object {
		public InputStream gadget {
			get;
			construct;
		}

		public string device_serial {
			get;
			construct;
		}

		private const string SHARED_DIR = "/data/local/tmp";
		private const int64 LISTEN_TIMEOUT = 5000000;
		private const uint LISTEN_POLL_INTERVAL = 50;

		public Session (InputStream gadget, string device_serial) {
			Object (
				gadget: gadget,
				device_serial: device_serial
			);
		}

		public async GadgetDetails spawn (string package, Cancellable? cancellable) throws Error, IOError {
			string instance_id = Uuid.string_random ().replace ("-", "");
			var files = new GadgetFiles (
				SHARED_DIR + "/frida-gadget-" + instance_id,
				"/data/data/" + package + "/gadget"
			);
			string unix_socket_path = "frida:" + package;

			var shell = new AdbShellSession ();
			yield shell.open (device_serial, cancellable);
			try {
				yield upload (files, unix_socket_path, cancellable);

				yield shell.check_call ("am set-debug-app -w --persistent '%s'".printf (package), cancellable);

				yield shell.check_call ("am force-stop '%s'".printf (package), cancellable);

				uint target_pid = yield launch_waiting_for_debugger (package, shell, cancellable);

				var jdwp = yield open_jdwp (target_pid, cancellable);

				var thread = yield break_in (jdwp, "Landroid/app/Activity;", "onCreate", null, shell, cancellable);

				var runtime = yield TargetRuntime.open (jdwp, thread, cancellable);
				yield load (files, runtime, unix_socket_path, shell, cancellable);

				return new GadgetDetails (target_pid, unix_socket_path, jdwp);
			} finally {
				shell.close.begin ();
			}
		}

		public async GadgetDetails attach (uint pid, Cancellable? cancellable) throws Error, IOError {
			var shell = new AdbShellSession ();
			yield shell.open (device_serial, cancellable);
			try {
				string package = yield query_package (pid, shell, cancellable);

				string unix_socket_path = "frida:%s:%u".printf (package, pid);
				if (yield is_listening (unix_socket_path, cancellable))
					return new GadgetDetails (pid, unix_socket_path, null);

				var files = new GadgetFiles (
					"%s/frida-gadget-%s-%u".printf (SHARED_DIR, package, pid),
					"/data/data/%s/gadget-%u".printf (package, pid)
				);

				var jdwp = yield open_jdwp (pid, cancellable);
				TargetRuntime? runtime = null;
				try {
					yield upload (files, unix_socket_path, cancellable);

					var thread = yield break_in (jdwp, "Landroid/os/Binder;", "execTransact",
						"(dumpsys meminfo %u > /dev/null 2>&1 &)".printf (pid), shell, cancellable);

					runtime = yield TargetRuntime.open (jdwp, thread, cancellable);
					yield load (files, runtime, unix_socket_path, shell, cancellable);
				} finally {
					release.begin (jdwp, runtime, files);
				}

				return new GadgetDetails (pid, unix_socket_path, null);
			} finally {
				shell.close.begin ();
			}
		}

		private async void upload (GadgetFiles files, string unix_socket_path, Cancellable? cancellable) throws Error, IOError {
			var so_meta = new AdbFileMetadata ();
			so_meta.mode = 0100755;
			so_meta.time_modified = new DateTime.now_utc ();

			yield AdbFileSync.send (gadget, so_meta, files.so_path_shared, device_serial, cancellable);

			var config = new Json.Builder ();
			config
				.begin_object ()
					.set_member_name ("interaction")
					.begin_object ()
						.set_member_name ("type")
						.add_string_value ("listen")
						.set_member_name ("address")
						.add_string_value ("unix:" + unix_socket_path)
						.set_member_name ("on_load")
						.add_string_value ("resume")
					.end_object ()
					.set_member_name ("teardown")
					.add_string_value ("full")
				.end_object ();
			string raw_config = Json.to_string (config.get_root (), false);
			var config_meta = new AdbFileMetadata ();
			config_meta.mode = 0100644;
			config_meta.time_modified = so_meta.time_modified;
			yield AdbFileSync.send (new MemoryInputStream.from_data (raw_config.data), config_meta, files.config_path_shared,
				device_serial, cancellable);
		}

		private async uint launch_waiting_for_debugger (string package, AdbShellSession shell, Cancellable? cancellable)
				throws Error, IOError {
			bool waiting = false;
			uint target_pid = 0;

			var tracker = new AdbJDWPTracker ();
			yield tracker.open (device_serial, cancellable);

			var attached_handler = tracker.debugger_attached.connect (pid => {
				target_pid = pid;
				if (waiting)
					launch_waiting_for_debugger.callback ();
			});
			try {
				yield shell.check_call (
					"am start -D $(cmd package resolve-activity --brief '%s'| tail -n 1)".printf (package),
					cancellable);

				if (target_pid == 0) {
					waiting = true;
					yield;
					waiting = false;
				}
			} finally {
				tracker.disconnect (attached_handler);
			}

			yield tracker.close (cancellable);

			return target_pid;
		}

		private async JDWP.Client open_jdwp (uint pid, Cancellable? cancellable) throws Error, IOError {
			var c = yield AdbClient.open (cancellable);
			yield c.request ("host:transport:" + device_serial, cancellable);
			try {
				yield c.request_protocol_change ("jdwp:%u".printf (pid), cancellable);
			} catch (Error e) {
				throw new Error.NOT_SUPPORTED ("Unable to attach to pid %u; only debuggable apps are supported on " +
					"jailed Android", pid);
			}

			return yield JDWP.Client.open (c.stream, cancellable);
		}

		private async JDWP.ThreadID break_in (JDWP.Client jdwp, string class_signature, string method_name, string? trigger,
				AdbShellSession shell, Cancellable? cancellable) throws Error, IOError {
			var klass = yield jdwp.get_class_by_signature (class_signature, cancellable);
			var methods = yield jdwp.get_methods (klass.ref_type.id, cancellable);
			foreach (var method in methods) {
				if (method.name == method_name) {
					yield jdwp.set_event_request (BREAKPOINT, JDWP.SuspendPolicy.EVENT_THREAD,
						new JDWP.EventModifier[] {
							new JDWP.LocationOnlyModifier (klass.ref_type, method.id),
							new JDWP.CountModifier (1),
						});
				}
			}

			bool waiting = false;
			JDWP.BreakpointEvent? breakpoint_event = null;

			var breakpoint_handler = jdwp.events_received.connect (events => {
				breakpoint_event = (JDWP.BreakpointEvent) events.items[0];
				if (waiting)
					break_in.callback ();
			});
			try {
				if (trigger != null)
					yield shell.check_call (trigger, cancellable);
				else
					yield jdwp.resume (cancellable);

				if (breakpoint_event == null) {
					waiting = true;
					yield;
					waiting = false;
				}
			} finally {
				jdwp.disconnect (breakpoint_handler);
			}

			yield jdwp.clear_all_breakpoints (cancellable);

			return breakpoint_event.thread;
		}

		private async void load (GadgetFiles files, TargetRuntime runtime, string unix_socket_path, AdbShellSession shell,
				Cancellable? cancellable) throws Error, IOError {
			yield runtime.exec ("cp %s %s".printf (files.so_path_shared, files.so_path_app), cancellable);
			yield runtime.exec ("cp %s %s".printf (files.config_path_shared, files.config_path_app), cancellable);

			yield shell.check_call ("rm -f %s; rm -f %s".printf (files.so_path_shared, files.config_path_shared), cancellable);

			yield runtime.load (files.so_path_app, cancellable);

			yield wait_until_listening (unix_socket_path, cancellable);
		}

		private async void wait_until_listening (string unix_socket_path, Cancellable? cancellable) throws Error, IOError {
			var main_context = MainContext.get_thread_default ();
			int64 deadline = get_monotonic_time () + LISTEN_TIMEOUT;

			while (!yield is_listening (unix_socket_path, cancellable)) {
				if (get_monotonic_time () >= deadline)
					throw new Error.TIMED_OUT ("Timed out waiting for Gadget to start listening");

				var delay = new TimeoutSource (LISTEN_POLL_INTERVAL);
				delay.set_callback (wait_until_listening.callback);
				delay.attach (main_context);
				yield;
			}
		}

		private async string query_package (uint pid, AdbShellSession shell, Cancellable? cancellable) throws Error, IOError {
			var result = yield shell.run ("cat /proc/%u/cmdline".printf (pid), cancellable);
			unowned uint8[] cmdline = result.stdout_bytes.get_data ();
			int length = 0;
			while (length != cmdline.length && cmdline[length] != 0)
				length++;
			if (result.status != 0 || length == 0)
				throw new Error.PROCESS_NOT_FOUND ("Unable to find process with pid %u", pid);

			string process_name = ((string) cmdline).ndup (length);
			return process_name.split (":", 2)[0];
		}

		private async bool is_listening (string unix_socket_path, Cancellable? cancellable) throws Error, IOError {
			var c = yield AdbClient.open (cancellable);

			bool listening = true;
			try {
				yield c.request ("host:transport:" + device_serial, cancellable);
				yield c.request_protocol_change ("localabstract:" + unix_socket_path, cancellable);
			} catch (Error e) {
				listening = false;
			}

			yield c.close (cancellable);

			return listening;
		}

		private static async void release (JDWP.Client jdwp, TargetRuntime? runtime, GadgetFiles files) {
			try {
				if (runtime != null)
					yield runtime.exec ("rm -f %s %s".printf (files.so_path_app, files.config_path_app), null);
				yield jdwp.resume (null);
			} catch (GLib.Error e) {
			}

			try {
				yield jdwp.close (null);
			} catch (IOError e) {
			}
		}
	}

	private sealed class GadgetFiles {
		public string so_path_shared;
		public string config_path_shared;
		public string so_path_app;
		public string config_path_app;

		public GadgetFiles (string shared_stem, string app_stem) {
			so_path_shared = shared_stem + ".so";
			config_path_shared = shared_stem + ".config";
			so_path_app = app_stem + ".so";
			config_path_app = app_stem + ".config";
		}
	}

	private sealed class TargetRuntime {
		private JDWP.Client jdwp;
		private JDWP.ThreadID thread;
		private JDWP.ClassInfo runtime_class;
		private JDWP.Object runtime;
		private JDWP.MethodID exec_method;
		private JDWP.MethodID load_method;
		private JDWP.ClassInfo process_class;
		private JDWP.MethodID wait_for_method;

		public static async TargetRuntime open (JDWP.Client jdwp, JDWP.ThreadID thread, Cancellable? cancellable)
				throws Error, IOError {
			var r = new TargetRuntime ();
			r.jdwp = jdwp;
			r.thread = thread;

			r.runtime_class = yield jdwp.get_class_by_signature ("Ljava/lang/Runtime;", cancellable);
			var get_runtime_method = JDWP.MethodID (0);
			foreach (var method in yield jdwp.get_methods (r.runtime_class.ref_type.id, cancellable)) {
				if (method.name == "getRuntime" && method.signature == "()Ljava/lang/Runtime;")
					get_runtime_method = method.id;
				else if (method.name == "exec" && method.signature == "(Ljava/lang/String;)Ljava/lang/Process;")
					r.exec_method = method.id;
				else if (method.name == "load" && method.signature == "(Ljava/lang/String;)V")
					r.load_method = method.id;
			}
			assert (get_runtime_method.handle != 0 && r.exec_method.handle != 0 && r.load_method.handle != 0);

			r.process_class = yield jdwp.get_class_by_signature ("Ljava/lang/Process;", cancellable);
			foreach (var method in yield jdwp.get_methods (r.process_class.ref_type.id, cancellable)) {
				if (method.name == "waitFor" && method.signature == "()I") {
					r.wait_for_method = method.id;
					break;
				}
			}
			assert (r.wait_for_method.handle != 0);

			r.runtime = (JDWP.Object) yield jdwp.invoke_static_method (r.runtime_class.ref_type, thread, get_runtime_method,
				{}, 0, cancellable);

			return r;
		}

		public async void exec (string command, Cancellable? cancellable) throws Error, IOError {
			var str = yield jdwp.create_string (command, cancellable);

			var process = (JDWP.Object) yield jdwp.invoke_instance_method (runtime.val, thread, runtime_class.ref_type.id,
				exec_method, new JDWP.Value[] { str, }, 0, cancellable);

			yield jdwp.invoke_instance_method (process.val, thread, process_class.ref_type.id, wait_for_method, {}, 0,
				cancellable);
		}

		public async void load (string path, Cancellable? cancellable) throws Error, IOError {
			var str = yield jdwp.create_string (path, cancellable);

			yield jdwp.invoke_instance_method (runtime.val, thread, runtime_class.ref_type.id, load_method,
				new JDWP.Value[] { str, }, 0, cancellable);
		}
	}
}
