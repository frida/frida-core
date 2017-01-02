namespace Frida.HostSessionTest {
	public static void add_tests () {
		GLib.Test.add_func ("/HostSession/Service/provider-available", () => {
			var h = new Harness ((h) => Service.provider_available.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Service/provider-unavailable", () => {
			var h = new Harness ((h) => Service.provider_unavailable.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Manual/full-cycle", () => {
			var h = new Harness.without_timeout ((h) => Service.Manual.full_cycle.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Manual/error-feedback", () => {
			var h = new Harness.without_timeout ((h) => Service.Manual.error_feedback.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Manual/torture", () => {
			var h = new Harness.without_timeout ((h) => Service.Manual.torture.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Fruity/PropertyList/can-construct-from-xml-document", () => {
			Fruity.PropertyList.can_construct_from_xml_document ();
		});

		GLib.Test.add_func ("/HostSession/Fruity/PropertyList/to-xml-yields-complete-document", () => {
			Fruity.PropertyList.to_xml_yields_complete_document ();
		});

		GLib.Test.add_func ("/HostSession/Fruity/backend", () => {
			var h = new Harness ((h) => Fruity.backend.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Fruity/large-messages", () => {
			var h = new Harness ((h) => Fruity.large_messages.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Droidy/backend", () => {
			var h = new Harness ((h) => Droidy.backend.begin (h as Harness));
			h.run ();
		});

#if LINUX
		GLib.Test.add_func ("/HostSession/Linux/backend", () => {
			var h = new Harness ((h) => Linux.backend.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Linux/spawn", () => {
			var h = new Harness ((h) => Linux.spawn.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Linux/Manual/spawn-android-app", () => {
			var h = new Harness ((h) => Linux.Manual.spawn_android_app.begin (h as Harness));
			h.run ();
		});
#endif

#if DARWIN
		GLib.Test.add_func ("/HostSession/Darwin/backend", () => {
			var h = new Harness ((h) => Darwin.backend.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Darwin/spawn-native", () => {
			var h = new Harness ((h) => Darwin.spawn_native.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Darwin/spawn-other", () => {
			var h = new Harness ((h) => Darwin.spawn_other.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Darwin/spawn-without-attach-native", () => {
			var h = new Harness ((h) => Darwin.spawn_without_attach_native.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Darwin/spawn-without-attach-other", () => {
			var h = new Harness ((h) => Darwin.spawn_without_attach_other.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Darwin/Manual/cross-arch", () => {
			var h = new Harness ((h) => Darwin.Manual.cross_arch.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Darwin/Manual/spawn-ios-app", () => {
			var h = new Harness ((h) => Darwin.Manual.spawn_ios_app.begin (h as Harness));
			h.run ();
		});
#endif

#if WINDOWS
		GLib.Test.add_func ("/HostSession/Windows/backend", () => {
			var h = new Harness ((h) => Windows.backend.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Windows/spawn", () => {
			var h = new Harness ((h) => Windows.spawn.begin (h as Harness));
			h.run ();
		});
#endif

		GLib.Test.add_func ("/HostSession/resource-leaks", () => {
			var h = new Harness ((h) => resource_leaks.begin (h as Harness));
			h.run ();
		});

	}

	namespace Service {

		private static async void provider_available (Harness h) {
			h.assert_no_providers_available ();
			var backend = new StubBackend ();
			h.service.add_backend (backend);
			yield h.process_events ();
			h.assert_no_providers_available ();

			yield h.service.start ();
			h.assert_no_providers_available ();
			yield h.process_events ();
			h.assert_n_providers_available (1);

			yield h.service.stop ();
			h.service.remove_backend (backend);

			h.done ();
		}

		private static async void provider_unavailable (Harness h) {
			var backend = new StubBackend ();
			h.service.add_backend (backend);
			yield h.service.start ();
			yield h.process_events ();
			h.assert_n_providers_available (1);

			backend.disable_provider ();
			h.assert_n_providers_available (0);

			yield h.service.stop ();
			h.service.remove_backend (backend);

			h.done ();
		}

		private class StubBackend : Object, HostSessionBackend {
			private StubProvider provider = new StubProvider ();

			public async void start () {
				var source = new IdleSource ();
				source.set_callback (() => {
					provider_available (provider);
					return false;
				});
				source.attach (MainContext.get_thread_default ());
			}

			public async void stop () {
			}

			public void disable_provider () {
				provider_unavailable (provider);
			}
		}

		private class StubProvider : Object, HostSessionProvider {
			public string id {
				get { return "stub"; }
			}

			public string name {
				get { return "Stub"; }
			}

			public ImageData? icon {
				get { return _icon; }
			}
			private ImageData? _icon;

			public HostSessionProviderKind kind {
				get { return HostSessionProviderKind.LOCAL_SYSTEM; }
			}

			public async HostSession create (string? location = null) throws Error {
				throw new Error.NOT_SUPPORTED ("Not implemented");
			}

			public async void destroy (HostSession session) throws Error {
				throw new Error.NOT_SUPPORTED ("Not implemented");
			}

			public async AgentSession obtain_agent_session (HostSession host_session, AgentSessionId agent_session_id) throws Error {
				throw new Error.NOT_SUPPORTED ("Not implemented");
			}
		}

		namespace Manual {

			private static async void full_cycle (Harness h) {
				if (!GLib.Test.slow ()) {
					stdout.printf ("<skipping, run in slow mode with target application running> ");
					h.done ();
					return;
				}

				try {
					var device_manager = new DeviceManager ();

					var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);

					print ("\n\nUsing \"%s\"\n", device.name);

					var process = yield device.find_process_by_name ("Twitter");

					uint pid;
					if (process != null) {
						pid = process.pid;
					} else {
						var raw_pid = prompt ("Enter PID:");
						pid = (uint) int.parse (raw_pid);
					}

					print ("Attaching to pid %u...\n", pid);
					var session = yield device.attach (pid);

					var scripts = new Gee.ArrayList<Script> ();
					var done = false;

					new Thread<bool> ("input-worker", () => {
						while (true) {
							print (
								"1. Add script\n" +
								"2. Load script\n" +
								"3. Remove script\n" +
								"4. Enable debugger\n" +
								"5. Disable debugger\n" +
								"6. Disable JIT\n"
							);

							var command = prompt (">");
							if (command == null)
								break;
							var choice = int.parse (command);

							switch (choice) {
								case 1:
									Idle.add (() => {
										add_script.begin (scripts, session);
										return false;
									});
									break;
								case 2:
								case 3: {
									var tokens = command.split(" ");
									if (tokens.length < 2) {
										printerr ("Missing argument\n");
										continue;
									}

									int64 script_index;
									if (!int64.try_parse (tokens[1], out script_index)) {
										printerr ("Invalid script index\n");
										continue;
									}

									Idle.add (() => {
										if (choice == 2)
											load_script.begin ((int) script_index, scripts);
										else
											remove_script.begin ((int) script_index, scripts);
										return false;
									});
									break;
								}
								case 4:
									Idle.add (() => {
										enable_debugger.begin (session);
										return false;
									});
									break;
								case 5:
									Idle.add (() => {
										disable_debugger.begin (session);
										return false;
									});
									break;
								case 6:
									Idle.add (() => {
										disable_jit.begin (session);
										return false;
									});
									break;
								default:
									break;
							}
						}

						print ("\n\n");

						Idle.add (() => {
							done = true;
							return false;
						});

						return true;
					});

					while (!done)
						yield h.process_events ();

					h.done ();
				} catch (Error e) {
					printerr ("\nFAIL: %s\n\n", e.message);
					assert_not_reached ();
				}
			}

			private static uint next_script_id = 1;

			private static async Script? add_script (Gee.ArrayList<Script> container, Session session) {
				Script script;

				try {
					var name = "hello%u".printf (next_script_id++);

					script = yield session.create_script (name,
						"'use strict';" +
						"var puts = new NativeFunction(Module.findExportByName(null, 'puts'), 'int', ['pointer']);" +
						"var i = 1;" +
						"setInterval(function () {" +
						"  puts(Memory.allocUtf8String('hello' + i++));" +
						"}, 1000);");

					script.message.connect ((message, data) => {
						print ("Got message: %s\n", message);
					});
				} catch (Error e) {
					printerr ("Unable to add script: %s\n", e.message);
					return null;
				}

				container.add (script);

				return script;
			}

			private static async void load_script (int index, Gee.ArrayList<Script> container) {
				if (index < 0 || index >= container.size) {
					printerr ("Invalid script index\n");
					return;
				}

				var script = container[index];

				try {
					yield script.load ();
				} catch (Error e) {
					printerr ("Unable to remove script: %s\n", e.message);
				}
			}

			private static async void remove_script (int index, Gee.ArrayList<Script> container) {
				if (index < 0 || index >= container.size) {
					printerr ("Invalid script index\n");
					return;
				}

				var script = container.remove_at (index);

				try {
					yield script.unload ();
				} catch (Error e) {
					printerr ("Unable to remove script: %s\n", e.message);
				}
			}

			private static async void enable_debugger (Session session) {
				try {
					yield session.enable_debugger (5858);
				} catch (Error e) {
					printerr ("Unable to enable debugger: %s\n", e.message);
				}
			}

			private static async void disable_debugger (Session session) {
				try {
					yield session.disable_debugger ();
				} catch (Error e) {
					printerr ("Unable to disable debugger: %s\n", e.message);
				}
			}

			private static async void disable_jit (Session session) {
				try {
					yield session.disable_jit ();
				} catch (Error e) {
					printerr ("Unable to disable JIT: %s\n", e.message);
				}
			}

			private static string prompt (string message) {
				stdout.printf ("%s ", message);
				stdout.flush ();
				return stdin.read_line ();
			}

			private static async void error_feedback (Harness h) {
				if (!GLib.Test.slow ()) {
					stdout.printf ("<skipping, run in slow mode> ");
					h.done ();
					return;
				}

				try {
					var device_manager = new DeviceManager ();

					var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);

					stdout.printf ("\n\nEnter an absolute path that does not exist: ");
					stdout.flush ();
					var inexistent_path = stdin.read_line ();
					try {
						stdout.printf ("Trying to spawn program at inexistent path '%s'...", inexistent_path);
						yield device.spawn (inexistent_path, new string[] { inexistent_path }, new string[] {});
						assert_not_reached ();
					} catch (Error e) {
						stdout.printf ("\nResult: \"%s\"\n", e.message);
						assert (e is Error.EXECUTABLE_NOT_FOUND);
						assert (e.message == "Unable to find executable at '%s'".printf (inexistent_path));
					}

					stdout.printf ("\nEnter an absolute path that exists but is not a valid executable: ");
					stdout.flush ();
					var nonexec_path = stdin.read_line ();
					try {
						stdout.printf ("Trying to spawn program at non-executable path '%s'...", nonexec_path);
						yield device.spawn (nonexec_path, new string[] { nonexec_path }, new string[] {});
						assert_not_reached ();
					} catch (Error e) {
						stdout.printf ("\nResult: \"%s\"\n", e.message);
						assert (e is Error.EXECUTABLE_NOT_SUPPORTED);
						assert (e.message == "Unable to spawn executable at '%s': unsupported file format".printf (nonexec_path));
					}

					var processes = yield device.enumerate_processes ();
					uint inexistent_pid = 100000;
					bool exists = false;
					do {
						exists = false;
						var num_processes = processes.size ();
						for (var i = 0; i != num_processes && !exists; i++) {
							var process = processes.get (i);
							if (process.pid == inexistent_pid) {
								exists = true;
								inexistent_pid++;
							}
						}
					} while (exists);

					try {
						stdout.printf ("\nTrying to attach to inexistent pid %u...", inexistent_pid);
						stdout.flush ();
						yield device.attach (inexistent_pid);
						assert_not_reached ();
					} catch (Error e) {
						stdout.printf ("\nResult: \"%s\"\n", e.message);
						assert (e is Error.PROCESS_NOT_FOUND);
						assert (e.message == "Unable to find process with pid %u".printf (inexistent_pid));
					}

					stdout.printf ("\nEnter PID of a process that you don't have access to: ");
					stdout.flush ();
					uint privileged_pid = (uint) int.parse (stdin.read_line ());

					try {
						stdout.printf ("Trying to attach to %u...", privileged_pid);
						stdout.flush ();
						yield device.attach (privileged_pid);
						assert_not_reached ();
					} catch (Error e) {
						stdout.printf ("\nResult: \"%s\"\n\n", e.message);
						assert (e is Error.PERMISSION_DENIED);
						assert (e.message == "Unable to access process with pid %u from the current user account".printf (privileged_pid));
					}

					yield device_manager.close ();

					h.done ();
				} catch (Error e) {
					printerr ("\nFAIL: %s\n\n", e.message);
					assert_not_reached ();
				}
			}

			private static async void torture (Harness h) {
				if (!GLib.Test.slow ()) {
					stdout.printf ("<skipping, run in slow mode with target application running> ");
					h.done ();
					return;
				}

				try {
					var device_manager = new DeviceManager ();

					var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);

					stdout.printf ("\n\nUsing \"%s\"\n", device.name);

					var process = yield device.find_process_by_name ("SpringBoard");

					uint pid;
					if (process != null) {
						pid = process.pid;
					} else {
						stdout.printf ("Enter PID: ");
						stdout.flush ();
						pid = (uint) int.parse (stdin.read_line ());
					}

					stdout.printf ("\n");
					var num_iterations = 100;
					for (var i = 0; i != num_iterations; i++) {
						stdout.printf ("%u of %u\n", i + 1, num_iterations);
						stdout.flush ();
						var session = yield device.attach (pid);
						yield session.detach ();
					}

					yield device_manager.close ();

					h.done ();
				} catch (Error e) {
					printerr ("\nFAIL: %s\n\n", e.message);
					assert_not_reached ();
				}
			}

		}

	}

	private static async void resource_leaks (Harness h) {
		try {
			var device_manager = new DeviceManager ();
			var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);
			var process = Frida.Test.Process.start (Frida.Test.Labrats.path_to_executable ("sleeper"));

			/* TODO: improve injectors to handle injection into a process that hasn't yet finished initializing */
			Thread.usleep (50000);

			/* Warm up static allocations */
			var session = yield device.attach (process.id);
			yield session.detach ();
			session = null;

			var usage_before = process.snapshot_resource_usage ();

			session = yield device.attach (process.id);
			yield session.detach ();
			session = null;

			var usage_after = process.snapshot_resource_usage ();

			usage_after.assert_equals (usage_before);

			yield device_manager.close ();

			h.done ();
		} catch (Error e) {
			printerr ("\nFAIL: %s\n\n", e.message);
			assert_not_reached ();
		}
	}

#if LINUX
	namespace Linux {

		private static async void backend (Harness h) {
			var backend = new LinuxHostSessionBackend ();
			h.service.add_backend (backend);
			yield h.service.start ();
			yield h.process_events ();
			h.assert_n_providers_available (1);
			var prov = h.first_provider ();

			assert (prov.name == "Local System");

			try {
				var session = yield prov.create ();
				var applications = yield session.enumerate_applications ();
				var processes = yield session.enumerate_processes ();
				assert (processes.length > 0);

				if (GLib.Test.verbose ()) {
					foreach (var app in applications)
						stdout.printf ("identifier='%s' name='%s'\n", app.identifier, app.name);

					foreach (var process in processes)
						stdout.printf ("pid=%u name='%s'\n", process.pid, process.name);
				}
			} catch (GLib.Error e) {
				printerr ("ERROR: %s\n", e.message);
				assert_not_reached ();
			}

			yield h.service.stop ();
			h.service.remove_backend (backend);
			h.done ();
		}

		private static async void spawn (Harness h) {
			if ((Frida.Test.os () == Frida.Test.OS.ANDROID || Frida.Test.os_arch_suffix () == "-linux-arm") && !GLib.Test.slow ()) {
				stdout.printf ("<skipping, run in slow mode> ");
				h.done ();
				return;
			}

			var backend = new LinuxHostSessionBackend ();
			h.service.add_backend (backend);
			yield h.service.start ();
			yield h.process_events ();
			h.assert_n_providers_available (1);
			var prov = h.first_provider ();

			try {
				var host_session = yield prov.create ();

				uint pid = 0;
				bool waiting = false;

				string received_output = null;
				var output_handler = host_session.output.connect ((source_pid, fd, data) => {
					assert (source_pid == pid);
					assert (fd == 1);

					var buf = new uint8[data.length + 1];
					Memory.copy (buf, data, data.length);
					buf[data.length] = '\0';
					char * chars = buf;
					received_output = (string) chars;

					if (waiting)
						spawn.callback ();
				});

				var target_path = Frida.Test.Labrats.path_to_executable ("sleeper");
				string[] argv = { target_path };
				string[] envp = {};
				pid = yield host_session.spawn (target_path, argv, envp);

				var session_id = yield host_session.attach_to (pid);
				var session = yield prov.obtain_agent_session (host_session, session_id);

				string received_message = null;
				var message_handler = session.message_from_script.connect ((script_id, message, has_data, data) => {
					received_message = message;
					if (waiting)
						spawn.callback ();
				});

				var script_id = yield session.create_script ("spawn",
					"'use strict';" +
					"var write = new NativeFunction(Module.findExportByName(null, 'write'), 'int', ['int', 'pointer', 'int']);" +
					"var message = Memory.allocUtf8String('Hello stdout');" +
					"write(1, message, 12);" +
					"Process.enumerateModules({" +
					"  onMatch: function (m) {" +
					"    if (m.name.indexOf('libc') === 0) {" +
					"      Interceptor.attach (Module.findExportByName(m.name, 'sleep'), {" +
					"        onEnter: function (args) {" +
					"          send({ seconds: args[0].toInt32() });" +
					"        }" +
					"      });" +
					"    }" +
					"  }," +
					"  onComplete: function () {}" +
					"});");
				yield session.load_script (script_id);

				if (received_output == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert (received_output == "Hello stdout");
				host_session.disconnect (output_handler);

				yield host_session.resume (pid);

				if (received_message == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert (received_message == "{\"type\":\"send\",\"payload\":{\"seconds\":60}}");
				session.disconnect (message_handler);

				yield host_session.kill (pid);
			} catch (GLib.Error e) {
				printerr ("Unexpected error: %s\n", e.message);
				assert_not_reached ();
			}

			yield h.service.stop ();
			h.service.remove_backend (backend);
			h.done ();
		}

		namespace Manual {

			private static async void spawn_android_app (Harness h) {
				if (!GLib.Test.slow ()) {
					stdout.printf ("<skipping, run in slow mode on Android device> ");
					h.done ();
					return;
				}

				h.disable_timeout (); /* this is a manual test after all */

				var backend = new LinuxHostSessionBackend ();
				h.service.add_backend (backend);
				yield h.service.start ();
				yield h.process_events ();
				var prov = h.first_provider ();

				try {
					var host_session = yield prov.create ();
					stdout.printf ("spawn(\"com.google.android.gm\")\n");
					var pid = yield host_session.spawn ("com.google.android.gm", new string[] { "com.google.android.gm" }, new string[] {});
					stdout.printf ("attach(%u)\n", pid);
					var id = yield host_session.attach_to (pid);
					stdout.printf ("obtain_agent_session()\n");
					var session = yield prov.obtain_agent_session (host_session, id);
					string received_message = null;
					var message_handler = session.message_from_script.connect ((script_id, message, has_data, data) => {
						received_message = message;
						spawn_android_app.callback ();
					});
					stdout.printf ("create_script()\n");
					var script_id = yield session.create_script ("spawn-android-app",
						"\"use strict\";" +
						"Java.perform(() => {" +
						"  const Activity = Java.use(\"android.app.Activity\");" +
						"  Activity.onResume.implementation = () => {" +
						"    send('onResume');" +
						"    this.onResume();" +
						"  };" +
						"});" +
						"setTimeout(() => { send('ready'); }, 1);");
					stdout.printf ("load_script()\n");
					session.load_script.begin (script_id);
					stdout.printf ("await_message()\n");
					yield;
					stdout.printf ("received_message: %s\n", received_message);
					assert (received_message == "{\"type\":\"send\",\"payload\":\"ready\"}");
					stdout.printf ("resume(%u)\n", pid);
					yield host_session.resume (pid);
					stdout.printf ("await_message()\n");
					yield;
					stdout.printf ("received_message: %s\n", received_message);
					session.disconnect (message_handler);
					assert (received_message == "{\"type\":\"send\",\"payload\":\"onResume\"}");
				} catch (GLib.Error e) {
					printerr ("ERROR: %s\n", e.message);
					assert_not_reached ();
				}

				yield h.service.stop ();
				h.service.remove_backend (backend);

				h.done ();
			}

		}

	}
#endif

#if DARWIN
	namespace Darwin {

		private static async void backend (Harness h) {
			var backend = new DarwinHostSessionBackend ();
			h.service.add_backend (backend);
			yield h.service.start ();
			yield h.process_events ();
			h.assert_n_providers_available (1);
			var prov = h.first_provider ();

			assert (prov.name == "Local System");

			if (Frida.Test.os () == Frida.Test.OS.MACOS) {
				var icon = prov.icon;
				assert (icon != null);
				assert (icon.width == 16 && icon.height == 16);
				assert (icon.rowstride == icon.width * 4);
				assert (icon.pixels.length > 0);
			}

			try {
				var session = yield prov.create ();
				var applications = yield session.enumerate_applications ();
				var processes = yield session.enumerate_processes ();
				assert (processes.length > 0);

				if (GLib.Test.verbose ()) {
					foreach (var app in applications)
						stdout.printf ("identifier='%s' name='%s'\n", app.identifier, app.name);

					foreach (var process in processes)
						stdout.printf ("pid=%u name='%s'\n", process.pid, process.name);
				}
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			yield h.service.stop ();
			h.service.remove_backend (backend);
			h.done ();
		}

		private static async void spawn_native (Harness h) {
			var target_name = (Frida.Test.os () == Frida.Test.OS.MACOS) ? "sleeper-macos" : "sleeper-ios";
			yield run_spawn_scenario (h, target_name);
		}

		private static async void spawn_other (Harness h) {
			var target_name = (Frida.Test.os () == Frida.Test.OS.MACOS) ? "sleeper-macos32" : "sleeper-ios32";
			yield run_spawn_scenario (h, target_name);
		}

		private static async void run_spawn_scenario (Harness h, string target_name) {
			var backend = new DarwinHostSessionBackend ();
			h.service.add_backend (backend);
			yield h.service.start ();
			yield h.process_events ();
			h.assert_n_providers_available (1);
			var prov = h.first_provider ();

			try {
				var host_session = yield prov.create ();

				uint pid = 0;
				bool waiting = false;

				string received_output = null;
				var output_handler = host_session.output.connect ((source_pid, fd, data) => {
					assert (source_pid == pid);
					assert (fd == 1);

					var buf = new uint8[data.length + 1];
					Memory.copy (buf, data, data.length);
					buf[data.length] = '\0';
					char * chars = buf;
					received_output = (string) chars;

					if (waiting)
						run_spawn_scenario.callback ();
				});

				var target_path = Frida.Test.Labrats.path_to_file (target_name);
				string[] argv = { target_path };
				string[] envp = {};
				pid = yield host_session.spawn (target_path, argv, envp);

				var session_id = yield host_session.attach_to (pid);
				var session = yield prov.obtain_agent_session (host_session, session_id);

				string received_message = null;
				var message_handler = session.message_from_script.connect ((script_id, message, has_data, data) => {
					received_message = message;
					if (waiting)
						run_spawn_scenario.callback ();
				});

				var script_id = yield session.create_script ("spawn",
					"'use strict';" +
					"var write = new NativeFunction(Module.findExportByName('libSystem.B.dylib', 'write'), 'int', ['int', 'pointer', 'int']);" +
					"var message = Memory.allocUtf8String('Hello stdout');" +
					"write(1, message, 12);" +
					"var sleepFuncName = (Process.arch === 'ia32') ? 'sleep$UNIX2003' : 'sleep';" +
					"Interceptor.attach(Module.findExportByName('libSystem.B.dylib', sleepFuncName), {" +
					"  onEnter: function (args) {" +
					"    send({ seconds: args[0].toInt32() });" +
					"  }" +
					"});");
				yield session.load_script (script_id);

				if (received_output == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert (received_output == "Hello stdout");
				host_session.disconnect (output_handler);

				yield host_session.resume (pid);

				if (received_message == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert (received_message == "{\"type\":\"send\",\"payload\":{\"seconds\":60}}");
				session.disconnect (message_handler);

				yield host_session.kill (pid);
			} catch (GLib.Error e) {
				printerr ("Unexpected error: %s\n", e.message);
				assert_not_reached ();
			}

			yield h.service.stop ();
			h.service.remove_backend (backend);
			h.done ();
		}

		private static async void spawn_without_attach_native (Harness h) {
			var target_name = (Frida.Test.os () == Frida.Test.OS.MACOS) ? "stdio-writer-macos" : "stdio-writer-ios";
			yield run_spawn_scenario_with_stdio (h, target_name);
		}

		private static async void spawn_without_attach_other (Harness h) {
			var target_name = (Frida.Test.os () == Frida.Test.OS.MACOS) ? "stdio-writer-macos32" : "stdio-writer-ios32";
			yield run_spawn_scenario_with_stdio (h, target_name);
		}

		private static async void run_spawn_scenario_with_stdio (Harness h, string target_name) {
			var backend = new DarwinHostSessionBackend ();
			h.service.add_backend (backend);
			yield h.service.start ();
			yield h.process_events ();
			h.assert_n_providers_available (1);
			var prov = h.first_provider ();

			try {
				var host_session = yield prov.create ();

				uint pid = 0;
				bool waiting = false;

				string received_stdout = null;
				string received_stderr = null;
				var output_handler = host_session.output.connect ((source_pid, fd, data) => {
					assert (source_pid == pid);

					if (data.length > 0) {
						var buf = new uint8[data.length + 1];
						Memory.copy (buf, data, data.length);
						buf[data.length] = '\0';
						char * chars = buf;
						var received_output = (string) chars;

						if (fd == 1)
							received_stdout = received_output;
						else if (fd == 2)
							received_stderr = received_output;
						else
							assert_not_reached ();
					} else {
						if (fd == 1)
							assert (received_stdout != null);
						else if (fd == 2)
							assert (received_stderr != null);
						else
							assert_not_reached ();
					}

					if (waiting)
						run_spawn_scenario_with_stdio.callback ();
				});

				var target_path = Frida.Test.Labrats.path_to_file (target_name);
				string[] argv = { target_path };
				string[] envp = {};
				pid = yield host_session.spawn (target_path, argv, envp);

				yield host_session.resume (pid);

				while (received_stdout == null || received_stderr == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert (received_stdout == "Hello stdout");
				assert (received_stderr == "Hello stderr");
				host_session.disconnect (output_handler);

				yield host_session.kill (pid);
			} catch (GLib.Error e) {
				printerr ("Unexpected error: %s\n", e.message);
				assert_not_reached ();
			}

			yield h.service.stop ();
			h.service.remove_backend (backend);
			h.done ();
		}

		namespace Manual {

			private static async void cross_arch (Harness h) {
				if (!GLib.Test.slow ()) {
					stdout.printf ("<skipping, run in slow mode with target application running> ");
					h.done ();
					return;
				}

				uint pid;

				try {
					string pgrep_output;
					GLib.Process.spawn_sync (null, new string[] { "/usr/bin/pgrep", "Safari" }, null, 0, null, out pgrep_output, null, null);
					pid = (uint) int.parse (pgrep_output);
				} catch (SpawnError spawn_error) {
					printerr ("ERROR: %s\n", spawn_error.message);
					assert_not_reached ();
				}

				var backend = new DarwinHostSessionBackend ();
				h.service.add_backend (backend);
				yield h.service.start ();
				yield h.process_events ();
				var prov = h.first_provider ();

				try {
					var host_session = yield prov.create ();
					var id = yield host_session.attach_to (pid);
					var session = yield prov.obtain_agent_session (host_session, id);
					string received_message = null;
					bool waiting = false;
					var message_handler = session.message_from_script.connect ((script_id, message, has_data, data) => {
						received_message = message;
						if (waiting)
							cross_arch.callback ();
					});
					var script_id = yield session.create_script ("test", "send('hello');");
					yield session.load_script (script_id);
					if (received_message == null) {
						waiting = true;
						yield;
						waiting = false;
					}
					assert (received_message == "{\"type\":\"send\",\"payload\":\"hello\"}");
					session.disconnect (message_handler);
				} catch (GLib.Error e) {
					printerr ("ERROR: %s\n", e.message);
					assert_not_reached ();
				}

				yield h.service.stop ();
				h.service.remove_backend (backend);

				h.done ();
			}

			private static async void spawn_ios_app (Harness h) {
				if (!GLib.Test.slow ()) {
					stdout.printf ("<skipping, run in slow mode on iOS device> ");
					h.done ();
					return;
				}

				h.disable_timeout (); /* this is a manual test after all */

				var backend = new DarwinHostSessionBackend ();
				h.service.add_backend (backend);
				yield h.service.start ();
				yield h.process_events ();
				var prov = h.first_provider ();

				try {
					var host_session = yield prov.create ();

					var pid = yield host_session.spawn ("com.atebits.Tweetie2", new string[] { "com.atebits.Tweetie2" }, new string[] {});

					var id = yield host_session.attach_to (pid);
					var session = yield prov.obtain_agent_session (host_session, id);

					bool waiting = false;
					string received_message = null;
					var message_handler = session.message_from_script.connect ((script_id, message, has_data, data) => {
						received_message = message;
						if (waiting)
							spawn_ios_app.callback ();
					});

					var script_id = yield session.create_script ("spawn-ios-app",
						"Interceptor.attach(Module.findExportByName('UIKit', 'UIApplicationMain'), function () {" +
						"  send('UIApplicationMain');" +
						"});" +
						"setTimeout(function () { send('ready'); }, 1);");

					yield session.load_script (script_id);
					if (received_message == null) {
						waiting = true;
						yield;
						waiting = false;
					}
					assert (received_message == "{\"type\":\"send\",\"payload\":\"ready\"}");
					received_message = null;

					yield host_session.resume (pid);
					if (received_message == null) {
						waiting = true;
						yield;
						waiting = false;
					}

					session.disconnect (message_handler);

					assert (received_message == "{\"type\":\"send\",\"payload\":\"UIApplicationMain\"}");
				} catch (GLib.Error e) {
					printerr ("ERROR: %s\n", e.message);
					assert_not_reached ();
				}

				yield h.service.stop ();
				h.service.remove_backend (backend);

				h.done ();
			}

		}

	}
#endif

#if WINDOWS
	namespace Windows {

		private static async void backend (Harness h) {
			var backend = new WindowsHostSessionBackend ();
			h.service.add_backend (backend);
			yield h.service.start ();
			yield h.process_events ();
			h.assert_n_providers_available (1);
			var prov = h.first_provider ();

			assert (prov.name == "Local System");

			var icon = prov.icon;
			assert (icon != null);
			assert (icon.width == 16 && icon.height == 16);
			assert (icon.rowstride == icon.width * 4);
			assert (icon.pixels.length > 0);

			try {
				var session = yield prov.create ();
				var processes = yield session.enumerate_processes ();
				assert (processes.length > 0);

				if (GLib.Test.verbose ()) {
					foreach (var process in processes)
						stdout.printf ("pid=%u name='%s'\n", process.pid, process.name);
				}
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			yield h.service.stop ();
			h.service.remove_backend (backend);

			h.done ();
		}

		private static async void spawn (Harness h) {
			var backend = new WindowsHostSessionBackend ();
			h.service.add_backend (backend);
			yield h.service.start ();
			yield h.process_events ();
			h.assert_n_providers_available (1);
			var prov = h.first_provider ();

			try {
				var host_session = yield prov.create ();

				uint pid = 0;
				bool waiting = false;

				string received_output = null;
				var output_handler = host_session.output.connect ((source_pid, fd, data) => {
					assert (source_pid == pid);
					assert (fd == 1);

					var buf = new uint8[data.length + 1];
					Memory.copy (buf, data, data.length);
					buf[data.length] = '\0';
					char * chars = buf;
					received_output = (string) chars;

					if (waiting)
						spawn.callback ();
				});

				var target_path = Frida.Test.Labrats.path_to_executable ("sleeper");
				string[] argv = { target_path };
				string[] envp = {};
				pid = yield host_session.spawn (target_path, argv, envp);

				var session_id = yield host_session.attach_to (pid);
				var session = yield prov.obtain_agent_session (host_session, session_id);

				string received_message = null;
				var message_handler = session.message_from_script.connect ((script_id, message, has_data, data) => {
					received_message = message;
					if (waiting)
						spawn.callback ();
				});

				var script_id = yield session.create_script ("spawn",
					"'use strict';" +
					"var STD_OUTPUT_HANDLE = -11;" +
					"var winAbi = (Process.pointerSize === 4) ? 'stdcall' : 'win64';" +
					"var GetStdHandle = new NativeFunction(Module.findExportByName('kernel32.dll', 'GetStdHandle'), 'pointer', ['int'], winAbi);" +
					"var WriteFile = new NativeFunction(Module.findExportByName('kernel32.dll', 'WriteFile'), 'int', ['pointer', 'pointer', 'uint', 'pointer', 'pointer'], winAbi);" +
					"var stdout = GetStdHandle(STD_OUTPUT_HANDLE);" +
					"var message = Memory.allocUtf8String('Hello stdout');" +
					"var success = WriteFile(stdout, message, 12, NULL, NULL);" +
					"Interceptor.attach (Module.findExportByName('user32.dll', 'GetMessageW'), {" +
					"  onEnter: function (args) {" +
					"    send('GetMessage');" +
					"  }" +
					"});");
				yield session.load_script (script_id);

				if (received_output == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert (received_output == "Hello stdout");
				host_session.disconnect (output_handler);

				yield host_session.resume (pid);

				if (received_message == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert (received_message == "{\"type\":\"send\",\"payload\":\"GetMessage\"}");
				session.disconnect (message_handler);

				yield host_session.kill (pid);
			} catch (GLib.Error e) {
				printerr ("Unexpected error: %s\n", e.message);
				assert_not_reached ();
			}

			yield h.service.stop ();
			h.service.remove_backend (backend);
			h.done ();
		}

	}
#endif

	namespace Fruity {

		private static async void backend (Harness h) {
			if (!GLib.Test.slow ()) {
				stdout.printf ("<skipping, run in slow mode with iOS device connected> ");
				h.done ();
				return;
			}

			var backend = new FruityHostSessionBackend ();
			h.service.add_backend (backend);
			yield h.service.start ();
			h.disable_timeout (); /* this is a manual test after all */
			yield h.wait_for_provider ();
			var prov = h.first_provider ();

#if WINDOWS
			assert (prov.name != "iOS Device"); /* should manage to extract a user-defined name */
#endif

			var icon = prov.icon;
			assert (icon != null);
			assert (icon.width == 16 && icon.height == 16);
			assert (icon.rowstride == icon.width * 4);
			assert (icon.pixels.length > 0);

			try {
				var session = yield prov.create ();
				var processes = yield session.enumerate_processes ();
				assert (processes.length > 0);

				if (GLib.Test.verbose ()) {
					foreach (var process in processes)
						stdout.printf ("pid=%u name='%s'\n", process.pid, process.name);
				}
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}

			yield h.service.stop ();
			h.service.remove_backend (backend);

			h.done ();
		}

		private static async void large_messages (Harness h) {
			if (!GLib.Test.slow ()) {
				stdout.printf ("<skipping, run in slow mode with iOS device connected> ");
				h.done ();
				return;
			}

			var backend = new FruityHostSessionBackend ();
			h.service.add_backend (backend);
			yield h.service.start ();
			h.disable_timeout (); /* this is a manual test after all */
			yield h.wait_for_provider ();
			var prov = h.first_provider ();

			try {
				stdout.printf ("connecting to frida-server\n");
				var host_session = yield prov.create ();
				stdout.printf ("enumerating processes\n");
				var processes = yield host_session.enumerate_processes ();
				assert (processes.length > 0);

				HostProcessInfo? process = null;
				foreach (var p in processes) {
					if (p.name == "hello-frida") {
						process = p;
						break;
					}
				}
				assert (process != null);

				stdout.printf ("attaching to target process\n");
				var session_id = yield host_session.attach_to (process.pid);
				var session = yield prov.obtain_agent_session (host_session, session_id);
				string received_message = null;
				var message_handler = session.message_from_script.connect ((script_id, message, has_data, data) => {
					received_message = message;
					large_messages.callback ();
				});
				stdout.printf ("creating script\n");
				var script_id = yield session.create_script ("large-messages",
					"function onMessage(message) {" +
					"  send(\"ACK: \" + message.length);" +
					"  recv(onMessage);" +
					"}" +
					"recv(onMessage);"
				);
				stdout.printf ("loading script\n");
				yield session.load_script (script_id);
				var steps = new uint[] { 1024, 4096, 8192, 16384, 32768 };
				var transport_overhead = 163;
				foreach (var step in steps) {
					var builder = new StringBuilder ();
					builder.append ("\"");
					for (var i = 0; i != step - transport_overhead; i++) {
						builder.append ("s");
					}
					builder.append ("\"");
					yield session.post_to_script (script_id, builder.str, false, new uint8[0]);
					yield;
					stdout.printf ("received message: '%s'\n", received_message);
				}
				session.disconnect (message_handler);

				yield session.destroy_script (script_id);
				yield session.close ();
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}

			yield h.service.stop ();
			h.service.remove_backend (backend);

			h.done ();
		}

		namespace PropertyList {

			private static void can_construct_from_xml_document () {
				var xml =
					"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
					"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n" +
					"<plist version=\"1.0\">\n" +
					"<dict>\n" +
					"	<key>DeviceID</key>\n" +
					"	<integer>2</integer>\n" +
					"	<key>MessageType</key>\n" +
					"	<string>Attached</string>\n" +
					"	<key>Properties</key>\n" +
					"	<dict>\n" +
					"		<key>ConnectionType</key>\n" +
					"		<string>USB</string>\n" +
					"		<key>DeviceID</key>\n" +
					"		<integer>2</integer>\n" +
					"		<key>LocationID</key>\n" +
					"		<integer>0</integer>\n" +
					"		<key>ProductID</key>\n" +
					"		<integer>4759</integer>\n" +
					"		<key>SerialNumber</key>\n" +
					"		<string>220f889780dda462091a65df48b9b6aedb05490f</string>\n" +
					"	</dict>\n" +
					"</dict>\n" +
					"</plist>\n";
				try {
					var plist = new Frida.Fruity.PropertyList.from_xml (xml);
					var plist_keys = plist.get_keys ();
					assert (plist_keys.length == 3);
					assert (plist.get_int ("DeviceID") == 2);
					assert (plist.get_string ("MessageType") == "Attached");

					var proplist = plist.get_plist ("Properties");
					var proplist_keys = proplist.get_keys ();
					assert (proplist_keys.length == 5);
					assert (proplist.get_string ("ConnectionType") == "USB");
					assert (proplist.get_int ("DeviceID") == 2);
					assert (proplist.get_int ("LocationID") == 0);
					assert (proplist.get_int ("ProductID") == 4759);
					assert (proplist.get_string ("SerialNumber") == "220f889780dda462091a65df48b9b6aedb05490f");
				} catch (IOError e) {
					assert_not_reached ();
				}
			}

			private static void to_xml_yields_complete_document () {
				var plist = new Frida.Fruity.PropertyList ();
				plist.set_string ("MessageType", "Detached");
				plist.set_int ("DeviceID", 2);

				var proplist = new Frida.Fruity.PropertyList ();
				proplist.set_string ("ConnectionType", "USB");
				proplist.set_int ("DeviceID", 2);
				plist.set_plist ("Properties", proplist);

				var actual_xml = plist.to_xml ();
				var expected_xml =
					"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
					"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n" +
					"<plist version=\"1.0\">\n" +
					"<dict>\n" +
					"	<key>DeviceID</key>\n" +
					"	<integer>2</integer>\n" +
					"	<key>MessageType</key>\n" +
					"	<string>Detached</string>\n" +
					"	<key>Properties</key>\n" +
					"	<dict>\n" +
					"		<key>ConnectionType</key>\n" +
					"		<string>USB</string>\n" +
					"		<key>DeviceID</key>\n" +
					"		<integer>2</integer>\n" +
					"	</dict>\n" +
					"</dict>\n" +
					"</plist>\n";
				assert (actual_xml == expected_xml);
			}

		}

	}

	namespace Droidy {

		private static async void backend (Harness h) {
			if (!GLib.Test.slow ()) {
				stdout.printf ("<skipping, run in slow mode with Android device connected> ");
				h.done ();
				return;
			}

			var backend = new DroidyHostSessionBackend ();
			h.service.add_backend (backend);
			yield h.service.start ();
			h.disable_timeout (); /* this is a manual test after all */
			yield h.wait_for_provider ();
			var prov = h.first_provider ();

			assert (prov.name != "Android Device");

			var icon = prov.icon;
			assert (icon != null);
			assert (icon.width == 16 && icon.height == 16);
			assert (icon.rowstride == icon.width * 4);
			assert (icon.pixels.length > 0);

			try {
				var session = yield prov.create ();
				var processes = yield session.enumerate_processes ();
				assert (processes.length > 0);

				if (GLib.Test.verbose ()) {
					foreach (var process in processes)
						stdout.printf ("pid=%u name='%s'\n", process.pid, process.name);
				}
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}

			yield h.service.stop ();
			h.service.remove_backend (backend);

			h.done ();
		}

	}

	public class Harness : Frida.Test.AsyncHarness {
		public HostSessionService service {
			get;
			private set;
		}

		private uint timeout = 20;

		private Gee.ArrayList<HostSessionProvider> available_providers = new Gee.ArrayList<HostSessionProvider> ();

		public Harness (owned Frida.Test.AsyncHarness.TestSequenceFunc func) {
			base ((owned) func);
		}

		public Harness.without_timeout (owned Frida.Test.AsyncHarness.TestSequenceFunc func) {
			base ((owned) func);
			timeout = 0;
		}

		construct {
			service = new HostSessionService ();
			service.provider_available.connect ((provider) => {
				assert (available_providers.add (provider));
			});
			service.provider_unavailable.connect ((provider) => {
				assert (available_providers.remove (provider));
			});
		}

		protected override uint provide_timeout () {
			return timeout;
		}

		public async void wait_for_provider () {
			while (available_providers.is_empty) {
				yield process_events ();
			}
		}

		public void assert_no_providers_available () {
			assert (available_providers.is_empty);
		}

		public void assert_n_providers_available (int n) {
			assert (available_providers.size == n);
		}

		public HostSessionProvider first_provider () {
			assert (available_providers.size >= 1);
			return available_providers[0];
		}
	}
}
