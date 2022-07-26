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

		GLib.Test.add_func ("/HostSession/Manual/spawn-gating", () => {
			var h = new Harness.without_timeout ((h) => Service.Manual.spawn_gating.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Manual/error-feedback", () => {
			var h = new Harness.without_timeout ((h) => Service.Manual.error_feedback.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Manual/performance", () => {
			var h = new Harness.without_timeout ((h) => Service.Manual.performance.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Manual/torture", () => {
			var h = new Harness.without_timeout ((h) => Service.Manual.torture.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Fruity/Plist/can-construct-from-xml-document", () => {
			Fruity.Plist.can_construct_from_xml_document ();
		});

		GLib.Test.add_func ("/HostSession/Fruity/Plist/to-xml-yields-complete-document", () => {
			Fruity.Plist.to_xml_yields_complete_document ();
		});

		GLib.Test.add_func ("/HostSession/Fruity/backend", () => {
			var h = new Harness ((h) => Fruity.backend.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Fruity/large-messages", () => {
			var h = new Harness ((h) => Fruity.large_messages.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Fruity/Manual/lockdown", () => {
			var h = new Harness ((h) => Fruity.Manual.lockdown.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Droidy/backend", () => {
			var h = new Harness ((h) => Droidy.backend.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Droidy/injector", () => {
			var h = new Harness ((h) => Droidy.injector.begin (h as Harness));
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

		GLib.Test.add_func ("/HostSession/Linux/ChildGating/fork", () => {
			var h = new Harness ((h) => Linux.fork.begin (h as Harness));
			h.run ();
		});

		var fork_symbol_names = new string[] {
			"fork",
			"vfork",
		};
		var exec_symbol_names = new string[] {
			"execl",
			"execlp",
			"execle",
			"execv",
			"execvp",
			"execve",
		};
		if (Gum.Module.find_export_by_name (null, "execvpe") != null) {
			exec_symbol_names += "execvpe";
		}
		foreach (var fork_symbol_name in fork_symbol_names) {
			foreach (var exec_symbol_name in exec_symbol_names) {
				var method = "%s+%s".printf (fork_symbol_name, exec_symbol_name);
				GLib.Test.add_data_func ("/HostSession/Linux/ChildGating/" + method, () => {
					var h = new Harness ((h) => Linux.fork_plus_exec.begin (h as Harness, method));
					h.run ();
				});
			}
		}

		GLib.Test.add_func ("/HostSession/Linux/ChildGating/bad-exec", () => {
			var h = new Harness ((h) => Linux.bad_exec.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Linux/ChildGating/bad-then-good-exec", () => {
			var h = new Harness ((h) => Linux.bad_then_good_exec.begin (h as Harness));
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

		if (can_test_cross_arch_injection) {
			GLib.Test.add_func ("/HostSession/Darwin/spawn-other", () => {
				var h = new Harness ((h) => Darwin.spawn_other.begin (h as Harness));
				h.run ();
			});
		}

		GLib.Test.add_func ("/HostSession/Darwin/spawn-without-attach-native", () => {
			var h = new Harness ((h) => Darwin.spawn_without_attach_native.begin (h as Harness));
			h.run ();
		});

		if (can_test_cross_arch_injection) {
			GLib.Test.add_func ("/HostSession/Darwin/spawn-without-attach-other", () => {
				var h = new Harness ((h) => Darwin.spawn_without_attach_other.begin (h as Harness));
				h.run ();
			});
		}

		GLib.Test.add_func ("/HostSession/Darwin/own-memory-ranges-should-be-cloaked", () => {
			var h = new Harness ((h) => Darwin.own_memory_ranges_should_be_cloaked.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Darwin/ExitMonitor/abort-from-js-thread-should-not-deadlock", () => {
			var h = new Harness ((h) => Darwin.ExitMonitor.abort_from_js_thread_should_not_deadlock.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Darwin/ChildGating/fork-native", () => {
			var h = new Harness ((h) => Darwin.fork_native.begin (h as Harness));
			h.run ();
		});

		if (can_test_cross_arch_injection) {
			GLib.Test.add_func ("/HostSession/Darwin/ChildGating/fork-other", () => {
				var h = new Harness ((h) => Darwin.fork_other.begin (h as Harness));
				h.run ();
			});
		}

		var fork_symbol_names = new string[] {
			"fork",
			"vfork",
		};
		var exec_symbol_names = new string[] {
			"execl",
			"execlp",
			"execle",
			"execv",
			"execvp",
			"execve",
		};
		foreach (var fork_symbol_name in fork_symbol_names) {
			foreach (var exec_symbol_name in exec_symbol_names) {
				var method = "%s+%s".printf (fork_symbol_name, exec_symbol_name);
				GLib.Test.add_data_func ("/HostSession/Darwin/ChildGating/" + method, () => {
					var h = new Harness ((h) => Darwin.fork_plus_exec.begin (h as Harness, method));
					h.run ();
				});
			}
		}

		GLib.Test.add_func ("/HostSession/Darwin/ChildGating/bad-exec", () => {
			var h = new Harness ((h) => Darwin.bad_exec.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Darwin/ChildGating/bad-then-good-exec", () => {
			var h = new Harness ((h) => Darwin.bad_then_good_exec.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Darwin/ChildGating/posix-spawn", () => {
			var h = new Harness ((h) => Darwin.posix_spawn.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Darwin/ChildGating/posix-spawn+setexec", () => {
			var h = new Harness ((h) => Darwin.posix_spawn_plus_setexec.begin (h as Harness));
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

#if FREEBSD
		GLib.Test.add_func ("/HostSession/FreeBSD/backend", () => {
			var h = new Harness ((h) => FreeBSD.backend.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/FreeBSD/spawn", () => {
			var h = new Harness ((h) => FreeBSD.spawn.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/FreeBSD/ChildGating/fork", () => {
			var h = new Harness ((h) => FreeBSD.fork.begin (h as Harness));
			h.run ();
		});

		var fork_symbol_names = new string[] {
			"fork",
			"vfork",
		};
		var exec_symbol_names = new string[] {
			"execl",
			"execlp",
			"execle",
			"execv",
			"execvp",
			"execve",
		};
		foreach (var fork_symbol_name in fork_symbol_names) {
			foreach (var exec_symbol_name in exec_symbol_names) {
				var method = "%s+%s".printf (fork_symbol_name, exec_symbol_name);
				GLib.Test.add_data_func ("/HostSession/FreeBSD/ChildGating/" + method, () => {
					var h = new Harness ((h) => FreeBSD.fork_plus_exec.begin (h as Harness, method));
					h.run ();
				});
			}
		}

		GLib.Test.add_func ("/HostSession/FreeBSD/ChildGating/bad-exec", () => {
			var h = new Harness ((h) => FreeBSD.bad_exec.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/FreeBSD/ChildGating/bad-then-good-exec", () => {
			var h = new Harness ((h) => FreeBSD.bad_then_good_exec.begin (h as Harness));
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

		GLib.Test.add_func ("/HostSession/Windows/ChildGating/create-process", () => {
			var h = new Harness ((h) => Windows.create_process.begin (h as Harness));
			h.run ();
		});
#endif

		GLib.Test.add_func ("/HostSession/resource-leaks", () => {
			var h = new Harness ((h) => resource_leaks.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/start-stop-fast", () => {
			var h = new Harness ((h) => start_stop_fast.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Local/latency-should-be-nominal", () => {
			var h = new Harness ((h) => Local.latency_should_be_nominal.begin (h as Harness));
			h.run ();
		});

		Connectivity.Strategy[] strategies = new Connectivity.Strategy[] {
			SERVER,
		};
		if (GLib.Test.slow ())
			strategies += Connectivity.Strategy.PEER;

		foreach (var strategy in strategies) {
			string prefix = "/HostSession/Connectivity/" + ((strategy == SERVER) ? "Server" : "Peer");

			GLib.Test.add_data_func (prefix + "/flawless", () => {
				var h = new Harness ((h) => Connectivity.flawless.begin (h as Harness, strategy));
				h.run ();
			});

			GLib.Test.add_data_func (prefix + "/rx-without-ack", () => {
				var h = new Harness ((h) => Connectivity.rx_without_ack.begin (h as Harness, strategy));
				h.run ();
			});

			GLib.Test.add_data_func (prefix + "/tx-not-sent", () => {
				var h = new Harness ((h) => Connectivity.tx_not_sent.begin (h as Harness, strategy));
				h.run ();
			});

			GLib.Test.add_data_func (prefix + "/tx-without-ack", () => {
				var h = new Harness ((h) => Connectivity.tx_without_ack.begin (h as Harness, strategy));
				h.run ();
			});

			GLib.Test.add_data_func (prefix + "/latency-should-be-nominal", () => {
				var h = new Harness ((h) => Connectivity.latency_should_be_nominal.begin (h as Harness, strategy));
				h.run ();
			});
		}

	}

	namespace Service {

		private static async void provider_available (Harness h) {
			try {
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
			} catch (IOError e) {
				assert_not_reached ();
			}

			h.done ();
		}

		private static async void provider_unavailable (Harness h) {
			try {
				var backend = new StubBackend ();
				h.service.add_backend (backend);
				yield h.service.start ();
				yield h.process_events ();
				h.assert_n_providers_available (1);

				backend.disable_provider ();
				h.assert_n_providers_available (0);

				yield h.service.stop ();
				h.service.remove_backend (backend);
			} catch (IOError e) {
				assert_not_reached ();
			}

			h.done ();
		}

		private class StubBackend : Object, HostSessionBackend {
			private StubProvider provider = new StubProvider ();

			public async void start (Cancellable? cancellable) {
				var source = new IdleSource ();
				source.set_callback (() => {
					provider_available (provider);
					return false;
				});
				source.attach (MainContext.get_thread_default ());
			}

			public async void stop (Cancellable? cancellable) {
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

			public Variant? icon {
				get { return null; }
			}

			public HostSessionProviderKind kind {
				get { return HostSessionProviderKind.LOCAL; }
			}

			public async HostSession create (HostSessionOptions? options, Cancellable? cancellable) throws Error, IOError {
				throw new Error.NOT_SUPPORTED ("Not implemented");
			}

			public async void destroy (HostSession session, Cancellable? cancellable) throws Error, IOError {
				throw new Error.NOT_SUPPORTED ("Not implemented");
			}

			public async AgentSession link_agent_session (HostSession host_session, AgentSessionId id, AgentMessageSink sink,
					Cancellable? cancellable) throws Error, IOError {
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
								"5. Disable debugger\n"
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
								case 3:
								case 4:
								case 5: {
									var tokens = command.split(" ");
									if (tokens.length < 2) {
										printerr ("Missing argument\n");
										continue;
									}

									int64 raw_script_index;
									if (!int64.try_parse (tokens[1], out raw_script_index)) {
										printerr ("Invalid script index\n");
										continue;
									}
									var script_index = (int) raw_script_index;

									Idle.add (() => {
										switch (choice) {
											case 2:
												load_script.begin (script_index, scripts);
												break;
											case 3:
												remove_script.begin (script_index, scripts);
												break;
											case 4:
												enable_debugger.begin (script_index,
													scripts);
												break;
											case 5:
												disable_debugger.begin (script_index,
													scripts);
												break;
											default:
												assert_not_reached ();
										}
										return false;
									});
									break;
								}
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
				} catch (GLib.Error e) {
					printerr ("\nFAIL: %s\n\n", e.message);
					assert_not_reached ();
				}
			}

			private static async Script? add_script (Gee.ArrayList<Script> container, Session session) {
				Script script;

				try {
					script = yield session.create_script ("""
						const puts = new NativeFunction(Module.getExportByName(null, 'puts'), 'int', ['pointer']);
						let i = 1;
						setInterval(() => {
						  puts(Memory.allocUtf8String('hello' + i++));
						}, 1000);
						""");

					script.message.connect ((message, data) => {
						print ("Got message: %s\n", message);
					});
				} catch (GLib.Error e) {
					printerr ("Unable to add script: %s\n", e.message);
					return null;
				}

				container.add (script);

				return script;
			}

			private static async void load_script (int index, Gee.ArrayList<Script> container) {
				Script script;
				if (!get_script (index, container, out script))
					return;

				try {
					yield script.load ();
				} catch (GLib.Error e) {
					printerr ("Unable to remove script: %s\n", e.message);
				}
			}

			private static async void remove_script (int index, Gee.ArrayList<Script> container) {
				Script script;
				if (!get_script (index, container, out script))
					return;

				container.remove_at (index);

				try {
					yield script.unload ();
				} catch (GLib.Error e) {
					printerr ("Unable to remove script: %s\n", e.message);
				}
			}

			private static async void enable_debugger (int index, Gee.ArrayList<Script> container) {
				Script script;
				if (!get_script (index, container, out script))
					return;

				try {
					yield script.enable_debugger (5858);
				} catch (GLib.Error e) {
					printerr ("Unable to enable debugger: %s\n", e.message);
				}
			}

			private static async void disable_debugger (int index, Gee.ArrayList<Script> container) {
				Script script;
				if (!get_script (index, container, out script))
					return;

				try {
					yield script.disable_debugger ();
				} catch (GLib.Error e) {
					printerr ("Unable to disable debugger: %s\n", e.message);
				}
			}

			private static bool get_script (int index, Gee.ArrayList<Script> container, out Script? script) {
				if (index < 0 || index >= container.size) {
					printerr ("Invalid script index\n");
					script = null;
					return false;
				}

				script = container[index];
				return true;
			}

			private static string prompt (string message) {
				stdout.printf ("%s ", message);
				stdout.flush ();
				return stdin.read_line ();
			}

			private static async void spawn_gating (Harness h) {
				if (!GLib.Test.slow ()) {
					stdout.printf ("<skipping, run in slow mode on an iOS or Android system> ");
					h.done ();
					return;
				}

				h.disable_timeout ();

				try {
					var main_loop = new MainLoop ();

					var device_manager = new DeviceManager ();

					var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);
					var spawn_added_handler = device.spawn_added.connect ((spawn) => {
						print ("spawn-added: pid=%u identifier=%s\n", spawn.pid, spawn.identifier);
						perform_resume.begin (device, spawn.pid);
					});
					var timer = new Timer ();
					yield device.enable_spawn_gating ();
					print ("spawn gating enabled in %u ms\n", (uint) (timer.elapsed () * 1000.0));

					install_signal_handlers (main_loop);

					main_loop.run ();

					device.disconnect (spawn_added_handler);

					timer.reset ();
					yield device.disable_spawn_gating ();
					print ("spawn gating disabled in %u ms\n", (uint) (timer.elapsed () * 1000.0));

					timer.reset ();
					yield device_manager.close ();
					print ("manager closed in %u ms\n", (uint) (timer.elapsed () * 1000.0));

					h.done ();
				} catch (GLib.Error e) {
					printerr ("\nFAIL: %s\n\n", e.message);
					assert_not_reached ();
				}
			}

			private static async void perform_resume (Device device, uint pid) {
				try {
					yield device.resume (pid);
				} catch (GLib.Error e) {
					printerr ("perform_resume(%u) failed: %s\n", pid, e.message);
				}
			}

#if WINDOWS
			private static void install_signal_handlers (MainLoop loop) {
			}
#else
			private static MainLoop current_main_loop = null;

			private static void install_signal_handlers (MainLoop loop) {
				current_main_loop = loop;
				Posix.signal (Posix.Signal.INT, on_stop_signal);
				Posix.signal (Posix.Signal.TERM, on_stop_signal);
			}

			private static void on_stop_signal (int sig) {
				stdout.flush ();
				Idle.add (() => {
					current_main_loop.quit ();
					return false;
				});
			}
#endif

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
						yield device.spawn (inexistent_path);
						assert_not_reached ();
					} catch (GLib.Error e) {
						stdout.printf ("\nResult: \"%s\"\n", e.message);
						assert_true (e is Error.EXECUTABLE_NOT_FOUND);
						assert_true (e.message == "Unable to find executable at '%s'".printf (inexistent_path));
					}

					stdout.printf ("\nEnter an absolute path that exists but is not a valid executable: ");
					stdout.flush ();
					var nonexec_path = stdin.read_line ();
					try {
						stdout.printf ("Trying to spawn program at non-executable path '%s'...", nonexec_path);
						yield device.spawn (nonexec_path);
						assert_not_reached ();
					} catch (Error e) {
						stdout.printf ("\nResult: \"%s\"\n", e.message);
						assert_true (e is Error.EXECUTABLE_NOT_SUPPORTED);
						assert_true (e.message == "Unable to spawn executable at '%s': unsupported file format".printf (nonexec_path));
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
						assert_true (e is Error.PROCESS_NOT_FOUND);
						assert_true (e.message == "Unable to find process with pid %u".printf (inexistent_pid));
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
						assert_true (e is Error.PERMISSION_DENIED);
						assert_true (e.message == "Unable to access process with pid %u from the current user account".printf (privileged_pid));
					}

					yield device_manager.close ();

					h.done ();
				} catch (GLib.Error e) {
					printerr ("\nFAIL: %s\n\n", e.message);
					assert_not_reached ();
				}
			}

			private static async void performance (Harness h) {
				if (!GLib.Test.slow ()) {
					stdout.printf ("<skipping, run in slow mode with target application running> ");
					h.done ();
					return;
				}

				try {
					var device_manager = new DeviceManager ();
					var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);
					var process = yield device.get_process_by_name ("loop64");
					var pid = process.pid;

					var timer = new Timer ();

					stdout.printf ("\n");
					var num_iterations = 3;
					for (var i = 0; i != num_iterations; i++) {
						stdout.printf ("%u of %u\n", i + 1, num_iterations);
						stdout.flush ();

						timer.reset ();
						var session = yield device.attach (pid);
						print ("attach took %u ms\n", (uint) (timer.elapsed () * 1000.0));
						var script = yield session.create_script ("true;");
						yield script.load ();

						yield script.unload ();
						yield session.detach ();

						Timeout.add (250, performance.callback);
						yield;
					}

					yield device_manager.close ();

					h.done ();
				} catch (GLib.Error e) {
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
				} catch (GLib.Error e) {
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
			var script = yield session.create_script ("true;");
			yield script.load ();
			yield script.unload ();
			script = null;
			yield detach_and_wait_for_cleanup (session);
			session = null;

			var usage_before = process.snapshot_resource_usage ();

			for (var i = 0; i != 1; i++) {
				session = yield device.attach (process.id);
				script = yield session.create_script ("true;");
				yield script.load ();
				yield script.unload ();
				script = null;
				yield detach_and_wait_for_cleanup (session);
				session = null;

				var usage_after = process.snapshot_resource_usage ();

				usage_after.assert_equals (usage_before);
			}

			yield device_manager.close ();

			h.done ();
		} catch (GLib.Error e) {
			printerr ("\nFAIL: %s\n\n", e.message);
			assert_not_reached ();
		}
	}

	private static async void detach_and_wait_for_cleanup (Session session) throws Error, IOError {
		yield session.detach ();

		/* The Darwin injector does cleanup 50ms after detecting that the remote thread is dead */
		Timeout.add (100, detach_and_wait_for_cleanup.callback);
		yield;
	}

	private static async void start_stop_fast (Harness h) {
		var device_manager = new DeviceManager ();
		device_manager.enumerate_devices.begin ();

		var timer = new Timer ();
		try {
			yield device_manager.close ();
		} catch (IOError e) {
			assert_not_reached ();
		}
		if (GLib.Test.verbose ()) {
			printerr ("close() took %u ms\n", (uint) (timer.elapsed () * 1000.0));
		}

		h.done ();
	}

	namespace Local {

		private static async void latency_should_be_nominal (Harness h) {
			h.disable_timeout ();

			try {
				var device_manager = new DeviceManager ();
				var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);

				yield Connectivity.measure_latency (h, device, SERVER);

				yield device_manager.close ();
			} catch (GLib.Error e) {
				printerr ("Oops: %s\n", e.message);
				assert_not_reached ();
			}

			h.done ();
		}

	}

	namespace Connectivity {

		private static async void flawless (Harness h, Strategy strategy) {
			uint seen_disruptions;
			yield run_reliability_scenario (h, strategy, (message, direction) => FORWARD, out seen_disruptions);
			assert (seen_disruptions == 0);
		}

		private static async void rx_without_ack (Harness h, Strategy strategy) {
			bool disrupted = false;
			uint seen_disruptions;
			yield run_reliability_scenario (h, strategy, (message, direction) => {
				if (message.get_message_type () == METHOD_CALL && message.get_member () == "PostMessages" &&
						direction == IN && !disrupted) {
					disrupted = true;
					return FORWARD_THEN_DISRUPT;
				}
				return FORWARD;
			}, out seen_disruptions);
			assert (seen_disruptions == 1);
		}

		private static async void tx_not_sent (Harness h, Strategy strategy) {
			bool disrupted = false;
			uint seen_disruptions;
			yield run_reliability_scenario (h, strategy, (message, direction) => {
				if (message.get_message_type () == METHOD_CALL && message.get_member () == "PostMessages" &&
						direction == OUT && !disrupted) {
					disrupted = true;
					return DISRUPT;
				}
				return FORWARD;
			}, out seen_disruptions);
			assert (seen_disruptions == 1);
		}

		private static async void tx_without_ack (Harness h, Strategy strategy) {
			bool disrupted = false;
			uint seen_disruptions;
			yield run_reliability_scenario (h, strategy, (message, direction) => {
				if (message.get_message_type () == METHOD_CALL && message.get_member () == "PostMessages" &&
						direction == OUT && !disrupted) {
					disrupted = true;
					return FORWARD_THEN_DISRUPT;
				}
				return FORWARD;
			}, out seen_disruptions);
			assert (seen_disruptions == 1);
		}

		private enum Strategy {
			SERVER,
			PEER
		}

		private static async void run_reliability_scenario (Harness h, Strategy strategy, owned ChaosProxy.Inducer on_message,
				out uint seen_disruptions) {
			try {
				uint seen_detaches = 0;
				uint seen_messages = 0;
				var messages_summary = new StringBuilder ();
				bool waiting = false;

				ControlService control_service;
				uint16 control_port = 27042;
				while (true) {
					var ep = new EndpointParameters ("127.0.0.1", control_port);
					control_service = new ControlService (ep);
					try {
						yield control_service.start ();
						break;
					} catch (Error e) {
						if (e is Error.ADDRESS_IN_USE) {
							control_port++;
							continue;
						}
						throw e;
					}
				}

				var proxy = new ChaosProxy (control_port, (owned) on_message);
				yield proxy.start ();

				var device_manager = new DeviceManager ();
				var device = yield device_manager.add_remote_device ("127.0.0.1:%u".printf (proxy.proxy_port));

				var process = Frida.Test.Process.create (Frida.Test.Labrats.path_to_executable ("sleeper"));

				var options = new SessionOptions ();
				options.persist_timeout = 5;
				var session = yield device.attach (process.id, options);
				var detached_handler = session.detached.connect ((reason, crash) => {
					if (reason == CONNECTION_TERMINATED) {
						seen_detaches++;
						Idle.add (() => {
							session.resume.begin ();
							return false;
						});
					} else {
						assert (reason == APPLICATION_REQUESTED);
					}
				});

				DBusConnection? peer_connection = null;
				uint filter_id = 0;
				if (strategy == PEER) {
					yield session.setup_peer_connection ();

					peer_connection = ((DBusProxy) session.session).g_connection;
					bool disrupting = false;
					var main_context = MainContext.ref_thread_default ();
					filter_id = peer_connection.add_filter ((conn, message, incoming) => {
						if (disrupting)
							return null;

						var direction = incoming ? ChaosProxy.Direction.IN : ChaosProxy.Direction.OUT;

						switch (proxy.on_message (message, direction)) {
							case FORWARD:
								break;
							case FORWARD_THEN_DISRUPT:
								disrupting = true;
								break;
							case DISRUPT:
								disrupting = true;
								message = null;
								break;
						}

						if (disrupting) {
							var source = new IdleSource ();
							source.set_callback (() => {
								peer_connection.close.begin ();
								return false;
							});
							source.attach (main_context);
						}

						return message;
					});
				}

				var script = yield session.create_script ("""
					recv(onMessage);
					function onMessage(message) {
					  const { serial, count } = message;
					  for (let i = 0; i !== count; i++) {
					    send({ id: serial + i });
					  }
					  recv(onMessage);
					}
					""");
				var message_handler = script.message.connect ((json, data) => {
					var parser = new Json.Parser ();
					try {
						parser.load_from_data (json);
					} catch (GLib.Error e) {
						assert_not_reached ();
					}

					var reader = new Json.Reader (parser.get_root ());

					assert (reader.read_member ("type") && reader.get_string_value () == "send");
					reader.end_member ();

					assert (reader.read_member ("payload") && reader.read_member ("id"));
					int64 id = reader.get_int_value ();

					if (messages_summary.len != 0)
						messages_summary.append_c (',');
					messages_summary.append (id.to_string ());
					seen_messages++;

					if (waiting)
						run_reliability_scenario.callback ();
				});
				yield script.load ();

				script.post ("""{"serial":10,"count":3}""");

				while (seen_messages < 3) {
					waiting = true;
					yield;
					waiting = false;
				}

				// In case some unexpected messages show up...
				Timeout.add (100, run_reliability_scenario.callback);
				yield;

				seen_disruptions = seen_detaches;
				assert (seen_messages == 3);
				assert (messages_summary.str == "10,11,12");

				script.disconnect (message_handler);
				if (peer_connection != null)
					peer_connection.remove_filter (filter_id);
				session.disconnect (detached_handler);

				yield device_manager.close ();
				proxy.close ();
				yield control_service.stop ();
			} catch (GLib.Error e) {
				printerr ("Oops: %s\n", e.message);
				assert_not_reached ();
			}

			h.done ();
		}

		private class ChaosProxy : Object {
			public uint16 proxy_port {
				get {
					return _proxy_port;
				}
			}

			public uint16 target_port {
				get;
				construct;
			}

			public Inducer on_message;

			private WebService service;
			private uint16 _proxy_port;
			private SocketAddress target_address;
			private Gee.Set<Cancellable> cancellables = new Gee.HashSet<Cancellable> ();

			public delegate Action Inducer (DBusMessage message, Direction direction);

			public enum Action {
				FORWARD,
				FORWARD_THEN_DISRUPT,
				DISRUPT,
			}

			public enum Direction {
				IN,
				OUT
			}

			public ChaosProxy (uint16 target_port, owned Inducer on_message) {
				Object (target_port: target_port);

				this.on_message = (owned) on_message;
			}

			construct {
				service = new WebService (new EndpointParameters ("127.0.0.1", 1337), CONTROL,
					PortConflictBehavior.PICK_NEXT);
				service.incoming.connect (on_incoming_connection);

				target_address = new InetSocketAddress.from_string ("127.0.0.1", target_port);
			}

			public async void start () {
				try {
					yield service.start (null);
				} catch (GLib.Error e) {
					assert_not_reached ();
				}

				_proxy_port = (uint16) ((InetSocketAddress) service.listen_address).port;
			}

			public void close () {
				foreach (var cancellable in cancellables)
					cancellable.cancel ();
				cancellables.clear ();

				service.stop ();
			}

			private void on_incoming_connection (IOStream proxy_connection, SocketAddress remote_address) {
				handle_incoming_connection.begin (proxy_connection);
			}

			private async void handle_incoming_connection (IOStream proxy_connection) throws GLib.Error {
				var cancellable = new Cancellable ();
				cancellables.add (cancellable);

				IOStream? target_stream = null;
				try {
					var client = new SocketClient ();
					SocketConnection target_connection = yield client.connect_async (target_address, cancellable);
					Tcp.enable_nodelay (target_connection.socket);
					target_stream = target_connection;

					WebServiceTransport transport = PLAIN;
					string? origin = null;

					target_stream = yield negotiate_connection (target_stream, transport, "lolcathost", origin,
						cancellable);

					handle_io.begin (Direction.OUT, proxy_connection.input_stream, target_stream.output_stream,
						cancellable);
					yield handle_io (Direction.IN, target_stream.input_stream, proxy_connection.output_stream,
						cancellable);
				} finally {
					cancellable.cancel ();
					cancellables.remove (cancellable);

					Idle.add (() => {
						if (target_stream != null)
							target_stream.close_async.begin ();
						proxy_connection.close_async.begin ();
						return false;
					});
				}
			}

			private async void handle_io (Direction direction, InputStream raw_input, OutputStream output,
					Cancellable cancellable) throws GLib.Error {
				var input = new BufferedInputStream (raw_input);

				ssize_t header_size = 16;
				int io_priority = Priority.DEFAULT;

				while (true) {
					ssize_t available = (ssize_t) input.get_available ();

					if (available < header_size) {
						available = yield input.fill_async (header_size - available, io_priority, cancellable);
						if (available < header_size)
							break;
					}

					ssize_t needed = DBusMessage.bytes_needed (input.peek_buffer ());

					ssize_t missing = needed - available;
					if (missing > 0)
						available = yield input.fill_async (missing, io_priority, cancellable);

					var blob = input.read_bytes (needed);
					unowned uint8[] data = blob.get_data ();

					var message = new DBusMessage.from_blob (data, DBusCapabilityFlags.NONE);

					Action action = on_message (message, direction);

					if (action == DISRUPT) {
						cancellable.cancel ();
						break;
					}

					size_t bytes_written;
					yield output.write_all_async (data, io_priority, cancellable, out bytes_written);

					if (action == FORWARD_THEN_DISRUPT) {
						cancellable.cancel ();
						break;
					}
				}
			}
		}

		private static async void latency_should_be_nominal (Harness h, Strategy strategy) {
			h.disable_timeout ();

			try {
				ControlService control_service;
				uint16 control_port = 27042;
				while (true) {
					var ep = new EndpointParameters ("127.0.0.1", control_port);
					control_service = new ControlService (ep);
					try {
						yield control_service.start ();
						break;
					} catch (Error e) {
						if (e is Error.ADDRESS_IN_USE) {
							control_port++;
							continue;
						}
						throw e;
					}
				}

				var device_manager = new DeviceManager ();
				var device = yield device_manager.add_remote_device ("127.0.0.1:%u".printf (control_port));

				yield measure_latency (h, device, strategy);

				yield device_manager.close ();
				yield control_service.stop ();
			} catch (GLib.Error e) {
				printerr ("Oops: %s\n", e.message);
				assert_not_reached ();
			}

			h.done ();
		}

		private async void measure_latency (Harness h, Device device, Strategy strategy) throws GLib.Error {
			h.disable_timeout ();

			var process = Frida.Test.Process.create (Frida.Test.Labrats.path_to_executable ("sleeper"));

			var session = yield device.attach (process.id);

			if (strategy == PEER)
				yield session.setup_peer_connection ();

			var script = yield session.create_script ("""
				recv('ping', onPing);
				function onPing(message) {
				  send({ type: 'pong' });
				  recv('ping', onPing);
				}
				""");
			var message_handler = script.message.connect ((json, data) => {
				var parser = new Json.Parser ();
				try {
					parser.load_from_data (json);
				} catch (GLib.Error e) {
					assert_not_reached ();
				}

				var reader = new Json.Reader (parser.get_root ());

				assert (reader.read_member ("type") && reader.get_string_value () == "send");
				reader.end_member ();

				assert (reader.read_member ("payload") && reader.read_member ("type") && reader.get_string_value () == "pong");
				reader.end_member ();

				measure_latency.callback ();
			});
			try {
				yield script.load ();

				var timer = new Timer ();
				for (int i = 0; i != 100; i++) {
					timer.reset ();
					script.post ("""{"type":"ping"}""");
					yield;
					printerr (" [%d: %u ms]", i + 1, (uint) (timer.elapsed () * 1000.0));

					Idle.add (measure_latency.callback);
					yield;

					if ((i + 1) % 10 == 0) {
						printerr ("\n");
						if (GLib.Test.verbose ())
							yield h.prompt_for_key ("Hit a key to do 10 more: ");
					}
				}
			} finally {
				script.disconnect (message_handler);
			}

			yield script.unload ();

			yield session.detach ();
		}

	}

#if LINUX
	namespace Linux {

		private static async void backend (Harness h) {
			var backend = new LinuxHostSessionBackend ();

			var prov = yield h.setup_local_backend (backend);

			assert_true (prov.name == "Local System");

			try {
				Cancellable? cancellable = null;

				var session = yield prov.create (null, cancellable);

				var applications = yield session.enumerate_applications (make_parameters_dict (), cancellable);
				var processes = yield session.enumerate_processes (make_parameters_dict (), cancellable);
				assert_true (processes.length > 0);

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

			yield h.teardown_backend (backend);

			h.done ();
		}

		private static async void spawn (Harness h) {
			if ((Frida.Test.os () == Frida.Test.OS.ANDROID || Frida.Test.os_arch_suffix () == "-linux-arm") &&
					!GLib.Test.slow ()) {
				stdout.printf ("<skipping, run in slow mode> ");
				h.done ();
				return;
			}

			var backend = new LinuxHostSessionBackend ();

			var prov = yield h.setup_local_backend (backend);

			try {
				Cancellable? cancellable = null;

				var host_session = yield prov.create (null, cancellable);

				uint pid = 0;
				bool waiting = false;

				string received_output = null;
				var output_handler = host_session.output.connect ((source_pid, fd, data) => {
					assert_true (source_pid == pid);
					assert_true (fd == 1);

					var buf = new uint8[data.length + 1];
					Memory.copy (buf, data, data.length);
					buf[data.length] = '\0';
					char * chars = buf;
					received_output = (string) chars;

					if (waiting)
						spawn.callback ();
				});

				var options = HostSpawnOptions ();
				options.stdio = PIPE;
				pid = yield host_session.spawn (Frida.Test.Labrats.path_to_executable ("sleeper"), options, cancellable);

				var session_id = yield host_session.attach (pid, make_parameters_dict (), cancellable);
				var session = yield prov.link_agent_session (host_session, session_id, h, cancellable);

				string received_message = null;
				var message_handler = h.message_from_script.connect ((script_id, message, data) => {
					received_message = message;
					if (waiting)
						spawn.callback ();
				});

				var script_id = yield session.create_script ("""
					var write = new NativeFunction(Module.getExportByName(null, 'write'), 'int', ['int', 'pointer', 'int']);
					var message = Memory.allocUtf8String('Hello stdout');
					write(1, message, 12);
					for (const m of Process.enumerateModules()) {
					  if (m.name.startsWith('libc')) {
					    Interceptor.attach (Module.getExportByName(m.name, 'sleep'), {
					      onEnter(args) {
					        send({ seconds: args[0].toInt32() });
					      }
					    });
					    break;
					  }
					}
					""", make_parameters_dict (), cancellable);
				yield session.load_script (script_id, cancellable);

				if (received_output == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (received_output == "Hello stdout");
				host_session.disconnect (output_handler);

				yield host_session.resume (pid, cancellable);

				if (received_message == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (received_message == "{\"type\":\"send\",\"payload\":{\"seconds\":60}}");
				h.disconnect (message_handler);

				yield host_session.kill (pid, cancellable);
			} catch (GLib.Error e) {
				printerr ("Unexpected error: %s\n", e.message);
				assert_not_reached ();
			}

			yield h.teardown_backend (backend);

			h.done ();
		}

		private static async void fork (Harness h) {
			yield Unix.run_fork_scenario (h, Frida.Test.Labrats.path_to_executable ("forker"));
		}

		private static async void fork_plus_exec (Harness h, string method) {
			yield Unix.run_fork_plus_exec_scenario (h, Frida.Test.Labrats.path_to_executable ("spawner"), method);
		}

		private static async void bad_exec (Harness h) {
			yield Unix.run_bad_exec_scenario (h, Frida.Test.Labrats.path_to_executable ("spawner"), "execv");
		}

		private static async void bad_then_good_exec (Harness h) {
			yield Unix.run_exec_scenario (h, Frida.Test.Labrats.path_to_executable ("spawner"), "spawn-bad-then-good-path", "execv");
		}

		namespace Manual {

			private static async void spawn_android_app (Harness h) {
				if (!GLib.Test.slow ()) {
					stdout.printf ("<skipping, run in slow mode on Android device> ");
					h.done ();
					return;
				}

				h.disable_timeout (); /* this is a manual test after all */

				try {
					var device_manager = new DeviceManager ();
					var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);

					string package_name = "com.android.settings";
					string? activity_name = ".SecuritySettings";
					string received_message = null;
					bool waiting = false;

					var options = new SpawnOptions ();
					if (activity_name != null)
						options.aux["activity"] = new Variant.string (activity_name);

					printerr ("device.spawn(\"%s\")\n", package_name);
					var pid = yield device.spawn (package_name, options);

					printerr ("device.attach(%u)\n", pid);
					var session = yield device.attach (pid);

					printerr ("session.create_script()\n");
					var script = yield session.create_script ("""
						Java.perform(() => {
						  const Activity = Java.use('android.app.Activity');
						  Activity.onResume.implementation = function () {
						    send('onResume');
						    this.onResume();
						  };
						});
						""");
					script.message.connect ((message, data) => {
						received_message = message;
						if (waiting)
							spawn_android_app.callback ();
					});

					printerr ("script.load()\n");
					yield script.load ();

					printerr ("device.resume(%u)\n", pid);
					yield device.resume (pid);

					printerr ("await_message()\n");
					while (received_message == null) {
						waiting = true;
						yield;
						waiting = false;
					}
					printerr ("received_message: %s\n", received_message);
					assert_true (received_message == "{\"type\":\"send\",\"payload\":\"onResume\"}");
					received_message = null;

					yield device_manager.close ();

					h.done ();
				} catch (GLib.Error e) {
					printerr ("ERROR: %s\n", e.message);
					assert_not_reached ();
				}
			}

		}

	}
#endif

#if DARWIN
	namespace Darwin {

		private static async void backend (Harness h) {
			var backend = new DarwinHostSessionBackend ();

			var prov = yield h.setup_local_backend (backend);

			assert_true (prov.name == "Local System");

			if (Frida.Test.os () == Frida.Test.OS.MACOS) {
				Variant? icon = prov.icon;
				assert_nonnull (icon);
				var dict = new VariantDict (icon);
				int64 width, height;
				assert_true (dict.lookup ("width", "x", out width));
				assert_true (dict.lookup ("height", "x", out height));
				assert_true (width == 16);
				assert_true (height == 16);
				VariantIter image;
				assert_true (dict.lookup ("image", "ay", out image));
				assert_true (image.n_children () == width * height * 4);
			}

			try {
				Cancellable? cancellable = null;

				var session = yield prov.create (null, cancellable);

				var applications = yield session.enumerate_applications (make_parameters_dict (), cancellable);
				var processes = yield session.enumerate_processes (make_parameters_dict (), cancellable);
				assert_true (processes.length > 0);

				if (GLib.Test.verbose ()) {
					foreach (var app in applications)
						stdout.printf ("identifier='%s' name='%s'\n", app.identifier, app.name);

					foreach (var process in processes)
						stdout.printf ("pid=%u name='%s'\n", process.pid, process.name);
				}
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			yield h.teardown_backend (backend);

			h.done ();
		}

		private static async void spawn_native (Harness h) {
			yield run_spawn_scenario (h, target_name_of_native ("sleeper"));
		}

		private static async void spawn_other (Harness h) {
			yield run_spawn_scenario (h, target_name_of_other ("sleeper"));
		}

		private static async void run_spawn_scenario (Harness h, string target_name) {
			var backend = new DarwinHostSessionBackend ();

			var prov = yield h.setup_local_backend (backend);

			try {
				Cancellable? cancellable = null;

				var host_session = yield prov.create (null, cancellable);

				uint pid = 0;
				bool waiting = false;

				string received_output = null;
				var output_handler = host_session.output.connect ((source_pid, fd, data) => {
					assert_true (source_pid == pid);
					assert_true (fd == 1);

					var buf = new uint8[data.length + 1];
					Memory.copy (buf, data, data.length);
					buf[data.length] = '\0';
					char * chars = buf;
					received_output = (string) chars;

					if (waiting)
						run_spawn_scenario.callback ();
				});

				var options = HostSpawnOptions ();
				options.stdio = PIPE;
				pid = yield host_session.spawn (Frida.Test.Labrats.path_to_file (target_name), options, cancellable);

				var session_id = yield host_session.attach (pid, make_parameters_dict (), cancellable);
				var session = yield prov.link_agent_session (host_session, session_id, h, cancellable);

				string received_message = null;
				var message_handler = h.message_from_script.connect ((script_id, message, data) => {
					received_message = message;
					if (waiting)
						run_spawn_scenario.callback ();
				});

				var script_id = yield session.create_script ("""
					const write = new NativeFunction(Module.getExportByName('libSystem.B.dylib', 'write'), 'int', ['int', 'pointer', 'int']);
					const message = Memory.allocUtf8String('Hello stdout');
					const cout = Module.getExportByName('libc++.1.dylib', '_ZNSt3__14coutE').readPointer();
					const properlyInitialized = !cout.isNull();
					write(1, message, 12);
					const getMainPtr = Module.findExportByName(null, 'CFRunLoopGetMain');
					if (getMainPtr !== null) {
					  const getMain = new NativeFunction(getMainPtr, 'pointer', []);
					  getMain();
					}
					const sleepFuncName = (Process.arch === 'ia32') ? 'sleep$UNIX2003' : 'sleep';
					Interceptor.attach(Module.getExportByName('libSystem.B.dylib', sleepFuncName), {
					  onEnter(args) {
					    send({ seconds: args[0].toInt32(), initialized: properlyInitialized });
					  }
					});
					""", make_parameters_dict (), cancellable);
				yield session.load_script (script_id, cancellable);

				if (received_output == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (received_output == "Hello stdout");
				host_session.disconnect (output_handler);

				yield host_session.resume (pid, cancellable);

				if (received_message == null) {
					waiting = true;
					yield;
					waiting = false;
				}
#if MACOS
				// FIXME: Improve early instrumentation on Monterey
				assert_true (received_message.has_prefix ("{\"type\":\"send\",\"payload\":{\"seconds\":60,\"initialized\":"));
#else
				assert_true (received_message == "{\"type\":\"send\",\"payload\":{\"seconds\":60,\"initialized\":true}}");
#endif
				h.disconnect (message_handler);

				yield host_session.kill (pid, cancellable);
			} catch (GLib.Error e) {
				printerr ("Unexpected error: %s\n", e.message);
				assert_not_reached ();
			}

			yield h.teardown_backend (backend);

			h.done ();
		}

		private static async void spawn_without_attach_native (Harness h) {
			yield run_spawn_scenario_with_stdio (h, target_name_of_native ("stdio-writer"));
		}

		private static async void spawn_without_attach_other (Harness h) {
			yield run_spawn_scenario_with_stdio (h, target_name_of_other ("stdio-writer"));
		}

		private static async void run_spawn_scenario_with_stdio (Harness h, string target_name) {
			var backend = new DarwinHostSessionBackend ();

			var prov = yield h.setup_local_backend (backend);

			try {
				Cancellable? cancellable = null;

				var host_session = yield prov.create (null, cancellable);

				uint pid = 0;
				bool waiting = false;

				string received_stdout = null;
				string received_stderr = null;
				var output_handler = host_session.output.connect ((source_pid, fd, data) => {
					assert_true (source_pid == pid);

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
							assert_nonnull (received_stdout);
						else if (fd == 2)
							assert_nonnull (received_stderr);
						else
							assert_not_reached ();
					}

					if (waiting)
						run_spawn_scenario_with_stdio.callback ();
				});

				var options = HostSpawnOptions ();
				options.stdio = PIPE;
				pid = yield host_session.spawn (Frida.Test.Labrats.path_to_file (target_name), options, cancellable);

				yield host_session.resume (pid, cancellable);

				while (received_stdout == null || received_stderr == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (received_stdout == "Hello stdout");
				assert_true (received_stderr == "Hello stderr");
				host_session.disconnect (output_handler);

				yield host_session.kill (pid, cancellable);
			} catch (GLib.Error e) {
				printerr ("Unexpected error: %s\n", e.message);
				assert_not_reached ();
			}

			yield h.teardown_backend (backend);

			h.done ();
		}

		private static async void own_memory_ranges_should_be_cloaked (Harness h) {
			if (Frida.Test.os () != Frida.Test.OS.MACOS || Frida.Test.cpu () != Frida.Test.CPU.X86_64) {
				stdout.printf ("<skipping, test only available on macOS/x86_64 for now> ");
				h.done ();
				return;
			}

			try {
				var device_manager = new DeviceManager ();
				var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);
				var process = Frida.Test.Process.start (Frida.Test.Labrats.path_to_executable ("sleeper"));

				/* TODO: improve injector to handle injection into a process that hasn't yet finished initializing */
				Thread.usleep (50000);

				/* Warm up static allocations */
				var session = yield device.attach (process.id);
				yield session.detach ();
				session = null;

				/* The injector does cleanup 50ms after detecting that the remote thread is dead */
				Timeout.add (100, own_memory_ranges_should_be_cloaked.callback);
				yield;

				var original_ranges = dump_ranges (process.id);

				session = yield device.attach (process.id);
				var script = yield session.create_script ("""
					const ranges = Process.enumerateRanges({ protection: '---', coalesce: true })
					    .map(range => `${range.base.toString()}-${range.base.add(range.size).toString()}`);
					send(ranges);
					""");
				string received_message = null;
				bool waiting = false;
				script.message.connect ((message, data) => {
					assert_null (received_message);
					received_message = message;
					if (waiting)
						own_memory_ranges_should_be_cloaked.callback ();
				});

				yield script.load ();

				if (received_message == null) {
					waiting = true;
					yield;
					waiting = false;
				}

				var message = Json.from_string (received_message).get_object ();
				assert_true (message.get_string_member ("type") == "send");

				var uncloaked_ranges = new Gee.ArrayList <string> ();
				message.get_array_member ("payload").foreach_element ((array, index, element) => {
					var range = element.get_string ();
					if (!original_ranges.contains (range)) {
						uncloaked_ranges.add (range);
					}
				});

				if (!uncloaked_ranges.is_empty) {
					printerr ("\n\nUH-OH, uncloaked_ranges.size=%d:\n", uncloaked_ranges.size);
					foreach (var range in uncloaked_ranges) {
						printerr ("\t%s\n", range);
					}
				}
				printerr ("\n");

				// assert_true (uncloaked_ranges.is_empty);

				yield script.unload ();

				yield device_manager.close ();

				h.done ();
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}
		}

		private Gee.HashSet<string> dump_ranges (uint pid) {
			var ranges = new Gee.ArrayList<Range> ();
			var range_by_end_address = new Gee.HashMap<string, Range> ();

			try {
				string vmmap_output;
				GLib.Process.spawn_sync (null, new string[] { "/usr/bin/vmmap", "-interleaved", "%u".printf (pid) }, null, 0, null, out vmmap_output, null, null);

				var range_pattern = new Regex ("([0-9a-f]{8,})-([0-9a-f]{8,})\\s+.+\\s+([rwx-]{3})\\/");
				MatchInfo match_info;
				assert_true (range_pattern.match (vmmap_output, 0, out match_info));
				while (match_info.matches ()) {
					var start = uint64.parse ("0x" + match_info.fetch (1));
					var end = uint64.parse ("0x" + match_info.fetch (2));
					var protection = match_info.fetch (3);

					var address_format = "0x%" + uint64.FORMAT_MODIFIER + "x";
					var start_str = start.to_string (address_format);
					var end_str = end.to_string (address_format);

					Range range;
					var existing_range = range_by_end_address[start_str];
					if (existing_range != null && existing_range.protection == protection) {
						existing_range.end = end_str;
						range = existing_range;
					} else {
						range = new Range (start_str, end_str, protection);
						ranges.add (range);
					}
					range_by_end_address[end_str] = range;

					match_info.next ();
				}
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			var result = new Gee.HashSet<string> ();
			foreach (var range in ranges)
				result.add ("%s-%s".printf (range.start, range.end));
			return result;
		}

		private class Range {
			public string start;
			public string end;
			public string protection;

			public Range (string start, string end, string protection) {
				this.start = start;
				this.end = end;
				this.protection = protection;
			}
		}

		namespace ExitMonitor {
			private static async void abort_from_js_thread_should_not_deadlock (Harness h) {
				try {
					var device_manager = new DeviceManager ();
					var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);
					var process = Frida.Test.Process.start (Frida.Test.Labrats.path_to_executable ("sleeper"));

					/* TODO: improve injector to handle injection into a process that hasn't yet finished initializing */
					Thread.usleep (50000);

					var session = yield device.attach (process.id);
					var script = yield session.create_script ("""
						rpc.exports = {
						  dispose() {
						    send('dispose');
						  }
						};

						const abort = new NativeFunction(Module.getExportByName('/usr/lib/system/libsystem_c.dylib', 'abort'), 'void', [], { exceptions: 'propagate' });
						setTimeout(() => { abort(); }, 50);
						""");

					string? detach_reason = null;
					string? received_message = null;
					bool waiting = false;
					session.detached.connect (reason => {
						detach_reason = reason.to_string ();
						if (waiting)
							abort_from_js_thread_should_not_deadlock.callback ();
					});
					script.message.connect ((message, data) => {
						assert_null (received_message);
						received_message = message;
						if (waiting)
							abort_from_js_thread_should_not_deadlock.callback ();
					});

					yield script.load ();

					while (received_message == null || detach_reason == null) {
						waiting = true;
						yield;
						waiting = false;
					}
					assert_true (received_message == "{\"type\":\"send\",\"payload\":\"dispose\"}");
					assert_true (detach_reason == "FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED");

					h.done ();
				} catch (GLib.Error e) {
					printerr ("ERROR: %s\n", e.message);
				}
			}
		}

		private static async void fork_native (Harness h) {
			yield Unix.run_fork_scenario (h, Frida.Test.Labrats.path_to_file (target_name_of_native ("forker")));
		}

		private static async void fork_other (Harness h) {
			yield Unix.run_fork_scenario (h, Frida.Test.Labrats.path_to_file (target_name_of_other ("forker")));
		}

		private static async void fork_plus_exec (Harness h, string method) {
			yield Unix.run_fork_plus_exec_scenario (h, Frida.Test.Labrats.path_to_executable ("spawner"), method);
		}

		private static async void bad_exec (Harness h) {
			yield Unix.run_bad_exec_scenario (h, Frida.Test.Labrats.path_to_executable ("spawner"), "execv");
		}

		private static async void bad_then_good_exec (Harness h) {
			yield Unix.run_exec_scenario (h, Frida.Test.Labrats.path_to_executable ("spawner"), "spawn-bad-then-good-path", "execv");
		}

		private static async void posix_spawn (Harness h) {
			yield Unix.run_posix_spawn_scenario (h, Frida.Test.Labrats.path_to_executable ("spawner"));
		}

		private static async void posix_spawn_plus_setexec (Harness h) {
			yield Unix.run_exec_scenario (h, Frida.Test.Labrats.path_to_executable ("spawner"), "spawn", "posix_spawn+setexec");
		}

		private static string target_name_of_native (string name) {
			string suffix = (Frida.Test.os () == Frida.Test.OS.MACOS) ? "macos" : "ios";

			return name + "-" + suffix;
		}

		private static string target_name_of_other (string name) {
			string suffix;
			if (Frida.Test.os () == Frida.Test.OS.MACOS) {
				suffix = "macos32";
			} else {
				suffix = (Gum.query_ptrauth_support () == SUPPORTED) ? "ios64" : "ios32";
			}

			return name + "-" + suffix;
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
					GLib.Process.spawn_sync (null, new string[] { "/usr/bin/pgrep", "Safari" }, null, 0, null,
						out pgrep_output, null, null);
					pid = (uint) int.parse (pgrep_output);
				} catch (SpawnError spawn_error) {
					printerr ("ERROR: %s\n", spawn_error.message);
					assert_not_reached ();
				}

				var backend = new DarwinHostSessionBackend ();

				var prov = yield h.setup_local_backend (backend);

				try {
					Cancellable? cancellable = null;

					var host_session = yield prov.create (null, cancellable);

					var id = yield host_session.attach (pid, make_parameters_dict (), cancellable);
					var session = yield prov.link_agent_session (host_session, id, h, cancellable);

					string received_message = null;
					bool waiting = false;
					var message_handler = h.message_from_script.connect ((script_id, message, data) => {
						received_message = message;
						if (waiting)
							cross_arch.callback ();
					});

					var script_id = yield session.create_script ("send('hello');", make_parameters_dict (),
						cancellable);
					yield session.load_script (script_id, cancellable);

					if (received_message == null) {
						waiting = true;
						yield;
						waiting = false;
					}

					assert_true (received_message == "{\"type\":\"send\",\"payload\":\"hello\"}");

					h.disconnect (message_handler);
				} catch (GLib.Error e) {
					printerr ("ERROR: %s\n", e.message);
					assert_not_reached ();
				}

				yield h.teardown_backend (backend);

				h.done ();
			}

			private static async void spawn_ios_app (Harness h) {
				if (!GLib.Test.slow ()) {
					stdout.printf ("<skipping, run in slow mode on iOS device> ");
					h.done ();
					return;
				}

				h.disable_timeout (); /* this is a manual test after all */

				var device_manager = new DeviceManager ();

				try {
					var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);
					device.output.connect ((pid, fd, data) => {
						var chars = data.get_data ();
						var len = chars.length;
						if (len == 0) {
							printerr ("[pid=%u fd=%d EOF]\n", pid, fd);
							return;
						}

						var buf = new uint8[len + 1];
						Memory.copy (buf, chars, len);
						buf[len] = '\0';
						string message = (string) buf;

						printerr ("[pid=%u fd=%d OUTPUT] %s", pid, fd, message);
					});

					/*
					string app_id = "com.apple.mobilesafari";
					string? url = "https://www.frida.re/docs/ios/";
					*/

					string app_id = "com.atebits.Tweetie2";
					string? url = null;

					string received_message = null;
					bool waiting = false;

					var options = new SpawnOptions ();
					// options.argv = { app_id, "hey", "you" };
					options.envp = { "OS_ACTIVITY_DT_MODE=YES", "NSUnbufferedIO=YES" };
					options.stdio = PIPE;
					if (url != null)
						options.aux["url"] = new Variant.string (url);
					// options.aux["aslr"] = new Variant.string ("disable");

					printerr ("device.spawn(\"%s\")\n", app_id);
					var pid = yield device.spawn (app_id, options);

					printerr ("device.attach(%u)\n", pid);
					var session = yield device.attach (pid);

					printerr ("session.create_script()\n");
					var script = yield session.create_script ("""
						Interceptor.attach(Module.getExportByName('UIKit', 'UIApplicationMain'), () => {
						  send('UIApplicationMain');
						});
						""");
					script.message.connect ((message, data) => {
						received_message = message;
						if (waiting)
							spawn_ios_app.callback ();
					});

					printerr ("script.load()\n");
					yield script.load ();

					printerr ("device.resume(%u)\n", pid);
					yield device.resume (pid);

					printerr ("await_message()\n");
					while (received_message == null) {
						waiting = true;
						yield;
						waiting = false;
					}
					printerr ("received_message: %s\n", received_message);
					assert_true (received_message == "{\"type\":\"send\",\"payload\":\"UIApplicationMain\"}");
					received_message = null;
				} catch (GLib.Error e) {
					printerr ("ERROR: %s\n", e.message);
				}

				yield h.prompt_for_key ("Hit a key to exit: ");

				try {
					yield device_manager.close ();
				} catch (IOError e) {
					assert_not_reached ();
				}

				h.done ();
			}

		}

	}
#endif

#if FREEBSD
	namespace FreeBSD {

		private static async void backend (Harness h) {
			var backend = new FreebsdHostSessionBackend ();

			var prov = yield h.setup_local_backend (backend);

			assert_true (prov.name == "Local System");

			try {
				Cancellable? cancellable = null;

				var session = yield prov.create (null, cancellable);

				var processes = yield session.enumerate_processes (make_parameters_dict (), cancellable);
				assert_true (processes.length > 0);

				if (GLib.Test.verbose ()) {
					foreach (var process in processes)
						stdout.printf ("pid=%u name='%s'\n", process.pid, process.name);
				}
			} catch (GLib.Error e) {
				printerr ("ERROR: %s\n", e.message);
				assert_not_reached ();
			}

			yield h.teardown_backend (backend);

			h.done ();
		}

		private static async void spawn (Harness h) {
			var backend = new FreebsdHostSessionBackend ();

			var prov = yield h.setup_local_backend (backend);

			try {
				Cancellable? cancellable = null;

				var host_session = yield prov.create (null, cancellable);

				uint pid = 0;
				bool waiting = false;

				string received_output = null;
				var output_handler = host_session.output.connect ((source_pid, fd, data) => {
					assert_true (source_pid == pid);
					assert_true (fd == 1);

					var buf = new uint8[data.length + 1];
					Memory.copy (buf, data, data.length);
					buf[data.length] = '\0';
					char * chars = buf;
					received_output = (string) chars;

					if (waiting)
						spawn.callback ();
				});

				var options = HostSpawnOptions ();
				options.stdio = PIPE;
				pid = yield host_session.spawn (Frida.Test.Labrats.path_to_executable ("sleeper"), options, cancellable);

				var session_id = yield host_session.attach (pid, make_parameters_dict (), cancellable);
				var session = yield prov.link_agent_session (host_session, session_id, h, cancellable);

				string received_message = null;
				var message_handler = h.message_from_script.connect ((script_id, message, data) => {
					received_message = message;
					if (waiting)
						spawn.callback ();
				});

				var script_id = yield session.create_script ("""
					var write = new NativeFunction(Module.getExportByName(null, 'write'), 'int', ['int', 'pointer', 'int']);
					var message = Memory.allocUtf8String('Hello stdout');
					write(1, message, 12);
					for (const m of Process.enumerateModules()) {
					  if (m.name.startsWith('libc')) {
					    Interceptor.attach (Module.getExportByName(m.name, 'sleep'), {
					      onEnter(args) {
					        send({ seconds: args[0].toInt32() });
					      }
					    });
					    break;
					  }
					}
					""", make_parameters_dict (), cancellable);
				yield session.load_script (script_id, cancellable);

				if (received_output == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (received_output == "Hello stdout");
				host_session.disconnect (output_handler);

				yield host_session.resume (pid, cancellable);

				if (received_message == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (received_message == "{\"type\":\"send\",\"payload\":{\"seconds\":60}}");
				h.disconnect (message_handler);

				yield host_session.kill (pid, cancellable);
			} catch (GLib.Error e) {
				printerr ("Unexpected error: %s\n", e.message);
				assert_not_reached ();
			}

			yield h.teardown_backend (backend);

			h.done ();
		}

		private static async void fork (Harness h) {
			yield Unix.run_fork_scenario (h, Frida.Test.Labrats.path_to_executable ("forker"));
		}

		private static async void fork_plus_exec (Harness h, string method) {
			yield Unix.run_fork_plus_exec_scenario (h, Frida.Test.Labrats.path_to_executable ("spawner"), method);
		}

		private static async void bad_exec (Harness h) {
			yield Unix.run_bad_exec_scenario (h, Frida.Test.Labrats.path_to_executable ("spawner"), "execv");
		}

		private static async void bad_then_good_exec (Harness h) {
			yield Unix.run_exec_scenario (h, Frida.Test.Labrats.path_to_executable ("spawner"), "spawn-bad-then-good-path", "execv");
		}

	}
#endif

#if !WINDOWS
	namespace Unix {

		public static async void run_fork_scenario (Harness h, string target_path) {
			try {
				var device_manager = new DeviceManager ();
				var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);

				string parent_detach_reason = null;
				string child_detach_reason = null;
				var parent_messages = new Gee.ArrayList <string> ();
				var child_messages = new Gee.ArrayList <string> ();
				Child the_child = null;
				bool waiting = false;

				if (GLib.Test.verbose ()) {
					device.output.connect ((pid, fd, data) => {
						var chars = data.get_data ();
						var len = chars.length;
						if (len == 0) {
							printerr ("[pid=%u fd=%d EOF]\n", pid, fd);
							return;
						}

						var buf = new uint8[len + 1];
						Memory.copy (buf, chars, len);
						buf[len] = '\0';
						string message = (string) buf;

						printerr ("[pid=%u fd=%d OUTPUT] %s", pid, fd, message);
					});
				}
				device.child_added.connect (child => {
					the_child = child;
					if (waiting)
						run_fork_scenario.callback ();
				});

				var options = new SpawnOptions ();
				options.stdio = PIPE;
				var parent_pid = yield device.spawn (target_path, options);
				var parent_session = yield device.attach (parent_pid);
				parent_session.detached.connect (reason => {
					parent_detach_reason = reason.to_string ();
					if (waiting)
						run_fork_scenario.callback ();
				});
				yield parent_session.enable_child_gating ();
				var parent_script = yield parent_session.create_script ("""
					Interceptor.attach(Module.getExportByName(null, 'puts'), {
					  onEnter(args) {
					    send('[PARENT] ' + args[0].readUtf8String());
					  }
					});
					""");
				parent_script.message.connect ((message, data) => {
					if (GLib.Test.verbose ())
						printerr ("Message from parent: %s\n", message);
					parent_messages.add (message);
					if (waiting)
						run_fork_scenario.callback ();
				});
				yield parent_script.load ();
				yield device.resume (parent_pid);
				while (parent_messages.is_empty) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (parent_messages.size == 1);
				assert_true (parse_string_message_payload (parent_messages[0]) == "[PARENT] Parent speaking");

				while (the_child == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				var child = the_child;
				the_child = null;
				assert_true (child.pid != parent_pid);
				assert_true (child.parent_pid == parent_pid);
				assert_true (child.origin == FORK);
				assert_null (child.identifier);
				assert_null (child.path);
				assert_null (child.argv);
				assert_null (child.envp);
				var child_session = yield device.attach (child.pid);
				child_session.detached.connect (reason => {
					child_detach_reason = reason.to_string ();
					if (waiting)
						run_fork_scenario.callback ();
				});
				var child_script = yield child_session.create_script ("""
					Interceptor.attach(Module.getExportByName(null, 'puts'), {
					  onEnter(args) {
					    send('[CHILD] ' + args[0].readUtf8String());
					  }
					});
					""");
				child_script.message.connect ((message, data) => {
					if (GLib.Test.verbose ())
						printerr ("Message from child: %s\n", message);
					child_messages.add (message);
					if (waiting)
						run_fork_scenario.callback ();
				});
				yield child_script.load ();
				yield device.resume (child.pid);
				while (child_messages.is_empty) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (child_messages.size == 1);
				assert_true (parse_string_message_payload (child_messages[0]) == "[CHILD] Child speaking");

				while (parent_detach_reason == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (parent_detach_reason == "FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED");

				while (child_detach_reason == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (child_detach_reason == "FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED");

				yield h.process_events ();
				assert_true (parent_messages.size == 1);
				assert_true (child_messages.size == 1);

				yield device_manager.close ();

				h.done ();
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}
		}

		public static async void run_fork_plus_exec_scenario (Harness h, string target_path, string method) {
			try {
				var device_manager = new DeviceManager ();
				var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);

				string parent_detach_reason = null;
				string child_pre_exec_detach_reason = null;
				string child_post_exec_detach_reason = null;
				var child_messages = new Gee.ArrayList <string> ();
				Child the_child = null;
				bool waiting = false;

				if (GLib.Test.verbose ()) {
					device.output.connect ((pid, fd, data) => {
						var chars = data.get_data ();
						var len = chars.length;
						if (len == 0) {
							printerr ("[pid=%u fd=%d EOF]\n", pid, fd);
							return;
						}

						var buf = new uint8[len + 1];
						Memory.copy (buf, chars, len);
						buf[len] = '\0';
						string message = (string) buf;

						printerr ("[pid=%u fd=%d OUTPUT] %s", pid, fd, message);
					});
				}
				device.child_added.connect (child => {
					the_child = child;
					if (waiting)
						run_fork_plus_exec_scenario.callback ();
				});

				var options = new SpawnOptions ();
				options.argv = { target_path, "spawn", method };
				options.stdio = PIPE;
				var parent_pid = yield device.spawn (target_path, options);
				var parent_session = yield device.attach (parent_pid);
				parent_session.detached.connect (reason => {
					parent_detach_reason = reason.to_string ();
					if (waiting)
						run_fork_plus_exec_scenario.callback ();
				});
				yield parent_session.enable_child_gating ();

				yield device.resume (parent_pid);

				while (the_child == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				var child_pre_exec = the_child;
				the_child = null;
				assert_true (child_pre_exec.pid != parent_pid);
				assert_true (child_pre_exec.parent_pid == parent_pid);
				assert_true (child_pre_exec.origin == FORK);
				assert_null (child_pre_exec.identifier);
				assert_null (child_pre_exec.path);
				assert_null (child_pre_exec.argv);
				assert_null (child_pre_exec.envp);

				var child_session_pre_exec = yield device.attach (child_pre_exec.pid);
				yield child_session_pre_exec.enable_child_gating ();
				child_session_pre_exec.detached.connect (reason => {
					child_pre_exec_detach_reason = reason.to_string ();
					if (waiting)
						run_fork_plus_exec_scenario.callback ();
				});

				yield device.resume (child_pre_exec.pid);

				while (child_pre_exec_detach_reason == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (child_pre_exec_detach_reason == "FRIDA_SESSION_DETACH_REASON_PROCESS_REPLACED");

				while (the_child == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				var child_post_exec = the_child;
				the_child = null;
				assert_true (child_post_exec.pid == child_pre_exec.pid);
				assert_true (child_post_exec.parent_pid == child_post_exec.pid);
				assert_true (child_post_exec.origin == EXEC);
				assert_null (child_post_exec.identifier);
				assert_nonnull (child_post_exec.path);
				assert_nonnull (child_post_exec.argv);
				assert_nonnull (child_post_exec.envp);

				var child_session_post_exec = yield device.attach (child_post_exec.pid);
				child_session_post_exec.detached.connect (reason => {
					child_post_exec_detach_reason = reason.to_string ();
					if (waiting)
						run_fork_plus_exec_scenario.callback ();
				});
				var script = yield child_session_post_exec.create_script ("""
					Interceptor.attach(Module.getExportByName(null, 'puts'), {
					  onEnter(args) {
					    send(args[0].readUtf8String());
					  }
					});
					""");
				script.message.connect ((message, data) => {
					if (GLib.Test.verbose ())
						printerr ("Message from child: %s\n", message);
					child_messages.add (message);
					if (waiting)
						run_fork_plus_exec_scenario.callback ();
				});
				yield script.load ();

				yield device.resume (child_post_exec.pid);

				while (child_messages.is_empty) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (child_messages.size == 1);
				assert_true (parse_string_message_payload (child_messages[0]) == method);

				while (child_post_exec_detach_reason == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (child_post_exec_detach_reason == "FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED");

				while (parent_detach_reason == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (parent_detach_reason == "FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED");

				yield h.process_events ();
				assert_true (child_messages.size == 1);

				yield device_manager.close ();

				h.done ();
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}
		}

		public static async void run_exec_scenario (Harness h, string target_path, string operation, string method) {
			try {
				var device_manager = new DeviceManager ();
				var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);

				string pre_exec_detach_reason = null;
				string post_exec_detach_reason = null;
				var messages = new Gee.ArrayList <string> ();
				Child the_child = null;
				bool waiting = false;

				if (GLib.Test.verbose ()) {
					device.output.connect ((pid, fd, data) => {
						var chars = data.get_data ();
						var len = chars.length;
						if (len == 0) {
							printerr ("[pid=%u fd=%d EOF]\n", pid, fd);
							return;
						}

						var buf = new uint8[len + 1];
						Memory.copy (buf, chars, len);
						buf[len] = '\0';
						string message = (string) buf;

						printerr ("[pid=%u fd=%d OUTPUT] %s", pid, fd, message);
					});
				}
				device.child_added.connect (child => {
					the_child = child;
					if (waiting)
						run_exec_scenario.callback ();
				});

				var options = new SpawnOptions ();
				options.argv = { target_path, operation, method };
				options.stdio = PIPE;
				var pre_exec_pid = yield device.spawn (target_path, options);
				var pre_exec_session = yield device.attach (pre_exec_pid);
				pre_exec_session.detached.connect (reason => {
					pre_exec_detach_reason = reason.to_string ();
					if (waiting)
						run_exec_scenario.callback ();
				});
				yield pre_exec_session.enable_child_gating ();

				yield device.resume (pre_exec_pid);

				while (pre_exec_detach_reason == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (pre_exec_detach_reason == "FRIDA_SESSION_DETACH_REASON_PROCESS_REPLACED");

				while (the_child == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				var child = the_child;
				the_child = null;
				assert_true (child.pid == pre_exec_pid);
				assert_true (child.parent_pid == pre_exec_pid);
				assert_true (child.origin == EXEC);
				assert_null (child.identifier);
				assert_nonnull (child.path);
				assert_true (Path.get_basename (child.path).has_prefix ("spawner-"));
				assert_nonnull (child.argv);
				assert_nonnull (child.envp);

				var post_exec_session = yield device.attach (child.pid);
				post_exec_session.detached.connect (reason => {
					post_exec_detach_reason = reason.to_string ();
					if (waiting)
						run_exec_scenario.callback ();
				});
				var script = yield post_exec_session.create_script ("""
					Interceptor.attach(Module.getExportByName(null, 'puts'), {
					  onEnter(args) {
					    send(args[0].readUtf8String());
					  }
					});
					""");
				script.message.connect ((message, data) => {
					if (GLib.Test.verbose ())
						printerr ("Message: %s\n", message);
					messages.add (message);
					if (waiting)
						run_exec_scenario.callback ();
				});
				yield script.load ();

				yield device.resume (child.pid);

				while (messages.is_empty) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (messages.size == 1);
				assert_true (parse_string_message_payload (messages[0]) == method);

				while (post_exec_detach_reason == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (post_exec_detach_reason == "FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED");

				yield h.process_events ();
				assert_true (messages.size == 1);

				yield device_manager.close ();

				h.done ();
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}
		}

		public static async void run_bad_exec_scenario (Harness h, string target_path, string method) {
			try {
				var device_manager = new DeviceManager ();
				var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);

				string detach_reason = null;
				bool waiting = false;

				if (GLib.Test.verbose ()) {
					device.output.connect ((pid, fd, data) => {
						var chars = data.get_data ();
						var len = chars.length;
						if (len == 0) {
							printerr ("[pid=%u fd=%d EOF]\n", pid, fd);
							return;
						}

						var buf = new uint8[len + 1];
						Memory.copy (buf, chars, len);
						buf[len] = '\0';
						string message = (string) buf;

						printerr ("[pid=%u fd=%d OUTPUT] %s", pid, fd, message);
					});
				}
				device.child_added.connect (child => {
					assert_not_reached ();
				});

				var options = new SpawnOptions ();
				options.argv = { target_path, "spawn-bad-path", method };
				options.stdio = PIPE;
				var parent_pid = yield device.spawn (target_path, options);
				var parent_session = yield device.attach (parent_pid);
				parent_session.detached.connect (reason => {
					detach_reason = reason.to_string ();
					if (waiting)
						run_bad_exec_scenario.callback ();
				});
				yield parent_session.enable_child_gating ();

				yield device.resume (parent_pid);

				while (detach_reason == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (detach_reason == "FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED");

				yield device_manager.close ();

				h.done ();
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}
		}

		public static async void run_posix_spawn_scenario (Harness h, string target_path) {
			var method = "posix_spawn";

			try {
				var device_manager = new DeviceManager ();
				var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);

				string parent_detach_reason = null;
				string child_detach_reason = null;
				var child_messages = new Gee.ArrayList <string> ();
				Child the_child = null;
				bool waiting = false;

				if (GLib.Test.verbose ()) {
					device.output.connect ((pid, fd, data) => {
						var chars = data.get_data ();
						var len = chars.length;
						if (len == 0) {
							printerr ("[pid=%u fd=%d EOF]\n", pid, fd);
							return;
						}

						var buf = new uint8[len + 1];
						Memory.copy (buf, chars, len);
						buf[len] = '\0';
						string message = (string) buf;

						printerr ("[pid=%u fd=%d OUTPUT] %s", pid, fd, message);
					});
				}
				device.child_added.connect (child => {
					the_child = child;
					if (waiting)
						run_posix_spawn_scenario.callback ();
				});

				var options = new SpawnOptions ();
				options.argv = { target_path, "spawn", method };
				options.stdio = PIPE;
				var parent_pid = yield device.spawn (target_path, options);
				var parent_session = yield device.attach (parent_pid);
				parent_session.detached.connect (reason => {
					parent_detach_reason = reason.to_string ();
					if (waiting)
						run_posix_spawn_scenario.callback ();
				});
				yield parent_session.enable_child_gating ();

				yield device.resume (parent_pid);

				while (the_child == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				var child = the_child;
				the_child = null;
				assert_true (child.pid != parent_pid);
				assert_true (child.parent_pid == parent_pid);
				assert_true (child.origin == SPAWN);
				assert_null (child.identifier);
				assert_nonnull (child.path);
				assert_true (Path.get_basename (child.path).has_prefix ("spawner-"));
				assert_nonnull (child.argv);
				assert_nonnull (child.envp);

				assert_null (parent_detach_reason);

				var child_session = yield device.attach (child.pid);
				child_session.detached.connect (reason => {
					child_detach_reason = reason.to_string ();
					if (waiting)
						run_posix_spawn_scenario.callback ();
				});
				var script = yield child_session.create_script ("""
					Interceptor.attach(Module.getExportByName(null, 'puts'), {
					  onEnter(args) {
					    send(args[0].readUtf8String());
					  }
					});
					""");
				script.message.connect ((message, data) => {
					if (GLib.Test.verbose ())
						printerr ("Message from child: %s\n", message);
					child_messages.add (message);
					if (waiting)
						run_posix_spawn_scenario.callback ();
				});
				yield script.load ();

				yield device.resume (child.pid);

				while (child_messages.is_empty) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (child_messages.size == 1);
				assert_true (parse_string_message_payload (child_messages[0]) == method);

				while (child_detach_reason == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (child_detach_reason == "FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED");

				while (parent_detach_reason == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (parent_detach_reason == "FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED");

				yield h.process_events ();
				assert_true (child_messages.size == 1);

				yield device_manager.close ();

				h.done ();
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}
		}

	}
#endif

#if WINDOWS
	namespace Windows {

		private static async void backend (Harness h) {
			var backend = new WindowsHostSessionBackend ();

			var prov = yield h.setup_local_backend (backend);

			assert_true (prov.name == "Local System");

			Variant? icon = prov.icon;
			assert_nonnull (icon);
			var dict = new VariantDict (icon);
			int64 width, height;
			assert_true (dict.lookup ("width", "x", out width));
			assert_true (dict.lookup ("height", "x", out height));
			assert_true (width == 16);
			assert_true (height == 16);
			VariantIter image;
			assert_true (dict.lookup ("image", "ay", out image));
			assert_true (image.n_children () == width * height * 4);

			try {
				Cancellable? cancellable = null;

				var session = yield prov.create (null, cancellable);

				var processes = yield session.enumerate_processes (make_parameters_dict (), cancellable);
				assert_true (processes.length > 0);

				if (GLib.Test.verbose ()) {
					foreach (var process in processes)
						stdout.printf ("pid=%u name='%s'\n", process.pid, process.name);
				}
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			yield h.teardown_backend (backend);

			h.done ();
		}

		private static async void spawn (Harness h) {
			var backend = new WindowsHostSessionBackend ();

			var prov = yield h.setup_local_backend (backend);

			try {
				Cancellable? cancellable = null;

				var host_session = yield prov.create (null, cancellable);

				uint pid = 0;
				bool waiting = false;

				string received_output = null;
				var output_handler = host_session.output.connect ((source_pid, fd, data) => {
					assert_true (source_pid == pid);
					assert_true (fd == 1);

					var buf = new uint8[data.length + 1];
					Memory.copy (buf, data, data.length);
					buf[data.length] = '\0';
					char * chars = buf;
					received_output = (string) chars;

					if (waiting)
						spawn.callback ();
				});

				var options = HostSpawnOptions ();
				options.stdio = PIPE;
				pid = yield host_session.spawn (Frida.Test.Labrats.path_to_executable ("sleeper"), options, cancellable);

				var session_id = yield host_session.attach (pid, make_parameters_dict (), cancellable);
				var session = yield prov.link_agent_session (host_session, session_id, h, cancellable);

				string received_message = null;
				var message_handler = h.message_from_script.connect ((script_id, json, data) => {
					received_message = json;
					if (waiting)
						spawn.callback ();
				});

				var script_id = yield session.create_script ("""
					const STD_OUTPUT_HANDLE = -11;
					const winAbi = (Process.pointerSize === 4) ? 'stdcall' : 'win64';
					const GetStdHandle = new NativeFunction(Module.getExportByName('kernel32.dll', 'GetStdHandle'), 'pointer', ['int'], winAbi);
					const WriteFile = new NativeFunction(Module.getExportByName('kernel32.dll', 'WriteFile'), 'int', ['pointer', 'pointer', 'uint', 'pointer', 'pointer'], winAbi);
					const stdout = GetStdHandle(STD_OUTPUT_HANDLE);
					const message = Memory.allocUtf8String('Hello stdout');
					const success = WriteFile(stdout, message, 12, NULL, NULL);
					Interceptor.attach(Module.getExportByName('user32.dll', 'GetMessageW'), {
					  onEnter(args) {
					    send('GetMessage');
					  }
					});
					""", make_parameters_dict (), cancellable);
				yield session.load_script (script_id, cancellable);

				if (received_output == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (received_output == "Hello stdout");
				host_session.disconnect (output_handler);

				yield host_session.resume (pid, cancellable);

				if (received_message == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (received_message == "{\"type\":\"send\",\"payload\":\"GetMessage\"}");
				h.disconnect (message_handler);

				yield host_session.kill (pid, cancellable);
			} catch (GLib.Error e) {
				printerr ("Unexpected error: %s\n", e.message);
				assert_not_reached ();
			}

			yield h.teardown_backend (backend);

			h.done ();
		}

		private static async void create_process (Harness h) {
			if (sizeof (void *) == 8 && !GLib.Test.slow ()) {
				stdout.printf ("<skipping due to pending 64-bit issue, run in slow mode> ");
				h.done ();
				return;
			}

			var target_path = Frida.Test.Labrats.path_to_executable ("spawner");
			var method = "CreateProcess";

			try {
				var device_manager = new DeviceManager ();
				var device = yield device_manager.get_device_by_type (DeviceType.LOCAL);

				string parent_detach_reason = null;
				string child_detach_reason = null;
				var child_messages = new Gee.ArrayList <string> ();
				Child the_child = null;
				bool waiting = false;

				if (GLib.Test.verbose ()) {
					device.output.connect ((pid, fd, data) => {
						var chars = data.get_data ();
						var len = chars.length;
						if (len == 0) {
							printerr ("[pid=%u fd=%d EOF]\n", pid, fd);
							return;
						}

						var buf = new uint8[len + 1];
						Memory.copy (buf, chars, len);
						buf[len] = '\0';
						string message = (string) buf;

						printerr ("[pid=%u fd=%d OUTPUT] %s", pid, fd, message);
					});
				}
				device.child_added.connect (child => {
					the_child = child;
					if (waiting)
						create_process.callback ();
				});

				var options = new SpawnOptions ();
				options.argv = { target_path, "spawn", method };
				options.stdio = PIPE;
				var parent_pid = yield device.spawn (target_path, options);
				var parent_session = yield device.attach (parent_pid);
				parent_session.detached.connect (reason => {
					parent_detach_reason = reason.to_string ();
					if (waiting)
						create_process.callback ();
				});
				yield parent_session.enable_child_gating ();

				yield device.resume (parent_pid);

				while (the_child == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				var child = the_child;
				the_child = null;
				assert_true (child.pid != parent_pid);
				assert_true (child.parent_pid == parent_pid);
				assert_true (child.origin == SPAWN);
				assert_null (child.identifier);
				assert_nonnull (child.path);
				assert_true (Path.get_basename (child.path).has_prefix ("spawner-"));
				assert_nonnull (child.argv);
				assert_null (child.envp);

				assert_null (parent_detach_reason);

				var child_session = yield device.attach (child.pid);
				child_session.detached.connect (reason => {
					child_detach_reason = reason.to_string ();
					if (waiting)
						create_process.callback ();
				});
				var script = yield child_session.create_script ("""
					Interceptor.attach(Module.getExportByName('kernel32.dll', 'OutputDebugStringW'), {
					  onEnter(args) {
					    send(args[0].readUtf16String());
					  }
					});
					""");
				script.message.connect ((message, data) => {
					if (GLib.Test.verbose ())
						printerr ("Message from child: %s\n", message);
					child_messages.add (message);
					if (waiting)
						create_process.callback ();
				});
				yield script.load ();

				yield device.resume (child.pid);

				while (child_messages.is_empty) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (child_messages.size == 1);
				assert_true (parse_string_message_payload (child_messages[0]) == method);

				while (child_detach_reason == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (child_detach_reason == "FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED");

				while (parent_detach_reason == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				assert_true (parent_detach_reason == "FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED");

				yield h.process_events ();
				assert_true (child_messages.size == 1);

				yield device_manager.close ();

				h.done ();
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}
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

			var prov = yield h.setup_remote_backend (backend);

#if WINDOWS
			assert_true (prov.name != "iOS Device"); /* should manage to extract a user-defined name */
#endif

			Variant? icon = prov.icon;
			assert_nonnull (icon);
			var dict = new VariantDict (icon);
			int64 width, height;
			assert_true (dict.lookup ("width", "x", out width));
			assert_true (dict.lookup ("height", "x", out height));
			assert_true (width == 16);
			assert_true (height == 16);
			VariantIter image;
			assert_true (dict.lookup ("image", "ay", out image));
			assert_true (image.n_children () == width * height * 4);

			try {
				Cancellable? cancellable = null;

				var session = yield prov.create (null, cancellable);
				var processes = yield session.enumerate_processes (make_parameters_dict (), cancellable);
				assert_true (processes.length > 0);

				if (GLib.Test.verbose ()) {
					foreach (var process in processes)
						stdout.printf ("pid=%u name='%s'\n", process.pid, process.name);
				}
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}

			yield h.teardown_backend (backend);

			h.done ();
		}

		private static async void large_messages (Harness h) {
			if (!GLib.Test.slow ()) {
				stdout.printf ("<skipping, run in slow mode with iOS device connected> ");
				h.done ();
				return;
			}

			var backend = new FruityHostSessionBackend ();

			var prov = yield h.setup_remote_backend (backend);

			try {
				Cancellable? cancellable = null;

				stdout.printf ("connecting to frida-server\n");
				var host_session = yield prov.create (null, cancellable);
				stdout.printf ("enumerating processes\n");
				var processes = yield host_session.enumerate_processes (make_parameters_dict (), cancellable);
				assert_true (processes.length > 0);

				HostProcessInfo? process = null;
				foreach (var p in processes) {
					if (p.name == "hello-frida") {
						process = p;
						break;
					}
				}
				assert_nonnull ((void *) process);

				stdout.printf ("attaching to target process\n");
				var session_id = yield host_session.attach (process.pid, make_parameters_dict (), cancellable);
				var session = yield prov.link_agent_session (host_session, session_id, h, cancellable);
				string received_message = null;
				var message_handler = h.message_from_script.connect ((script_id, json, data) => {
					received_message = json;
					large_messages.callback ();
				});
				stdout.printf ("creating script\n");
				var script_id = yield session.create_script ("""
					function onMessage(message) {
					  send('ACK: ' + message.length);
					  recv(onMessage);
					}
					recv(onMessage);
					""", make_parameters_dict (), cancellable);
				stdout.printf ("loading script\n");
				yield session.load_script (script_id, cancellable);
				var steps = new uint[] { 1024, 4096, 8192, 16384, 32768 };
				var transport_overhead = 163;
				foreach (var step in steps) {
					var builder = new StringBuilder ();
					builder.append ("\"");
					for (var i = 0; i != step - transport_overhead; i++) {
						builder.append ("s");
					}
					builder.append ("\"");
					yield session.post_messages ({ AgentMessage (SCRIPT, script_id, builder.str, false, {}) }, 0,
						cancellable);
					yield;
					stdout.printf ("received message: '%s'\n", received_message);
				}
				h.disconnect (message_handler);

				yield session.destroy_script (script_id, cancellable);
				yield session.close (cancellable);
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}

			yield h.teardown_backend (backend);

			h.done ();
		}

		namespace Manual {

			private static async void lockdown (Harness h) {
				if (!GLib.Test.slow ()) {
					stdout.printf ("<skipping, run in slow mode with iOS device connected> ");
					h.done ();
					return;
				}

				h.disable_timeout ();

				var device_id = "<device-id>";
				var app_id = "<app-id>";
				string? target_name = null;
				uint target_pid = 0;

				var device_manager = new DeviceManager ();

				try {
					var device = yield device_manager.get_device_by_id (device_id);

					device.output.connect ((pid, fd, data) => {
						var chars = data.get_data ();
						var len = chars.length;
						if (len == 0) {
							printerr ("[pid=%u fd=%d EOF]\n", pid, fd);
							return;
						}

						var buf = new uint8[len + 1];
						Memory.copy (buf, chars, len);
						buf[len] = '\0';
						string message = (string) buf;

						printerr ("[pid=%u fd=%d OUTPUT] %s", pid, fd, message);
					});

					var timer = new Timer ();

					printerr ("device.enumerate_applications()");
					timer.reset ();
					var apps = yield device.enumerate_applications ();
					printerr (" => got %d apps, took %u ms\n", apps.size (), (uint) (timer.elapsed () * 1000.0));
					if (GLib.Test.verbose ()) {
						var length = apps.size ();
						for (int i = 0; i != length; i++) {
							var app = apps.get (i);
							printerr ("\t%s\n", app.identifier);
						}
					}

					if (target_name != null) {
						timer.reset ();
						var process = yield device.get_process_by_name (target_name);
						target_pid = process.pid;
						printerr (" => resolved to pid=%u, took %u ms\n", target_pid, (uint) (timer.elapsed () * 1000.0));
					}

					uint pid;
					if (target_pid != 0) {
						pid = target_pid;
					} else {
						printerr ("device.spawn()");
						timer.reset ();
						pid = yield device.spawn (app_id);
						printerr (" => pid=%u, took %u ms\n", pid, (uint) (timer.elapsed () * 1000.0));
					}

					printerr ("device.attach(pid=%u)", pid);
					timer.reset ();
					var session = yield device.attach (pid);
					printerr (" => took %u ms\n", (uint) (timer.elapsed () * 1000.0));

					printerr ("session.create_script()");
					timer.reset ();
					var script = yield session.create_script ("""
						send(Module.getExportByName(null, 'open'));
						""");
					printerr (" => took %u ms\n", (uint) (timer.elapsed () * 1000.0));

					string received_message = null;
					bool waiting = false;
					script.message.connect ((message, data) => {
						received_message = message;
						if (waiting)
							lockdown.callback ();
					});

					printerr ("script.load()");
					timer.reset ();
					yield script.load ();
					printerr (" => took %u ms\n", (uint) (timer.elapsed () * 1000.0));

					printerr ("await_message()");
					while (received_message == null) {
						waiting = true;
						yield;
						waiting = false;
					}
					printerr (" => received_message: %s\n", received_message);
					received_message = null;

					if (target_pid == 0) {
						printerr ("device.resume(pid=%u)", pid);
						timer.reset ();
						yield device.resume (pid);
						printerr (" => took %u ms\n", (uint) (timer.elapsed () * 1000.0));
					}

					yield h.prompt_for_key ("Hit a key to exit: ");
				} catch (GLib.Error e) {
					printerr ("\nFAIL: %s\n\n", e.message);
				}

				h.done ();
			}

		}

		namespace Plist {

			private static void can_construct_from_xml_document () {
				var xml = """
					<?xml version="1.0" encoding="UTF-8"?>
					<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
					<plist version="1.0">
					<dict>
						<key>DeviceID</key>
						<integer>2</integer>
						<key>MessageType</key>
						<string>Attached</string>
						<key>Properties</key>
						<dict>
							<key>ConnectionType</key>
							<string>USB</string>
							<key>DeviceID</key>
							<integer>2</integer>
							<key>LocationID</key>
							<integer>0</integer>
							<key>ProductID</key>
							<integer>4759</integer>
							<key>SerialNumber</key>
							<string>220f889780dda462091a65df48b9b6aedb05490f</string>
							<key>ExtraBoolTrue</key>
							<true/>
							<key>ExtraBoolFalse</key>
							<false/>
							<key>ExtraData</key>
							<data>AQID</data>
							<key>ExtraStrings</key>
							<array>
								<string>A</string>
								<string>B</string>
							</array>
						</dict>
					</dict>
					</plist>
				""";

				try {
					var plist = new Frida.Fruity.Plist.from_xml (xml);
					assert_true (plist.size == 3);
					assert_true (plist.get_integer ("DeviceID") == 2);
					assert_true (plist.get_string ("MessageType") == "Attached");

					var properties = plist.get_dict ("Properties");
					assert_true (properties.size == 9);
					assert_true (properties.get_string ("ConnectionType") == "USB");
					assert_true (properties.get_integer ("DeviceID") == 2);
					assert_true (properties.get_integer ("LocationID") == 0);
					assert_true (properties.get_integer ("ProductID") == 4759);
					assert_true (properties.get_string ("SerialNumber") == "220f889780dda462091a65df48b9b6aedb05490f");

					assert_true (properties.get_boolean ("ExtraBoolTrue") == true);
					assert_true (properties.get_boolean ("ExtraBoolFalse") == false);

					var extra_data = properties.get_bytes ("ExtraData");
					assert_true (extra_data.length == 3);
					assert_true (extra_data[0] == 0x01);
					assert_true (extra_data[1] == 0x02);
					assert_true (extra_data[2] == 0x03);

					var extra_strings = properties.get_array ("ExtraStrings");
					assert_true (extra_strings.length == 2);
					assert_true (extra_strings.get_string (0) == "A");
					assert_true (extra_strings.get_string (1) == "B");
				} catch (Frida.Fruity.PlistError e) {
					printerr ("%s\n", e.message);
					assert_not_reached ();
				}
			}

			private static void to_xml_yields_complete_document () {
				var plist = new Frida.Fruity.Plist ();
				plist.set_string ("MessageType", "Detached");
				plist.set_integer ("DeviceID", 2);

				var properties = new Frida.Fruity.PlistDict ();
				properties.set_string ("ConnectionType", "USB");
				properties.set_integer ("DeviceID", 2);
				properties.set_boolean ("ExtraBoolTrue", true);
				properties.set_boolean ("ExtraBoolFalse", false);
				properties.set_bytes ("ExtraData", new Bytes ({ 0x01, 0x02, 0x03 }));
				var extra_strings = new Frida.Fruity.PlistArray ();
				extra_strings.add_string ("A");
				extra_strings.add_string ("B");
				properties.set_array ("ExtraStrings", extra_strings);
				plist.set_dict ("Properties", properties);

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
					"		<key>ExtraBoolFalse</key>\n" +
					"		<false/>\n" +
					"		<key>ExtraBoolTrue</key>\n" +
					"		<true/>\n" +
					"		<key>ExtraData</key>\n" +
					"		<data>AQID</data>\n" +
					"		<key>ExtraStrings</key>\n" +
					"		<array>\n" +
					"			<string>A</string>\n" +
					"			<string>B</string>\n" +
					"		</array>\n" +
					"	</dict>\n" +
					"</dict>\n" +
					"</plist>\n";
				assert_true (actual_xml == expected_xml);
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

			var prov = yield h.setup_remote_backend (backend);

			assert_true (prov.name != "Android Device");

			Variant? icon = prov.icon;
			assert_nonnull (icon);
			var dict = new VariantDict (icon);
			int64 width, height;
			assert_true (dict.lookup ("width", "x", out width));
			assert_true (dict.lookup ("height", "x", out height));
			assert_true (width == 16);
			assert_true (height == 16);
			VariantIter image;
			assert_true (dict.lookup ("image", "ay", out image));
			assert_true (image.n_children () == width * height * 4);

			try {
				Cancellable? cancellable = null;

				var session = yield prov.create (null, cancellable);
				var processes = yield session.enumerate_processes (make_parameters_dict (), cancellable);
				assert_true (processes.length > 0);

				if (GLib.Test.verbose ()) {
					foreach (var process in processes)
						stdout.printf ("pid=%u name='%s'\n", process.pid, process.name);
				}
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}

			yield h.teardown_backend (backend);

			h.done ();
		}

		private static async void injector (Harness h) {
			if (!GLib.Test.slow ()) {
				stdout.printf ("<skipping, run in slow mode with Android device connected> ");
				h.done ();
				return;
			}

			string device_serial = "<device-serial>";
			string debuggable_app = "<app-id>";
			string gadget_path = "/path/to/frida-gadget-arm64.so";
			Cancellable? cancellable = null;

			try {
				var gadget_file = File.new_for_path (gadget_path);
				InputStream gadget = yield gadget_file.read_async (Priority.DEFAULT, cancellable);

				var details = yield Frida.Droidy.Injector.inject (gadget, debuggable_app, device_serial, cancellable);

				printerr ("inject() => %p\n", details);
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
			}

			h.done ();
		}
	}

	private static string parse_string_message_payload (string json) {
		Json.Object message;
		try {
			message = Json.from_string (json).get_object ();
		} catch (GLib.Error e) {
			assert_not_reached ();
		}

		assert_true (message.get_string_member ("type") == "send");

		return message.get_string_member ("payload");
	}

	public class Harness : Frida.Test.AsyncHarness, AgentMessageSink {
		public signal void message_from_script (AgentScriptId script_id, string message, Bytes? data);

		public HostSessionService service {
			get;
			private set;
		}

		private uint timeout = 90;

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
				assert_true (available_providers.add (provider));
			});
			service.provider_unavailable.connect ((provider) => {
				assert_true (available_providers.remove (provider));
			});
		}

		protected override uint provide_timeout () {
			return timeout;
		}

		public async HostSessionProvider setup_local_backend (HostSessionBackend backend) {
			yield add_backend_and_start (backend);

			yield process_events ();
			assert_n_providers_available (1);

			return first_provider ();
		}

		public async HostSessionProvider setup_remote_backend (HostSessionBackend backend) {
			yield add_backend_and_start (backend);

			disable_timeout ();
			yield wait_for_provider ();

			return first_provider ();
		}

		private async void add_backend_and_start (HostSessionBackend backend) {
			service.add_backend (backend);

			try {
				yield service.start ();
			} catch (IOError e) {
				assert_not_reached ();
			}
		}

		public async void teardown_backend (HostSessionBackend backend) {
			try {
				yield service.stop ();
			} catch (IOError e) {
				assert_not_reached ();
			}

			service.remove_backend (backend);
		}

		public async void wait_for_provider () {
			while (available_providers.is_empty) {
				yield process_events ();
			}
		}

		public void assert_no_providers_available () {
			assert_true (available_providers.is_empty);
		}

		public void assert_n_providers_available (int n) {
			assert_true (available_providers.size == n);
		}

		public HostSessionProvider first_provider () {
			assert_true (available_providers.size >= 1);
			return available_providers[0];
		}

		public async char prompt_for_key (string message) {
			char key = 0;

			var done = false;

			new Thread<bool> ("input-worker", () => {
				stdout.printf ("%s", message);
				stdout.flush ();

				key = (char) stdin.getc ();

				Idle.add (() => {
					done = true;
					return false;
				});

				return true;
			});

			while (!done)
				yield process_events ();

			return key;
		}

		protected async void post_messages (AgentMessage[] messages, uint batch_id,
				Cancellable? cancellable) throws Error, IOError {
			foreach (var m in messages) {
				message_from_script (m.script_id, m.text, m.has_data ? new Bytes (m.data) : null);
			}
		}
	}
}
