namespace Frida.InjectorTest {
	public static void add_tests () {
		GLib.Test.add_func ("/Injector/inject-current-arch", () => {
			test_injection (Frida.Test.Arch.CURRENT);
		});

		GLib.Test.add_func ("/Injector/inject-other-arch", () => {
			test_injection (Frida.Test.Arch.OTHER);
		});

		GLib.Test.add_func ("/Injector/resource-leaks", test_resource_leaks);
	}

	private static void test_injection (Frida.Test.Arch arch) {
		var logfile = File.new_for_path (Frida.Test.path_to_temporary_file ("test-injection.log"));
		try {
			logfile.delete ();
		} catch (GLib.Error delete_error) {
		}
		var envp = new string[] {
			"FRIDA_LABRAT_LOGFILE=" + logfile.get_path ()
		};

		var rat = new Labrat ("sleeper", envp, arch);

		if (Frida.Test.os () == Frida.Test.OS.LINUX || Frida.Test.os () == Frida.Test.OS.QNX) {
			/* TODO: improve injector to handle injection into a process that hasn't yet finished initializing */
			Thread.usleep (50000);
		}

		rat.inject ("simple-agent", "", arch);
		rat.wait_for_uninject ();

		if (Frida.Test.os () != Frida.Test.OS.WINDOWS) {
			/* TODO: improve simple-agent-windows.c */
			assert (content_of (logfile) == ">m<");
		}

		var requested_exit_code = 43;
		rat.inject ("simple-agent", requested_exit_code.to_string (), arch);
		rat.wait_for_uninject ();

		switch (Frida.Test.os ()) {
			case Frida.Test.OS.WINDOWS:
				break;
			case Frida.Test.OS.MACOS: /* using Mapper */
			case Frida.Test.OS.ANDROID:
				assert (content_of (logfile) == ">m<>m");
				break;
			case Frida.Test.OS.LINUX:
				if (Frida.Test.libc () == Frida.Test.Libc.UCLIBC) {
					assert (content_of (logfile) == ">m<>m");
				} else {
					assert (content_of (logfile) == ">m<>m<");
				}
				break;
			default:
				assert (content_of (logfile) == ">m<>m<");
				break;
		}

		var exit_code = rat.wait_for_process_to_exit ();
		assert (exit_code == requested_exit_code);

		try {
			logfile.delete ();
		} catch (GLib.Error delete_error) {
			assert_not_reached ();
		}

		rat.close ();
	}

	private static void test_resource_leaks () {
		var logfile = File.new_for_path (Frida.Test.path_to_temporary_file ("test-leaks.log"));
		var envp = new string[] {
			"FRIDA_LABRAT_LOGFILE=" + logfile.get_path ()
		};

		var rat = new Labrat ("sleeper", envp);

		if (Frida.Test.os () == Frida.Test.OS.LINUX || Frida.Test.os () == Frida.Test.OS.QNX) {
			/* TODO: improve injector to handle injection into a process that hasn't yet finished initializing */
			Thread.usleep (50000);
		}

		/* Warm up static allocations */
		rat.inject ("simple-agent", "");
		rat.wait_for_uninject ();

		var usage_before = rat.process.snapshot_resource_usage ();

		rat.inject ("simple-agent", "");
		rat.wait_for_uninject ();

		var usage_after = rat.process.snapshot_resource_usage ();

		usage_after.assert_equals (usage_before);

		rat.inject ("simple-agent", "0");
		rat.wait_for_uninject ();
		rat.wait_for_process_to_exit ();

		rat.close ();
	}

	private static string content_of (File file) {
		try {
			uint8[] contents;
			file.load_contents (null, out contents, null);
			unowned string str = (string) contents;
			return str;
		} catch (GLib.Error load_error) {
			stderr.printf ("%s: %s\n", file.get_path (), load_error.message);
			assert_not_reached ();
		}
	}

	private class Labrat {
		public Frida.Test.Process process {
			get;
			private set;
		}

		private Injector injector;

		public Labrat (string name, string[] envp, Frida.Test.Arch arch = Frida.Test.Arch.CURRENT) {
			try {
				process = Frida.Test.Process.start (Frida.Test.Labrats.path_to_executable (name), null, envp, arch);
			} catch (Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}
		}

		public void close () {
			var loop = new MainLoop ();
			Idle.add (() => {
				do_close.begin (loop);
				return false;
			});
			loop.run ();
		}

		private async void do_close (MainLoop loop) {
			injector = null;

			/* Queue an idle handler, allowing MainContext to perform any outstanding completions, in turn cleaning up resources */
			Idle.add (() => {
				loop.quit ();
				return false;
			});
		}

		public void inject (string name, string data, Frida.Test.Arch arch = Frida.Test.Arch.CURRENT) {
			var loop = new MainLoop ();
			Idle.add (() => {
				perform_injection.begin (name, data, arch, loop);
				return false;
			});
			loop.run ();
		}

		private async void perform_injection (string name, string data, Frida.Test.Arch arch, MainLoop loop) {
			if (injector == null)
				injector = Injector.new ();

			try {
				var path = Frida.Test.Labrats.path_to_library (name, arch);
				assert (FileUtils.test (path, FileTest.EXISTS));

				yield injector.inject_library_file (process.id, path, "frida_agent_main", data);
			} catch (Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}

			loop.quit ();
		}

		public void wait_for_uninject () {
			var loop = new MainLoop ();

			var handler_id = injector.uninjected.connect ((id) => {
				loop.quit ();
			});

			var timed_out = false;
			var timeout_id = Timeout.add_seconds (1, () => {
				timed_out = true;
				loop.quit ();
				return false;
			});

			loop.run ();

			assert (!timed_out);
			Source.remove (timeout_id);
			injector.disconnect (handler_id);
		}

		public int wait_for_process_to_exit () {
			int exitcode = -1;

			try {
				exitcode = process.join (1000);
			} catch (Error e) {
				stdout.printf ("\n\nunexpected error: %s\n", e.message);
				assert_not_reached ();
			}

			return exitcode;
		}
	}
}
