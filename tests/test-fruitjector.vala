#if DARWIN
namespace Frida.FruitjectorTest {
	public static void add_tests () {
		GLib.Test.add_func ("/Fruitjector/inject-current-arch", () => {
			test_injection (Frida.Test.Arch.CURRENT);
		});

		GLib.Test.add_func ("/Fruitjector/inject-other-arch", () => {
			if (sizeof (void *) != 8) {
				stdout.printf ("<64-bit only> ");
				return;
			}

			test_injection (Frida.Test.Arch.OTHER);
		});
	}

	private static void test_injection (Frida.Test.Arch arch) {
		var tests_dir = Path.get_dirname (Frida.Test.Process.current.filename);

		var logfile = File.new_for_path (Path.build_filename (tests_dir, "unixattacker.log"));
		try {
			logfile.delete ();
		} catch (GLib.Error delete_error) {
		}
		var envp = new string[] {
			"FRIDA_LABRAT_LOGFILE=" + logfile.get_path ()
		};

		var rat = new LabRat (tests_dir, "unixvictim", envp, arch);

		rat.inject ("unixattacker", "");
		rat.wait_for_uninject ();

		assert (content_of (logfile) == ">m<");

		var requested_exit_code = 43;
		rat.inject ("unixattacker", requested_exit_code.to_string ());
		rat.wait_for_uninject ();

		assert (content_of (logfile) == ">m<>m");

		var exit_code = rat.wait_for_process_to_exit ();
		assert (exit_code == requested_exit_code);

		try {
			logfile.delete ();
		} catch (GLib.Error delete_error) {
			assert_not_reached ();
		}

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

	private class LabRat {
		public Frida.Test.Process process {
			get;
			private set;
		}

		private string data_directory;
		private Fruitjector injector;

		public LabRat (string dir, string name, string[] envp, Frida.Test.Arch arch) {
			data_directory = Path.build_filename (dir, "data");
			var rat_file = Path.build_filename (data_directory, name + os_suffix ());

			var argv = new string[] {
				rat_file
			};

			try {
				process = Frida.Test.Process.start (rat_file, argv, envp, arch);
			} catch (Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}
		}

		private static string os_suffix () {
			switch (Frida.Test.os ()) {
				case Frida.Test.OS.MAC:
					return "-mac";
				case Frida.Test.OS.IOS:
					return "-ios";
				default:
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
			if (injector != null) {
				yield injector.close ();
				injector = null;
			}

			/* Queue an idle handler, allowing MainContext to perform any outstanding completions, in turn cleaning up resources */
			Idle.add (() => {
				loop.quit ();
				return false;
			});
		}

		public void inject (string name, string data_string) {
			var loop = new MainLoop ();
			Idle.add (() => {
				do_injection.begin (name, data_string, loop);
				return false;
			});
			loop.run ();
		}

		private async void do_injection (string name, string data_string, MainLoop loop) {
			if (injector == null)
				injector = new Fruitjector ();

			try {
				var dylib = Path.build_filename (data_directory, name + os_suffix () + ".dylib");
				assert (FileUtils.test (dylib, FileTest.EXISTS));

				AgentResource agent;

				try {
					agent = new AgentResource (name, File.new_for_path (dylib).read (null));
				} catch (GLib.Error file_error) {
					assert_not_reached ();
				}

				yield injector.inject (process.id, agent, data_string);
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
#endif
