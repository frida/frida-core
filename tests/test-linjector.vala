#if LINUX
namespace Frida.LinjectorTest {
	public static void add_tests () {
		GLib.Test.add_func ("/Linjector/inject", () => {
			var tests_dir = Path.get_dirname (Frida.Test.Process.current.filename);

			var logfile = File.new_for_path (Path.build_filename (tests_dir, "inject-attacker.log"));

			try {
				logfile.delete ();
			} catch (Error delete_error) {
			}

			var rat = new LabRat (tests_dir, "inject-victim", logfile.get_path ());

			rat.inject ("libinject-attacker.so", "");
			rat.wait_for_uninject ();

			assert (content_of (logfile) == ">m<");

			var requested_exit_code = 43;
			rat.inject ("libinject-attacker.so", requested_exit_code.to_string ());
			rat.wait_for_uninject ();

			assert (content_of (logfile) == ">m<>m<");

			var exit_code = rat.wait_for_process_to_exit ();
			assert (exit_code == requested_exit_code);

			try {
				logfile.delete ();
			} catch (Error delete_error) {
				assert_not_reached ();
			}
		});
	}

	private static string content_of (File file) {
		try {
			uint8[] contents;
			file.load_contents (null, out contents);
			unowned string str = (string) contents;
			return str;
		} catch (Error load_error) {
			stderr.printf ("%s: %s\n", file.get_path (), load_error.message);
			assert_not_reached ();
		}
	}

	private class LabRat {
		public Frida.Test.Process process {
			get;
			private set;
		}

		private string rat_directory;
		private Linjector injector;

		public LabRat (string dir, string name, string logfile) {
			rat_directory = dir;
			var rat_file = Path.build_filename (rat_directory, name);

			Environment.set_variable ("FRIDA_LABRAT_LOGFILE", logfile, true);

			try {
				process = Frida.Test.Process.start (rat_file);
			} catch (IOError e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}
		}

		public void inject (string name, string data_string) {
			var loop = new MainLoop ();
			Idle.add (() => {
				do_injection (name, data_string, loop);
				return false;
			});
			loop.run ();
		}

		private async void do_injection (string name, string data_string, MainLoop loop) {
			if (injector == null)
				injector = new Linjector ();

			try {
				var sofile = Path.build_filename (rat_directory, name);
				if (!FileUtils.test (sofile, FileTest.EXISTS))
					sofile = Path.build_filename (rat_directory, ".libs", name);
				assert (FileUtils.test (sofile, FileTest.EXISTS));

				AgentDescriptor desc;

				try {
					desc = new AgentDescriptor (name, File.new_for_path (sofile).read (null));
				} catch (Error io_error) {
					assert_not_reached ();
				}

				yield injector.inject (process.id, desc, data_string);
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
			} catch (IOError e) {
				stdout.printf ("\n\nunexpected error: %s\n", e.message);
				assert_not_reached ();
			}

			return exitcode;
		}
	}
}
#endif
