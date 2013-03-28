namespace Zed.FruitjectorTest {
	public static void add_tests () {
		GLib.Test.add_func ("/Fruitjector/inject", () => {
			var tests_dir = Path.get_dirname (Zed.Test.Process.current.filename);

			var logfile = File.new_for_path (Path.build_filename (tests_dir, "inject-attacker.log"));

			try {
				logfile.delete ();
			} catch (Error delete_error) {
			}

			var rat = new LabRat (tests_dir, "inject-victim", logfile.get_path ());

			rat.inject ("libinject-attacker.dylib", "");
			rat.wait_for_uninject ();

			assert (content_of (logfile) == ">m<");

			var requested_exit_code = 43;
			rat.inject ("libinject-attacker.dylib", requested_exit_code.to_string ());
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
		public Zed.Test.Process process {
			get;
			private set;
		}

		private MainContext main_context;
		private string rat_directory;
		private Fruitjector injector;

		public LabRat (string dir, string name, string logfile) {
			main_context = new MainContext ();
			main_context.push_thread_default ();

			rat_directory = dir;
			var rat_file = Path.build_filename (rat_directory, name);

			Environment.set_variable ("ZED_LABRAT_LOGFILE", logfile, true);

			try {
				process = Zed.Test.Process.start (rat_file);
			} catch (IOError e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}
		}

		~LabRat () {
			main_context.pop_thread_default ();
		}

		public void inject (string name, string data_string) {
			var loop = new MainLoop (main_context);
			var source = new IdleSource ();
			source.set_callback (() => {
				do_injection (name, data_string, loop);
				return false;
			});
			source.attach (main_context);
			loop.run ();
		}

		private async void do_injection (string name, string data_string, MainLoop loop) {
			if (injector == null)
				injector = new Fruitjector ();

			try {
				var dylib = Path.build_filename (rat_directory, name);
				if (!FileUtils.test (dylib, FileTest.EXISTS))
					dylib = Path.build_filename (rat_directory, ".libs", name);
				assert (FileUtils.test (dylib, FileTest.EXISTS));

				AgentDescriptor desc;

				try {
					desc = new AgentDescriptor (name, File.new_for_path (dylib).read (null));
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
			var loop = new MainLoop (main_context);

			var handler_id = injector.uninjected.connect ((id) => {
				loop.quit ();
			});

			var timed_out = false;
			var timeout = new TimeoutSource.seconds (1);
			timeout.set_callback (() => {
				timed_out = true;
				loop.quit ();
				return false;
			});
			timeout.attach (main_context);

			loop.run ();

			assert (!timed_out);
			timeout.destroy ();
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