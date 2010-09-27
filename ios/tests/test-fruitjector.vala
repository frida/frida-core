namespace Zid.FruitjectorTest {
	public static void add_tests () {
		GLib.Test.add_func ("/Fruitjector/inject", () => {
			var logfile = File.new_for_path (Path.build_filename (Config.PKGTESTDIR, "inject-attacker.log"));

			try {
				logfile.delete ();
			} catch (Error delete_error) {
			}

			var rat = new LabRat ("inject-victim");

			rat.inject ("inject-attacker.dylib", "");
			rat.wait_for_uninject ();

			try {
				string log_of_first_injection;
				logfile.load_contents (null, out log_of_first_injection);
				assert (log_of_first_injection == ">m<");
			} catch (Error first_load_error) {
				assert_not_reached ();
			}

			var requested_exit_code = 43;
			rat.inject ("inject-attacker.dylib", requested_exit_code.to_string ());
			rat.wait_for_uninject ();

			try {
				string log_of_second_injection;
				logfile.load_contents (null, out log_of_second_injection);
				assert (log_of_second_injection == ">m<>m<");
			} catch (Error second_load_error) {
				assert_not_reached ();
			}

			var exit_code = rat.wait_for_process_to_exit ();
			assert (exit_code == requested_exit_code);

			try {
				logfile.delete ();
			} catch (Error delete_error) {
				assert_not_reached ();
			}
		});
	}

	private class LabRat {
		public Zid.Test.Process process {
			get;
			private set;
		}

		private MainContext main_context;
		private string rat_directory;
		private Fruitjector injector;

		public LabRat (string name) {
			main_context = new MainContext ();
			main_context.push_thread_default ();

			rat_directory = Config.PKGTESTDIR;
			var rat_file = Path.build_filename (rat_directory, name);

			try {
				process = Zid.Test.Process.start (rat_file);
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
				yield injector.inject (process.id, dylib, data_string);
			} catch (IOError e) {
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
			bool wait_for_exit_timed_out = false;

			try {
				exitcode = process.join (1000);
			} catch (IOError e) {
				var timed_out_error = new IOError.TIMED_OUT ("");
				if (e.code == timed_out_error.code)
					wait_for_exit_timed_out = true;
				else
					assert_not_reached ();
			}

			assert (!wait_for_exit_timed_out);

			return exitcode;
		}
	}
}
