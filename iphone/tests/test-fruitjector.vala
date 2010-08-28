namespace Zid.FruitjectorTest {
	public static void add_tests () {
		GLib.Test.add_func ("/Fruitjector/inject", () => {
			var rat = new LabRat ("inject-victim");
			Thread.usleep (10000); /* give it 10 ms to settle */
			rat.inject ("inject-attacker.dylib");
			var exit_code = rat.wait_for_process_to_exit ();
			assert (exit_code == 42);
		});
	}

	private class LabRat {
		public Zid.Test.Process process {
			get;
			private set;
		}

		private string rat_directory;
		private Fruitjector injector;

		public LabRat (string name) {
			rat_directory = Config.PKGTESTDIR;
			var rat_file = Path.build_filename (rat_directory, name);

			try {
				process = Zid.Test.Process.start (rat_file);
			} catch (IOError e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}
		}

		public void inject (string name) {
			var loop = new MainLoop ();
			Idle.add (() => {
				do_injection (name, loop);
				return false;
			});
			loop.run ();
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

		private async void do_injection (string name, MainLoop loop) {
			if (injector == null)
				injector = new Fruitjector ();

			try {
				var dylib = Path.build_filename (rat_directory, name);
				yield injector.inject (process.id, dylib);
			} catch (IOError e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}

			loop.quit ();
		}
	}
}
