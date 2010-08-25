namespace Zid.FruitjectorTest {
	public static void add_tests () {
		GLib.Test.add_func ("/Fruitjector/inject", () => {
			var rat = new LabRat ("victim-busy");
			Thread.usleep (10000); /* give it 10 ms to settle */
			rat.inject ("attacker.dylib");
			rat.wait_for_process_to_exit ();
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
			rat_directory = Path.build_filename (Config.PKGDATADIR,
				"tests", "labrats");
			var rat_file = Path.build_filename (rat_directory, name);
			process = Zid.Test.Process.start (rat_file);
		}

		public void inject (string name) {
			var loop = new MainLoop ();
			Idle.add (() => {
				do_injection (name, loop);
				return false;
			});
			loop.run ();
		}

		public long wait_for_process_to_exit () {
			long exitcode = -1;
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

			string inject_error = null;

			try {
				var dylib = Path.build_filename (rat_directory, name);
				yield injector.inject ((int) process.id, dylib);
			} catch (IOError e) {
				inject_error = e.message;
			}

			assert (inject_error == null);

			loop.quit ();
		}
	}
}
