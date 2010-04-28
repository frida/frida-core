namespace Zed.Test.Winjector {
	public static void add_tests () {
		GLib.Test.add_func ("/Winjector/inject-x86", () => {
			var rat = new LabRat ("winvictim-busy32");
			Thread.usleep (10000); /* give it 10 ms to settle */
			rat.inject ("winattacker%u.dll");
			long exitcode = rat.wait_for_process_to_exit ();
			assert (exitcode == 133742);
		});

		GLib.Test.add_func ("/Winjector/inject-x64", () => {
			var rat = new LabRat ("winvictim-busy64");
			Thread.usleep (10000); /* give it 10 ms to settle */
			rat.inject ("winattacker%u.dll");
			long exitcode = rat.wait_for_process_to_exit ();
			assert (exitcode == 133742);
		});
	}

	private class LabRat {
		public Process process {
			get;
			private set;
		}

		private string rat_directory;

		public LabRat (string name) {
			var self_filename = Process.current.filename;
			rat_directory = Path.build_filename (Path.get_dirname (Path.get_dirname (Path.get_dirname (Path.get_dirname (self_filename)))),
				"tests", "labrats");

			var rat_file = Path.build_filename (rat_directory, name + ".exe");
			process = Process.start (rat_file);
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
			} catch (ProcessError e) {
				var timed_out_error = new ProcessError.TIMED_OUT ("");
				if (e.code == timed_out_error.code)
					wait_for_exit_timed_out = true;
				else
					assert_not_reached ();
			}

			assert (!wait_for_exit_timed_out);

			return exitcode;
		}

		private async void do_injection (string name, MainLoop loop) {
			var injector = new Service.Winjector ();

			string inject_error = null;

			var rat_file = Path.build_filename (rat_directory, name);
			try {
				yield injector.inject ((uint32) process.id, rat_file);
			} catch (Service.WinjectorError e) {
				inject_error = e.message;
			}

			yield injector.close ();

			assert (inject_error == null);

			loop.quit ();
		}
	}
}
