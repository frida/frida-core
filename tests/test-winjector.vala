namespace Zed.Test.Winjector {
	public static void add_tests () {
		GLib.Test.add_func ("/Winjector/inject-x86", () => {
			var rat = new LabRat ("winvictim-busy32");
			Thread.usleep (10000); /* give it 10 ms to settle */
			rat.inject ("winattacker32");
			long exitcode = rat.process.join ();
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
			print ("starting %s\n", rat_file);
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

		private async void do_injection (string name, MainLoop loop) {
			var injector = new Service.Winjector ();
			var rat_file = Path.build_filename (rat_directory, name + ".dll");
			try {
				yield injector.inject ((uint32) process.id, rat_file);
			} catch (Service.WinjectorError e) {
				assert_not_reached ();
			}

			loop.quit ();
		}
	}
}
