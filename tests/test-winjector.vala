namespace Zed.Test {
	private static void winjector_add_tests () {
		GLib.Test.add_func ("/winjector/inject-x86", () => {
			var rat = new LabRat ("winvictim32");
			rat.inject ("winattacker");
			assert (rat.process.join () == 133742);
		});
	}

	private class LabRat {
		public Platform.Process process {
			get;
			private set;
		}

		private string rat_directory;

		public LabRat (string name) {
			var self_filename = Platform.Process.current.filename;
			rat_directory = Path.build_filename (Path.get_dirname (Path.get_dirname (Path.get_dirname (self_filename))),
				"tests", "labrats");

			var rat_file = Path.build_filename (rat_directory, name + ".exe");
			process = Platform.Process.start (rat_file);
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
				yield injector.inject_async (rat_file, process.id);
			} catch (Service.WinjectorError e) {
				assert_not_reached ();
			}

			loop.quit ();
		}
	}
}
