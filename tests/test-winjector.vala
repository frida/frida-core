using WinIpc;

namespace Zed.Test.Winjector {
	public static void add_tests () {
		GLib.Test.add_func ("/Winjector/inject/x86", () => {
			var rat = new LabRat ("winvictim-busy32");
			Thread.usleep (10000); /* give it 10 ms to settle */
			var proxy = rat.inject ("winattacker%u.dll");
			proxy.emit ("ExitProcess", new Variant ("u", 12345));
			long exitcode = rat.wait_for_process_to_exit ();
			rat.close ();
			assert (exitcode == 12345);
		});

		GLib.Test.add_func ("/Winjector/inject/x64", () => {
			var rat = new LabRat ("winvictim-busy64");
			Thread.usleep (10000); /* give it 10 ms to settle */
			var proxy = rat.inject ("winattacker%u.dll");
			proxy.emit ("ExitProcess", new Variant ("u", 54321));
			long exitcode = rat.wait_for_process_to_exit ();
			rat.close ();
			assert (exitcode == 54321);
		});
	}

	private class LabRat {
		public Process process {
			get;
			private set;
		}

		private string rat_directory;
		private Proxy cur_proxy;
		private Service.Winjector injector;

		public LabRat (string name) {
			var self_filename = Process.current.filename;
			rat_directory = Path.build_filename (Path.get_dirname (Path.get_dirname (Path.get_dirname (Path.get_dirname (self_filename)))),
				"tests", "labrats");

			var rat_file = Path.build_filename (rat_directory, name + ".exe");
			process = Process.start (rat_file);
		}

		public Proxy inject (string name) {
			var loop = new MainLoop ();
			Idle.add (() => {
				do_injection (name, loop);
				return false;
			});
			loop.run ();

			Proxy proxy = cur_proxy;
			cur_proxy = null;
			return proxy;
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

		public void close () {
			var loop = new MainLoop ();
			Idle.add (() => {
				do_close (loop);
				return false;
			});
			loop.run ();
		}

		private async void do_injection (string name, MainLoop loop) {
			if (injector == null)
				injector = new Service.Winjector ();

			string inject_error = null;

			Service.AgentDescriptor desc;

			try {
				var dll32 = File.new_for_path (Path.build_filename (rat_directory, name.printf (32))).read (null);
				var dll64 = File.new_for_path (Path.build_filename (rat_directory, name.printf (64))).read (null);
				desc = new Service.AgentDescriptor (name, dll32, dll64);
			} catch (Error io_error) {
				assert_not_reached ();
			}

			try {
				cur_proxy = yield injector.inject ((uint32) process.id, desc);
			} catch (Service.WinjectorError e) {
				inject_error = e.message;
			}

			if (inject_error != null) {
				yield injector.close ();
				injector = null;
			}

			assert (inject_error == null);

			loop.quit ();
		}

		private async void do_close (MainLoop loop) {
			if (injector != null) {
				yield injector.close ();
				injector = null;
			}

			loop.quit ();
		}
	}
}
