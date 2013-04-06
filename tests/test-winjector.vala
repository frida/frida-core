#if WINDOWS
namespace Frida.WinjectorTest {
	public static void add_tests () {
		GLib.Test.add_func ("/Winjector/inject/x86", () => {
			try {
				var rat = new LabRat ("winvictim-busy32");
				rat.inject ("winattacker%u.dll", "12345");
				long exitcode = rat.wait_for_process_to_exit ();
				rat.close ();
				assert (exitcode == 12345);
			} catch (IOError e) {
				assert_not_reached ();
			}
		});

		GLib.Test.add_func ("/Winjector/inject/x64", () => {
			try {
				var rat = new LabRat ("winvictim-busy64");
				rat.inject ("winattacker%u.dll", "54321");
				long exitcode = rat.wait_for_process_to_exit ();
				rat.close ();
				assert (exitcode == 54321);
			} catch (IOError e) {
				printerr ("(skipping; requires a 64 bit system) ");
			}
		});
	}

	private class LabRat : Object {
		public string name {
			get;
			construct;
		}

		public Frida.Test.Process process {
			get;
			private set;
		}

		private string rat_directory;
		private Winjector injector;

		public LabRat (string name) throws IOError {
			Object (name: name);

			var self_filename = Frida.Test.Process.current.filename;
			rat_directory = Path.build_filename (Path.get_dirname (Path.get_dirname (Path.get_dirname (Path.get_dirname (self_filename)))),
				"tests", "labrats");

			var rat_file = Path.build_filename (rat_directory, name + ".exe");
			process = Frida.Test.Process.start (rat_file);
		}

		public void inject (string name, string data_string) {
			var loop = new MainLoop ();
			Idle.add (() => {
				do_injection (name, data_string, loop);
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

		public void close () {
			var loop = new MainLoop ();
			Idle.add (() => {
				do_close (loop);
				return false;
			});
			loop.run ();
		}

		private async void do_injection (string name, string data_string, MainLoop loop) {
			if (injector == null)
				injector = new Winjector ();

			string inject_error = null;

			AgentDescriptor desc;

			try {
				var dll32 = File.new_for_path (Path.build_filename (rat_directory, name.printf (32))).read (null);
				var dll64 = File.new_for_path (Path.build_filename (rat_directory, name.printf (64))).read (null);
				desc = new AgentDescriptor (name, dll32, dll64);
			} catch (Error io_error) {
				assert_not_reached ();
			}

			try {
				yield injector.inject ((uint32) process.id, desc, data_string);
			} catch (IOError e) {
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
#endif
