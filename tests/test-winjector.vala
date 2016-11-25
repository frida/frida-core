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
			} catch (Error e) {
				stdout.printf ("ERROR: '%s'\n", e.message);
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
			} catch (Error e) {
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

		public LabRat (string name) throws Error {
			Object (name: name);

			var self_filename = Frida.Test.Process.current.filename;
			rat_directory = Path.build_filename (Path.get_dirname (Path.get_dirname (Path.get_dirname (Path.get_dirname (Path.get_dirname (self_filename))))),
				"frida-core", "tests", "labrats");

			var rat_file = Path.build_filename (rat_directory, name + ".exe");
			var argv = new string[] {
				rat_file
			};
			var envp = new string[] {};
			process = Frida.Test.Process.start (rat_file, argv, envp, Frida.Test.Arch.CURRENT);
		}

		public void inject (string name, string data) {
			var loop = new MainLoop ();
			Idle.add (() => {
				do_injection.begin (name, data, loop);
				return false;
			});
			loop.run ();
		}

		public long wait_for_process_to_exit () {
			long exitcode = -1;
			bool wait_for_exit_timed_out = false;

			try {
				exitcode = process.join (1000);
			} catch (Error e) {
				assert (e is Error.TIMED_OUT);
				wait_for_exit_timed_out = true;
			}

			assert (!wait_for_exit_timed_out);

			return exitcode;
		}

		public void close () {
			var loop = new MainLoop ();
			Idle.add (() => {
				do_close.begin (loop);
				return false;
			});
			loop.run ();
		}

		private async void do_injection (string name, string data, MainLoop loop) {
			if (injector == null)
				injector = new Winjector ();

			string inject_error = null;

			AgentDescriptor desc;

			try {
				var dll32 = File.new_for_path (Path.build_filename (rat_directory, name.printf (32))).read (null);
				var dll64 = File.new_for_path (Path.build_filename (rat_directory, name.printf (64))).read (null);
				desc = new AgentDescriptor (name, dll32, dll64);
			} catch (GLib.Error io_error) {
				assert_not_reached ();
			}

			try {
				yield injector.inject_library_resource ((uint32) process.id, desc, "frida_agent_main", data);
			} catch (Error e) {
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

			/* Queue an idle handler, allowing MainContext to perform any outstanding completions, in turn cleaning up resources */
			Idle.add (() => {
				loop.quit ();
				return false;
			});
		}
	}
}
#endif
