#if LINUX
namespace Frida.LinjectorTest {
	public static void add_tests () {
		GLib.Test.add_func ("/Linjector/inject", () => {
			var tests_dir = Path.get_dirname (Frida.Test.Process.current.filename);

			var logfile = File.new_for_path (Path.build_filename (tests_dir, "inject-attacker.log"));
			try {
				logfile.delete ();
			} catch (GLib.Error delete_error) {
			}
			var envp = new string[] {
				"FRIDA_LABRAT_LOGFILE=" + logfile.get_path ()
			};

			var rat = new LabRat (tests_dir, "unixvictim", envp);

			/* TODO: improve Linjector to handle injection into a process that hasn't yet finished initializing */
			Thread.usleep (50000);

			rat.inject ("unixattacker", "");
			rat.wait_for_uninject ();

			assert (content_of (logfile) == ">m<");

			var requested_exit_code = 43;
			rat.inject ("unixattacker", requested_exit_code.to_string ());
			rat.wait_for_uninject ();

			if (Frida.Test.os () == Frida.Test.OS.ANDROID || Frida.Test.libc () == Frida.Test.Libc.UCLIBC) {
				assert (content_of (logfile) == ">m<>m");
			} else {
				assert (content_of (logfile) == ">m<>m<");
			}

			var exit_code = rat.wait_for_process_to_exit ();
			assert (exit_code == requested_exit_code);

			try {
				logfile.delete ();
			} catch (GLib.Error delete_error) {
				assert_not_reached ();
			}
		});
	}

	private static string content_of (File file) {
		try {
			uint8[] contents;
			file.load_contents (null, out contents, null);
			unowned string str = (string) contents;
			return str;
		} catch (GLib.Error load_error) {
			stderr.printf ("%s: %s\n", file.get_path (), load_error.message);
			assert_not_reached ();
		}
	}

	private class LabRat {
		public Frida.Test.Process process {
			get;
			private set;
		}

		private string data_directory;
		private Linjector injector;

		public LabRat (string dir, string name, string[] envp) {
			data_directory = Path.build_filename (dir, "data");
			var rat_file = Path.build_filename (data_directory, name + Frida.Test.arch_suffix ());

			var argv = new string[] {
				rat_file
			};

			try {
				process = Frida.Test.Process.start (rat_file, argv, envp, Frida.Test.Arch.CURRENT);
			} catch (Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}
		}

		public void inject (string name, string data) {
			var loop = new MainLoop ();
			Idle.add (() => {
				do_injection.begin (name, data, loop);
				return false;
			});
			loop.run ();
		}

		private async void do_injection (string name, string data, MainLoop loop) {
			if (injector == null)
				injector = new Linjector ();

			try {
				var sofile = Path.build_filename (data_directory, name + Frida.Test.arch_suffix () + ".so");
				assert (FileUtils.test (sofile, FileTest.EXISTS));

				AgentResource agent;

				try {
					var file = File.new_for_path (sofile).read (null);
					var stub = new MemoryInputStream ();
					InputStream so32, so64;
					if (sizeof (void *) == 4) {
						so32 = file;
						so64 = stub;
					} else {
						so32 = stub;
						so64 = file;
					}
					agent = new AgentResource (name + "-%u.so", so32, so64);
				} catch (GLib.Error io_error) {
					assert_not_reached ();
				}

				yield injector.inject_library_resource (process.id, agent, "frida_agent_main", data);
			} catch (Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}

			loop.quit ();
		}

		public void wait_for_uninject () {
			var loop = new MainLoop ();

			var handler_id = injector.uninjected.connect ((id) => {
				loop.quit ();
			});

			var timed_out = false;
			var timeout_id = Timeout.add_seconds (1, () => {
				timed_out = true;
				loop.quit ();
				return false;
			});

			loop.run ();

			assert (!timed_out);
			Source.remove (timeout_id);
			injector.disconnect (handler_id);
		}

		public int wait_for_process_to_exit () {
			int exitcode = -1;

			try {
				exitcode = process.join (1000);
			} catch (Error e) {
				stdout.printf ("\n\nunexpected error: %s\n", e.message);
				assert_not_reached ();
			}

			return exitcode;
		}
	}
}
#endif
