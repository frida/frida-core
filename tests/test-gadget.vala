namespace Frida.GadgetTest {
	public static void add_tests () {
		GLib.Test.add_func ("/Gadget/Standalone/load-script", Standalone.load_script);
	}

	namespace Standalone {
		private static void load_script () {
			if (!GLib.Test.slow ()) {
				stdout.printf ("<skipping, run in slow mode> ");
				return;
			}

			string shlib_extension;
#if DARWIN
			shlib_extension = "dylib";
#else
			shlib_extension = "so";
#endif
			var frida_root_dir = Path.get_dirname (Path.get_dirname (Frida.Test.Process.current.filename));
			var gadget_filename = Path.build_filename (frida_root_dir, "lib", "gadget", ".libs", "libfrida-gadget." + shlib_extension);

			var tests_dir = Path.get_dirname (Frida.Test.Process.current.filename);
			var data_dir = Path.build_filename (tests_dir, "data");
			var rat_file = Path.build_filename (data_dir, "unixvictim" + os_suffix ());
			var script_file = File.new_for_path (Path.build_filename (data_dir, "test-gadget-standalone.js"));
			var log_file = File.new_for_path (Path.build_filename (tests_dir, "test-gadget-standalone.log"));

			var argv = new string[] {
				rat_file
			};
			var envp = new string[] {
				"DYLD_INSERT_LIBRARIES=" + gadget_filename,
				"FRIDA_GADGET_SCRIPT=" + script_file.get_path (),
				"FRIDA_GADGET_TEST_LOGFILE=" + log_file.get_path ()
			};

			try {
				var process = Frida.Test.Process.start (rat_file, argv, envp, Frida.Test.Arch.CURRENT);
				process.join (1000);
			} catch (Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}
		}

		private static string os_suffix () {
			switch (Frida.Test.os ()) {
				case Frida.Test.OS.MAC:
					return "-mac";
				case Frida.Test.OS.IOS:
					return "-ios";
				default:
					assert_not_reached ();
			}
		}
	}
}
