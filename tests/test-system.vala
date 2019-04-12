namespace Frida.SystemTest {
	public static void add_tests () {
		GLib.Test.add_func ("/System/enumerate-processes-returns-processes-with-icons", () => {
			var timer = new Timer ();
			var processes = System.enumerate_processes ();
			var time_spent_on_first_run = timer.elapsed ();

			assert_true (processes.length > 0);

			switch (Frida.Test.os ()) {
				case Frida.Test.OS.WINDOWS:
				case Frida.Test.OS.IOS:
					int num_icons_seen = 0;
					foreach (var p in processes) {
						if (p.small_icon.pixels != "" && p.large_icon.pixels != "")
							num_icons_seen++;
					}
					assert_true (num_icons_seen > 0);
					break;
			}

			timer.start ();
			processes = System.enumerate_processes ();
			var time_spent_on_second_run = timer.elapsed ();

			if (GLib.Test.verbose ())
				stdout.printf (" [spent %f and %f] ", time_spent_on_first_run, time_spent_on_second_run);

			if (Frida.Test.os () == Frida.Test.OS.IOS) {
				assert_true (time_spent_on_second_run <= time_spent_on_first_run / 2.0);
			}
		});
	}
}
