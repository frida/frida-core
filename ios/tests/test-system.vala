namespace Zid.SystemTest {
	public static void add_tests () {
		GLib.Test.add_func ("/System/enumerate-processes", () => {
			var processes = System.enumerate_processes ();
			assert (processes.length > 0);

			int num_icons_seen = 0;
			foreach (var p in processes) {
				if (p.small_icon.data != "" && p.large_icon.data != "")
					num_icons_seen++;
			}
			assert (num_icons_seen > 0);
		});
	}
}
