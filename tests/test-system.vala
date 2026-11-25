namespace Frida.SystemTest {
	public void add_tests () {
		GLib.Test.add_func ("/System/enumerate-processes-returns-processes-with-icons", () => {
			var options = new ProcessQueryOptions ();
			options.scope = FULL;

			var timer = new Timer ();
			var processes = System.enumerate_processes (options);
			var time_spent_on_first_run = timer.elapsed ();

			assert_true (processes.length > 0);

			switch (Frida.Test.os ()) {
				case Frida.Test.OS.WINDOWS:
					int num_icons_seen = 0;
					foreach (var p in processes) {
						if (p.parameters.contains ("icons"))
							num_icons_seen++;
					}
					assert_true (num_icons_seen > 0);
					break;
				default:
					break;
			}

			timer.start ();
			processes = System.enumerate_processes (options);
			var time_spent_on_second_run = timer.elapsed ();

			if (GLib.Test.verbose ())
				stdout.printf (" [spent %f and %f] ", time_spent_on_first_run, time_spent_on_second_run);
		});

#if !QNX
		GLib.Test.add_func ("/System/ResourceDirectory/provide-reuses-intact-file", () => {
			var data = new Bytes ("hello".data);
			string digest = Checksum.compute_for_bytes (SHA256, data);
			var dir = ResourceDirectory.open ({ "reuse " + digest });

			try {
				string first = dir.provide ("reuse", data, digest, 0644);
				var inode = File.new_for_path (first).query_info (FileAttribute.UNIX_INODE, NONE)
					.get_attribute_uint64 (FileAttribute.UNIX_INODE);

				string second = dir.provide ("reuse", data, digest, 0644);
				assert_true (second == first);
				assert_true (File.new_for_path (second).query_info (FileAttribute.UNIX_INODE, NONE)
					.get_attribute_uint64 (FileAttribute.UNIX_INODE) == inode);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			new TemporaryDirectory.with_file (File.new_for_path (dir.path), true).destroy ();
		});

		GLib.Test.add_func ("/System/ResourceDirectory/provide-replaces-modified-file", () => {
			var data = new Bytes ("pristine".data);
			string digest = Checksum.compute_for_bytes (SHA256, data);
			var dir = ResourceDirectory.open ({ "replace " + digest });

			try {
				string path = dir.provide ("replace", data, digest, 0644);
				FileUtils.set_contents (path, "tampered");

				assert_true (dir.provide ("replace", data, digest, 0644) == path);

				string contents;
				FileUtils.get_contents (path, out contents);
				assert_true (contents == "pristine");
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			new TemporaryDirectory.with_file (File.new_for_path (dir.path), true).destroy ();
		});
#endif
	}
}
