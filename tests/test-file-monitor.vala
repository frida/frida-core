namespace Frida.FileMonitorTest {
	public void add_tests () {
		GLib.Test.add_func ("/FileMonitor/Directory/write-in-place", () => {
			var h = new Harness ((h) => Directory.write_in_place.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/FileMonitor/Directory/create-file", () => {
			var h = new Harness ((h) => Directory.create_file.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/FileMonitor/Directory/delete-file", () => {
			var h = new Harness ((h) => Directory.delete_file.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/FileMonitor/Directory/rename-over", () => {
			var h = new Harness ((h) => Directory.rename_over.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/FileMonitor/Directory/ignore-subdirectory", () => {
			var h = new Harness ((h) => Directory.ignore_subdirectory.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/FileMonitor/Directory/quiet-after-disable", () => {
			var h = new Harness ((h) => Directory.quiet_after_disable.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/FileMonitor/File/write-in-place", () => {
			var h = new Harness ((h) => SingleFile.write_in_place.begin (h as Harness));
			h.run ();
		});
	}

	namespace Directory {
		private async void write_in_place (Harness h) {
			if (h.skip_without_monitor_backend ())
				return;

			var dir = h.make_directory ();
			var path = Path.build_filename (dir, "existing.txt");
			h.write_file (path, "before");

			var monitor = yield h.start_monitor (dir);

			h.append_to_file (path, "after");
			yield monitor.wait_for (path, CHANGED);
			yield monitor.wait_for (path, CHANGES_DONE_HINT);

			yield monitor.stop ();
			h.done ();
		}

		private async void create_file (Harness h) {
			if (h.skip_without_monitor_backend ())
				return;

			var dir = h.make_directory ();
			var path = Path.build_filename (dir, "new.txt");

			var monitor = yield h.start_monitor (dir);

			h.write_file (path, "hello");
			yield monitor.wait_for (path, CREATED);

			yield monitor.stop ();
			h.done ();
		}

		private async void delete_file (Harness h) {
			if (h.skip_without_monitor_backend ())
				return;

			var dir = h.make_directory ();
			var path = Path.build_filename (dir, "doomed.txt");
			h.write_file (path, "bye");

			var monitor = yield h.start_monitor (dir);

			FileUtils.unlink (path);
			yield monitor.wait_for (path, DELETED);

			yield monitor.stop ();
			h.done ();
		}

		private async void rename_over (Harness h) {
			if (h.skip_without_monitor_backend ())
				return;

			var dir = h.make_directory ();
			var path = Path.build_filename (dir, "target.txt");
			var replacement_path = Path.build_filename (dir, "target.txt.tmp");
			h.write_file (path, "old");

			var monitor = yield h.start_monitor (dir);

			h.write_file (replacement_path, "new");
			yield monitor.wait_for (replacement_path, CREATED);

			FileUtils.rename (replacement_path, path);
			yield monitor.wait_for (replacement_path, DELETED);
			yield monitor.wait_for (path, CREATED);

			yield monitor.stop ();
			h.done ();
		}

		private async void ignore_subdirectory (Harness h) {
			if (h.skip_without_monitor_backend ())
				return;

			var dir = h.make_directory ();
			var subdir = Path.build_filename (dir, "nested");
			DirUtils.create (subdir, 0755);
			var sentinel_path = Path.build_filename (dir, "sentinel.txt");

			var monitor = yield h.start_monitor (dir);

			h.write_file (Path.build_filename (subdir, "deep.txt"), "deep");
			h.write_file (sentinel_path, "done");
			yield monitor.wait_for (sentinel_path, CREATED);

			assert_false (monitor.has_seen_path_under (subdir));

			yield monitor.stop ();
			h.done ();
		}

		private async void quiet_after_disable (Harness h) {
			if (h.skip_without_monitor_backend ())
				return;

			var dir = h.make_directory ();
			var path = Path.build_filename (dir, "existing.txt");
			h.write_file (path, "before");

			var disabled_monitor = yield h.start_monitor (dir);
			var witness = yield h.start_monitor (dir);
			yield disabled_monitor.stop ();

			h.append_to_file (path, "after");
			yield witness.wait_for (path, CHANGES_DONE_HINT);
			yield h.sleep (500);

			assert_true (disabled_monitor.changes.is_empty);

			yield witness.stop ();
			h.done ();
		}
	}

	namespace SingleFile {
		private async void write_in_place (Harness h) {
			if (h.skip_without_monitor_backend ())
				return;

			var dir = h.make_directory ();
			var path = Path.build_filename (dir, "watched.txt");
			h.write_file (path, "before");

			var monitor = yield h.start_monitor (path);

			h.append_to_file (path, "after");
			yield monitor.wait_for (path, CHANGED);
			yield monitor.wait_for (path, CHANGES_DONE_HINT);

			yield monitor.stop ();
			h.done ();
		}
	}

	private sealed class Harness : Frida.Test.AsyncHarness {
		private Gee.List<string> directories = new Gee.ArrayList<string> ();

		public Harness (owned Frida.Test.AsyncHarness.TestSequenceFunc func) {
			base ((owned) func);
		}

		public bool skip_without_monitor_backend () {
			if (Frida.Test.os () != Frida.Test.OS.QNX)
				return false;

			stdout.printf ("<skipping, GLib has no file monitor backend on QNX> ");
			done ();
			return true;
		}

		public override void done () {
			foreach (var dir in directories)
				remove_tree (dir);

			base.done ();
		}

		public string make_directory () {
			string dir;
			try {
				dir = DirUtils.make_tmp ("frida-file-monitor-XXXXXX");
			} catch (FileError e) {
				assert_not_reached ();
			}
			directories.add (dir);
			return dir;
		}

		public void write_file (string path, string contents) {
			var stream = FileStream.open (path, "w");
			stream.puts (contents);
		}

		public void append_to_file (string path, string contents) {
			var stream = FileStream.open (path, "a");
			stream.puts (contents);
		}

		public async RecordingMonitor start_monitor (string path) {
			var monitor = new RecordingMonitor (path);
			try {
				yield monitor.monitor.enable ();
			} catch (GLib.Error e) {
				printerr ("%s\n", e.message);
				assert_not_reached ();
			}
			return monitor;
		}

		public async void sleep (uint milliseconds) {
			Timeout.add (milliseconds, sleep.callback);
			yield;
		}

		private static void remove_tree (string path) {
			try {
				var dir = Dir.open (path);
				string? name;
				while ((name = dir.read_name ()) != null) {
					var child = Path.build_filename (path, name);
					if (FileUtils.test (child, IS_DIR))
						remove_tree (child);
					else
						FileUtils.unlink (child);
				}
			} catch (FileError e) {
			}
			DirUtils.remove (path);
		}
	}

	private sealed class RecordingMonitor : Object {
		public Frida.FileMonitor monitor;
		public Gee.List<Change> changes = new Gee.ArrayList<Change> ();

		private SourceFunc? on_change;

		public RecordingMonitor (string path) {
			monitor = new Frida.FileMonitor (path);
			monitor.change.connect (on_monitor_change);
		}

		public async void stop () {
			try {
				yield monitor.disable ();
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
		}

		public async void wait_for (string path, FileMonitorEvent event) {
			while (!has_seen (path, event)) {
				on_change = wait_for.callback;
				yield;
			}
		}

		public bool has_seen_path_under (string dir) {
			foreach (var change in changes) {
				if (change.file_path == dir || change.file_path.has_prefix (dir + Path.DIR_SEPARATOR_S))
					return true;
			}
			return false;
		}

		private bool has_seen (string path, FileMonitorEvent event) {
			foreach (var change in changes) {
				if (change.file_path == path && change.event == event)
					return true;
			}
			return false;
		}

		private void on_monitor_change (string file_path, string? other_file_path, FileMonitorEvent event) {
			if (GLib.Test.verbose ())
				printerr ("[%s] %s\n", event.to_string (), file_path);

			changes.add (new Change (file_path, event));

			if (on_change != null)
				Idle.add ((owned) on_change);
		}
	}

	private sealed class Change {
		public string file_path;
		public FileMonitorEvent event;

		public Change (string file_path, FileMonitorEvent event) {
			this.file_path = file_path;
			this.event = event;
		}
	}
}
