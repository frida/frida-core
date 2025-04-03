namespace Frida {
	public sealed class FileMonitor : Object {
		public signal void change (string file_path, string? other_file_path, FileMonitorEvent event);

		public string path {
			get;
			construct;
		}

		private GLib.FileMonitor monitor;

		public FileMonitor (string path) {
			Object (path: path);
		}

		~FileMonitor () {
			clear ();
		}

		public async void enable (Cancellable? cancellable = null) throws Error, IOError {
			if (monitor != null)
				throw new Error.INVALID_OPERATION ("Already enabled");

			var file = File.parse_name (path);

			try {
				monitor = file.monitor (FileMonitorFlags.NONE, cancellable);
			} catch (GLib.Error e) {
				throw new Error.INVALID_OPERATION ("%s", e.message);
			}

			monitor.changed.connect (on_changed);
		}

		public void enable_sync (Cancellable? cancellable = null) throws Error, IOError {
			var task = create<EnableTask> () as EnableTask;
			task.execute (cancellable);
		}

		private class EnableTask : FileMonitorTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.enable (cancellable);
			}
		}

		public async void disable (Cancellable? cancellable = null) throws Error, IOError {
			if (monitor == null)
				throw new Error.INVALID_OPERATION ("Already disabled");

			clear ();
		}

		private void clear () {
			if (monitor == null)
				return;

			monitor.changed.disconnect (on_changed);
			monitor.cancel ();
			monitor = null;
		}

		public void disable_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<DisableTask> ().execute (cancellable);
		}

		private class DisableTask : FileMonitorTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.disable (cancellable);
			}
		}

		private void on_changed (File file, File? other_file, FileMonitorEvent event) {
			change (file.get_parse_name (), (other_file != null) ? other_file.get_parse_name () : null, event);
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		private abstract class FileMonitorTask<T> : AsyncTask<T> {
			public weak FileMonitor parent {
				get;
				construct;
			}
		}
	}
}
