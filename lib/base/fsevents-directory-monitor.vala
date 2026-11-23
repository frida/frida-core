namespace Frida {
	public sealed class FSEventsDirectoryMonitor : GLib.FileMonitor {
		public File directory {
			get;
			construct;
		}

		private string real_path;
		private File real_directory;
		private DirectoryState directory_state = PRESENT;
		private Gee.Map<string, Entry> entries = new Gee.HashMap<string, Entry> ();

		private MainContext main_context;
		private Darwin.GCD.DispatchQueue event_queue =
			new Darwin.GCD.DispatchQueue ("fsevents-directory-monitor", Darwin.GCD.DispatchQueueAttr.SERIAL);
		private Darwin.FSEvents.Stream? stream;

		private Mutex mutex;
		private Gee.List<string> pending_names = new Gee.ArrayList<string> ();
		private Gee.Map<string, Darwin.FSEvents.EventFlags> pending_flags = new Gee.HashMap<string, Darwin.FSEvents.EventFlags> ();
		private ScanScope pending_scope = NAMES;
		private Source? pending_source;

		private const double LATENCY = 0.1;
		private const Darwin.FSEvents.EventFlags HISTORY_LOST_FLAGS = MustScanSubDirs | UserDropped | KernelDropped;

		private enum DirectoryState {
			PRESENT,
			DELETED
		}

		private enum ScanScope {
			NAMES,
			DIRECTORY
		}

		private enum EntryChange {
			NONE,
			CREATED,
			CONTENTS,
			ATTRIBUTES
		}

		public FSEventsDirectoryMonitor (File directory) throws GLib.Error {
			Object (directory: directory);

			real_path = Posix.realpath (directory.get_path ());
			if (real_path == null)
				throw new IOError.FAILED ("%s", strerror (errno));
			real_directory = File.new_for_path (real_path);

			main_context = MainContext.ref_thread_default ();

			start_stream ();
			take_snapshot ();
		}

		public override bool cancel () {
			if (stream != null) {
				stream.stop ();
				stream.invalidate ();
				wait_for_callback_in_flight ();
				stream = null;
			}

			mutex.lock ();
			if (pending_source != null) {
				pending_source.destroy ();
				pending_source = null;
			}
			mutex.unlock ();

			return true;
		}

		private void start_stream () throws Error {
			Darwin.FSEvents.StreamContext context = { 0, };
			context.info = this;

			var path = CoreFoundation.String.make (real_path);
			var paths = new CoreFoundation.Array (null, ((CoreFoundation.Type[]) &path)[:1]);

			stream = new Darwin.FSEvents.Stream (null, on_stream_events_wrapper, context, paths,
				Darwin.FSEvents.EventId.SINCE_NOW, LATENCY, FileEvents);
			stream.set_dispatch_queue (event_queue);

			if (!stream.start ())
				throw new Error.NOT_SUPPORTED ("Unable to start FSEvents stream");
		}

		private void take_snapshot () {
			foreach (var name in list_names ()) {
				var entry = Entry.read (real_directory.get_child (name));
				if (entry != null)
					entries[name] = entry;
			}
		}

		private void wait_for_callback_in_flight () {
			event_queue.dispatch_sync (() => {});
		}

		private static void on_stream_events_wrapper (Darwin.FSEvents.Stream stream, void * info, size_t num_events,
				string[] event_paths, Darwin.FSEvents.EventFlags[] event_flags, Darwin.FSEvents.EventId[] event_ids) {
			unowned FSEventsDirectoryMonitor monitor = (FSEventsDirectoryMonitor) info;
			monitor.on_stream_events (event_paths[:num_events], event_flags[:num_events]);
		}

		private void on_stream_events (string[] paths, Darwin.FSEvents.EventFlags[] flags) {
			mutex.lock ();

			for (var i = 0; i != paths.length; i++) {
				unowned string path = paths[i];
				var event_flags = flags[i];

				if ((event_flags & HISTORY_LOST_FLAGS) != 0 || path == real_path) {
					pending_scope = DIRECTORY;
				} else if (Path.get_dirname (path) == real_path) {
					var name = Path.get_basename (path);
					if (pending_flags.has_key (name))
						pending_flags[name] = pending_flags[name] | event_flags;
					else {
						pending_names.add (name);
						pending_flags[name] = event_flags;
					}
				}
			}

			bool work_pending = !pending_names.is_empty || pending_scope == DIRECTORY;
			if (work_pending && pending_source == null) {
				var source = new IdleSource ();
				source.set_callback (process_pending_events);
				source.attach (main_context);
				pending_source = source;
			}

			mutex.unlock ();
		}

		private bool process_pending_events () {
			mutex.lock ();
			var names = pending_names;
			var flags = pending_flags;
			var scope = pending_scope;
			pending_names = new Gee.ArrayList<string> ();
			pending_flags = new Gee.HashMap<string, Darwin.FSEvents.EventFlags> ();
			pending_scope = NAMES;
			pending_source = null;
			mutex.unlock ();

			if (scope == DIRECTORY)
				rescan (names, flags);
			else
				foreach (var name in names)
					reconcile (name, flags[name]);

			return Source.REMOVE;
		}

		private void rescan (Gee.List<string> names, Gee.Map<string, Darwin.FSEvents.EventFlags> flags) {
			var candidates = new Gee.HashSet<string> ();
			candidates.add_all (names);
			candidates.add_all (entries.keys);
			candidates.add_all (list_names ());

			foreach (var name in candidates)
				reconcile (name, flags[name]);

			if (FileUtils.test (real_path, IS_DIR)) {
				directory_state = PRESENT;
			} else if (directory_state == PRESENT) {
				directory_state = DELETED;
				emit_event (directory, null, DELETED);
			}
		}

		private void reconcile (string name, Darwin.FSEvents.EventFlags flags) {
			var file = directory.get_child (name);
			Entry? previous = entries[name];
			Entry? current = Entry.read (real_directory.get_child (name));

			if (current == null) {
				if (previous != null) {
					entries.unset (name);
					emit_event (file, null, DELETED);
				}
				return;
			}

			entries[name] = current;

			switch (describe_change (previous, current, flags)) {
				case CREATED:
					emit_event (file, null, CREATED);
					emit_event (file, null, CHANGES_DONE_HINT);
					break;
				case CONTENTS:
					emit_event (file, null, CHANGED);
					emit_event (file, null, CHANGES_DONE_HINT);
					break;
				case ATTRIBUTES:
					emit_event (file, null, ATTRIBUTE_CHANGED);
					break;
				case NONE:
					break;
			}
		}

		private static EntryChange describe_change (Entry? previous, Entry current, Darwin.FSEvents.EventFlags flags) {
			if (previous == null || current.inode != previous.inode)
				return CREATED;
			if (current.file_type == DIRECTORY)
				return NONE;
			if (current.size != previous.size || current.modified != previous.modified)
				return CONTENTS;
			if (current.changed != previous.changed)
				return ATTRIBUTES;
			if ((flags & Darwin.FSEvents.EventFlags.ItemModified) != 0 && current.has_coarse_timestamps ())
				return CONTENTS;
			return NONE;
		}

		private Gee.List<string> list_names () {
			var names = new Gee.ArrayList<string> ();

			try {
				var dir = Dir.open (real_path);
				string? name;
				while ((name = dir.read_name ()) != null)
					names.add (name);
			} catch (FileError e) {
			}

			return names;
		}

		private class Entry {
			public FileType file_type;
			public uint64 inode;
			public int64 size;
			public uint64 modified;
			public uint64 changed;

			private const uint64 NANOSECONDS_PER_SECOND = 1000000000;

			private const string ATTRIBUTES =
				FileAttribute.STANDARD_TYPE + "," +
				FileAttribute.UNIX_INODE + "," +
				FileAttribute.STANDARD_SIZE + "," +
				FileAttribute.TIME_MODIFIED + "," +
				FileAttribute.TIME_MODIFIED_NSEC + "," +
				FileAttribute.TIME_CHANGED + "," +
				FileAttribute.TIME_CHANGED_NSEC;

			public static Entry? read (File file) {
				FileInfo info;
				try {
					info = file.query_info (ATTRIBUTES, NOFOLLOW_SYMLINKS);
				} catch (GLib.Error e) {
					return null;
				}

				var entry = new Entry ();
				entry.file_type = info.get_file_type ();
				entry.inode = info.get_attribute_uint64 (FileAttribute.UNIX_INODE);
				entry.size = info.get_size ();
				entry.modified = read_timestamp (info, FileAttribute.TIME_MODIFIED, FileAttribute.TIME_MODIFIED_NSEC);
				entry.changed = read_timestamp (info, FileAttribute.TIME_CHANGED, FileAttribute.TIME_CHANGED_NSEC);
				return entry;
			}

			public bool has_coarse_timestamps () {
				return modified % NANOSECONDS_PER_SECOND == 0;
			}

			private static uint64 read_timestamp (FileInfo info, string seconds_attribute, string nanoseconds_attribute) {
				var seconds = info.get_attribute_uint64 (seconds_attribute);
				var nanoseconds = info.get_attribute_uint32 (nanoseconds_attribute);
				return (seconds * NANOSECONDS_PER_SECOND) + nanoseconds;
			}
		}
	}
}
