namespace Frida {
	namespace System {
		public extern static Frida.HostApplicationInfo get_frontmost_application (FrontmostQueryOptions options) throws Error;
		public extern static Frida.HostApplicationInfo[] enumerate_applications (ApplicationQueryOptions options);
		public extern static Frida.HostProcessInfo[] enumerate_processes (ProcessQueryOptions options);
		public extern static void kill (uint pid);
	}

	public sealed class ApplicationEnumerator : Object {
		private ThreadPool<EnumerateRequest> pool;
		private MainContext main_context;

		construct {
			try {
				pool = new ThreadPool<EnumerateRequest>.with_owned_data (handle_request, 1, false);
			} catch (ThreadError e) {
				assert_not_reached ();
			}

			main_context = MainContext.ref_thread_default ();
		}

		public async HostApplicationInfo[] enumerate_applications (ApplicationQueryOptions options) {
			var request = new EnumerateRequest (options, enumerate_applications.callback);
			try {
				pool.add (request);
			} catch (ThreadError e) {
				assert_not_reached ();
			}
			yield;
			return request.result;
		}

		private void handle_request (owned EnumerateRequest request) {
			var applications = System.enumerate_applications (request.options);

			var source = new IdleSource ();
			source.set_callback (() => {
				request.complete (applications);
				return false;
			});
			source.attach (main_context);
		}

		private class EnumerateRequest {
			public ApplicationQueryOptions options {
				get;
				private set;
			}

			public HostApplicationInfo[] result {
				get;
				private set;
			}

			private SourceFunc? handler;

			public EnumerateRequest (ApplicationQueryOptions options, owned SourceFunc handler) {
				this.options = options;
				this.handler = (owned) handler;
			}

			public void complete (HostApplicationInfo[] applications) {
				this.result = applications;
				handler ();
				handler = null;
			}
		}
	}

	public sealed class ProcessEnumerator : Object {
		private ThreadPool<EnumerateRequest> pool;
		private MainContext main_context;

		construct {
			try {
				pool = new ThreadPool<EnumerateRequest>.with_owned_data (handle_request, 1, false);
			} catch (ThreadError e) {
				assert_not_reached ();
			}

			main_context = MainContext.ref_thread_default ();
		}

		public async HostProcessInfo[] enumerate_processes (ProcessQueryOptions options) {
			var request = new EnumerateRequest (options, enumerate_processes.callback);
			try {
				pool.add (request);
			} catch (ThreadError e) {
				assert_not_reached ();
			}
			yield;
			return request.result;
		}

		private void handle_request (owned EnumerateRequest request) {
			var processes = System.enumerate_processes (request.options);

			var source = new IdleSource ();
			source.set_callback (() => {
				request.complete (processes);
				return false;
			});
			source.attach (main_context);
		}

		private class EnumerateRequest {
			public ProcessQueryOptions options {
				get;
				private set;
			}

			public HostProcessInfo[] result {
				get;
				private set;
			}

			private SourceFunc? handler;

			public EnumerateRequest (ProcessQueryOptions options, owned SourceFunc handler) {
				this.options = options;
				this.handler = (owned) handler;
			}

			public void complete (HostProcessInfo[] processes) {
				this.result = processes;
				handler ();
				handler = null;
			}
		}
	}

	public sealed class TemporaryDirectory {
		private string? name;

		public string path {
			owned get {
				if (file == null) {
					if (name != null)
						file = File.new_for_path (Path.build_filename (root_directory, name));
					else
						file = File.new_for_path (root_directory);

					try {
						file.make_directory_with_parents ();
					} catch (GLib.Error e) {
						// Following operations will fail
					}

					if (is_ours)
						claim ();
				}

				return file.get_path ();
			}
		}
		private File? file;
		private FileLock? file_lock;

		public bool is_ours {
			get;
			private set;
		}

		public static TemporaryDirectory system_default {
			owned get {
				return new TemporaryDirectory.with_file (File.new_for_path (root_directory), false);
			}
		}

		internal static string root_directory {
			owned get {
				string? root = fixed_root;
				if (root == null)
					return system_tmp_directory;

				try {
					File.new_for_path (root).make_directory_with_parents ();
				} catch (GLib.Error e) {
				}

				return ResourceDirectory.is_trusted_root (root, NOFOLLOW_SYMLINKS) ? root : system_tmp_directory;
			}
		}

		internal static string? fixed_root {
			owned get {
				return (fixed_name != null) ? Path.build_filename (system_tmp_directory, fixed_name) : null;
			}
		}

		private static string system_tmp_directory {
			owned get {
				return (sysroot != null)
					? Path.build_filename (sysroot, get_system_tmp ())
					: get_system_tmp ();
			}
		}

		private static string? fixed_name = null;
		private static string? sysroot = null;

		internal const string LOCK_NAME = ".lock";

		public TemporaryDirectory () {
#if !QNX
			this.name = make_name ();
			this.is_ours = true;
#endif
		}

		public TemporaryDirectory.with_file (File file, bool is_ours) {
			this.file = file;
			this.is_ours = is_ours;
		}

		~TemporaryDirectory () {
			destroy ();
		}

		public static void always_use (string? name) {
			fixed_name = name;
		}

		public static void use_sysroot (string? root) {
			sysroot = root;
		}

		public void destroy () {
			if (is_ours && file != null) {
				ResourceDirectory.remove_tree (file);
				file_lock = null;
			}
		}

		public static string make_name () {
			var builder = new StringBuilder ("frida-");
			for (var i = 0; i != 16; i++)
				builder.append_printf ("%02x", Random.int_range (0, 256));
			return builder.str;
		}

		private void claim () {
			try {
				file_lock = FileLock.open (Path.build_filename (file.get_path (), LOCK_NAME), true);
				file_lock.acquire (EXCLUSIVE, false);
			} catch (Error e) {
				file_lock = null;
			}

			ResourceDirectory.reclaim_stale (file.get_parent ().get_path ());
		}

		private extern static string get_system_tmp ();
	}

	public sealed class TemporaryFile {
		public string path {
			owned get {
				return file.get_path ();
			}
		}
		private File file;

		public TemporaryDirectory parent {
			get {
				return directory;
			}
		}
		private TemporaryDirectory directory;

		public TemporaryFile.from_stream (string name, InputStream istream, TemporaryDirectory? directory = null) throws Error {
			if (directory != null)
				this.directory = directory;
			else
				this.directory = TemporaryDirectory.system_default;

			string file_path = Path.build_filename (this.directory.path, name);
			string directory_path = Path.get_dirname (file_path);

			if (!FileUtils.test (directory_path, GLib.FileTest.IS_DIR)) {
				try {
					File tmp_dir = File.new_for_path (directory_path);
					tmp_dir.make_directory_with_parents ();
				} catch (GLib.Error e) {
					throw new Error.PERMISSION_DENIED ("%s", e.message);
				}
			}

			this.file = File.new_for_path (file_path);

			try {
				// FIXME: REPLACE_DESTINATION doesn't work?!
				file.delete ();
			} catch (GLib.Error delete_error) {
			}

			try {
				var ostream = file.create (FileCreateFlags.REPLACE_DESTINATION, null);

				var buf_size = 128 * 1024;
				var buf = new uint8[buf_size];

				while (true) {
					var bytes_read = istream.read (buf);
					if (bytes_read == 0)
						break;
					buf.resize ((int) bytes_read);

					size_t bytes_written;
					ostream.write_all (buf, out bytes_written);
				}

				ostream.close (null);
			} catch (GLib.Error e) {
				throw new Error.PERMISSION_DENIED ("%s", e.message);
			}
		}

		public TemporaryFile (File file, TemporaryDirectory directory) {
			this.file = file;
			this.directory = directory;
		}

		~TemporaryFile () {
			destroy ();
		}

		public void destroy () {
			if (file != null) {
				try {
					file.delete (null);
				} catch (GLib.Error e) {
				}
				file = null;
			}
			directory = null;
		}
	}

	public sealed class ResourceDirectory {
		public string path {
			get {
				return _path;
			}
		}
		private string _path;

		private FileLock? file_lock;
		private TemporaryDirectory? fallback;

		private static RecMutex mutex;
		private static Gee.HashMap<string, ResourceDirectory>? directories;
		private static Gee.HashSet<string>? reclaimed_roots;

		private const int64 RESOURCE_TTL = 24 * 3600;
		private const int64 LEGACY_TTL = 3 * 24 * 3600;
		private const int64 PARTIAL_TTL = 3600;

		private const string INFO_ATTRIBUTES = FileAttribute.STANDARD_TYPE + "," + FileAttribute.STANDARD_SIZE + "," +
			FileAttribute.UNIX_UID + "," + FileAttribute.UNIX_MODE + "," + FileAttribute.UNIX_DEVICE + "," +
			FileAttribute.UNIX_INODE + "," + FileAttribute.TIME_MODIFIED + ",time::modified-nsec," +
			FileAttribute.TIME_CHANGED + ",time::changed-nsec";

		public static ResourceDirectory open (string[] manifest) {
			string root = TemporaryDirectory.root_directory;
			string path = Path.build_filename (root, "frida-%s-%s".printf (version_string (), compute_id (manifest)));

			mutex.lock ();
			if (directories == null)
				directories = new Gee.HashMap<string, ResourceDirectory> ();
			ResourceDirectory? dir = directories[path];
			if (dir == null) {
				dir = new ResourceDirectory (root, path);
				directories[path] = dir;
			}
			mutex.unlock ();

			reclaim_stale (root);

			return dir;
		}

		public string provide (string name, Bytes data, string digest, int mode) throws Error {
			var file = File.new_for_path (Path.build_filename (_path, name));
			var record = file.get_parent ().get_child ("." + file.get_basename ());

			if (!is_intact (file, record, digest))
				write (file, record, data, digest, mode);

			return file.get_path ();
		}

		internal static void reclaim_stale (string root) {
			mutex.lock ();
			if (reclaimed_roots == null)
				reclaimed_roots = new Gee.HashSet<string> ();
			bool first_time = reclaimed_roots.add (root);
			mutex.unlock ();
			if (!first_time)
				return;

			new Thread<bool> ("frida-reclaim", () => {
				reclaim_entries_of (root);
				return true;
			});
		}

		private static void reclaim_entries_of (string root) {
			Dir dir;
			try {
				dir = Dir.open (root);
			} catch (FileError e) {
				return;
			}

			string? name;
			while ((name = dir.read_name ()) != null) {
				if (!name.has_prefix ("frida-"))
					continue;
				string path = Path.build_filename (root, name);
				mutex.lock ();
				bool in_use = directories != null && directories.has_key (path);
				mutex.unlock ();
				if (in_use)
					continue;
				try {
					maybe_reclaim (File.new_for_path (path), name, root == TemporaryDirectory.fixed_root);
				} catch (GLib.Error e) {
				}
			}
		}

		internal static void remove_tree (File file) {
			try {
				var enumerator = file.enumerate_children (FileAttribute.STANDARD_NAME + "," + FileAttribute.STANDARD_TYPE,
					NOFOLLOW_SYMLINKS);
				FileInfo info;
				while ((info = enumerator.next_file ()) != null) {
					File child = file.get_child (info.get_name ());
					if (info.get_file_type () == DIRECTORY)
						remove_tree (child);
					else
						delete_quietly (child);
				}
			} catch (GLib.Error e) {
			}

			delete_quietly (file);
		}

		private ResourceDirectory (string root, string path) {
			try {
				File.new_for_path (root).make_directory_with_parents ();
			} catch (GLib.Error e) {
			}

			try {
				if (!is_trusted_root (root, NONE))
					throw new Error.PERMISSION_DENIED ("Refusing to share resources in %s", root);
				claim (path);
				_path = path;
			} catch (Error e) {
				fallback = new TemporaryDirectory ();
				_path = fallback.path;
			}
		}

		private void claim (string path) throws Error {
			var dir = File.new_for_path (path);
			string lock_path = Path.build_filename (path, TemporaryDirectory.LOCK_NAME);
			while (file_lock == null) {
				try {
					dir.make_directory ();
					FileUtils.chmod (path, 0755);
				} catch (GLib.Error e) {
					if (!(e is IOError.EXISTS))
						throw new Error.PERMISSION_DENIED ("%s", e.message);
				}

				check_ours (dir, DIRECTORY);

				var candidate = FileLock.open (lock_path, true);
				if (candidate == null)
					continue;
				if (candidate.acquire (SHARED, true) == ACQUIRED && !candidate.is_at (lock_path))
					continue;
				file_lock = candidate;
			}

			try {
				File.new_for_path (lock_path).set_attribute_uint64 (FileAttribute.TIME_MODIFIED, get_real_time () / 1000000,
					NOFOLLOW_SYMLINKS);
				remove_stale_staged_files (dir);
			} catch (GLib.Error e) {
			}
		}

		private static string compute_id (string[] manifest) {
			var checksum = new Checksum (SHA256);
#if !WINDOWS
			checksum.update ("%u\n".printf ((uint) Posix.geteuid ()).data, -1);
#endif
			foreach (unowned string entry in manifest) {
				checksum.update (entry.data, entry.length);
				checksum.update ("\n".data, 1);
			}
			return checksum.get_string ()[:16];
		}

		private static void remove_stale_staged_files (File dir) throws GLib.Error {
			var enumerator = dir.enumerate_children (FileAttribute.STANDARD_NAME + "," + FileAttribute.TIME_MODIFIED,
				NOFOLLOW_SYMLINKS);
			FileInfo info;
			while ((info = enumerator.next_file ()) != null) {
				if (/\.[0-9a-f]{12}$/.match (info.get_name ()) && seconds_since (info) > PARTIAL_TTL)
					delete_quietly (dir.get_child (info.get_name ()));
			}
		}

		private static bool is_intact (File file, File record, string digest) {
			try {
				FileInfo info = file.query_info (INFO_ATTRIBUTES, NOFOLLOW_SYMLINKS);
				if (info.get_file_type () != REGULAR || !is_private (info))
					return false;

				uint8[] contents;
				record.load_contents (null, out contents, null);
				return (string) contents == make_record (digest, info);
			} catch (GLib.Error e) {
				return false;
			}
		}

		private static void write (File file, File record, Bytes data, string digest, int mode) throws Error {
			try {
				file.get_parent ().make_directory_with_parents ();
			} catch (GLib.Error e) {
			}

			try {
				File staged = write_staged (file, data, mode);
				staged.move (file, OVERWRITE | NOFOLLOW_SYMLINKS);

				FileInfo info = file.query_info (INFO_ATTRIBUTES, NOFOLLOW_SYMLINKS);
				File staged_record = write_staged (record, new Bytes (make_record (digest, info).data), 0644);
				staged_record.move (record, OVERWRITE | NOFOLLOW_SYMLINKS);
			} catch (GLib.Error e) {
				throw new Error.PERMISSION_DENIED ("%s", e.message);
			}
		}

		private static File write_staged (File file, Bytes data, int mode) throws GLib.Error {
			File staged = file.get_parent ().get_child ("%s.%08x%04x".printf (file.get_basename (), Random.next_int (),
				Random.int_range (0, 0x10000)));
			var output = staged.create (PRIVATE);
			size_t bytes_written;
			output.write_all (data.get_data (), out bytes_written);
			output.close ();
			FileUtils.chmod (staged.get_path (), mode);
			return staged;
		}

		private static string make_record (string digest, FileInfo info) {
			return "%s %s %s %s %s.%s %s.%s\n".printf (
				digest,
				info.get_size ().to_string (),
				info.get_attribute_uint32 (FileAttribute.UNIX_DEVICE).to_string (),
				info.get_attribute_uint64 (FileAttribute.UNIX_INODE).to_string (),
				info.get_attribute_uint64 (FileAttribute.TIME_MODIFIED).to_string (),
				info.get_attribute_uint32 ("time::modified-nsec").to_string (),
				info.get_attribute_uint64 (FileAttribute.TIME_CHANGED).to_string (),
				info.get_attribute_uint32 ("time::changed-nsec").to_string ());
		}

		internal static bool is_trusted_root (string root, FileQueryInfoFlags flags) {
#if WINDOWS
			return true;
#else
			FileInfo info;
			try {
				info = File.new_for_path (root).query_info (INFO_ATTRIBUTES, flags);
			} catch (GLib.Error e) {
				return false;
			}
			uint32 uid = info.get_attribute_uint32 (FileAttribute.UNIX_UID);
			uint32 mode = info.get_attribute_uint32 (FileAttribute.UNIX_MODE);
			bool owned_by_us_or_root = uid == Posix.geteuid () || uid == 0;
			bool writable_by_others = (mode & 0022) != 0;
			bool sticky = (mode & 01000) != 0;
			return info.get_file_type () == DIRECTORY && owned_by_us_or_root && (!writable_by_others || sticky);
#endif
		}

		private static void check_ours (File file, FileType type) throws Error {
			try {
				FileInfo info = file.query_info (INFO_ATTRIBUTES, NOFOLLOW_SYMLINKS);
				if (info.get_file_type () != type || !is_private (info))
					throw new Error.PERMISSION_DENIED ("Refusing to use %s", file.get_path ());
			} catch (GLib.Error e) {
				throw new Error.PERMISSION_DENIED ("%s", e.message);
			}
		}

		private static bool is_private (FileInfo info) {
#if WINDOWS
			return true;
#else
			return info.get_attribute_uint32 (FileAttribute.UNIX_UID) == Posix.geteuid () &&
				(info.get_attribute_uint32 (FileAttribute.UNIX_MODE) & 0022) == 0;
#endif
		}

		private static void maybe_reclaim (File dir, string name, bool in_fixed_root) throws GLib.Error {
			FileInfo info = dir.query_info (INFO_ATTRIBUTES, NOFOLLOW_SYMLINKS);
			if (!is_private (info))
				return;

			if (info.get_file_type () == REGULAR) {
				if (in_fixed_root)
					dir.delete ();
				return;
			}

			bool session = is_session_name (name);
			if (info.get_file_type () != DIRECTORY || !(session || is_resource_name (name) || is_doomed_name (name)))
				return;

			var lock_file = dir.get_child (TemporaryDirectory.LOCK_NAME);
			FileLock? dir_lock = FileLock.open (lock_file.get_path (), false);
			if (dir_lock == null) {
				int64 ttl = session ? LEGACY_TTL : PARTIAL_TTL;
				if (seconds_since_newest_change (dir) > ttl)
					remove_tree (dir);
				return;
			}

			if (dir_lock.acquire (EXCLUSIVE, false) != ACQUIRED)
				return;

			if (is_resource_name (name) && seconds_since_change (lock_file) < RESOURCE_TTL)
				return;

			var doomed = dir.get_parent ().get_child ("%s.%08x%04x".printf (name, Random.next_int (),
				Random.int_range (0, 0x10000)));
			dir.move (doomed, NOFOLLOW_SYMLINKS);
			remove_tree (doomed);
		}

		private static bool is_session_name (string name) {
			return /^frida-[0-9a-f]{32}$/.match (name);
		}

		private static bool is_resource_name (string name) {
			return /^frida-.+-[0-9a-f]{16}$/.match (name);
		}

		private static bool is_doomed_name (string name) {
			return /^frida-.+\.[0-9a-f]{12}$/.match (name);
		}

		private static int64 seconds_since_newest_change (File dir) throws GLib.Error {
			int64 result = seconds_since_change (dir);
			var enumerator = dir.enumerate_children (FileAttribute.STANDARD_NAME + "," + FileAttribute.TIME_MODIFIED,
				NOFOLLOW_SYMLINKS);
			FileInfo info;
			while ((info = enumerator.next_file ()) != null)
				result = int64.min (result, seconds_since (info));
			return result;
		}

		private static int64 seconds_since_change (File file) throws GLib.Error {
			return seconds_since (file.query_info (FileAttribute.TIME_MODIFIED, NOFOLLOW_SYMLINKS));
		}

		private static int64 seconds_since (FileInfo info) {
			return (get_real_time () / 1000000) - (int64) info.get_attribute_uint64 (FileAttribute.TIME_MODIFIED);
		}

		private static void delete_quietly (File file) {
			try {
				file.delete ();
			} catch (GLib.Error e) {
			}
		}
	}

	private sealed class FileLock {
		public enum Mode {
			SHARED,
			EXCLUSIVE
		}

		public enum Outcome {
			ACQUIRED,
			BUSY,
			UNSUPPORTED
		}

#if WINDOWS
		private void * handle;
#else
		private int fd;
#endif

		public static FileLock? open (string path, bool create) throws Error {
#if WINDOWS
			void * handle = _open (path, create);
			if (handle == null)
				return null;
			return new FileLock (handle);
#else
			int fd = Posix.open (path, Posix.O_RDWR | (create ? Posix.O_CREAT : 0), 0644);
			if (fd == -1) {
				if (errno == Posix.ENOENT)
					return null;
				throw new Error.PERMISSION_DENIED ("Unable to open %s: %s", path, strerror (errno));
			}
			Posix.fcntl (fd, Posix.F_SETFD, Posix.FD_CLOEXEC);
			return new FileLock (fd);
#endif
		}

#if WINDOWS
		private FileLock (void * handle) {
			this.handle = handle;
		}

		~FileLock () {
			_close (handle);
		}
#else
		private FileLock (int fd) {
			this.fd = fd;
		}

		~FileLock () {
			Posix.close (fd);
		}
#endif

		public Outcome acquire (Mode mode, bool wait) {
#if WINDOWS
			bool busy;
			if (_acquire (handle, mode == EXCLUSIVE, wait, out busy))
				return ACQUIRED;
			return busy ? Outcome.BUSY : Outcome.UNSUPPORTED;
#else
			int operation = ((mode == EXCLUSIVE) ? LOCK_EX : LOCK_SH) | (wait ? 0 : LOCK_NB);
			int res = flock (fd, operation);
			while (res == -1 && errno == Posix.EINTR)
				res = flock (fd, operation);
			if (res == 0)
				return ACQUIRED;
			return (errno == Posix.EWOULDBLOCK) ? Outcome.BUSY : Outcome.UNSUPPORTED;
#endif
		}

		public bool is_at (string path) {
#if WINDOWS
			return true;
#else
			Posix.Stat ours;
			Posix.Stat current;
			if (Posix.fstat (fd, out ours) != 0)
				return false;
			if (Posix.lstat (path, out current) != 0)
				return false;
			return ours.st_dev == current.st_dev && ours.st_ino == current.st_ino;
#endif
		}

#if WINDOWS
		private extern static void * _open (string path, bool create) throws Error;
		private extern static void _close (void * handle);
		private extern static bool _acquire (void * handle, bool exclusive, bool wait, out bool busy);
#else
		[CCode (cname = "flock", cheader_filename = "sys/file.h")]
		private extern static int flock (int fd, int operation);

		[CCode (cname = "LOCK_SH", cheader_filename = "sys/file.h")]
		private extern const int LOCK_SH;
		[CCode (cname = "LOCK_EX", cheader_filename = "sys/file.h")]
		private extern const int LOCK_EX;
		[CCode (cname = "LOCK_NB", cheader_filename = "sys/file.h")]
		private extern const int LOCK_NB;
#endif
	}
}
