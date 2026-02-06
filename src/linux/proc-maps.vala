namespace Frida {
	public sealed class ProcMapsSnapshot : Object {
		public class Mapping {
			public uint64 start;
			public uint64 end;
			public uint64 file_offset;
			public string module_id;
		}

		private Gee.ArrayList<Mapping> maps = new Gee.ArrayList<Mapping> ();

		public static ProcMapsSnapshot from_pid (uint32 pid) throws Error {
			var snap = new ProcMapsSnapshot ();
			snap.build_from_pid (pid);
			return snap;
		}

		private ProcMapsSnapshot () {
		}

		private void build_from_pid (uint32 pid) throws Error {
			maps.clear ();

			var it = ProcMapsIter.for_pid (pid);

			while (it.next ()) {
				var m = new Mapping ();
				m.start = it.start_address;
				m.end = it.end_address;
				m.file_offset = it.file_offset;
				m.module_id = normalize_module_id (it.path);

				maps.add (m);
			}
		}

		private static string normalize_module_id (string path) {
			const string suffix = " (deleted)";
			if (path.has_suffix (suffix))
				return path.substring (0, path.length - suffix.length);
			return path;
		}

		public Mapping? find_mapping (uint64 addr) {
			int lo = 0;
			int hi = maps.size - 1;

			while (lo <= hi) {
				int mid = lo + ((hi - lo) / 2);
				var m = maps[mid];

				if (addr < m.start)
					hi = mid - 1;
				else if (addr >= m.end)
					lo = mid + 1;
				else
					return m;
			}

			return null;
		}
	}

	public class ProcMapsSoEntry {
		public uint64 base_address;
		public string path;
		public string identity;

		private ProcMapsSoEntry (uint64 base_address, string path, string identity) {
			this.base_address = base_address;
			this.path = path;
			this.identity = identity;
		}

		public static ProcMapsSoEntry? find_by_address (uint pid, uint64 address) {
			var iter = ProcMapsIter.for_pid (pid);
			while (iter.next ()) {
				uint64 start = iter.start_address;
				uint64 end = iter.end_address;
				if (address >= start && address < end)
					return new ProcMapsSoEntry (start, iter.path, iter.identity);
			}

			return null;
		}

		public static ProcMapsSoEntry? find_by_path (uint pid, string path) {
			var candidates = new Gee.ArrayList<Candidate> ();
			Candidate? latest_candidate = null;
			var iter = ProcMapsIter.for_pid (pid);
#if ANDROID
			unowned string libc_path = Gum.Process.get_libc_module ().path;
#endif
			while (iter.next ()) {
				string current_path = iter.path;
				if (current_path == "[page size compat]")
					continue;
				if (current_path != path) {
					latest_candidate = null;
					continue;
				}

				string flags = iter.flags;

#if ANDROID
				if (current_path == libc_path && flags[3] == 's')
					continue;
#endif

				if (iter.file_offset == 0) {
					latest_candidate = new Candidate () {
						entry = new ProcMapsSoEntry (iter.start_address, current_path, iter.identity),
						total_ranges = 0,
						executable_ranges = 0,
					};
					candidates.add (latest_candidate);
				}

				if (latest_candidate != null) {
					latest_candidate.total_ranges++;
					if (flags[2] == 'x')
						latest_candidate.executable_ranges++;
				}
			}

			candidates.sort ((a, b) => b.score () - a.score ());

			if (candidates.is_empty)
				return null;

			return candidates.first ().entry;
		}

		private class Candidate {
			public ProcMapsSoEntry entry;
			public uint total_ranges;
			public uint executable_ranges;

			public int score () {
				int result = (int) total_ranges;
				if (executable_ranges == 0)
					result = -result;
				return result;
			}
		}
	}

	public sealed class ProcMapsIter {
		private string? contents;
		private MatchInfo? info;
		private uint offset = 0;

		public uint64 start_address {
			get {
				return uint64.parse (info.fetch (1), 16);
			}
		}

		public uint64 end_address {
			get {
				return uint64.parse (info.fetch (2), 16);
			}
		}

		public string flags {
			owned get {
				return info.fetch (3);
			}
		}

		public uint64 file_offset {
			get {
				return uint64.parse (info.fetch (4), 16);
			}
		}

		public string identity {
			owned get {
				return info.fetch (5);
			}
		}

		public string path {
			owned get {
				return info.fetch (6);
			}
		}

		public static ProcMapsIter for_pid (uint pid) {
			return new ProcMapsIter (pid);
		}

		private ProcMapsIter (uint pid) {
			try {
				FileUtils.get_contents ("/proc/%u/maps".printf (pid), out contents);
			} catch (FileError e) {
				return;
			}

			if (!/^([0-9a-f]+)-([0-9a-f]+) (\S{4}) ([0-9a-f]+) ([0-9a-f]{2,}:[0-9a-f]{2,} \d+) +([^\n]+)$/m.match (
					contents, 0, out info)) {
				assert_not_reached ();
			}
		}

		public bool next () {
			if (info == null)
				return false;

			if (offset > 0) {
				try {
					info.next ();
				} catch (RegexError e) {
					return false;
				}
			}
			offset++;

			return info.matches ();
		}
	}
}
