namespace Frida {
	public sealed class ProcMapsSnapshot : Object {
		public uint32 gen {
			get;
			internal set;
			default = 1;
		}

		private Gee.List<Mapping> maps = new Gee.ArrayList<Mapping> ();

		public class Mapping {
			public uint64 start;
			public uint64 end;
			public uint64 file_offset;

			public DevId device;
			public uint64 inode;

			public string module_id;

			public uint32 start_gen;
			public uint32 end_gen;
		}

		public static ProcMapsSnapshot from_pid (uint32 pid) throws Error {
			var snap = new ProcMapsSnapshot ();
			snap.build_from_pid (pid);
			return snap;
		}

		private void build_from_pid (uint32 pid) throws Error {
			maps.clear ();

			var it = ProcMapsIter.for_pid (pid);

			while (it.next ()) {
				var m = new Mapping ();

				m.start = it.start_address;
				m.end = it.end_address;
				m.file_offset = it.file_offset;

				m.device = it.device;
				m.inode = it.inode;

				m.module_id = normalize_module_id (it.path);

				m.start_gen = 1;
				m.end_gen = 0;

				maps.add (m);
			}
		}

		public void apply_create (uint32 new_gen, uint64 start, uint64 end, uint64 file_offset, DevId device, uint64 inode,
				string module_id) {
			end_range_at_gen (start, end, new_gen);

			var m = new Mapping ();
			m.start = start;
			m.end = end;
			m.file_offset = file_offset;
			m.device = device;
			m.inode = inode;
			m.module_id = module_id;
			m.start_gen = new_gen;
			m.end_gen = 0;

			insert_sorted (m);
			gen = new_gen;
		}

		public void apply_destroy_range (uint32 new_gen, uint64 start, uint64 end) {
			end_range_at_gen (start, end, new_gen);
			gen = new_gen;
		}

		private void insert_sorted (Mapping m) {
			int i = 0;
			while (i < maps.size && maps[i].start < m.start)
				i++;
			maps.insert (i, m);
		}

		private void end_range_at_gen (uint64 start, uint64 end, uint32 gen) {
			for (int i = maps.size - 1; i >= 0; i--) {
				var m = maps[i];

				bool active = m.end_gen == 0;
				if (!active)
					continue;

				bool disjoint = end <= m.start || start >= m.end;
				if (disjoint)
					continue;

				bool full_cover = start <= m.start && end >= m.end;
				if (full_cover) {
					m.end_gen = gen;
					continue;
				}

				bool chop_head = start <= m.start && end < m.end;
				if (chop_head) {
					var dead = new Mapping ();
					dead.start = m.start;
					dead.end = end;
					dead.file_offset = m.file_offset;
					dead.device = m.device;
					dead.inode = m.inode;
					dead.module_id = m.module_id;
					dead.start_gen = m.start_gen;
					dead.end_gen = gen;

					uint64 delta = end - m.start;
					m.start = end;
					m.file_offset += delta;

					maps.insert (i + 1, dead);
					continue;
				}

				bool chop_tail = start > m.start && end >= m.end;
				if (chop_tail) {
					var dead = new Mapping ();
					dead.start = start;
					dead.end = m.end;
					dead.file_offset = m.file_offset + (start - m.start);
					dead.device = m.device;
					dead.inode = m.inode;
					dead.module_id = m.module_id;
					dead.start_gen = m.start_gen;
					dead.end_gen = gen;

					m.end = start;

					maps.insert (i + 1, dead);
					continue;
				}

				bool split_middle = start > m.start && end < m.end;
				if (split_middle) {
					var dead = new Mapping ();
					dead.start = start;
					dead.end = end;
					dead.file_offset = m.file_offset + (start - m.start);
					dead.device = m.device;
					dead.inode = m.inode;
					dead.module_id = m.module_id;
					dead.start_gen = m.start_gen;
					dead.end_gen = gen;

					var right = new Mapping ();
					right.start = end;
					right.end = m.end;
					right.file_offset = m.file_offset + (end - m.start);
					right.device = m.device;
					right.inode = m.inode;
					right.module_id = m.module_id;
					right.start_gen = m.start_gen;
					right.end_gen = 0;

					m.end = start;

					maps.insert (i + 1, dead);
					maps.insert (i + 2, right);
				}
			}
		}

		private static string normalize_module_id (string path) {
			const string suffix = " (deleted)";
			if (path.has_suffix (suffix))
				return path.substring (0, path.length - suffix.length);
			return path;
		}

		public Mapping? find_mapping_at_gen (uint64 addr, uint32 gen) {
			int lo = 0;
			int hi = maps.size - 1;

			while (lo <= hi) {
				int mid = lo + ((hi - lo) / 2);
				var m = maps[mid];

				if (addr < m.start)
					hi = mid - 1;
				else if (addr >= m.end)
					lo = mid + 1;
				else {
					for (int i = mid; i >= 0; i--) {
						var c = maps[i];
						if (addr < c.start)
							break;

						bool match = mapping_contains (c, addr) && mapping_alive_at (c, gen);
						if (match)
							return c;
					}

					for (int i = mid + 1; i < maps.size; i++) {
						var c = maps[i];
						if (addr < c.start)
							break;

						bool match = mapping_contains (c, addr) && mapping_alive_at (c, gen);
						if (match)
							return c;
					}

					return null;
				}
			}

			return null;
		}

		private bool mapping_contains (Mapping m, uint64 addr) {
			return addr >= m.start && addr < m.end;
		}

		private bool mapping_alive_at (Mapping m, uint32 gen) {
			bool started = m.start_gen <= gen;
			bool not_ended = m.end_gen == 0 || gen < m.end_gen;
			return started && not_ended;
		}
	}

	public class ProcMapsSoEntry {
		public uint64 base_address;
		public string path;
		public DevId device;
		public uint64 inode;

		private ProcMapsSoEntry (uint64 base_address, string path, DevId device, uint64 inode) {
			this.base_address = base_address;
			this.path = path;
			this.device = device;
			this.inode = inode;
		}

		public static ProcMapsSoEntry? find_by_address (uint pid, uint64 address) {
			var iter = ProcMapsIter.for_pid (pid);
			while (iter.next ()) {
				uint64 start = iter.start_address;
				uint64 end = iter.end_address;
				if (address >= start && address < end)
					return new ProcMapsSoEntry (start, iter.path, iter.device, iter.inode);
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
						entry = new ProcMapsSoEntry (iter.start_address, current_path, iter.device, iter.inode),
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

		public uint64 dev {
			get {
				var s = info.fetch (5);
				int colon = s.index_of_char (':');

				uint64 major = uint64.parse (s.substring (0, colon), 16);
				uint64 minor = uint64.parse (s.substring (colon + 1), 16);

				return (major << 32) | minor;
			}
		}

		public DevId device {
			get {
				var s = info.fetch (5);
				int colon = s.index_of_char (':');

				uint32 major = (uint32) uint64.parse (s.substring (0, colon), 16);
				uint32 minor = (uint32) uint64.parse (s.substring (colon + 1), 16);

				return DevId (major, minor);
			}
		}

		public uint64 inode {
			get {
				return uint64.parse (info.fetch (6));
			}
		}

		public string path {
			owned get {
				return info.fetch (7);
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

			if (!/^([0-9a-f]+)-([0-9a-f]+) (\S{4}) ([0-9a-f]+) ([0-9a-f]{2,}:[0-9a-f]{2,}) (\d+) +([^\n]+)$/m.match (
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
