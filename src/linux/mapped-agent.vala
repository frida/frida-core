namespace Frida {
	internal sealed class MappedAgent {
		private uint pid;
		private Bytes blob;
		private Gum.ElfModule module;
		private size_t capacity;

		private const size_t RUNTIME_SLACK = 1024 * 1024;

		public MappedAgent (uint pid, FileDescriptorBased library_so) throws Error {
			this.pid = pid;

			try {
				blob = new MappedFile.from_fd (library_so.get_fd (), false).get_bytes ();
				module = new Gum.ElfModule.from_blob (blob);
			} catch (GLib.Error e) {
				throw new Error.INVALID_ARGUMENT ("Unable to parse agent: %s", e.message);
			}

			capacity = round_size_to_page_size ((size_t) module.mapped_size) + RUNTIME_SLACK;
		}

		public Bytes make_request () {
			Gee.List<string> missing = new TargetLibraries (pid).find_missing (module);

			var header = HelperMappedAgentRequest ();
			header.size = capacity;
			header.dependency_count = missing.size;

			var request = new ByteArray ();
			request.append ((uint8[]) &header);
			foreach (string name in missing) {
				uint16 length = (uint16) name.length;
				request.append ((uint8[]) &length);
				request.append (name.data);
			}

			return ByteArray.free_to_bytes (request);
		}

		public Bytes map (uint64 base_address, string entrypoint) throws Error {
			try {
				var libraries = new TargetLibraries (pid);
				var memory = new MappedAgentMemory (pid, blob, module, base_address, capacity);

				var mapper = Gum.Mapper.new_take_blob ("frida-agent.so", blob, libraries.make_resolver (module));
				mapper.set_target (memory);

				Gum.Address extra_address;
				mapper.map (0, out extra_address);

				Gum.Address entrypoint_address = mapper.resolve (entrypoint);
				if (entrypoint_address == 0)
					throw new Error.INVALID_ARGUMENT ("Unable to find entrypoint");

				return memory.finish (mapper.constructor (), mapper.destructor (), entrypoint_address);
			} catch (Gum.Error e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
		}
	}

	private sealed class TargetLibraries {
		private uint pid;
		private ProcMapsSnapshot maps;
		private Gee.Map<string, Gum.ElfModule> modules = new Gee.HashMap<string, Gum.ElfModule> ();

		public TargetLibraries (uint pid) {
			this.pid = pid;
			this.maps = ProcMapsSnapshot.from_pid (pid);
		}

		public Gee.List<string> find_missing (Gum.ElfModule agent) {
			var missing = new Gee.ArrayList<string> ();
			agent.enumerate_dependencies (d => {
				if (find (d.name) == null)
					missing.add (d.name);
				return true;
			});
			return missing;
		}

		public Gum.ElfModuleResolver make_resolver (Gum.ElfModule agent) throws Error {
			var resolver = new Gum.ElfModuleResolver ();

			var pending = new Gee.ArrayQueue<string> ();
			var seen = new Gee.HashSet<string> ();
			agent.enumerate_dependencies (d => {
				pending.offer (d.name);
				return true;
			});

			string? name;
			while ((name = pending.poll ()) != null) {
				ProcMapsSnapshot.Mapping? mapping = find (name);
				if (mapping == null)
					throw new Error.NOT_SUPPORTED ("Unable to find %s in the target process", name);
				if (!seen.add (mapping.path))
					continue;

				Gum.ElfModule library = load (mapping);
				resolver.add_module (library, mapping.start);

				library.enumerate_dependencies (d => {
					pending.offer (d.name);
					return true;
				});
			}

			return resolver;
		}

		private ProcMapsSnapshot.Mapping? find (string name) {
			foreach (ProcMapsSnapshot.Mapping m in maps) {
				if (is_library_start (m) && library_name_matches (name, Path.get_basename (m.path)))
					return m;
			}

			foreach (ProcMapsSnapshot.Mapping m in maps) {
				if (!is_library_start (m))
					continue;
				try {
					if (load (m).soname == name)
						return m;
				} catch (Error e) {
				}
			}

			return null;
		}

		private static bool is_library_start (ProcMapsSnapshot.Mapping m) {
			return m.file_offset == 0 && m.path.has_prefix ("/");
		}

		private static bool library_name_matches (string name, string basename) {
			switch (name) {
				case "ld-android.so":
					return basename == "linker" || basename == "linker64";
				case "libc.so":
					return basename == name || basename.has_prefix ("ld-musl-");
				default:
					return basename == name;
			}
		}

		private Gum.ElfModule load (ProcMapsSnapshot.Mapping mapping) throws Error {
			Gum.ElfModule? module = modules[mapping.path];
			if (module == null) {
				module = open_mapped_file (mapping);
				if (module == null)
					module = copy_from_target (mapping);
				modules[mapping.path] = module;
			}
			return module;
		}

		private Gum.ElfModule? open_mapped_file (ProcMapsSnapshot.Mapping mapping) {
			try {
				return new Gum.ElfModule.from_file (("/proc/%u/map_files/%" + uint64.FORMAT_MODIFIER + "x-%" +
					uint64.FORMAT_MODIFIER + "x").printf (pid, mapping.start, mapping.end));
			} catch (Gum.Error e) {
			}

			string path = "/proc/%u/root%s".printf (pid, mapping.path);
			Posix.Stat st;
			if (Posix.stat (path, out st) != 0 || st.st_ino != mapping.inode)
				return null;

			try {
				return new Gum.ElfModule.from_file (path);
			} catch (Gum.Error e) {
				return null;
			}
		}

		private Gum.ElfModule copy_from_target (ProcMapsSnapshot.Mapping first) throws Error {
			var segments = new Gee.ArrayList<ProcMapsSnapshot.Mapping> ();
			uint64 end = first.end;
			foreach (ProcMapsSnapshot.Mapping m in maps) {
				if (m.path == first.path && m.inode == first.inode && m.readable) {
					segments.add (m);
					end = uint64.max (end, m.end);
				}
			}

			var image = new uint8[end - first.start];
			var mem = new FileDescriptor (Posix.open ("/proc/%u/mem".printf (pid), Posix.O_RDONLY));
			if (mem.handle == -1)
				throw new Error.PERMISSION_DENIED ("Unable to read memory of process %u", pid);
			foreach (ProcMapsSnapshot.Mapping m in segments)
				mem.pread (image[m.start - first.start:m.end - first.start], m.start);

			var blob = new Bytes.take ((owned) image);
			var module = (Gum.ElfModule) Object.new (typeof (Gum.ElfModule),
				"base-address", (Gum.Address) first.start,
				"source-path", first.path,
				"source-blob", blob,
				"source-mode", Gum.ElfSourceMode.ONLINE);
			try {
				module.load ();
			} catch (Gum.Error e) {
				throw new Error.NOT_SUPPORTED ("Unable to parse %s: %s", first.path, e.message);
			}
			return module;
		}
	}

	private sealed class MappedAgentMemory : Object, Gum.ProcessMemory {
		private uint pid;
		private Bytes blob;
		private Gum.ElfModule agent;
		private uint64 base_address;
		private size_t capacity;

		private uint8[]? shadow;
		private bool[] dirty;
		private ByteArray ops = new ByteArray ();
		private uint op_count;

		public MappedAgentMemory (uint pid, Bytes blob, Gum.ElfModule agent, uint64 base_address, size_t capacity) {
			this.pid = pid;
			this.blob = blob;
			this.agent = agent;
			this.base_address = base_address;
			this.capacity = capacity;
		}

		public Bytes finish (uint64 constructor, uint64 destructor, uint64 entrypoint) {
			var writes = new ByteArray ();
			uint write_count = 0;
			size_t page_size = Gum.query_page_size ();
			uint page = 0;
			while (page != dirty.length) {
				if (!dirty[page]) {
					page++;
					continue;
				}

				uint first = page;
				while (page != dirty.length && dirty[page])
					page++;

				size_t offset = first * page_size;
				size_t size = (page - first) * page_size;

				var op = HelperMappedAgentOp ();
				op.type = WRITE;
				op.address = base_address + offset;
				op.size = size;
				writes.append ((uint8[]) &op);
				writes.append (shadow[offset:offset + size]);
				write_count++;
			}

			var header = HelperMappedAgent ();
			header.constructor = constructor;
			header.destructor = destructor;
			header.entrypoint = entrypoint;
			header.op_count = write_count + op_count;

			var plan = new ByteArray.sized ((uint) (sizeof (HelperMappedAgent) + writes.len + ops.len));
			plan.append ((uint8[]) &header);
			plan.append (writes.data);
			plan.append (ops.data);

			return ByteArray.free_to_bytes (plan);
		}

		public Gum.ProcessId get_pid () {
			return pid;
		}

		public Gum.Address alloc (size_t size, size_t alignment) {
			if (shadow != null || size > capacity)
				return 0;

			shadow = new uint8[capacity];
			dirty = new bool[capacity / Gum.query_page_size ()];

			return base_address;
		}

		public Gum.Address alloc_near (Gum.Address near_address, size_t max_distance, size_t size, size_t alignment) {
			return 0;
		}

		public void free (Gum.Address address, size_t size) {
		}

		public bool read (Gum.Address address, uint8[] buffer) {
			if (!contains (address, buffer.length))
				return false;
			Memory.copy (buffer, (uint8 *) shadow + (address - base_address), buffer.length);
			return true;
		}

		public bool write (Gum.Address address, uint8[] data) {
			if (!contains (address, data.length))
				return false;
			size_t offset = (size_t) (address - base_address);
			Memory.copy ((uint8 *) shadow + offset, data, data.length);
			size_t page_size = Gum.query_page_size ();
			for (size_t page = offset / page_size; page * page_size < offset + data.length; page++)
				dirty[page] = true;
			return true;
		}

		public bool map (Gum.Address address, size_t size, uint8[] data, Gum.PageProtection prot) {
			uint64 offset;
			size_t file_size;
			if (find_file_range (address, out offset, out file_size)) {
				unowned uint8[] file = blob.get_data ();
				size_t n = size_t.min (data.length, file_size);
				if (data.length - n < Gum.query_page_size () && Memory.cmp ((uint8 *) file + offset, data, n) == 0) {
					add_op (MAP, prot, address, size, offset);
					return true;
				}
			}

			return write (address, data) && protect (address, size, prot);
		}

		public bool protect (Gum.Address address, size_t size, Gum.PageProtection prot) {
			add_op (PROTECT, prot, address, size, 0);
			return true;
		}

		public bool mark_code (Gum.Address address, size_t size) {
			add_op (MARK_CODE, Gum.PageProtection.READ | Gum.PageProtection.EXECUTE, address, size, 0);
			return true;
		}

		private bool contains (uint64 address, size_t size) {
			return shadow != null && address >= base_address && address + size <= base_address + capacity;
		}

		private bool find_file_range (uint64 address, out uint64 offset, out size_t file_size) {
			uint64 vaddr = address - base_address + agent.base_address;
			uint64 found_offset = 0;
			size_t found_size = 0;
			agent.enumerate_segments (s => {
				if (vaddr < s.vm_address || vaddr >= s.vm_address + s.file_size)
					return true;
				found_offset = s.file_offset + (vaddr - s.vm_address);
				found_size = (size_t) (s.vm_address + s.file_size - vaddr);
				return false;
			});

			offset = found_offset;
			file_size = found_size;

			return found_size != 0 && found_offset % Gum.query_page_size () == 0;
		}

		private void add_op (HelperMappedAgentOpType type, Gum.PageProtection prot, uint64 address, size_t size,
				uint64 offset) {
			var op = HelperMappedAgentOp ();
			op.type = type;
			op.prot = prot;
			op.address = address;
			op.size = size;
			op.offset = offset;
			ops.append ((uint8[]) &op);
			op_count++;
		}
	}
}
