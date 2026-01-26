namespace Frida {
	private uint linux_major = 0;
	private uint linux_minor = 0;

	public bool check_kernel_version (uint major, uint minor) {
		if (linux_major == 0) {
			var name = Posix.utsname ();
			name.release.scanf ("%u.%u", out linux_major, out linux_minor);
		}

		return (linux_major == major && linux_minor >= minor) || linux_major > major;
	}

	public sealed class PidFileDescriptor : FileDescriptor {
		private uint pid;

		private PidFileDescriptor (int fd, uint pid) {
			base (fd);
			this.pid = pid;
		}

		public static bool is_supported () {
			return check_kernel_version (5, 3);
		}

		public static bool getfd_is_supported () {
			return check_kernel_version (5, 6);
		}

		public static PidFileDescriptor from_pid (uint pid) throws Error {
			int fd = pidfd_open (pid, 0);
			if (fd == -1)
				throw_pidfd_error (pid, errno);
			return new PidFileDescriptor (fd, pid);
		}

		public FileDescriptor getfd (int targetfd) throws Error {
			int fd = pidfd_getfd (handle, targetfd, 0);
			if (fd == -1)
				throw_pidfd_error (pid, errno);
			return new FileDescriptor (fd);
		}

		private static int pidfd_open (uint pid, uint flags) {
			return Linux.syscall (LinuxSyscall.PIDFD_OPEN, pid, flags);
		}

		private static int pidfd_getfd (int pidfd, int targetfd, uint flags) {
			return Linux.syscall (LinuxSyscall.PIDFD_GETFD, pidfd, targetfd, flags);
		}

		[NoReturn]
		private static void throw_pidfd_error (uint pid, int err) throws Error {
			switch (err) {
				case Posix.ESRCH:
					throw new Error.PROCESS_NOT_FOUND ("Process not found");
				case Posix.EPERM:
					throw new Error.PERMISSION_DENIED ("Unable to use pidfd for pid %u: %s", pid, strerror (err));
				default:
					throw new Error.NOT_SUPPORTED ("Unable to use pidfd for pid %u: %s", pid, strerror (err));
			}
		}
	}

	namespace MemoryFileDescriptor {
		public bool is_supported () {
			return check_kernel_version (3, 17);
		}

		public static FileDescriptor from_bytes (string name, Bytes bytes) {
			assert (is_supported ());

			var fd = new FileDescriptor (memfd_create (name, 0));
			unowned uint8[] data = bytes.get_data ();
			ssize_t n = Posix.write (fd.handle, data, data.length);
			assert (n == data.length);
			return fd;
		}

		private int memfd_create (string name, uint flags) {
			return Linux.syscall (LinuxSyscall.MEMFD_CREATE, name, flags);
		}
	}

	[CCode (gir_namespace = "FridaBpf", gir_version = "1.0")]
	namespace Bpf {
		public FileDescriptor load_program_from_elf (BpfProgramType prog_type, Gum.ElfModule elf, string section_name,
				Gee.Map<string, Map> maps, string license) throws Error {
			Bytes relocated_prog = relocate_program_section (elf, section_name, maps);
			unowned BpfInsn[] insns = (BpfInsn[]) relocated_prog.get_data ();

			return load_program (prog_type, insns, license);
		}

		private FileDescriptor load_program (BpfProgramType prog_type, BpfInsn[] insns, string license) throws Error {
			const uint32 log_size = 65536;

			uint8[] logbuf = new uint8[log_size];

			var attr = BpfAttrProgLoad ();

			attr.prog_type = prog_type;
			attr.insn_cnt = insns.length;
			attr.insns = (uintptr) (insns.length > 0 ? &insns[0] : null);
			attr.license = (uintptr) license;

			attr.log_level = 1;
			attr.log_size = log_size;
			attr.log_buf = (uintptr) (&logbuf[0]);

			try {
				return new FileDescriptor (bpf_call (PROG_LOAD, &attr, (size_t) sizeof (BpfAttrProgLoad)));
			} catch (Error e) {
				unowned string verifier_log = (string) &logbuf[0];
				if (verifier_log.length == 0)
					throw e;
				var message = new StringBuilder.sized (1024);
				message
					.append (e.message)
					.append (": ")
					.append (verifier_log);
				throw new Error.INVALID_ARGUMENT ("%s", message.str);
			}
		}

		private Bytes relocate_program_section (Gum.ElfModule elf, string section_name, Gee.Map<string, Map> maps)
				throws Error {
			Gum.ElfSectionDetails? section = null;

			elf.enumerate_sections (s => {
				if (s.name == section_name) {
					section = s;
					return false;
				}
				return true;
			});

			if (section == null)
				throw new Error.PROTOCOL ("Missing '%s' section in eBPF ELF", section_name);

			var sec_off = (size_t) section.offset;
			var sec_size = (size_t) section.size;

			var relocated = new Bytes (elf.get_file_data ()[sec_off:sec_off + sec_size]);
			var buf = new Buffer (relocated);

			string rel_section_name = ".rel" + section_name;
			Error? pending_error = null;

			elf.enumerate_relocations (r => {
				unowned string parent = r.parent.name;
				if (parent != rel_section_name)
					return true;

				unowned string sym = r.symbol.name;

				Map? map = maps[sym];
				if (map == null) {
					pending_error = new Error.NOT_SUPPORTED ("No Bpf.Map provided for symbol '%s'".printf (sym));
					return false;
				}

				try {
					apply_bpf_map_relocation (r, map, buf);
				} catch (Error e) {
					pending_error = e;
					return false;
				}

				return true;
			});

			if (pending_error != null)
				throw pending_error;

			return buf.bytes;
		}

		private void apply_bpf_map_relocation (Gum.ElfRelocationDetails r, Map map, Buffer buf) throws Error {
			size_t off = (size_t) r.address;
			if (off + 16 > buf.bytes.get_size ())
				throw new Error.NOT_SUPPORTED ("BPF relocation out of range");

			uint8 code0 = buf.read_uint8 (off + 0);
			if (code0 != 0x18)
				throw new Error.NOT_SUPPORTED ("Expected LD_IMM64 at relocation site (got 0x%02x)".printf (code0));

			uint8 dst_src = buf.read_uint8 (off + 1);
			uint8 dst = dst_src & 0x0f;
			const uint8 BPF_PSEUDO_MAP_FD = 1;
			uint8 patched_dst_src = dst | (BPF_PSEUDO_MAP_FD << 4);
			buf.write_uint8 (off + 1, patched_dst_src);
			buf.write_int32 (off + 4, map.fd.handle);
			buf.write_int32 (off + 12, 0);
		}

		public abstract class Map {
			public BpfMapType map_type {
				get;
				private set;
			}

			public FileDescriptor fd {
				get;
				private set;
			}

			protected Map (BpfMapType type, FileDescriptor fd) {
				this.map_type = type;
				this.fd = fd;
			}
		}

		public sealed class ArrayMap : Map {
			public ArrayMap (size_t value_size, size_t max_entries) throws Error {
				var attr = BpfAttrMapCreate ();
				attr.map_type = ARRAY;
				attr.key_size = (uint32) sizeof (uint32);
				attr.value_size = (uint32) value_size;
				attr.max_entries = (uint32) max_entries;

				base (ARRAY, new FileDescriptor (bpf_call (MAP_CREATE, &attr, sizeof (BpfAttrMapCreate))));
			}

			public void update_u32 (uint32 key, uint32 val) throws Error {
				Bpf.update_map_value (fd, key, &val);
			}

			public uint32 lookup_u32 (uint32 key) throws Error {
				uint32 val = 0;
				Bpf.lookup_map_value (fd, key, &val);
				return val;
			}

			public void update_raw (uint32 key, void * val) throws Error {
				Bpf.update_map_value (fd, key, val);
			}

			public void lookup_raw (uint32 key, void * val) throws Error {
				Bpf.lookup_map_value (fd, key, val);
			}
		}

		public sealed class PercpuArrayMap : Map {
			public PercpuArrayMap (size_t value_size, size_t max_entries) throws Error {
				var attr = BpfAttrMapCreate ();
				attr.map_type = PERCPU_ARRAY;
				attr.key_size = (uint32) sizeof (uint32);
				attr.value_size = (uint32) value_size;
				attr.max_entries = (uint32) max_entries;

				base (PERCPU_ARRAY, new FileDescriptor (bpf_call (MAP_CREATE, &attr, sizeof (BpfAttrMapCreate))));
			}
		}

		public sealed class StackTraceMap : Map {
			public size_t max_stack_depth {
				get;
				private set;
			}

			public size_t max_entries {
				get;
				private set;
			}

			public StackTraceMap (size_t max_stack_depth, size_t max_entries, BpfStackTraceMapFlags flags = 0) throws Error {
				var attr = BpfAttrMapCreate ();
				attr.map_type = STACK_TRACE;
				attr.key_size = (uint32) sizeof (uint32);
				attr.value_size = (uint32) (max_stack_depth * (uint32) sizeof (uint64));
				attr.max_entries = (uint32) max_entries;
				attr.map_flags = flags;

				base (STACK_TRACE, new FileDescriptor (bpf_call (MAP_CREATE, &attr, sizeof (BpfAttrMapCreate))));

				this.max_stack_depth = max_stack_depth;
				this.max_entries = max_entries;
			}

			public void lookup_raw (uint32 stack_id, void * out_value) throws Error {
				Bpf.lookup_map_value (fd, stack_id, out_value);
			}
		}

		public sealed class RingbufMap : Map {
			public size_t size_bytes {
				get;
				private set;
			}

			public RingbufMap (size_t size_bytes) throws Error {
				var attr = BpfAttrMapCreate ();
				attr.map_type = RINGBUF;
				attr.key_size = 0;
				attr.value_size = 0;
				attr.max_entries = (uint32) size_bytes;

				base (RINGBUF, new FileDescriptor (bpf_call (MAP_CREATE, &attr, sizeof (BpfAttrMapCreate))));

				this.size_bytes = size_bytes;
			}
		}

		public sealed class RingbufReader : Object {
			public delegate void RecordHandler (uint8[] payload);

			private RingbufMap map;

			private uint8 * consumer_map;
			private uint8 * producer_map;

			private uint8 * producer_page;
			private uint8 * data_base;

			private uint64 * consumer_pos;
			private uint64 * producer_pos;

			public RingbufReader (RingbufMap map) throws Error {
				this.map = map;

				var page_size = (size_t) Posix.getpagesize ();
				int fd = map.fd.handle;

				void * mem = Posix.mmap (null, page_size, Posix.PROT_READ | Posix.PROT_WRITE, Posix.MAP_SHARED, fd, 0);
				if (mem == Posix.MAP_FAILED)
					throw_errno ("mmap(consumer) failed");
				consumer_map = mem;

				size_t prod_len = page_size + (2 * map.size_bytes);
				mem = Posix.mmap (null, prod_len, Posix.PROT_READ, Posix.MAP_SHARED, fd, (Posix.off_t) page_size);
				if (mem == Posix.MAP_FAILED)
					throw_errno ("mmap(producer+data) failed");
				producer_map = mem;

				producer_page = producer_map;
				data_base = producer_map + page_size;

				consumer_pos = consumer_map;
				producer_pos = producer_page;
			}

			~RingbufReader () {
				var page_size = (size_t) Posix.getpagesize ();

				if (consumer_map != null)
					Posix.munmap (consumer_map, page_size);

				if (producer_map != null)
					Posix.munmap (producer_map, page_size + (2 * map.size_bytes));
			}

			private static uint32 round_up_8 (uint32 x) {
				return (x + 7U) & ~7U;
			}

			public void drain (RecordHandler on_record) {
				while (true) {
					uint64 prod = Atomics.load_u64_acquire (producer_pos);
					uint64 cons = Atomics.load_u64_acquire (consumer_pos);

					if (cons >= prod)
						return;

					size_t data_size = map.size_bytes;
					uint64 mask = data_size - 1;
					uint64 off = cons & mask;
					uint8 * hdrp = data_base + off;

					uint32 hdr_len = Atomics.load_u32_acquire ((uint32 *) hdrp);
					uint32 flags_mask = BpfRingbufFlags.BUSY | BpfRingbufFlags.DISCARD;
					uint32 flags = hdr_len & flags_mask;
					uint32 sample_len = hdr_len & ~flags_mask;

					if ((flags & BpfRingbufFlags.BUSY) != 0)
						return;

					assert (sample_len <= data_size - BPF_RINGBUF_HEADER_SIZE);

					uint32 total_len = round_up_8 (sample_len + BPF_RINGBUF_HEADER_SIZE);

					if ((flags & BpfRingbufFlags.DISCARD) != 0) {
						Atomics.store_u64_release (consumer_pos, cons + total_len);
						continue;
					}

					unowned uint8[] payload = (uint8[]) (hdrp + BPF_RINGBUF_HEADER_SIZE);
					on_record (payload[:sample_len]);

					Atomics.store_u64_release (consumer_pos, cons + total_len);
				}
			}
		}

		private void lookup_map_value (FileDescriptor map_fd, uint32 key, void * value) throws Error {
			var attr = BpfAttrMapElem ();
			attr.map_fd = map_fd.handle;
			attr.key = (uintptr) (&key);
			attr.value = (uintptr) value;

			bpf_call (MAP_LOOKUP_ELEM, &attr, sizeof (BpfAttrMapElem));
		}

		private void update_map_value (FileDescriptor map_fd, uint32 key, void * value) throws Error {
			var attr = BpfAttrMapElem ();
			attr.map_fd = map_fd.handle;
			attr.key = (uintptr) (&key);
			attr.value = (uintptr) value;
			attr.flags = BPF_ANY;

			bpf_call (MAP_UPDATE_ELEM, &attr, sizeof (BpfAttrMapElem));
		}

		private int bpf_call (BpfCommand cmd, void * attr, size_t attr_size) throws Error {
			int r = Linux.syscall (LinuxSyscall.BPF, cmd, attr, attr_size);
			if (r == -1)
				throw_errno ("bpf() failed (cmd=%d)".printf (cmd));
			return r;
		}
	}

	namespace PerfEvent {
		public class Monitor {
			public FileDescriptor fd;

			public Monitor (PerfEventAttr * attr, int pid, int cpu, int group_fd, uint flags) throws Error {
				int r = Linux.syscall (LinuxSyscall.PERF_EVENT_OPEN, attr, pid, cpu, group_fd, flags);
				if (r == -1)
					throw_errno ("perf_event_open() failed");
				this.fd = new FileDescriptor (r);
			}

			public void set_bpf (FileDescriptor program) throws Error {
				if (Posix.ioctl (fd.handle, (int) PerfEventIoctl.SET_BPF, program.handle) == -1)
					throw_errno ("PerfEventIoctl.SET_BPF failed");
			}

			public void enable () throws Error {
				if (Posix.ioctl (fd.handle, (int) PerfEventIoctl.ENABLE, 0) == -1)
					throw_errno ("PerfEventIoctl.ENABLE failed");
			}

			public void disable () throws Error {
				if (Posix.ioctl (fd.handle, (int) PerfEventIoctl.DISABLE, 0) == -1)
					throw_errno ("PerfEventIoctl.DISABLE failed");
			}
		}

		public uint32 get_tracepoint_id (string category, string name) throws Error {
			string[] roots = {
				"/sys/kernel/tracing",
				"/sys/kernel/debug/tracing",
			};

			foreach (var root in roots) {
				string path = "%s/events/%s/%s/id".printf (root, category, name);
				if (!FileUtils.test (path, FileTest.EXISTS))
					continue;

				string contents;
				try {
					FileUtils.get_contents (path, out contents);
				} catch (FileError e) {
					throw new Error.PERMISSION_DENIED ("%s", e.message);
				}

				return uint.parse (contents.chomp ());
			}

			throw new Error.NOT_SUPPORTED ("Tracefs not available (need tracefs/debugfs mounted and readable)");
		}
	}

	private void throw_errno (string message) throws Error {
		throw new Error.NOT_SUPPORTED ("%s (errno=%d: %s)".printf (message, Posix.errno, Posix.strerror (Posix.errno)));
	}
}
