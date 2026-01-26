namespace Frida {
	public sealed class SyscallTracer : Object {
		public uint pid {
			get;
			construct;
		}

		private Bpf.ArrayMap? target_tgid;

		private Bpf.RingbufReader? events_reader;
		private Source? events_source;

		private Bpf.StackTraceMap? stacks;

		private FileDescriptor? prog_fd;

		private Gee.Collection<PerfEvent.Monitor> monitors = new Gee.ArrayList<PerfEvent.Monitor> ();

		private static string?[] syscall_names;

		private const size_t RINGBUF_SIZE = 1U << 22;

		private const size_t MAX_DEPTH = 16;
		private const size_t MAX_STACK_ENTRIES = 16384;
		private const size_t MAX_PATH = 256;
		private const size_t MAX_SOCK = 128;

		public SyscallTracer (uint pid) {
			Object (pid: pid);
		}

		static construct {
			var syscall_enum = (EnumClass) typeof (LinuxSyscall).class_ref ();

			var max_value = 0;
			for (uint i = 0; i != syscall_enum.n_values; i++) {
				var v = syscall_enum.values[i].value;
				if (v > max_value)
					max_value = v;
			}

			syscall_names = new string?[max_value + 1];

			for (uint i = 0; i != syscall_enum.n_values; i++) {
				var ev = syscall_enum.values[i];
				syscall_names[ev.value] = ev.value_nick.replace ("-", "_");
			}
		}

		protected override void dispose () {
			stop ();

			base.dispose ();
		}

		public void start () throws Error {
			target_tgid = new Bpf.ArrayMap (sizeof (uint32), 1);
			target_tgid.update_u32 (0, pid);

			var events = new Bpf.RingbufMap (RINGBUF_SIZE);
			events_reader = new Bpf.RingbufReader (events);

			stacks = new Bpf.StackTraceMap (MAX_DEPTH, MAX_STACK_ENTRIES);

			Gum.ElfModule elf;
			try {
				var raw_elf = new Bytes.static (Frida.Data.HelperBackend.get_syscall_tracer_elf_blob ().data);
				elf = new Gum.ElfModule.from_blob (raw_elf);
			} catch (Gum.Error e) {
				assert_not_reached ();
			}

			var maps = new Gee.HashMap<string, Bpf.Map> ();
			maps["target_tgid"] = target_tgid;
			maps["events"] = events;
			maps["stacks"] = stacks;

			prog_fd = Bpf.load_program_from_elf (TRACEPOINT, elf, "tracepoint/raw_syscalls/sys_enter", maps, "Dual BSD/GPL");

			uint32 tp_id = PerfEvent.get_tracepoint_id ("raw_syscalls", "sys_enter");

			uint ncpus = get_num_processors ();
			for (uint cpu = 0; cpu != ncpus; cpu++) {
				var pea = PerfEventAttr ();
				pea.event_type = TRACEPOINT;
				pea.size = (uint32) sizeof (PerfEventAttr);
				pea.config = tp_id;
				pea.sample_period = 1; // TODO: Is this used?

				var monitor = new PerfEvent.Monitor (&pea, -1, 0, -1, 0);
				if (cpu == 0)
					monitor.set_bpf (prog_fd);
				monitor.enable ();

				monitors.add (monitor);
			}

			var ch = new IOChannel.unix_new (events.fd.handle);
			var src = new IOSource (ch, IN);
			var state = new WatchState (this, events_reader);
			src.set_callback (state.on_ready);
			src.attach (MainContext.get_thread_default ());
			events_source = src;
		}

		public void stop () {
			events_source?.destroy ();
			events_source = null;

			foreach (var monitor in monitors) {
				try {
					monitor.disable ();
				} catch (Error e) {
					assert_not_reached ();
				}
			}
			monitors.clear ();

			prog_fd = null;
			stacks = null;
			events_reader = null;
			target_tgid = null;
		}

		private void handle_event (uint8[] payload) {
			assert (payload.length >= sizeof (SyscallEvent));

			unowned SyscallEvent * e = (SyscallEvent *) payload;

			size_t header_len = sizeof (SyscallEvent);
			size_t payload_len = (size_t) e->payload_len;
			assert (payload.length == header_len + payload_len);

			uint8 * p = (uint8 *) payload + header_len;

			switch ((EventKind) e->kind) {
			case OPENAT: {
				assert (payload_len == sizeof (PayloadOpenat));

				unowned PayloadOpenat * o = (PayloadOpenat *) p;
				unowned string path = (o->path_len != 0) ? (string) &o->path[0] : "";

				log_event (e, "dfd=%d path=\"%s\" flags=%d mode=0%o", o->dfd, path, o->flags, o->mode);
				break;
			}
			case STATFS: {
				assert (payload_len == sizeof (PayloadStatfs));

				unowned PayloadStatfs * s = (PayloadStatfs *) p;
				unowned string path = (s->path_len != 0) ? (string) &s->path[0] : "";

				log_event (e, "path=\"%s\"", path);
				break;
			}
			case CONNECT: {
				assert (payload_len == sizeof (PayloadConnect));

				unowned PayloadConnect * c = (PayloadConnect *) p;

				log_event (e, "fd=%d family=%u addrlen=%u", c->fd, c->family, c->addrlen);
				break;
			}

			default:
				log_event (e);
				break;
			}
		}

		private void log_event (SyscallEvent * e, string format = "", ...) {
			uint nr = (uint) e->syscall_nr;
			unowned string? name = null;
			if (nr < syscall_names.length)
				name = syscall_names[nr];

			var args = va_list ();
			print ("[time=%" + uint64.FORMAT + " tgid=%u tid=%u stack_id=%d] %s %s\n",
				e->time_ns,
				e->tgid,
				e->tid,
				e->stack_id,
				(name != null) ? name : "?",
				format.vprintf (args));
		}

		private enum EventKind {
			GENERIC,
			OPENAT,
			STATFS,
			CONNECT,
		}

		[Compact]
		private struct SyscallEvent {
			public uint64 time_ns;
			public uint32 tgid;
			public uint32 tid;
			public uint32 syscall_nr;
			public int32 stack_id;
			public uint16 kind;
			public uint16 payload_len;
		}

		[Compact]
		private struct PayloadOpenat {
			public int32 dfd;
			public int32 flags;
			public uint32 mode;
			public uint32 path_len;
			public uint8 path[MAX_PATH];
		}

		[Compact]
		private struct PayloadStatfs {
			public uint32 path_len;
			public uint8 path[MAX_PATH];
		}

		[Compact]
		private struct PayloadConnect {
			public int32 fd;
			public uint32 addrlen;
			public uint16 family;
			public uint16 pad;
			public uint8 addr[MAX_SOCK];
		}

		private sealed class WatchState : Object {
			public unowned SyscallTracer tracer;
			public Bpf.RingbufReader reader;

			public WatchState (SyscallTracer tracer, Bpf.RingbufReader reader) {
				this.tracer = tracer;
				this.reader = reader;
			}

			public bool on_ready (IOChannel ch, IOCondition cond) {
				reader.drain (payload => {
					assert (payload.length >= sizeof (SyscallEvent));
					tracer.handle_event (payload);
				});
				return Source.CONTINUE;
			}
		}
	}
}
