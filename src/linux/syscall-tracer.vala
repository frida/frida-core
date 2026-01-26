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

		private Bpf.HashMap? readlinkat_args;

		private FileDescriptor? prog_enter_fd;
		private FileDescriptor? prog_exit_fd;

		private Gee.Collection<PerfEvent.Monitor> monitors = new Gee.ArrayList<PerfEvent.Monitor> ();

		private static string?[] syscall_names;

		private const size_t RINGBUF_SIZE = 1U << 22;

		private const size_t MAX_DEPTH = 16;
		private const size_t MAX_STACK_ENTRIES = 16384;
		private const size_t MAX_READLINKAT_ARGS_ENTRIES = 4096;
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

			readlinkat_args = new Bpf.HashMap (sizeof (uint64) + sizeof (uint32) + sizeof (uint32),
				MAX_READLINKAT_ARGS_ENTRIES);

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
			maps["readlinkat_args"] = readlinkat_args;

			prog_enter_fd = Bpf.load_program_from_elf (TRACEPOINT, elf, "tracepoint/raw_syscalls/sys_enter", maps, "Dual BSD/GPL");
			prog_exit_fd = Bpf.load_program_from_elf (TRACEPOINT, elf, "tracepoint/raw_syscalls/sys_exit", maps, "Dual BSD/GPL");

			uint32 enter_tp_id = PerfEvent.get_tracepoint_id ("raw_syscalls", "sys_enter");
			uint32 exit_tp_id = PerfEvent.get_tracepoint_id ("raw_syscalls", "sys_exit");

			uint ncpus = get_num_processors ();
			for (uint cpu = 0; cpu != ncpus; cpu++) {
				{
					var pea = PerfEventAttr ();
					pea.event_type = TRACEPOINT;
					pea.size = (uint32) sizeof (PerfEventAttr);
					pea.config = enter_tp_id;
					pea.sample_period = 1;

					var m = new PerfEvent.Monitor (&pea, -1, 0, -1, 0);
					if (cpu == 0)
						m.set_bpf (prog_enter_fd);
					m.enable ();
					monitors.add (m);
				}

				{
					var pea = PerfEventAttr ();
					pea.event_type = TRACEPOINT;
					pea.size = (uint32) sizeof (PerfEventAttr);
					pea.config = exit_tp_id;
					pea.sample_period = 1;

					var m = new PerfEvent.Monitor (&pea, -1, 0, -1, 0);
					if (cpu == 0)
						m.set_bpf (prog_exit_fd);
					m.enable ();
					monitors.add (m);
				}
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

			prog_exit_fd = null;
			prog_enter_fd = null;
			readlinkat_args = null;
			stacks = null;
			events_reader = null;
			target_tgid = null;
		}

		private void handle_event (uint8[] payload) {
			assert (payload.length >= sizeof (SyscallEvent));

			unowned SyscallEvent * e = (SyscallEvent *) payload;

			var phase = (Phase) e->phase;

			size_t header_len = sizeof (SyscallEvent);
			size_t payload_len = (size_t) e->payload_len;
			assert (payload.length == header_len + payload_len);

			uint8 * p = (uint8 *) payload + header_len;

			switch ((EventKind) e->kind) {
			case OPENAT: {
				if (phase == ENTER) {
					assert (payload_len == sizeof (PayloadOpenat));

					unowned PayloadOpenat * o = (PayloadOpenat *) p;
					unowned string path = (o->path_len != 0) ? (string) &o->path[0] : "";

					log_event (e, "enter dfd=%d path=\"%s\" flags=%d mode=0%o", o->dfd, path, o->flags, o->mode);
				} else {
					log_event (e, "exit ret=%" + int64.FORMAT, e->retval);
				}
				break;
			}
			case FACCESSAT: {
				if (phase == ENTER) {
					assert (payload_len == sizeof (PayloadFaccessat));

					unowned PayloadFaccessat * a = (PayloadFaccessat *) p;
					unowned string path = (a->path_len != 0) ? (string) &a->path[0] : "";

					log_event (e, "enter dfd=%d path=\"%s\" mode=%d flags=%d", a->dfd, path, a->mode, a->flags);
				} else {
					log_event (e, "exit ret=%" + int64.FORMAT, e->retval);
				}
				break;
			}
			case STATFS: {
				if (phase == ENTER) {
					assert (payload_len == sizeof (PayloadStatfs));

					unowned PayloadStatfs * s = (PayloadStatfs *) p;
					unowned string path = (s->path_len != 0) ? (string) &s->path[0] : "";

					log_event (e, "enter path=\"%s\"", path);
				} else {
					log_event (e, "exit ret=%" + int64.FORMAT, e->retval);
				}
				break;
			}
			case NEWFSTATAT: {
				if (phase == ENTER) {
					assert (payload_len == sizeof (PayloadNewfstatat));

					unowned PayloadNewfstatat * s = (PayloadNewfstatat *) p;
					unowned string path = (s->path_len != 0) ? (string) &s->path[0] : "";

					log_event (e, "enter dfd=%d path=\"%s\" flags=%d", s->dfd, path, s->flags);
				} else {
					log_event (e, "exit ret=%" + int64.FORMAT, e->retval);
				}
				break;
			}
			case READLINKAT: {
				if (phase == ENTER) {
					assert (payload_len == sizeof (PayloadReadlinkat));
					unowned PayloadReadlinkat * r = (PayloadReadlinkat *) p;
					unowned string path = (r->path_len != 0) ? (string) &r->path[0] : "";
					log_event (e, "enter dfd=%d path=\"%s\" bufsize=%u", r->dfd, path, r->bufsize);
				} else {
					assert (payload_len == sizeof (PayloadReadlinkatExit));
					unowned PayloadReadlinkatExit * x = (PayloadReadlinkatExit *) p;
					unowned string link = (x->link_len != 0) ? (string) &x->link[0] : "";
					log_event (e, "exit ret=%" + int64.FORMAT + " link=\"%s\"", e->retval, link);
				}
				break;
			}
			case CONNECT: {
				if (phase == ENTER) {
					assert (payload_len == sizeof (PayloadConnect));

					unowned PayloadConnect * c = (PayloadConnect *) p;

					string peer = format_sockaddr (
						c->family,
						c->addrlen,
						(uint8 *) &c->addr[0],
						MAX_SOCK
					);

					log_event (e, "enter fd=%d %s (family=%u addrlen=%u)", c->fd, peer, c->family, c->addrlen);
				} else {
					log_event (e, "exit ret=%" + int64.FORMAT, e->retval);
				}
				break;
			}
			default:
				if (phase == ENTER)
					log_event (e, "enter");
				else
					log_event (e, "exit ret=%" + int64.FORMAT, e->retval);
				break;
			}
		}

		private void log_event (SyscallEvent * e, string format = "", ...) {
			int nr = e->syscall_nr;
			unowned string? name = null;
			if (nr >= 0 && nr < syscall_names.length)
				name = syscall_names[nr];

			var args = va_list ();
			print ("[time=%" + uint64.FORMAT + " tgid=%u tid=%u stack_id=%d] %s %s\n",
				e->time_ns,
				e->tgid,
				e->tid,
				e->stack_id,
				(name != null) ? name : "%d".printf (nr),
				format.vprintf (args));
		}

		private enum EventKind {
			GENERIC,
			OPENAT,
			FACCESSAT,
			STATFS,
			NEWFSTATAT,
			READLINKAT,
			CONNECT,
		}

		private enum Phase {
			ENTER,
			EXIT,
		}

		[Compact]
		private struct SyscallEvent {
			public uint64 time_ns;
			public uint32 tgid;
			public uint32 tid;

			public int32 syscall_nr;
			public int32 stack_id;

			public uint16 kind;
			public uint16 payload_len;

			public uint16 phase;
			public int64 retval;
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
		private struct PayloadFaccessat {
			public int32 dfd;
			public int32 mode;
			public int32 flags;
			public uint32 path_len;
			public uint8 path[MAX_PATH];
		}

		[Compact]
		private struct PayloadStatfs {
			public uint32 path_len;
			public uint8 path[MAX_PATH];
		}

		[Compact]
		private struct PayloadNewfstatat {
			public int32 dfd;
			public int32 flags;
			public uint32 path_len;
			public uint8 path[MAX_PATH];
		}

		[Compact]
		private struct PayloadReadlinkat {
			public int32 dfd;
			public uint32 bufsize;
			public uint32 path_len;
			public uint8 path[MAX_PATH];
		}

		[Compact]
		private struct PayloadReadlinkatExit {
			public uint32 link_len;
			public uint8 link[MAX_PATH];
		}

		[Compact]
		private struct PayloadConnect {
			public int32 fd;
			public uint32 addrlen;
			public uint16 family;
			public uint16 pad;
			public uint8 addr[MAX_SOCK];
		}

		[Compact]
		private struct SockaddrIn {
			public uint16 sin_family;
			public uint16 sin_port;      // network byte order
			public uint32 sin_addr;      // network byte order
			public uint8  sin_zero[8];
		}

		[Compact]
		private struct In6Addr {
			public uint8 addr[16];
		}

		[Compact]
		private struct SockaddrIn6 {
			public uint16 sin6_family;
			public uint16 sin6_port;     // network byte order
			public uint32 sin6_flowinfo; // network byte order (usually 0)
			public In6Addr sin6_addr;
			public uint32 sin6_scope_id; // host order
		}

		[Compact]
		private struct SockaddrUn {
			public uint16 sun_family;
			public uint8  sun_path[108]; // Linux sizeof(sockaddr_un.sun_path)
		}

		private static string inet_ntop_to_string (int af, uint8 * src, size_t srclen) {
			uint8 buf[46];
			unowned string? res = Posix.inet_ntop (af, (void *) src, buf);
			return (res != null) ? res : "?";
		}

		private static string format_sockaddr (uint16 family, uint32 addrlen, uint8 * addr, size_t addr_buf_len) {
			// Clamp to what we actually have
			size_t len = (size_t) addrlen;
			if (len > addr_buf_len)
				len = addr_buf_len;

			switch ((int) family) {
			case Posix.AF_INET: {
				if (len < sizeof (SockaddrIn))
					return "inet: <truncated>";

				unowned SockaddrIn * sa = (SockaddrIn *) addr;
				uint16 port = uint16.from_network (sa->sin_port);

				// sin_addr is 4 bytes in network order
				string ip = inet_ntop_to_string (Posix.AF_INET, (uint8 *) &sa->sin_addr, 4);
				return "%s:%u".printf (ip, port);
			}

			case Posix.AF_INET6: {
				if (len < sizeof (SockaddrIn6))
					return "inet6: <truncated>";

				unowned SockaddrIn6 * sa6 = (SockaddrIn6 *) addr;
				uint16 port = uint16.from_network (sa6->sin6_port);

				string ip = inet_ntop_to_string (Posix.AF_INET6, (uint8 *) &sa6->sin6_addr.addr[0], 16);

				// Wrap IPv6 in brackets when appending port (common convention)
				if (sa6->sin6_scope_id != 0)
					return "[%s%%%u]:%u".printf (ip, sa6->sin6_scope_id, port);

				return "[%s]:%u".printf (ip, port);
			}

			case Posix.AF_UNIX: {
				// Linux: sockaddr_un has sun_family + sun_path
				if (len < 2)
					return "unix: <truncated>";

				unowned SockaddrUn * sun = (SockaddrUn *) addr;

				// Actual path bytes available in this instance:
				// addrlen may be smaller than full struct; subtract family (2 bytes)
				size_t path_bytes = (len > 2) ? (len - 2) : 0;
				if (path_bytes > 108)
					path_bytes = 108;

				if (path_bytes == 0)
					return "unix:\"\"";

				// Abstract namespace: first byte is '\0' (not NUL-terminated string)
				if (sun->sun_path[0] == 0) {
					// Render abstract as @ + bytes until end (or NUL if present)
					// We’ll stop at first NUL after the leading 0, or at path_bytes.
					size_t n = 1;
					while (n < path_bytes && sun->sun_path[n] != 0)
						n++;

					// Copy bytes [1..n) into a string safely
					// Note: abstract names are bytes; treat as UTF-8-ish for logging
					uint8[] tmp = new uint8[n]; // includes leading 0, we'll skip it
					Memory.copy (&tmp[0], &sun->sun_path[0], n);
					// Build string from bytes after leading 0
					string name = (n > 1) ? ((string) (&tmp[1])) : "";
					return "unix:@%s".printf (name);
				}

				// Filesystem path: sun_path is NUL-terminated (usually)
				// Ensure we don’t read past what we got:
				size_t n2 = 0;
				while (n2 < path_bytes && sun->sun_path[n2] != 0)
					n2++;

				uint8[] tmp2 = new uint8[n2 + 1];
				Memory.copy (&tmp2[0], &sun->sun_path[0], n2);
				tmp2[n2] = 0;

				return "unix:\"%s\"".printf ((string) &tmp2[0]);
			}

			default:
				return "family=%u addrlen=%u".printf (family, addrlen);
			}
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
