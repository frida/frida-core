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

		private Bpf.HashMap? inflight;

		private FileDescriptor? prog_enter_fd;
		private FileDescriptor? prog_exit_fd;

		private Gee.Collection<PerfEvent.Monitor> monitors = new Gee.ArrayList<PerfEvent.Monitor> ();

		private static string?[] syscall_names;

		private const size_t RINGBUF_SIZE = 1U << 22;

		private const size_t MAX_DEPTH = 16;
		private const size_t MAX_STACK_ENTRIES = 16384;
		private const size_t MAX_INFLIGHT_COPIES = 4096;
		private const size_t MAX_PATH = 256;
		private const size_t MAX_SOCK = 128;

		private const size_t SYSCALL_NARGS = 6;

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

			inflight = new Bpf.HashMap (sizeof (Inflight), MAX_INFLIGHT_COPIES);

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
			maps["inflight"] = inflight;

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
			inflight = null;
			stacks = null;
			events_reader = null;
			target_tgid = null;
		}

		private void handle_event (uint8[] buf) {
			assert (buf.length >= sizeof (SyscallEventCommon));

			unowned SyscallEventCommon * c = (SyscallEventCommon *) buf;
			var phase = (Phase) c->phase;

			size_t header_len = sizeof (SyscallEventCommon);
			size_t payload_len = (size_t) c->payload_len;
			uint16 attach_count = c->attach_count;

			assert (header_len + payload_len <= buf.length);

			uint8 * p = (uint8 *) buf + header_len;
			uint8 * payload_end = p + payload_len;

			uint8 * a = null;

			uint64 args[SYSCALL_NARGS];
			int64 retval = 0;

			if (phase == Phase.ENTER) {
				assert ((size_t) (payload_end - p) >= sizeof (SyscallEnterPayload));
				unowned SyscallEnterPayload * ep = (SyscallEnterPayload *) p;

				for (int i = 0; i < SYSCALL_NARGS; i++)
					args[i] = ep->args[i];

				a = (uint8 *) p + sizeof (SyscallEnterPayload);
			} else {
				assert ((size_t) (payload_end - p) >= sizeof (SyscallExitPayload));
				unowned SyscallExitPayload * xp = (SyscallExitPayload *) p;

				retval = xp->retval;
				a = (uint8 *) p + sizeof (SyscallExitPayload);
			}

			string?[] str_arg = new string?[SYSCALL_NARGS];
			var bytes_arg = new Bytes?[SYSCALL_NARGS];
			var out_bytes = new Bytes?[SYSCALL_NARGS];

			for (uint i = 0; i < attach_count; i++) {
				assert ((size_t)(payload_end - a) >= sizeof (AttachHeader));
				unowned AttachHeader * h = (AttachHeader *) a;
				a += sizeof (AttachHeader);

				uint idx = h->arg_index;
				size_t len = (size_t) h->len;

				assert (a + len <= payload_end);

				if (idx < SYSCALL_NARGS) {
					switch ((AttachType) h->type) {
					case AttachType.STRING_ARG:
						str_arg[idx] = (len != 0) ? (string) a : "";
						break;
					case AttachType.BYTES_ARG: {
						var b = new uint8[len];
						Memory.copy (&b[0], a, len);
						bytes_arg[idx] = new Bytes.take ((owned) b);
						break;
					}
					case AttachType.OUT_BYTES: {
						var b = new uint8[len];
						Memory.copy (&b[0], a, len);
						out_bytes[idx] = new Bytes.take ((owned) b);
						break;
					}
					default:
						break;
					}
				}

				a += len;
			}

			unowned string? name = null;
			if (c->syscall_nr >= 0 && c->syscall_nr < syscall_names.length)
				name = syscall_names[c->syscall_nr];

			if (phase == Phase.ENTER) {
				if (name == "connect" && bytes_arg[1] != null) {
					unowned uint8[] sa = bytes_arg[1].get_data ();
					uint16 fam = 0;
					if (sa.length >= 2)
						fam = *((uint16 *) sa);
					string peer = format_sockaddr (fam, (uint32) sa.length, (uint8 *) &sa[0], sa.length);
					print ("[time=%" + uint64.FORMAT + " tgid=%u tid=%u stack_id=%d] %s enter %s\n",
						c->time_ns, c->tgid, c->tid, c->stack_id,
						(name != null) ? name : "%d".printf (c->syscall_nr),
						peer);
					return;
				}

				var rendered = new StringBuilder ();
				for (int i = 0; i < SYSCALL_NARGS; i++) {
					if (i != 0)
						rendered.append (", ");
					if (str_arg[i] != null)
						rendered.append_printf ("arg%d=\"%s\"", i, str_arg[i]);
					else
						rendered.append_printf ("arg%d=0x%" + uint64.FORMAT_MODIFIER + "x", i, args[i]);
				}

				print ("[time=%" + uint64.FORMAT + " tgid=%u tid=%u stack_id=%d] %s enter %s\n",
					c->time_ns, c->tgid, c->tid, c->stack_id,
					(name != null) ? name : "%d".printf (c->syscall_nr),
					rendered.str);
			} else {
				string extra = "";
				if (out_bytes[2] != null) {
					unowned uint8[] ob = out_bytes[2].get_data ();
					unowned string s = (ob.length != 0) ? (string) &ob[0] : "";
					extra = " out(arg2)=\"%s\"".printf (s);
				}

				print ("[time=%" + uint64.FORMAT + " tgid=%u tid=%u stack_id=%d] %s exit ret=0x%" +
						int64.FORMAT_MODIFIER + "x%s\n",
					c->time_ns, c->tgid, c->tid, c->stack_id,
					(name != null) ? name : "%d".printf (c->syscall_nr),
					retval, extra);
			}
		}

		private enum Phase {
			ENTER,
			EXIT,
		}

		private enum AttachType {
			STRING_ARG,
			BYTES_ARG,
			OUT_BYTES,
		}

		[Compact]
		private struct SyscallEventCommon {
			public uint64 time_ns;
			public uint32 tgid;
			public uint32 tid;

			public int32 syscall_nr;
			public int32 stack_id;

			public uint16 phase;

			public uint16 payload_len;
			public uint16 attach_count;
		}

		[Compact]
		private struct SyscallEnterPayload {
			public uint64 args[6];
		}

		[Compact]
		private struct SyscallExitPayload {
			public int64 retval;
		}

		[Compact]
		private struct AttachHeader {
			public uint16 type;
			public uint16 arg_index;
			public uint32 len;
		}

		[Compact]
		private struct Inflight {
			public int32 syscall_nr;

			public uint16 kind;
			public uint16 _pad0;

			public InflightOutCopy u;
		}

		[Compact]
		private struct InflightOutCopy {
			public uint16 arg_index;
			public uint16 _pad1;

			public uint64 user_ptr;
			public uint32 max_len;
			public uint32 _pad2;
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
					assert (payload.length >= sizeof (SyscallEventCommon));
					tracer.handle_event (payload);
				});
				return Source.CONTINUE;
			}
		}

		private static string format_sockaddr (uint16 family, uint32 addrlen, uint8 * addr, size_t addr_buf_len) {
			size_t len = (size_t) addrlen;
			if (len > addr_buf_len)
				len = addr_buf_len;

			switch ((int) family) {
			case Posix.AF_INET: {
				if (len < sizeof (SockaddrIn))
					return "inet: <truncated>";

				unowned SockaddrIn * sa = (SockaddrIn *) addr;
				uint16 port = uint16.from_network (sa->sin_port);

				string ip = inet_ntop_to_string (Posix.AF_INET, (uint8 *) &sa->sin_addr, 4);
				return "%s:%u".printf (ip, port);
			}

			case Posix.AF_INET6: {
				if (len < sizeof (SockaddrIn6))
					return "inet6: <truncated>";

				unowned SockaddrIn6 * sa6 = (SockaddrIn6 *) addr;
				uint16 port = uint16.from_network (sa6->sin6_port);

				string ip = inet_ntop_to_string (Posix.AF_INET6, (uint8 *) &sa6->sin6_addr.addr[0], 16);

				if (sa6->sin6_scope_id != 0)
					return "[%s%%%u]:%u".printf (ip, sa6->sin6_scope_id, port);

				return "[%s]:%u".printf (ip, port);
			}

			case Posix.AF_UNIX: {
				if (len < 2)
					return "unix: <truncated>";

				unowned SockaddrUn * sun = (SockaddrUn *) addr;

				size_t path_bytes = (len > 2) ? (len - 2) : 0;
				if (path_bytes > 108)
					path_bytes = 108;

				if (path_bytes == 0)
					return "unix:\"\"";

				if (sun->sun_path[0] == 0) {
					size_t n = 1;
					while (n < path_bytes && sun->sun_path[n] != 0)
						n++;

					uint8[] tmp = new uint8[n];
					Memory.copy (&tmp[0], &sun->sun_path[0], n);
					string name = (n > 1) ? ((string) (&tmp[1])) : "";
					return "unix:@%s".printf (name);
				}

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

		private static string inet_ntop_to_string (int af, uint8 * src, size_t srclen) {
			uint8 buf[46];
			unowned string? res = Posix.inet_ntop (af, (void *) src, buf);
			return (res != null) ? res : "?";
		}

		[Compact]
		private struct SockaddrIn {
			public uint16 sin_family;
			public uint16 sin_port;
			public uint32 sin_addr;
			public uint8  sin_zero[8];
		}

		[Compact]
		private struct In6Addr {
			public uint8 addr[16];
		}

		[Compact]
		private struct SockaddrIn6 {
			public uint16 sin6_family;
			public uint16 sin6_port;
			public uint32 sin6_flowinfo;
			public In6Addr sin6_addr;
			public uint32 sin6_scope_id;
		}

		[Compact]
		private struct SockaddrUn {
			public uint16 sun_family;
			public uint8  sun_path[108];
		}
	}
}
