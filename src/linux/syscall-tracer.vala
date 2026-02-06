public sealed class Frida.SyscallTracer : Object {
	public signal void events_available ();

	public State state {
		get {
			return _state;
		}
	}

	public enum State {
		STOPPED,
		STARTED,
	}

	private State _state = STOPPED;

	private Bpf.HashMap? target_tgids;
	private Bpf.HashMap? target_uids;

	private Bpf.RingbufReader? events_reader;
	private IOChannel? events_channel;
	private Source? events_source;

	private Bpf.PercpuArrayMap? stats;

	private Bpf.StackTraceMap? stacks;

	private Bpf.HashMap? inflight;

	private FileDescriptor? prog_enter_fd;
	private FileDescriptor? prog_exit_fd;

	private Gee.Collection<PerfEvent.Monitor> monitors = new Gee.ArrayList<PerfEvent.Monitor> ();

	private const size_t RINGBUF_SIZE = 1U << 22;

	private const size_t MAX_TARGET_TGIDS = 4096;
	private const size_t MAX_TARGET_UIDS = 256;
	private const size_t MAX_STACK_ENTRIES = 16384;
	private const size_t MAX_INFLIGHT_COPIES = 4096;
	private const size_t INFLIGHT_SIZE = (4 + 2 + 2) + (2 + 2) + (8 + 4 + 4);

	private const size_t MAX_DEPTH = 16;
	private const size_t MAX_PATH = 256;
	private const size_t MAX_SOCK = 128;

	public const size_t SYSCALL_NARGS = 6;

	protected override void dispose () {
		stop ();

		base.dispose ();
	}

	public void start () throws Error {
		assert (state == STOPPED);

		target_tgids = new Bpf.HashMap (sizeof (uint8), MAX_TARGET_TGIDS);
		target_uids = new Bpf.HashMap (sizeof (uint8), MAX_TARGET_UIDS);

		var events = new Bpf.RingbufMap (RINGBUF_SIZE);
		events_reader = new Bpf.RingbufReader (events);

		stats = new Bpf.PercpuArrayMap (sizeof (Stats), 1);

		stacks = new Bpf.StackTraceMap (MAX_DEPTH, MAX_STACK_ENTRIES);

		inflight = new Bpf.HashMap (INFLIGHT_SIZE, MAX_INFLIGHT_COPIES);

		Gum.ElfModule elf;
		try {
			var raw_elf = new Bytes.static (Frida.Data.HelperBackend.get_syscall_tracer_elf_blob ().data);
			elf = new Gum.ElfModule.from_blob (raw_elf);
		} catch (Gum.Error e) {
			assert_not_reached ();
		}

		var maps = new Gee.HashMap<string, Bpf.Map> ();
		maps["target_tgids"] = target_tgids;
		maps["target_uids"] = target_uids;
		maps["events"] = events;
		maps["stats"] = stats;
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

		events_channel = new IOChannel.unix_new (events.fd.handle);
		arm_events_watch ();

		_state = STARTED;
	}

	public void stop () {
		events_source?.destroy ();
		events_source = null;
		events_channel = null;

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
		stats = null;
		events_reader = null;
		target_uids = null;
		target_tgids = null;

		_state = STOPPED;
	}

	public void add_target_tgid (uint tgid) throws Error {
		uint8 v = 1;
		target_tgids.update_raw (tgid, &v);
	}

	public void remove_target_tgid (uint tgid) throws Error {
		target_tgids.remove (tgid);
	}

	public void add_target_uid (uint uid) throws Error {
		uint8 v = 1;
		target_uids.update_raw (uid, &v);
	}

	public void remove_target_uid (uint uid) throws Error {
		target_uids.remove (uid);
	}

	public DrainStatus drain_events (SyscallEventHandler on_event) {
		var status = events_reader.drain (payload => {
			assert (payload.length >= sizeof (SyscallEventCommon));
			unowned SyscallEventCommon * c = (SyscallEventCommon *) payload;
			SyscallEventView ev = { c, payload };

			return (on_event (ev) == CONTINUE)
					? Bpf.RingbufReader.RecordAction.CONTINUE
					: Bpf.RingbufReader.RecordAction.STOP;
		});

		if (status == DRAINED)
			arm_events_watch ();

		return (status == DRAINED)
			? DrainStatus.DRAINED
			: DrainStatus.STOPPED;
	}

	public enum DrainStatus {
		DRAINED,
		STOPPED,
	}

	public delegate EventFlow SyscallEventHandler (SyscallEventView ev);

	public enum EventFlow {
		CONTINUE,
		STOP,
	}

	public struct SyscallEventView {
		public SyscallEventCommon * common;
		public unowned uint8[] bytes;
	}

	private void arm_events_watch () {
		if (events_source != null)
			return;

		var src = new IOSource (events_channel, IOCondition.IN);
		var state = new WatchState (this, events_reader);
		src.set_callback (state.on_ready);
		src.attach (MainContext.get_thread_default ());
		events_source = src;
	}

	private class WatchState : Object {
		public unowned SyscallTracer tracer;
		public Bpf.RingbufReader reader;

		public WatchState (SyscallTracer tracer, Bpf.RingbufReader reader) {
			this.tracer = tracer;
			this.reader = reader;
		}

		public bool on_ready (IOChannel ch, IOCondition cond) {
			tracer.on_ringbuffer_readable ();
			return Source.REMOVE;
		}
	}

	private void on_ringbuffer_readable () {
		events_source?.destroy ();
		events_source = null;

		events_available ();
	}

	public struct SyscallEventCommon {
		public uint64 time_ns;
		public uint32 tgid;
		public uint32 tid;

		public int32 syscall_nr;
		public int32 stack_id;

		public uint16 phase;

		public uint16 payload_len;
		public uint16 attachment_count;
	}

	public enum Phase {
		ENTER,
		EXIT,
	}

	public struct SyscallEnterPayload {
		public uint64 args[6];
	}

	public struct SyscallExitPayload {
		public int64 retval;
	}

	public struct AttachmentHeader {
		public uint16 type;
		public uint16 arg_index;
		public uint32 len;
	}

	public enum AttachmentType {
		STRING,
		BYTES,
	}

	public void resolve_stacks (uint32[] stack_ids, StackFramesHandler on_frames) {
		uint64 tmp[MAX_DEPTH];

		foreach (var sid in stack_ids) {
			uint n = 0;

			try {
				stacks.lookup_raw (sid, (void *) tmp);

				for (uint i = 0; i != MAX_DEPTH; i++) {
					if (tmp[i] == 0)
						break;
					n++;
				}
			} catch (Error e) {
			}

			on_frames (sid, tmp[:n]);
		}
	}

	public delegate void StackFramesHandler (uint32 stack_id, uint64[] frames);

	public Stats read_stats () throws Error {
		Stats total = Stats ();

		stats.foreach_value<Stats?> (0, (cpu, s) => {
			total.emitted_events += s.emitted_events;
			total.emitted_bytes += s.emitted_bytes;

			total.dropped_events += s.dropped_events;
			total.dropped_bytes += s.dropped_bytes;
		});

		return total;
	}

	public struct Stats {
		public uint64 emitted_events;
		public uint64 emitted_bytes;

		public uint64 dropped_events;
		public uint64 dropped_bytes;
	}
}
