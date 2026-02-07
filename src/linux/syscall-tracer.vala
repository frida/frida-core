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

	private BpfMap? target_tgids;
	private BpfMap? target_uids;

	private BpfRingbufReader? events_reader;
	private IOChannel? events_channel;
	private Source? events_source;

	private BpfMap? stats;

	private BpfMap? stacks;

	private Gee.Collection<BpfLink> links = new Gee.ArrayList<BpfLink> ();

	public const size_t SYSCALL_NARGS = 6;

	protected override void dispose () {
		stop ();

		base.dispose ();
	}

	public void start () throws Error {
		assert (state == STOPPED);

		var obj = BpfObject.open ("syscall-tracer.elf", Frida.Data.HelperBackend.get_syscall_tracer_elf_blob ().data);

		target_tgids = obj.maps.get_by_name ("target_tgids");
		target_uids = obj.maps.get_by_name ("target_uids");
		var events = obj.maps.get_by_name ("events");
		stats = obj.maps.get_by_name ("stats");
		stacks = obj.maps.get_by_name ("stacks");

		obj.prepare ();

		events_reader = new BpfRingbufReader (events);

		obj.load ();

		foreach (var program in obj.programs) {
			var link = program.attach ();
			links.add (link);
		}

		events_channel = new IOChannel.unix_new (events.fd);
		arm_events_watch ();

		_state = STARTED;
	}

	public void stop () {
		events_source?.destroy ();
		events_source = null;
		events_channel = null;

		links.clear ();

		events_reader = null;
		stacks = null;
		stats = null;
		target_uids = null;
		target_tgids = null;

		_state = STOPPED;
	}

	public void add_target_tgid (uint tgid) throws Error {
		target_tgids.update_u32_u8 (tgid, 1);
	}

	public void remove_target_tgid (uint tgid) throws Error {
		target_tgids.remove_u32 (tgid);
	}

	public void add_target_uid (uint uid) throws Error {
		target_uids.update_u32_u8 (uid, 1);
	}

	public void remove_target_uid (uint uid) throws Error {
		target_uids.remove_u32 (uid);
	}

	public DrainStatus drain_events (SyscallEventHandler on_event) {
		var status = events_reader.drain (payload => {
			assert (payload.length >= sizeof (SyscallEventCommon));
			unowned SyscallEventCommon * c = (SyscallEventCommon *) payload;
			SyscallEventView ev = { c, payload };

			return (on_event (ev) == CONTINUE)
					? BpfRingbufReader.RecordAction.CONTINUE
					: BpfRingbufReader.RecordAction.STOP;
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
		public BpfRingbufReader reader;

		public WatchState (SyscallTracer tracer, BpfRingbufReader reader) {
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
		var tmp = new uint64[stacks.value_size / sizeof (uint64)];

		foreach (var sid in stack_ids) {
			uint n = 0;

			try {
				stacks.lookup_raw ((uint8[]) &sid, (uint8[]) tmp);

				for (uint i = 0; i != tmp.length; i++) {
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

		uint32 key = 0;
		stats.foreach_percpu_value<Stats?> ((uint8[]) &key, (cpu, s) => {
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
