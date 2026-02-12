public sealed class Frida.Softwall : Object {
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

	private BpfMap? rules_by_id;
	private BpfMap? inode_index;

	private BpfMap? stats;

	private BpfRingbufReader? events_reader;
	private IOChannel? events_channel;
	private Source? events_source;

	private Gee.Collection<BpfLink> links = new Gee.ArrayList<BpfLink> ();

	private uint32 next_rule_id = 1;

	protected override void dispose () {
		stop ();

		base.dispose ();
	}

	public void start () throws Error {
		assert (state == STOPPED);

		var obj = BpfObject.open ("softwall.elf", Frida.Data.HelperBackend.get_softwall_elf_blob ().data);

		target_tgids = obj.maps.get_by_name ("target_tgids");
		target_uids = obj.maps.get_by_name ("target_uids");

		rules_by_id = obj.maps.get_by_name ("rules_by_id");
		inode_index = obj.maps.get_by_name ("inode_index");

		var events = obj.maps.get_by_name ("audit_events");

		stats = obj.maps.get_by_name ("stats");

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
		events_reader = null;

		links.clear ();

		stats = null;

		inode_index = null;
		rules_by_id = null;

		target_uids = null;
		target_tgids = null;

		next_rule_id = 1;

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

	public enum Action {
		DENY,
		NOT_FOUND,
	}

	public uint32 add_file_open_rule (string path, Action action) throws Error {
		assert (state == STARTED);

		uint64 dev, ino;
		resolve_path_to_inode (path, out dev, out ino);

		var id = next_rule_id++;
		var errno_neg = map_action_to_errno (action);

		var rule = FileOpenRule ();
		rule.dev = dev;
		rule.ino = ino;
		rule.errno_neg = errno_neg;
		rule._pad0 = 0;

		rules_by_id.update_raw ((uint8[]) &id, (uint8[]) &rule);

		var key = InodeKey ();
		key.dev = dev;
		key.ino = ino;

		inode_index.update_raw ((uint8[]) &key, (uint8[]) &id);

		return id;
	}

	public void remove_rule (uint32 id) throws Error {
		assert (state == STARTED);

		var rule = FileOpenRule ();
		try {
			rules_by_id.lookup_raw ((uint8[]) &id, (uint8[]) &rule);
		} catch (Error e) {
			throw new Error.INVALID_ARGUMENT ("Unknown rule id: %u".printf (id));
		}

		var key = InodeKey ();
		key.dev = rule.dev;
		key.ino = rule.ino;

		try {
			inode_index.remove_raw ((uint8[]) &key);
		} catch (Error e) {
		}

		rules_by_id.remove_u32 (id);
	}

	public DrainStatus drain_events (AuditEventHandler on_event) {
		var status = events_reader.drain (payload => {
			assert (payload.length >= sizeof (AuditEvent));
			var e = (AuditEvent *) payload;

			return (on_event (e) == CONTINUE)
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

	public delegate EventFlow AuditEventHandler (AuditEvent * ev);

	public enum EventFlow {
		CONTINUE,
		STOP,
	}

	private void arm_events_watch () {
		if (events_source != null)
			return;

		var src = new IOSource (events_channel, IOCondition.IN);
		var state = new AuditEventsWatchState (this);
		src.set_callback (state.on_ready);
		src.attach (MainContext.get_thread_default ());
		events_source = src;
	}

	private class AuditEventsWatchState : Object {
		public unowned Softwall wall;

		public AuditEventsWatchState (Softwall wall) {
			this.wall = wall;
		}

		public bool on_ready (IOChannel ch, IOCondition cond) {
			wall.on_events_readable ();
			return Source.REMOVE;
		}
	}

	private void on_events_readable () {
		events_source?.destroy ();
		events_source = null;

		events_available ();
	}

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

	private static int32 map_action_to_errno (Action action) {
		switch (action) {
			case Action.NOT_FOUND:
				return -Posix.ENOENT;
			case Action.DENY:
			default:
				return -Posix.EACCES;
		}
	}

	private static void resolve_path_to_inode (string path, out uint64 dev, out uint64 ino) throws Error {
		Posix.Stat st;
		if (Posix.stat (path, out st) != 0)
			throw new Error.INVALID_ARGUMENT ("Unable to stat path: %s", path);

		dev = (uint64) st.st_dev;
		ino = (uint64) st.st_ino;
	}

	public struct Event {
		public uint64 time_ns;
		public uint32 tgid;
		public uint32 tid;

		public uint16 type;

		public uint16 _pad0;
	}

	public enum EventType {
		AUDIT
	}

	public struct AuditEvent {
		public Event parent;

		public uint32 rule_id;

		public uint32 _pad0;
	}

	public struct InodeKey {
		public uint64 dev;
		public uint64 ino;
	}

	private struct FileOpenRule {
		public uint64 dev;
		public uint64 ino;

		public int32 errno_neg;
		public uint32 _pad0;
	}

	public struct Stats {
		public uint64 emitted_events;
		public uint64 emitted_bytes;

		public uint64 dropped_events;
		public uint64 dropped_bytes;
	}
}
