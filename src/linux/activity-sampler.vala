public sealed class Frida.ActivitySampler : Object {
	public uint pid {
		get;
		construct;
	}

	private Bpf.ArrayMap? target_tgid;

	private Bpf.RingbufReader? events_reader;
	private Source? events_source;

	private FileDescriptor? prog_fd;

	private Gee.Collection<PerfEvent.Monitor> monitors = new Gee.ArrayList<PerfEvent.Monitor> ();

	private const size_t RINGBUF_SIZE = 1U << 22;

	public ActivitySampler (uint pid) {
		Object (pid: pid);
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

		Gum.ElfModule elf;
		try {
			var raw_elf = new Bytes.static (Frida.Data.HelperBackend.get_activity_sampler_elf_blob ().data);
			elf = new Gum.ElfModule.from_blob (raw_elf);
		} catch (Gum.Error e) {
			assert_not_reached ();
		}

		var maps = new Gee.HashMap<string, Bpf.Map> ();
		maps["target_tgid"] = target_tgid;
		maps["events"] = events;

		prog_fd = Bpf.load_program_from_elf (PERF_EVENT, elf, "perf_event", maps, "Dual BSD/GPL");

		uint ncpus = get_num_processors ();
		for (uint cpu = 0; cpu != ncpus; cpu++) {
			var pea = PerfEventAttr ();
			pea.event_type = SOFTWARE;
			pea.size = (uint32) sizeof (PerfEventAttr);
			pea.config = PERF_EVENT_COUNT_SW_CPU_CLOCK;
			pea.sample_period = 1;

			var monitor = new PerfEvent.Monitor (&pea, -1, (int) cpu, -1, 0);
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
		events_reader = null;
		target_tgid = null;
	}

	private void handle_sample (SampleEvent * e) {
		printerr ("[ActivitySampler %p] tgid=%u tid=%u time=%" + uint64.FORMAT + " stack_err=%d depth=%u\n",
			this, e->tgid, e->tid, e->time_ns, e->stack_err, e->depth);

		for (uint32 i = 0; i != e->depth; i++)
			printerr ("\t0x%lx\n", (ulong) e->ips[i]);
	}

	private struct SampleEvent {
		public uint64 time_ns;
		public uint32 tgid;
		public uint32 tid;
		public int32 stack_err;
		public uint32 depth;
		public uint64 ips[16];
	}

	private class WatchState : Object {
		public unowned ActivitySampler sampler;
		public Bpf.RingbufReader reader;

		public WatchState (ActivitySampler sampler, Bpf.RingbufReader reader) {
			this.sampler = sampler;
			this.reader = reader;
		}

		public bool on_ready (IOChannel ch, IOCondition cond) {
			reader.drain (payload => {
				assert (payload.length == sizeof (SampleEvent));
				sampler.handle_sample ((SampleEvent *) payload);
				return CONTINUE;
			});
			return Source.CONTINUE;
		}
	}
}
