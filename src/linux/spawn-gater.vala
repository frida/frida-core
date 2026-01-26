namespace Frida {
	public sealed class SpawnGater : Object {
		public delegate void ProcessSpawnedCallback(int pid, string command);
		private Bpf.RingbufReader? events_reader;

		private const size_t RINGBUF_SIZE = 1U << 22;
		private const size_t MAX_FILENAME = 256;

		private Source? events_source;

		private FileDescriptor? prog_fd;

		private Gee.Collection<PerfEvent.Monitor> monitors = new Gee.ArrayList<PerfEvent.Monitor> ();

		private ProcessSpawnedCallback pid_callback;

		public SpawnGater () {

		}

		protected override void dispose() {
			base.dispose ();
		}

		public void start () throws Error {
			var events = new Bpf.RingbufMap (RINGBUF_SIZE);
			events_reader = new Bpf.RingbufReader (events);

			Gum.ElfModule elf;
			try {
				var raw_elf = new Bytes.static (Frida.Data.HelperBackend.get_spawn_gater_elf_blob ().data);
				elf = new Gum.ElfModule.from_blob (raw_elf);
			} catch (Gum.Error e) {
				assert_not_reached ();
			}

			var maps = new Gee.HashMap<string, Bpf.Map> ();
			maps["events"] = events;

			prog_fd = Bpf.load_program_from_elf (TRACEPOINT, elf, "tracepoint/syscalls/sys_enter_execve", maps, "Dual BSD/GPL");

			uint32 tp_id = PerfEvent.get_tracepoint_id ("syscalls", "sys_enter_execve");

			uint ncpus = get_num_processors ();
			for (uint cpu = 0; cpu != ncpus; cpu++) {
				var pea = PerfEventAttr ();
				pea.event_type = TRACEPOINT;
				pea.size = (uint32) sizeof (PerfEventAttr);
				pea.config = tp_id;
				pea.sample_period = 1;

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
			events_reader = null;
		}

		public void set_callback(ProcessSpawnedCallback callback) {
			pid_callback = callback;
		}

		private void handle_event (ExecveEvent * e) {
			pid_callback (e->pid, (string) e->command);
		}

		private struct ExecveEvent {
			public int pid;
			public char command[MAX_FILENAME];
		}

		private sealed class WatchState : Object {
			public unowned SpawnGater gater;
			public Bpf.RingbufReader reader;

			public WatchState (SpawnGater gater, Bpf.RingbufReader reader) {
				this.gater = gater;
				this.reader = reader;
			}

			public bool on_ready (IOChannel ch, IOCondition cond) {
				reader.drain ((payload, len) => {
					assert (len == sizeof (ExecveEvent));
					gater.handle_event (payload);
				});
				return Source.CONTINUE;
			}
		}
	}
}
