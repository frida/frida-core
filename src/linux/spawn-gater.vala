namespace Frida {
	public sealed class SpawnGater : Object {
		public signal void spawn_added (HostSpawnInfo info);
		public signal void spawn_removed (HostSpawnInfo info);

		public LinuxHelper helper {
			get;
			construct;
		}

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

		private Gee.Map<uint, HostSpawnInfo?> pending_spawn = new Gee.HashMap<uint, HostSpawnInfo?> ();

		private BpfRingbufReader? events_reader;
		private IOChannel? events_channel;
		private Source? events_source;

		private Gee.Collection<BpfLink> links = new Gee.ArrayList<BpfLink> ();

		private const size_t RINGBUF_SIZE = 1U << 22;
		private const size_t MAX_FILENAME = 256;

		public SpawnGater (LinuxHelper helper) {
			Object (helper: helper);
		}

		protected override void dispose () {
			stop ();

			base.dispose ();
		}

		public void start () throws Error {
			assert (state == STOPPED);

			var obj = BpfObject.open ("spawn-gater.elf", Frida.Data.HelperBackend.get_spawn_gater_elf_blob ().data);

			var events = obj.maps.get_by_name ("events");

			obj.prepare ();

			events_reader = new BpfRingbufReader (events);

			obj.load ();

			foreach (var program in obj.programs) {
				var link = program.attach ();
				links.add (link);
			}

			events_channel = new IOChannel.unix_new (events.fd);
			var src = new IOSource (events_channel, IOCondition.IN);
			var state = new EventsWatchState (this);
			src.set_callback (state.on_ready);
			src.attach (MainContext.get_thread_default ());
			events_source = src;

			_state = STARTED;
		}

		public void stop () {
			if (_state == STOPPED)
				return;

			links.clear ();

			events_source?.destroy ();
			events_source = null;

			process_pending_events ();

			foreach (var spawn in pending_spawn.values) {
				spawn_removed (spawn);
				perform_resume.begin (spawn.pid);
			}
			pending_spawn.clear ();

			events_channel = null;
			events_reader = null;

			_state = STOPPED;
		}

		public HostSpawnInfo[] enumerate_pending_spawn () {
			var result = new HostSpawnInfo[pending_spawn.size];
			var index = 0;
			foreach (var spawn in pending_spawn.values)
				result[index++] = spawn;
			return result;
		}

		public bool try_resume (uint pid) {
			HostSpawnInfo? spawn;
			if (!pending_spawn.unset (pid, out spawn))
				return false;
			spawn_removed (spawn);
			perform_resume.begin (pid);
			return true;
		}

		private async void perform_resume (uint pid) {
			try {
				yield helper.resume (pid, null);
			} catch (GLib.Error e) {
				if (e is Error.INVALID_ARGUMENT)
					Posix.kill ((Posix.pid_t) pid, Posix.Signal.CONT);
			}
		}

		private void process_pending_events () {
			events_reader.drain (payload => {
				assert (payload.length == sizeof (ExecveEvent));
				handle_event (payload);
				return CONTINUE;
			});
		}

		private void handle_event (ExecveEvent * e) {
			var info = HostSpawnInfo (e->pid, (string) e->command);
			pending_spawn[e->pid] = info;
			spawn_added (info);
		}

		private struct ExecveEvent {
			public int pid;
			public char command[MAX_FILENAME];
		}

		private class EventsWatchState : Object {
			public unowned SpawnGater gater;

			public EventsWatchState (SpawnGater gater) {
				this.gater = gater;
			}

			public bool on_ready (IOChannel ch, IOCondition cond) {
				gater.process_pending_events ();
				return Source.CONTINUE;
			}
		}
	}
}
