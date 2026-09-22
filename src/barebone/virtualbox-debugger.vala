[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	public sealed class VirtualBoxDebugger : Object, Debugger {
		public TargetArch arch {
			get;
			set;
			default = X64;
		}

		public uint pointer_size {
			get;
			set;
			default = 8;
		}

		public ByteOrder byte_order {
			get;
			set;
			default = LITTLE_ENDIAN;
		}

		public DebuggerState state {
			get {
				return _state;
			}
		}

		public DebuggerException? exception {
			get {
				return _exception;
			}
		}

		public Gee.Set<string> features {
			get {
				return _features;
			}
		}

		private VirtualBoxConsole console;
		private DebuggerState _state = STOPPED;
		private DebuggerException? _exception;
		private Gee.Set<string> _features = new Gee.HashSet<string> ();
		private Gee.List<VirtualBoxThread> threads = new Gee.ArrayList<VirtualBoxThread> ();
		private Gee.List<Gee.Map<string, uint64?>>? core_registers;
		private Gee.List<Gee.Map<string, uint64?>>? full_registers;
		private Gee.Map<uint64?, VirtualBoxBreakpoint> breakpoints =
			new Gee.HashMap<uint64?, VirtualBoxBreakpoint> (Numeric.uint64_hash, Numeric.uint64_equal);

		private VirtualBoxDebugger (VirtualBoxConsole console) {
			this.console = console;
		}

		public static async VirtualBoxDebugger open (string host, uint16 port, Cancellable? cancellable)
				throws Error, IOError {
			var console = yield VirtualBoxConsole.open (host, port, cancellable);

			var debugger = new VirtualBoxDebugger (console);
			debugger._features.add ("virtualbox");

			yield console.halt (cancellable);
			yield debugger.note_stopped (cancellable);

			return debugger;
		}

		internal async Gee.Map<string, uint64?> read_registers (uint cpu, Cancellable? cancellable)
				throws Error, IOError {
			if (full_registers == null)
				full_registers = yield console.read_registers (cancellable);
			return full_registers[(int) cpu];
		}

		internal async uint64? read_register (uint cpu, string name, Cancellable? cancellable)
				throws Error, IOError {
			if (name in VirtualBoxConsole.CORE_REGISTERS) {
				if (core_registers == null)
					core_registers = yield console.read_core_registers (cancellable);
				return core_registers[(int) cpu][name];
			}

			uint64? val = (yield read_registers (cpu, cancellable))[name];
			if (val != null)
				return val;

			return yield console.read_one_register (cpu, name, cancellable);
		}

		internal async void write_register (uint cpu, string name, uint64 val, Cancellable? cancellable)
				throws Error, IOError {
			yield console.write_register (cpu, name, val, cancellable);
			forget_registers ();
		}

		private void forget_registers () {
			core_registers = null;
			full_registers = null;
		}

		private async void note_stopped (Cancellable? cancellable) throws Error, IOError {
			full_registers = null;
			core_registers = yield console.read_core_registers (cancellable);

			if (threads.size != core_registers.size) {
				threads.clear ();
				for (int i = 0; i != core_registers.size; i++)
					threads.add (new VirtualBoxThread (i, this));
			}

			VirtualBoxThread resting = threads[0];
			for (int i = 0; i != core_registers.size; i++) {
				uint64? cs = core_registers[i]["cs"];
				if (cs != null && (cs & RING_MASK) == 0) {
					resting = threads[i];
					break;
				}
			}

			VirtualBoxBreakpoint? hit = null;
			for (int i = 0; i != core_registers.size; i++) {
				uint64? pc = core_registers[i]["rip"];
				if (pc == null)
					continue;
				VirtualBoxBreakpoint? bp = breakpoints[pc];
				if (bp != null) {
					hit = bp;
					resting = threads[i];
					break;
				}
			}

			change_state (STOPPED, new DebuggerException (SIGTRAP, hit, resting));
		}

		public bool has_register (string name) {
			return name == "rip" || name == "rsp" || name == "gs_base" || name == "cr3" || name == "lstar";
		}

		public BufferBuilder make_buffer_builder () {
			return new BufferBuilder (byte_order, pointer_size);
		}

		public Buffer make_buffer (Bytes bytes) {
			return new Buffer (bytes, byte_order, pointer_size);
		}

		public async Bytes read_byte_array (uint64 address, size_t size, Cancellable? cancellable = null)
				throws Error, IOError {
			return yield console.read_memory (address, size, cancellable);
		}

		public async void write_byte_array (uint64 address, Bytes bytes, Cancellable? cancellable = null)
				throws Error, IOError {
			yield console.write_memory (address, bytes, cancellable);
		}

		public async Buffer read_buffer (uint64 address, size_t size, Cancellable? cancellable = null)
				throws Error, IOError {
			return make_buffer (yield read_byte_array (address, size, cancellable));
		}

		public async void resume (Cancellable? cancellable = null) throws Error, IOError {
			forget_registers ();
			yield console.resume (cancellable);
			change_state (RUNNING, null);
		}

		public async void stop (Cancellable? cancellable = null) throws Error, IOError {
			if (_state == STOPPED)
				return;

			yield console.halt (cancellable);
			yield note_stopped (cancellable);
		}

		public void restart () throws Error {
			throw new Error.NOT_SUPPORTED ("The VirtualBox debugger console cannot restart the guest");
		}

		public async DebuggerException continue_until_exception (Cancellable? cancellable = null)
				throws Error, IOError {
			yield release_parked_processors (cancellable);
			yield resume (cancellable);

			while (true) {
				yield sleep (POLL_INTERVAL_MSEC, cancellable);

				yield console.halt (cancellable);
				yield note_stopped (cancellable);

				if (_exception.breakpoint != null)
					return _exception;

				forget_registers ();
				yield console.resume (cancellable);
			}
		}

		private async void release_parked_processors (Cancellable? cancellable) throws Error, IOError {
			if (_state != STOPPED || breakpoints.is_empty)
				return;

			var parked = new Gee.ArrayList<VirtualBoxBreakpoint> ();
			foreach (var registers in yield console.read_core_registers (cancellable)) {
				uint64? pc = registers["rip"];
				if (pc == null)
					continue;

				VirtualBoxBreakpoint? bp = breakpoints[pc];
				if (bp != null && !parked.contains (bp))
					parked.add (bp);
			}
			if (parked.is_empty)
				return;

			foreach (var bp in parked)
				yield bp.disable (cancellable);

			forget_registers ();
			yield console.resume (cancellable);
			yield sleep (RELEASE_PERIOD_MSEC, cancellable);
			yield console.halt (cancellable);

			foreach (var bp in parked)
				yield bp.enable (cancellable);

			forget_registers ();
		}

		private async void sleep (uint msec, Cancellable? cancellable) throws IOError {
			var source = new TimeoutSource (msec);
			source.set_callback (sleep.callback);
			source.attach (MainContext.get_thread_default ());
			yield;

			cancellable.set_error_if_cancelled ();
		}

		public async DebuggerBreakpoint add_breakpoint (BreakpointKind kind, uint64 address, size_t size,
				Cancellable? cancellable = null) throws Error, IOError {
			var breakpoint = new VirtualBoxBreakpoint (kind, address, size, console);
			yield breakpoint.enable (cancellable);
			breakpoints[address] = breakpoint;

			breakpoint.removed.connect (() => breakpoints.unset (address));

			return breakpoint;
		}

		public async void set_physical_memory_mode (bool enabled, Cancellable? cancellable = null)
				throws Error, IOError {
			console.physical_addressing = enabled;
		}

		public async string run_remote_command (string command, Cancellable? cancellable = null)
				throws Error, IOError {
			return yield console.run (command, cancellable);
		}

		public async void detach (Cancellable? cancellable = null) throws Error, IOError {
			yield console.resume (cancellable);
			change_state (RUNNING, null);
		}

		public async void close (Cancellable? cancellable = null) throws IOError {
			try {
				yield console.resume (cancellable);
			} catch (Error e) {
			}
			change_state (CLOSED, null);
		}

		private void change_state (DebuggerState new_state, DebuggerException? new_exception) {
			_state = new_state;
			_exception = new_exception;
			notify_property ("state");
			notify_property ("exception");
		}

		private const uint POLL_INTERVAL_MSEC = 50;
		private const uint RELEASE_PERIOD_MSEC = 5;
		private const uint64 RING_MASK = 3;
		private const uint SIGTRAP = 5;
	}

	public sealed class VirtualBoxThread : Object, DebuggerThread {
		public string id {
			get {
				return _id;
			}
		}

		public string? name {
			get {
				return _name;
			}
		}

		public Debugger debugger {
			get {
				return owner;
			}
		}

		private string _id;
		private string? _name;
		private uint cpu;
		private weak VirtualBoxDebugger owner;

		public VirtualBoxThread (uint cpu, VirtualBoxDebugger owner) {
			_id = "%u".printf (cpu + 1);
			_name = "CPU %u".printf (cpu);
			this.cpu = cpu;
			this.owner = owner;
		}

		public async void step (Cancellable? cancellable = null) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("VirtualBox cannot single-step the guest");
		}

		public void step_and_continue () throws Error {
			throw new Error.NOT_SUPPORTED ("The VirtualBox debugger console steps synchronously");
		}

		public async uint64 read_register (string name, Cancellable? cancellable = null) throws Error, IOError {
			uint64? val = yield owner.read_register (cpu, name, cancellable);
			if (val == null)
				throw new Error.NOT_SUPPORTED ("Register “%s” is not exposed by VirtualBox", name);
			return val;
		}

		public async void write_register (string name, uint64 val, Cancellable? cancellable = null)
				throws Error, IOError {
			yield owner.write_register (cpu, name, val, cancellable);
		}

		public async Gee.Map<string, Variant> read_registers (Cancellable? cancellable = null)
				throws Error, IOError {
			var raw = yield owner.read_registers (cpu, cancellable);

			var registers = new Gee.HashMap<string, Variant> ();
			foreach (var e in raw.entries)
				registers[e.key] = new Variant.uint64 (e.value);

			return registers;
		}

		public async void write_registers (Gee.Map<string, Variant> regs, Cancellable? cancellable = null)
				throws Error, IOError {
			var current = yield owner.read_registers (cpu, cancellable);

			foreach (var e in regs.entries) {
				uint64 val = e.value.get_uint64 ();
				if (current[e.key] == val)
					continue;

				yield owner.write_register (cpu, e.key, val, cancellable);
			}
		}
	}

	public sealed class VirtualBoxBreakpoint : Object, DebuggerBreakpoint {
		public signal void removed ();

		public BreakpointKind kind {
			get {
				return _kind;
			}
		}

		public uint64 address {
			get {
				return _address;
			}
		}

		public size_t size {
			get {
				return _size;
			}
		}

		private BreakpointKind _kind;
		private uint64 _address;
		private size_t _size;
		private VirtualBoxConsole console;
		private Bytes? displaced;

		public VirtualBoxBreakpoint (BreakpointKind kind, uint64 address, size_t size, VirtualBoxConsole console) {
			_kind = kind;
			_address = address;
			_size = size;
			this.console = console;
		}

		public async void enable (Cancellable? cancellable = null) throws Error, IOError {
			if (displaced != null)
				return;

			displaced = yield console.read_memory (address, SPIN.length, cancellable);
			yield console.write_memory (address, new Bytes (SPIN), cancellable);
		}

		public async void disable (Cancellable? cancellable = null) throws Error, IOError {
			if (displaced == null)
				return;

			yield console.write_memory (address, displaced, cancellable);
			displaced = null;
		}

		public async void remove (Cancellable? cancellable = null) throws Error, IOError {
			yield disable (cancellable);

			removed ();
		}

		private const uint8[] SPIN = { 0xeb, 0xfe };
	}
}
