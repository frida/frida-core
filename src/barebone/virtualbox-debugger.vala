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
			yield debugger.refresh_threads (cancellable);

			return debugger;
		}

		private async void refresh_threads (Cancellable? cancellable) throws Error, IOError {
			uint count = yield console.query_cpu_count (cancellable);

			threads.clear ();
			for (uint i = 0; i != count; i++)
				threads.add (new VirtualBoxThread (i, console, this));

			_exception = new DebuggerException (SIGTRAP, null, threads[0]);
		}

		public bool has_register (string name) {
			return name == "rip" || name == "rsp" || name == "gs_base" || name == "cr3";
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
			yield console.resume (cancellable);
			change_state (RUNNING, null);
		}

		public async void stop (Cancellable? cancellable = null) throws Error, IOError {
			if (_state == STOPPED)
				return;

			yield console.halt (cancellable);
			change_state (STOPPED, _exception);
		}

		public void restart () throws Error {
			throw new Error.NOT_SUPPORTED ("The VirtualBox debugger console cannot restart the guest");
		}

		public async DebuggerException continue_until_exception (Cancellable? cancellable = null)
				throws Error, IOError {
			yield resume (cancellable);

			while (true) {
				yield sleep (POLL_INTERVAL_MSEC, cancellable);

				yield console.halt (cancellable);

				foreach (VirtualBoxThread thread in threads) {
					uint64 pc = yield thread.read_register ("rip", cancellable);
					VirtualBoxBreakpoint? bp = breakpoints[pc];
					if (bp != null) {
						var caught = new DebuggerException (SIGTRAP, bp, thread);
						change_state (STOPPED, caught);
						return caught;
					}
				}

				yield console.resume (cancellable);
			}
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
			throw new Error.NOT_SUPPORTED ("The VirtualBox debugger console addresses memory virtually");
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
		private const uint SIGTRAP = 5;
	}

	public sealed class VirtualBoxThread : Object, DebuggerThread {
		public string id {
			get;
			construct;
		}

		public string? name {
			get;
			construct;
		}

		public Debugger debugger {
			get {
				return owner;
			}
		}

		private uint cpu;
		private VirtualBoxConsole console;
		private weak VirtualBoxDebugger owner;

		public VirtualBoxThread (uint cpu, VirtualBoxConsole console, VirtualBoxDebugger owner) {
			Object (
				id: "%u".printf (cpu + 1),
				name: "CPU %u".printf (cpu)
			);
			this.cpu = cpu;
			this.console = console;
			this.owner = owner;
		}

		public async void step (Cancellable? cancellable = null) throws Error, IOError {
			yield console.run ("t", cancellable);
		}

		public void step_and_continue () throws Error {
			throw new Error.NOT_SUPPORTED ("The VirtualBox debugger console steps synchronously");
		}

		public async uint64 read_register (string name, Cancellable? cancellable = null) throws Error, IOError {
			var registers = yield console.read_registers (cpu, cancellable);
			uint64? val = registers[name];
			if (val == null)
				throw new Error.NOT_SUPPORTED ("Register “%s” is not exposed by VirtualBox", name);
			return val;
		}

		public async void write_register (string name, uint64 val, Cancellable? cancellable = null)
				throws Error, IOError {
			yield console.write_register (cpu, name, val, cancellable);
		}

		public async Gee.Map<string, Variant> read_registers (Cancellable? cancellable = null)
				throws Error, IOError {
			var raw = yield console.read_registers (cpu, cancellable);

			var registers = new Gee.HashMap<string, Variant> ();
			foreach (var e in raw.entries)
				registers[e.key] = new Variant.uint64 (e.value);

			return registers;
		}

		public async void write_registers (Gee.Map<string, Variant> regs, Cancellable? cancellable = null)
				throws Error, IOError {
			foreach (var e in regs.entries)
				yield console.write_register (cpu, e.key, e.value.get_uint64 (), cancellable);
		}
	}

	public sealed class VirtualBoxBreakpoint : Object, DebuggerBreakpoint {
		public signal void removed ();

		public BreakpointKind kind {
			get;
			construct;
		}

		public uint64 address {
			get;
			construct;
		}

		public size_t size {
			get;
			construct;
		}

		private VirtualBoxConsole console;
		private Bytes? displaced;

		public VirtualBoxBreakpoint (BreakpointKind kind, uint64 address, size_t size, VirtualBoxConsole console) {
			Object (
				kind: kind,
				address: address,
				size: size
			);
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
