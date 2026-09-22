namespace Frida {
	public interface Debugger : Object {
		public abstract TargetArch arch {
			get;
			set;
		}

		public abstract uint pointer_size {
			get;
			set;
		}

		public abstract ByteOrder byte_order {
			get;
			set;
		}

		public abstract DebuggerState state {
			get;
		}

		public abstract DebuggerException? exception {
			get;
		}

		public abstract Gee.Set<string> features {
			get;
		}

		public abstract bool has_register (string name);

		public abstract BufferBuilder make_buffer_builder ();
		public abstract Buffer make_buffer (Bytes bytes);

		public abstract async Bytes read_byte_array (uint64 address, size_t size, Cancellable? cancellable = null)
			throws Error, IOError;
		public abstract async void write_byte_array (uint64 address, Bytes bytes, Cancellable? cancellable = null)
			throws Error, IOError;
		public abstract async Buffer read_buffer (uint64 address, size_t size, Cancellable? cancellable = null)
			throws Error, IOError;

		public abstract async void resume (Cancellable? cancellable = null) throws Error, IOError;
		public abstract async DebuggerException continue_until_exception (Cancellable? cancellable = null)
			throws Error, IOError;
		public abstract async void stop (Cancellable? cancellable = null) throws Error, IOError;
		public abstract void restart () throws Error;

		public abstract async DebuggerBreakpoint add_breakpoint (BreakpointKind kind, uint64 address, size_t size,
			Cancellable? cancellable = null) throws Error, IOError;

		public abstract async void set_physical_memory_mode (bool enabled, Cancellable? cancellable = null)
			throws Error, IOError;

		public abstract async string run_remote_command (string command, Cancellable? cancellable = null)
			throws Error, IOError;

		public abstract async void detach (Cancellable? cancellable = null) throws Error, IOError;
		public abstract async void close (Cancellable? cancellable = null) throws IOError;
	}

	public interface DebuggerThread : Object {
		public abstract string id {
			get;
		}

		public abstract string? name {
			get;
		}

		public abstract Debugger debugger {
			get;
		}

		public abstract async void step (Cancellable? cancellable = null) throws Error, IOError;
		public abstract void step_and_continue () throws Error;

		public abstract async uint64 read_register (string name, Cancellable? cancellable = null) throws Error, IOError;
		public abstract async void write_register (string name, uint64 val, Cancellable? cancellable = null)
			throws Error, IOError;
		public abstract async Gee.Map<string, Variant> read_registers (Cancellable? cancellable = null)
			throws Error, IOError;
		public abstract async void write_registers (Gee.Map<string, Variant> regs, Cancellable? cancellable = null)
			throws Error, IOError;
	}

	public interface DebuggerBreakpoint : Object {
		public abstract BreakpointKind kind {
			get;
		}

		public abstract uint64 address {
			get;
		}

		public abstract size_t size {
			get;
		}

		public abstract async void enable (Cancellable? cancellable = null) throws Error, IOError;
		public abstract async void disable (Cancellable? cancellable = null) throws Error, IOError;
		public abstract async void remove (Cancellable? cancellable = null) throws Error, IOError;
	}

	public class DebuggerException : Object {
		public uint signum {
			get;
			construct;
		}

		public DebuggerBreakpoint? breakpoint {
			get;
			construct;
		}

		public DebuggerThread thread {
			get;
			construct;
		}

		public DebuggerException (uint signum, DebuggerBreakpoint? breakpoint, DebuggerThread thread) {
			Object (
				signum: signum,
				breakpoint: breakpoint,
				thread: thread
			);
		}

		public virtual string to_string () {
			return "signum=%u".printf (signum);
		}
	}

	public enum DebuggerState {
		STOPPED,
		RUNNING,
		STOPPING,
		CLOSED;

		public string to_nick () {
			return Marshal.enum_to_nick<DebuggerState> (this);
		}
	}

	public enum BreakpointKind {
		SOFT,
		HARD,
		WRITE,
		READ,
		ACCESS;

		public static BreakpointKind from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<BreakpointKind> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<BreakpointKind> (this);
		}
	}

	public enum TargetArch {
		UNKNOWN,
		IA32,
		X64,
		ARM,
		ARM64,
		MIPS;

		public static TargetArch from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<TargetArch> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<TargetArch> (this);
		}
	}
}
