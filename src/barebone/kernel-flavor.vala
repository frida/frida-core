[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	/**
	 * What differs between the kernels we inject into: how the target is brought to a
	 * quiescent state beforehand, and how it is let go afterwards.
	 */
	internal interface KernelFlavor : Object {
		public abstract async void prepare (Cancellable? cancellable) throws Error, IOError;
		public abstract async void settle (Cancellable? cancellable) throws Error, IOError;
	}

	internal sealed class BareKernelFlavor : Object, KernelFlavor {
		private Machine machine;

		public BareKernelFlavor (Machine machine) {
			this.machine = machine;
		}

		public async void prepare (Cancellable? cancellable) throws Error, IOError {
		}

		public async void settle (Cancellable? cancellable) throws Error, IOError {
			yield machine.gdb.continue (cancellable);
		}
	}

	internal sealed class XnuKernelFlavor : Object, KernelFlavor {
		private Machine machine;
		private uint64 kernel_base;
		private SymbolInfo thread_block;
		private SymbolInfo? panic;

		public XnuKernelFlavor (Machine machine, uint64 kernel_base, Gee.Map<string, SymbolInfo> symbols)
				throws Error {
			this.machine = machine;
			this.kernel_base = kernel_base;

			thread_block = symbols["thread_block"];
			if (thread_block == null)
				throw new Error.NOT_SUPPORTED ("Missing symbol for thread_block");

			panic = symbols["panic"];
		}

		public async void prepare (Cancellable? cancellable) throws Error, IOError {
			uint64 thread_block_address = kernel_base + thread_block.offset;

			var arm64 = machine as Arm64Machine;
			if (panic != null && arm64 != null)
				arm64.call_landing_zone = kernel_base + panic.offset;

			yield machine.enter_exception_level (1, 1000, cancellable);

			yield run_until_thread_block (thread_block_address, cancellable);

			if (arm64 != null)
				yield arm64.learn_permission_templates (thread_block_address, cancellable);
		}

		public async void settle (Cancellable? cancellable) throws Error, IOError {
			GDB.Client gdb = machine.gdb;

			// The vphone research kernel panics on any synchronous exception taken while a
			// debugger is attached, which the worker hits in the allocator during gum_init.
			var arm64 = machine as Arm64Machine;
			bool post_inject_access_uses_bridge = arm64 != null && arm64.physical_memory != null;
			if (post_inject_access_uses_bridge)
				yield gdb.detach (cancellable);
			else
				yield gdb.continue (cancellable);
		}

		private async void run_until_thread_block (uint64 address, Cancellable? cancellable) throws Error, IOError {
			GDB.Client gdb = machine.gdb;
			var bp = yield gdb.add_breakpoint (SOFT, address, 4, cancellable);

			GDB.Breakpoint? hit = null;
			do {
				var exception = yield gdb.continue_until_exception (cancellable);
				hit = exception.breakpoint;
			} while (hit != bp);

			yield bp.remove (cancellable);
		}
	}

	internal sealed class Win9xKernelFlavor : Object, KernelFlavor {
		private Machine machine;
		private uint64 yield_point;

		public Win9xKernelFlavor (Machine machine, Gee.Map<string, SymbolInfo> symbols) throws Error {
			this.machine = machine;

			SymbolInfo? get_system_time = symbols["Get_System_Time"];
			if (get_system_time == null)
				throw new Error.NOT_SUPPORTED ("Missing symbol for Get_System_Time");
			yield_point = get_system_time.offset;
		}

		public async void prepare (Cancellable? cancellable) throws Error, IOError {
			yield run_until_yield_point (cancellable);
		}

		public async void settle (Cancellable? cancellable) throws Error, IOError {
			yield machine.gdb.continue (cancellable);
		}

		private async void run_until_yield_point (Cancellable? cancellable) throws Error, IOError {
			GDB.Client gdb = machine.gdb;
			var bp = yield gdb.add_breakpoint (SOFT, yield_point, 1, cancellable);

			GDB.Breakpoint? hit = null;
			do {
				var exception = yield gdb.continue_until_exception (cancellable);
				hit = exception.breakpoint;
			} while (hit != bp);

			yield bp.remove (cancellable);
		}
	}

	internal sealed class WinNtKernelFlavor : Object, KernelFlavor {
		private Machine machine;
		private uint64 yield_point;

		public WinNtKernelFlavor (Machine machine, Gee.Map<string, SymbolInfo> symbols) throws Error {
			this.machine = machine;

			// A thread in this system service is at PASSIVE_LEVEL on its own kernel stack, which the
			// agent needs to start.
			SymbolInfo? wait_for_single_object = symbols["NtWaitForSingleObject"];
			if (wait_for_single_object == null)
				throw new Error.NOT_SUPPORTED ("Missing symbol for NtWaitForSingleObject");
			yield_point = wait_for_single_object.offset;
		}

		public async void prepare (Cancellable? cancellable) throws Error, IOError {
			yield run_until_yield_point (cancellable);
		}

		public async void settle (Cancellable? cancellable) throws Error, IOError {
			yield machine.gdb.continue (cancellable);
		}

		private async void run_until_yield_point (Cancellable? cancellable) throws Error, IOError {
			GDB.Client gdb = machine.gdb;
			var bp = yield gdb.add_breakpoint (SOFT, yield_point, 1, cancellable);

			GDB.Breakpoint? hit = null;
			do {
				var exception = yield gdb.continue_until_exception (cancellable);
				hit = exception.breakpoint;
			} while (hit != bp);

			yield bp.remove (cancellable);
		}
	}
}
