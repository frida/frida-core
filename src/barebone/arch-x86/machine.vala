[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	public sealed class IA32Machine : Object, Machine {
		public override GDB.Client gdb {
			get;
			set;
		}

		public override string llvm_target {
			get { return "x86-unknown-none"; }
		}

		public override string llvm_code_model {
			get { return "small"; }
		}

		public IA32Machine (GDB.Client gdb) {
			Object (gdb: gdb);
		}

		public async size_t query_page_size (Cancellable? cancellable) throws Error, IOError {
			return 4096;
		}

		public async void enumerate_ranges (Gum.PageProtection prot, FoundRangeFunc func, Cancellable? cancellable)
				throws Error, IOError {
			throw_not_supported ();
		}

		public async Allocation allocate_pages (uint64 physical_address, uint num_pages, Cancellable? cancellable)
				throws Error, IOError {
			throw_not_supported ();
		}

		public async Gee.List<uint64?> scan_ranges (Gee.List<Gum.MemoryRange?> ranges, MatchPattern pattern, uint max_matches,
				Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public void apply_relocation (Gum.ElfRelocationDetails r, uint64 base_va, Buffer relocated) throws Error {
			throw_not_supported ();
		}

		public async uint64 invoke (uint64 impl, uint64[] args, uint64 landing_zone, Cancellable? cancellable)
				throws Error, IOError {
			throw_not_supported ();
		}

		public async CallFrame load_call_frame (GDB.Thread thread, uint arity, Cancellable? cancellable) throws Error, IOError {
			var regs = yield thread.read_registers (cancellable);

			uint64 original_esp = regs["esp"].get_uint64 ();
			var stack = yield gdb.read_buffer (original_esp, (1 + arity) * 4, cancellable);

			return new IA32CallFrame (thread, regs, stack, original_esp);
		}

		private class IA32CallFrame : Object, CallFrame {
			public uint64 return_address {
				get { return stack.read_uint32 (0); }
			}

			public Gee.Map<string, Variant> registers {
				get { return regs; }
			}

			private GDB.Thread thread;

			private Gee.Map<string, Variant> regs;

			private Buffer stack;
			private uint64 original_esp;
			private State stack_state = PRISTINE;

			private enum State {
				PRISTINE,
				MODIFIED
			}

			public IA32CallFrame (GDB.Thread thread, Gee.Map<string, Variant> regs, Buffer stack, uint64 original_esp) {
				this.thread = thread;

				this.regs = regs;

				this.stack = stack;
				this.original_esp = original_esp;
			}

			public uint64 get_nth_argument (uint n) {
				size_t offset;
				if (try_get_stack_offset_of_nth_argument (n, out offset))
					return stack.read_uint32 (offset);
				return uint64.MAX;
			}

			public void replace_nth_argument (uint n, uint64 val) {
				size_t offset;
				if (try_get_stack_offset_of_nth_argument (n, out offset)) {
					stack.write_uint32 (offset, (uint32) val);
					invalidate_stack ();
				}
			}

			private bool try_get_stack_offset_of_nth_argument (uint n, out size_t offset) {
				size_t start = (1 + n) * 4;
				size_t end = start + 4;
				if (end > stack.bytes.get_size ()) {
					offset = 0;
					return false;
				}

				offset = start;
				return true;
			}

			public uint64 get_return_value () {
				return regs["eax"].get_uint64 ();
			}

			public void replace_return_value (uint64 retval) {
				regs["eax"] = retval;
				invalidate_regs ();
			}

			public void force_return () {
				regs["eip"] = return_address;
				invalidate_regs ();
			}

			private void invalidate_regs () {
				regs.set_data ("dirty", true);
			}

			private void invalidate_stack () {
				stack_state = MODIFIED;
			}

			public async void commit (Cancellable? cancellable) throws Error, IOError {
				if (regs.get_data<bool> ("dirty"))
					yield thread.write_registers (regs, cancellable);

				if (stack_state == MODIFIED)
					yield thread.client.write_byte_array (original_esp, stack.bytes, cancellable);
			}
		}

		public uint64 address_from_funcptr (uint64 ptr) {
			return ptr;
		}

		public size_t breakpoint_size_from_funcptr (uint64 ptr) {
			return 1;
		}

		public async InlineHook create_inline_hook (uint64 target, uint64 handler, Allocator allocator, Cancellable? cancellable)
				throws Error, IOError {
			throw_not_supported ();
		}
	}
}
