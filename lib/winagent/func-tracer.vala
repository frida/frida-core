using Gee;

namespace Zed {
	public class FuncTracer : Object, Gum.InvocationListener {
		private WinIpc.Proxy proxy;

		public FuncTracer (WinIpc.Proxy proxy) {
			this.proxy = proxy;
		}

		public extern void attach ();
		public extern void detach ();

		public void on_enter (Gum.InvocationContext context, Gum.InvocationContext parent_context, void * cpu_context, void * function_arguments) {
			FuncState state = (FuncState) context.thread_data;

			if (state.is_stalking) {
				/*state.stalker.unfollow_me ();*/
				state.has_been_stalked = true;
				state.is_stalking = false;

				Idle.add (() => {
					submit (state);
					return false;
				});
			} else if (!state.has_been_stalked) {
				state.is_stalking = true;
				state.stalker.follow_me (state);
			}
		}

		public void on_leave (Gum.InvocationContext context, Gum.InvocationContext parent_context, void * function_return_value) {
		}

		public void * provide_thread_data (void * function_instance_data, uint thread_id) {
			return ref_object_hack (new FuncState ());
		}

		private async void submit (FuncState state) {
			for (uint i = 0; i != state.seen_function_count; i++) {
				Variant arg;

				var addr = FunctionAddress.resolve (state.seen_functions[i]);
				if (addr != null)
					arg = new Variant ("(ssu)", addr.module_name, addr.function_name, addr.offset);
				else
					arg = new Variant ("(ssu)", "", "", state.seen_functions[i]);

				try {
					yield proxy.emit ("FuncEvent", arg);
				} catch (WinIpc.ProxyError e) {
					error (e.message);
					return;
				}
			}
		}

		private extern void * ref_object_hack (Object obj);

		private class FuncState : Object, Gum.EventSink {
			public bool has_been_stalked {
				get;
				set;
			}

			public bool is_stalking {
				get;
				set;
			}

			public Gum.Stalker stalker {
				get;
				private set;
			}

			private const uint CAPACITY = 50000;

			public size_t[] seen_functions = new size_t[CAPACITY];
			public uint seen_function_count = 0;

			public FuncState () {
				has_been_stalked = false;
				is_stalking = false;
				stalker = new Gum.Stalker ();
			}

			public Gum.EventType query_mask () {
				return Gum.EventType.CALL;
			}

			public void process (void * opaque_event) {
				unowned Gum.CallEvent ev = (Gum.CallEvent) opaque_event;
				assert (seen_function_count != seen_functions.length);
				seen_functions[seen_function_count++] = (uint32) ev.target;
			}
		}
	}

	public class FunctionAddress {
		public string module_name {
			get;
			private set;
		}

		public size_t offset {
			get;
			private set;
		}

		public string function_name {
			get;
			set;
		}

		public FunctionAddress (string module_name, size_t offset) {
			this.module_name = module_name;
			this.offset = offset;
			this.function_name = "";
		}

		public extern static FunctionAddress? resolve (size_t address);
	}
}
