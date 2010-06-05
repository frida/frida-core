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
				state.stalker.unfollow_me ();
				state.has_been_stalked = true;
				state.is_stalking = false;

				Idle.add (() => {
					submit (state);
					return false;
				});
			}
		}

		public void on_leave (Gum.InvocationContext context, Gum.InvocationContext parent_context, void * function_return_value) {
			FuncState state = (FuncState) context.thread_data;

			if (!state.has_been_stalked) {
				state.is_stalking = true;
				state.stalker.follow_me (state);
			}
		}

		public void * provide_thread_data (void * function_instance_data, uint thread_id) {
			return ref_object_hack (new FuncState ());
		}

		private async void submit (FuncState state) {
			for (uint i = 0; i != state.seen_call_count; i++) {
				unowned Gum.CallEvent ev = state.seen_calls[i];
				Variant arg;

				var site_addr = FunctionAddress.resolve ((size_t) ev.location);
				var target_addr = FunctionAddress.resolve ((size_t) ev.target);
				if (site_addr != null && target_addr != null) {
					arg = new Variant ("(i(ssu)(ssu))",
						ev.depth,
						site_addr.module_name, site_addr.function_name, site_addr.offset,
						target_addr.module_name, target_addr.function_name, target_addr.offset);
				} else {
					arg = new Variant ("(i(ssu)(ssu))",
						ev.depth,
						"", "", (uint32) ev.location,
						"", "", (uint32) ev.target);
				}

				try {
					yield proxy.emit ("FuncEvent", arg);
				} catch (WinIpc.ProxyError e1) {
					error (e1.message);
					return;
				}
			}

			try {
				yield proxy.emit ("FuncEvent", new Variant ("(i(ssu)(ssu))",
					state.seen_call_count,
					"This", "Is", 42,
					"The", "End", 43));
			} catch (WinIpc.ProxyError e2) {
				error (e2.message);
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

			public Gum.CallEvent[] seen_calls = new Gum.CallEvent[CAPACITY];
			public uint seen_call_count = 0;

			public FuncState () {
				has_been_stalked = false;
				is_stalking = false;
				stalker = new Gum.Stalker ();
			}

			public Gum.EventType query_mask () {
				return Gum.EventType.CALL;
			}

			public void process (void * opaque_event) {
				Memory.copy (&seen_calls[seen_call_count], opaque_event, sizeof (Gum.CallEvent));
				seen_call_count++;
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
