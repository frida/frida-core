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

				/*
				unowned RecvArgs args = (RecvArgs) function_arguments;
				int sock_handle = args.s;*/

				Idle.add (() => {
					var builder = new VariantBuilder (VariantType.ARRAY);
					builder.add ("u", state.seen_function_count);
					for (uint i = 0; i != state.seen_function_count; i++) {
						builder.add ("u", state.seen_functions[i]);
						if (i == 20)
							break;
					}
					proxy.emit ("FuncEvent", builder.end ());

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

			public uint32[] seen_functions = new uint32[31337];
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
				assert (seen_function_count + 1 < seen_functions.length);
				seen_functions[seen_function_count++] = (uint32) ev.target;
			}
		}
	}

	[Compact]
	public class RecvArgs {
		public int s;
		public char * buf;
		public int len;
		public int flags;
	}
}
