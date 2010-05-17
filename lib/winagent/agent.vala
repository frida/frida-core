namespace Zed {
	namespace Agent {
		private static WinIpc.ClientProxy proxy;
		private static Zed.GstTracer gst_tracer;

		public void main (string ipc_server_address) {
			var loop = new MainLoop ();

			proxy = new WinIpc.ClientProxy (ipc_server_address);
			proxy.add_notify_handler ("Stop", "", (arg) => {
				loop.quit ();
			});

			Idle.add (() => {
				do_establish (proxy);
				return false;
			});

			loop.run ();

			if (gst_tracer != null) {
				gst_tracer.detach ();
				gst_tracer = null;
			}
		}

		private async void do_establish (WinIpc.ClientProxy proxy) {
			try {
				yield proxy.establish ();
			} catch (WinIpc.ProxyError e) {
				error (e.message);
				return;
			}

			gst_tracer = new Zed.GstTracer (proxy);
			gst_tracer.attach ();
		}
	}

	public class GstTracer : Object, Gum.InvocationListener {
		private WinIpc.Proxy proxy;

		public GstTracer (WinIpc.Proxy proxy) {
			this.proxy = proxy;
		}

		public extern void attach ();
		public extern void detach ();

		public void on_enter (Gum.InvocationContext context, Gum.InvocationContext parent_context, void * cpu_context, void * function_arguments) {
			GstFunction func = (GstFunction) context.instance_data;
			if (func == GstFunction.PAD_PUSH)
				on_pad_push (function_arguments);
			else if (func == GstFunction.OBJECT_FREE)
				on_object_free (function_arguments);
			else
				assert_not_reached ();
		}

		public void on_leave (Gum.InvocationContext context, Gum.InvocationContext parent_context, void * function_return_value) {
		}

		public void * provide_thread_data (void * function_instance_data, uint thread_id) {
			return null;
		}

		public extern void on_pad_push (void * arguments);
		public extern void on_object_free (void * arguments);

		public void submit_pad_push_event (string pad_name) {
			Idle.add (() => {
				proxy.emit ("FunctionCall", new Variant ("s", pad_name));
				return false;
			});
		}
	}

	public enum GstFunction {
		PAD_PUSH = 1,
		OBJECT_FREE
	}
}

