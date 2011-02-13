namespace Zed.Agent {
	public class GMainWatchdog : Object, Gum.InvocationListener {
		private Gum.Interceptor interceptor = Gum.Interceptor.obtain ();
		private bool is_enabled = false;

		private Gee.HashMap<void *, TimerSource> source_by_main_context = new Gee.HashMap<void *, TimerSource> ();

		~GMainWatchdog () {
			if (is_enabled)
				interceptor.detach_listener (this);
		}

		public void set_enabled (bool enable) throws IOError {
			if (enable) {
				if (is_enabled)
					throw new IOError.FAILED ("already enabled");

				string glib_module_name = null;
				Gum.Process.enumerate_modules ((name, address, path) => {
					if (name.down ().str ("glib-2.0") != null) {
						glib_module_name = name;
						return false;
					}

					return true;
				});

				if (glib_module_name == null)
					throw new IOError.FAILED ("glib library not loaded");

				var function_address = Gum.Module.find_export_by_name (glib_module_name, "g_main_context_dispatch");
				if (function_address == null)
					throw new IOError.FAILED ("g_main_context_dispatch not found");

				interceptor.attach_listener (function_address, this);
				is_enabled = true;
			} else {
				if (!is_enabled)
					throw new IOError.FAILED ("not enabled");
				interceptor.detach_listener (this);
				source_by_main_context.clear ();
				is_enabled = false;
			}
		}

		private struct DispatchInvocation {
			unowned TimerSource ts;
		}

		public void on_enter (Gum.InvocationContext context) {
			var main_context = context.get_nth_argument (0);
			assert (main_context != null);

			TimerSource ts = null;

			lock (source_by_main_context) {
				ts = source_by_main_context[main_context];
				if (ts == null) {
					ts = new TimerSource ();
					ts.source.attach (MainContext.default ());
					source_by_main_context[main_context] = ts;
				}
			}

			DispatchInvocation * invocation = context.get_listener_function_invocation_data (sizeof (DispatchInvocation));
			invocation.ts = ts;

			ts.dispatch_beginning ();
		}

		public void on_leave (Gum.InvocationContext context) {
			DispatchInvocation * invocation = context.get_listener_function_invocation_data (sizeof (DispatchInvocation));
			invocation.ts.dispatch_ended ();
		}

		private class TimerSource : Object {
			public Source source {
				get;
				private set;
			}
			private TimerSourceFuncs funcs;

			private Timer timer = new Timer ();
			private bool active = false;
			private double max_duration = 0.500;

			construct {
				funcs.prepare = do_prepare;
				funcs.check = do_check;
				funcs.dispatch = do_dispatch;
				funcs.finalize = do_finalize;

				TimerSourceFuncs * funcs_ptr = &funcs;
				SourceFuncs * source_funcs = (SourceFuncs *) funcs_ptr;
				source = new Source (source_funcs, (uint) (sizeof (RawSource) + sizeof (void *)));
				*((TimerSource **) ((Source *) source + 1)) = this;
			}

			~TimerSource () {
				source.destroy ();
			}

			public void dispatch_beginning () {
				lock (source) {
					active = true;
					timer.start ();
				}
				MainContext.default ().wakeup ();
			}

			public void dispatch_ended () {
				lock (source) {
					active = false;
					timer.stop ();
				}
				MainContext.default ().wakeup ();
			}

			private bool prepare (out int timeout) {
				timeout = compute_remaining_milliseconds ();
				return timeout == 0;
			}

			private bool check () {
				return compute_remaining_milliseconds () == 0;
			}

			private int compute_remaining_milliseconds () {
				lock (source) {
					var remaining = (int) ((max_duration - timer.elapsed ()) * 1000.0);
					if (remaining < 0)
						return 0;
					return remaining;
				}
			}

			private static bool do_prepare (Source source, out int timeout) {
				unowned TimerSource * instance = *((TimerSource **) ((Source *) source + 1));
				return instance->prepare (out timeout);
			}

			private static bool do_check (Source source) {
				unowned TimerSource * instance = *((TimerSource **) ((Source *) source + 1));
				return instance->check ();
			}

			private static bool do_dispatch (Source source, SourceFunc callback) {
				breakpoint ();
				return true;
			}

			private static void do_finalize (Source source) {
			}
		}

		protected struct RawSource {
			public void * callback_data;
			public void * callback_funcs;

			public void * source_funcs;
			public uint ref_count;

			public MainContext * context;

			public int priority;
			public uint flags;
			public uint source_id;

			public void * poll_fds;

			public void * prev;
			public void * next;

			public void * name;
			public void * reserved2;
		}

		[CCode (has_target = false)]
		public delegate bool TimerSourcePrepareFunc (Source source, out int timeout);
		[CCode (has_target = false)]
		public delegate bool TimerSourceCheckFunc (Source source);
		[CCode (has_target = false)]
		public delegate bool TimerSourceDispatchFunc (Source source, SourceFunc callback);
		[CCode (has_target = false)]
		public delegate void TimerSourceFinalizeFunc (Source source);

		private struct TimerSourceFuncs {
			public TimerSourcePrepareFunc prepare;
			public TimerSourceCheckFunc check;
			public TimerSourceDispatchFunc dispatch;
			public TimerSourceFinalizeFunc finalize;
		}
	}
}
