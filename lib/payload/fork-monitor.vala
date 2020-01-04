namespace Frida {
#if WINDOWS
	public class ForkMonitor : Object {
		public weak ForkHandler handler {
			get;
			construct;
		}

		public ForkMonitor (ForkHandler handler) {
			Object (handler: handler);
		}
	}
#else
	public class ForkMonitor : Object, Gum.InvocationListener {
		public weak ForkHandler handler {
			get;
			construct;
		}

		private State state = IDLE;
		private ChildRecoveryBehavior child_recovery_behavior = NORMAL;

		private static void * fork_impl;
		private static void * vfork_impl;

		private enum State {
			IDLE,
			FORKING,
		}

		private enum ChildRecoveryBehavior {
			NORMAL,
			DEFERRED_UNTIL_SET_ARGV0
		}

		private enum HookId {
			FORK,
			SET_ARGV0
		}

		public ForkMonitor (ForkHandler handler) {
			Object (handler: handler);
		}

		static construct {
			unowned string libc = Gum.Process.query_libc_name ();
			fork_impl = Gum.Module.find_export_by_name (libc, "fork");
			vfork_impl = Gum.Module.find_export_by_name (libc, "vfork");
		}

		construct {
			var interceptor = Gum.Interceptor.obtain ();

			unowned Gum.InvocationListener listener = this;

#if ANDROID
			if (get_executable_path ().has_prefix ("/system/bin/app_process")) {
				try {
					string cmdline;
					FileUtils.get_contents ("/proc/self/cmdline", out cmdline);
					if (cmdline == "zygote" || cmdline == "zygote64") {
						var set_argv0 = Gum.Module.find_export_by_name ("libandroid_runtime.so", "_Z27android_os_Process_setArgV0P7_JNIEnvP8_jobjectP8_jstring");
						if (set_argv0 != null) {
							interceptor.attach (set_argv0, listener, (void *) HookId.SET_ARGV0);
							child_recovery_behavior = DEFERRED_UNTIL_SET_ARGV0;
						}
					}
				} catch (FileError e) {
				}
			}
#endif

			interceptor.attach (fork_impl, listener, (void *) HookId.FORK);
			interceptor.replace (vfork_impl, fork_impl);
		}

		public override void dispose () {
			var interceptor = Gum.Interceptor.obtain ();

			interceptor.revert (vfork_impl);
			interceptor.detach (this);

			base.dispose ();
		}

		private void on_enter (Gum.InvocationContext context) {
			var hook_id = (HookId) context.get_listener_function_data ();
			switch (hook_id) {
				case FORK:	on_fork_enter (context);	break;
				case SET_ARGV0:	on_set_argv0_enter (context);	break;
				default:	assert_not_reached ();
			}
		}

		private void on_leave (Gum.InvocationContext context) {
			var hook_id = (HookId) context.get_listener_function_data ();
			switch (hook_id) {
				case FORK:	on_fork_leave (context);	break;
				case SET_ARGV0:	on_set_argv0_leave (context);	break;
				default:	assert_not_reached ();
			}
		}

		public void on_fork_enter (Gum.InvocationContext context) {
			state = FORKING;
			handler.prepare_to_fork ();
		}

		public void on_fork_leave (Gum.InvocationContext context) {
			int result = (int) context.get_return_value ();
			if (result != 0) {
				handler.recover_from_fork_in_parent ();
				state = IDLE;
			} else {
				if (child_recovery_behavior == NORMAL) {
					handler.recover_from_fork_in_child (null);
					state = IDLE;
				} else {
					child_recovery_behavior = NORMAL;
				}
			}
		}

		public void on_set_argv0_enter (Gum.InvocationContext context) {
			SetArgV0Invocation * invocation = context.get_listener_invocation_data (sizeof (SetArgV0Invocation));
			invocation.env = context.get_nth_argument (0);
			invocation.name_obj = context.get_nth_argument (2);
		}

		public void on_set_argv0_leave (Gum.InvocationContext context) {
			SetArgV0Invocation * invocation = context.get_listener_invocation_data (sizeof (SetArgV0Invocation));

			if (state != FORKING)
				return;

			var env = invocation.env;
			var env_vtable = *env;

			var get_string_utf_chars = (GetStringUTFCharsFunc) env_vtable[169];
			var release_string_utf_chars = (ReleaseStringUTFCharsFunc) env_vtable[170];

			var name_obj = invocation.name_obj;
			var name_utf8 = get_string_utf_chars (env, name_obj);

			handler.recover_from_fork_in_child (name_utf8);
			state = IDLE;

			release_string_utf_chars (env, name_obj, name_utf8);
		}

		private struct SetArgV0Invocation {
			public void *** env;
			public void * name_obj;
		}

		[CCode (has_target = false)]
		private delegate string * GetStringUTFCharsFunc (void * env, void * str_obj, out uint8 is_copy = null);

		[CCode (has_target = false)]
		private delegate string * ReleaseStringUTFCharsFunc (void * env, void * str_obj, string * str_utf8);
	}
#endif

	public interface ForkHandler : Object {
		public abstract void prepare_to_fork ();
		public abstract void recover_from_fork_in_parent ();
		public abstract void recover_from_fork_in_child (string? identifier);
	}
}
