namespace Frida {
#if WINDOWS
	public sealed class ForkMonitor : Object {
		public weak ForkHandler handler {
			get;
			construct;
		}

		public ForkMonitor (ForkHandler handler) {
			Object (handler: handler);
		}
	}
#else
	public sealed class ForkMonitor : Object, Gum.InvocationListener {
		public weak ForkHandler handler {
			get;
			construct;
		}

		private State state = IDLE;
		private HookId forking_hook = HookId.FORK;
		private ChildRecoveryBehavior child_recovery_behavior = NORMAL;
		private string? identifier;

		private static void * fork_impl;
		private static void * vfork_impl;
		private static void * clone_impl;
		private static void * clone3_impl;
		private static void * syscall_impl;
		private static void * bionic_clone_impl;

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
			CLONE,
			CLONE3,
			SYSCALL,
			SET_ARGV0,
			SET_CTX
		}

		public ForkMonitor (ForkHandler handler) {
			Object (handler: handler);
		}

		static construct {
			var libc = Gum.Process.get_libc_module ();
			fork_impl = (void *) libc.find_export_by_name ("fork");
			vfork_impl = (void *) libc.find_export_by_name ("vfork");
			clone_impl = (void *) libc.find_export_by_name ("clone");
			clone3_impl = (void *) libc.find_export_by_name ("clone3");
			syscall_impl = (void *) libc.find_export_by_name ("syscall");
#if ANDROID
			bionic_clone_impl = (void *) libc.find_export_by_name ("__clone");
			if (bionic_clone_impl == null)
				bionic_clone_impl = (void *) libc.find_symbol_by_name ("__bionic_clone");
#endif
		}

		construct {
			var interceptor = Gum.Interceptor.obtain ();

			unowned Gum.InvocationListener listener = this;

#if ANDROID
			if (get_executable_path ().has_prefix ("/system/bin/app_process")) {
				try {
					string cmdline;
					FileUtils.get_contents ("/proc/self/cmdline", out cmdline);
					if (cmdline == "zygote" || cmdline == "zygote64" || cmdline == "usap32" || cmdline == "usap64") {
						var runtime = Gum.Process.find_module_by_name ("libandroid_runtime.so");
						if (runtime != null) {
							var set_argv0 = (void *) runtime.find_export_by_name ("_Z27android_os_Process_setArgV0P7_JNIEnvP8_jobjectP8_jstring");
							if (set_argv0 != null) {
								var set_argv0_options = Gum.AttachOptions ();
								set_argv0_options.listener_function_data = (void *) HookId.SET_ARGV0;
								interceptor.attach (set_argv0, listener, set_argv0_options);
								child_recovery_behavior = DEFERRED_UNTIL_SET_ARGV0;
							}
						}

						var selinux = Gum.Process.find_module_by_name ("libselinux.so");
						if (selinux != null) {
							var setcontext = (void *) selinux.find_export_by_name ("selinux_android_setcontext");
							if (setcontext != null) {
								var setcontext_options = Gum.AttachOptions ();
								setcontext_options.listener_function_data = (void *) HookId.SET_CTX;
								interceptor.attach (setcontext, listener, setcontext_options);
							}
						}
					}
				} catch (FileError e) {
				}
			}
#endif

			var fork_options = Gum.AttachOptions ();
			fork_options.listener_function_data = (void *) HookId.FORK;
			interceptor.attach (fork_impl, listener, fork_options);
			if (vfork_impl != null)
				interceptor.replace (vfork_impl, fork_impl);

#if LINUX
			attach_if_present (interceptor, listener, clone_impl, HookId.CLONE);
			attach_if_present (interceptor, listener, clone3_impl, HookId.CLONE3);
			attach_if_present (interceptor, listener, syscall_impl, HookId.SYSCALL);
			if (bionic_clone_impl != null && bionic_clone_impl != clone_impl)
				attach_if_present (interceptor, listener, bionic_clone_impl, HookId.CLONE);
#endif
		}

#if LINUX
		private static void attach_if_present (Gum.Interceptor interceptor, Gum.InvocationListener listener,
				void * impl, HookId hook_id) {
			if (impl == null)
				return;
			var options = Gum.AttachOptions ();
			options.listener_function_data = (void *) hook_id;
			interceptor.attach (impl, listener, options);
		}
#endif

		public override void dispose () {
			var interceptor = Gum.Interceptor.obtain ();

			if (vfork_impl != null)
				interceptor.revert (vfork_impl);
			interceptor.detach (this);

			base.dispose ();
		}

		private void on_enter (Gum.InvocationContext context) {
			var hook_id = (HookId) context.get_listener_function_data ();
			switch (hook_id) {
				case FORK:	on_fork_enter (context);	break;
				case CLONE:	on_clone_enter (context);	break;
				case CLONE3:	on_clone3_enter (context);	break;
				case SYSCALL:	on_syscall_enter (context);	break;
				case SET_ARGV0:	on_set_argv0_enter (context);	break;
				case SET_CTX:   on_set_ctx_enter (context);	break;
				default:	assert_not_reached ();
			}
		}

		private void on_leave (Gum.InvocationContext context) {
			var hook_id = (HookId) context.get_listener_function_data ();
			switch (hook_id) {
				case FORK:	on_fork_leave (context);	break;
				case CLONE:	on_clone_leave (context);	break;
				case CLONE3:	on_clone3_leave (context);	break;
				case SYSCALL:	on_syscall_leave (context);	break;
				case SET_ARGV0:	on_set_argv0_leave (context);	break;
				case SET_CTX:   on_set_ctx_leave (context);	break;
				default:	assert_not_reached ();
			}
		}

		public void on_fork_enter (Gum.InvocationContext context) {
			begin_process_creation (HookId.FORK);
		}

		public void on_fork_leave (Gum.InvocationContext context) {
			finish_process_creation (HookId.FORK, (int) context.get_return_value ());
		}

		public void on_clone_enter (Gum.InvocationContext context) {
			if (state != State.IDLE)
				return;

			size_t a0 = (size_t) context.get_nth_argument (0);
			size_t a2 = (size_t) context.get_nth_argument (2);
			size_t flags;
			bool libc_style = a0 > 0x10000;
			if (libc_style) {
				/* clone(fn, stack, flags, ...) — child starts at fn, does not return. */
				if (a0 != 0)
					return;
				flags = a2;
			} else {
				flags = a0;
			}

			if (!_frida_fork_monitor_flags_create_process (flags))
				return;

			begin_process_creation (HookId.CLONE);
		}

		public void on_clone_leave (Gum.InvocationContext context) {
			finish_process_creation (HookId.CLONE, (int) context.get_return_value ());
		}

		public void on_clone3_enter (Gum.InvocationContext context) {
			if (state != State.IDLE)
				return;

			size_t flags;
			if (!_frida_fork_monitor_clone3_creates_process (
					context.get_nth_argument (0),
					(size_t) context.get_nth_argument (1),
					out flags)) {
				return;
			}

			begin_process_creation (HookId.CLONE3);
		}

		public void on_clone3_leave (Gum.InvocationContext context) {
			finish_process_creation (HookId.CLONE3, (int) context.get_return_value ());
		}

		public void on_syscall_enter (Gum.InvocationContext context) {
			if (state != State.IDLE)
				return;

			size_t flags;
			ssize_t number = (ssize_t) context.get_nth_argument (0);
			if (!_frida_fork_monitor_syscall_creates_process (number,
					(size_t) context.get_nth_argument (1),
					(size_t) context.get_nth_argument (2),
					out flags)) {
				return;
			}

			begin_process_creation (HookId.SYSCALL);
		}

		public void on_syscall_leave (Gum.InvocationContext context) {
			finish_process_creation (HookId.SYSCALL, (int) context.get_return_value ());
		}

		private void begin_process_creation (HookId hook) {
			state = FORKING;
			forking_hook = hook;
			identifier = null;
			handler.prepare_to_fork ();
		}

		private void finish_process_creation (HookId hook, int result) {
			if (state != State.FORKING || forking_hook != hook)
				return;

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
			if (identifier == null) {
				void *** env = context.get_nth_argument (0);
				void * name_obj = context.get_nth_argument (2);

				var env_vtable = *env;

				var get_string_utf_chars = (GetStringUTFCharsFunc) env_vtable[169];
				var release_string_utf_chars = (ReleaseStringUTFCharsFunc) env_vtable[170];

				var name_utf8 = get_string_utf_chars (env, name_obj);

				identifier = name_utf8;

				release_string_utf_chars (env, name_obj, name_utf8);
			}
		}

		public void on_set_argv0_leave (Gum.InvocationContext context) {
			if (state == FORKING) {
				handler.recover_from_fork_in_child (identifier);
				state = IDLE;
			}
		}

		public void on_set_ctx_enter (Gum.InvocationContext context) {
			string * nice_name = context.get_nth_argument (3);
			identifier = nice_name;

			if (state == IDLE)
				handler.prepare_to_specialize (identifier);
		}

		public void on_set_ctx_leave (Gum.InvocationContext context) {
			if (state == IDLE)
				handler.recover_from_specialization (identifier);
		}

		[CCode (cname = "_frida_fork_monitor_flags_create_process", cheader_filename = "fork-monitor-glue.h")]
		private static extern bool _frida_fork_monitor_flags_create_process (size_t flags);

		[CCode (cname = "_frida_fork_monitor_syscall_creates_process", cheader_filename = "fork-monitor-glue.h")]
		private static extern bool _frida_fork_monitor_syscall_creates_process (ssize_t number, size_t arg0, size_t arg1,
			out size_t flags);

		[CCode (cname = "_frida_fork_monitor_clone3_creates_process", cheader_filename = "fork-monitor-glue.h")]
		private static extern bool _frida_fork_monitor_clone3_creates_process (void * args, size_t size, out size_t flags);

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

		public abstract void prepare_to_specialize (string identifier);
		public abstract void recover_from_specialization (string identifier);
	}
}
