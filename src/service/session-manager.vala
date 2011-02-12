namespace Frida {
	/* TODO: find a suitable home for this code */

	public class SessionManager : Object {
		public MainContext main_context {
			get;
			private set;
		}

		private Zed.HostSessionService service = new Zed.HostSessionService.with_local_backend_only ();
		private Zed.HostSessionProvider local_provider;
		private Zed.HostSession local_session;

		private Gee.HashMap<uint, Session> session_by_pid = new Gee.HashMap<uint, Session> ();

		public SessionManager (MainContext main_context) {
			this.main_context = main_context;
		}

		public override void dispose () {
			try {
				(create<CloseTask> () as CloseTask).start_and_wait_for_completion ();
			} catch (Error e) {
				assert_not_reached ();
			}

			base.dispose ();
		}

		public Session obtain_session_for (uint pid) throws Error {
			var task = create<ObtainSessionTask> () as ObtainSessionTask;
			task.pid = pid;
			return task.start_and_wait_for_completion ();
		}

		public void _release_session (Session session) {
			var session_did_exist = session_by_pid.unset (session.pid);
			assert (session_did_exist);
		}

		private Object create<T> () {
			return Object.new (typeof (T), manager: this);
		}

		private class CloseTask : AsyncTask<void> {
			protected override void validate_operation () throws Error {
			}

			protected override async void perform_operation () throws Error {
				var service = manager.service;
				if (service == null)
					return;
				yield service.stop ();
				manager.service = null;

				manager.local_provider = null;
				manager.local_session = null;

				manager.session_by_pid = null;
			}
		}

		private class ObtainSessionTask : ManagerTask<Session> {
			public uint pid;

			protected override async Session perform_operation () throws Error {
				var session = manager.session_by_pid[pid];
				if (session == null) {
					yield manager.ensure_host_session_is_available ();

					var agent_session_id = yield manager.local_session.attach_to (pid);
					var agent_session = yield manager.local_provider.obtain_agent_session (agent_session_id);
					session = new Session (manager, pid, agent_session);
					manager.session_by_pid[pid] = session;
				}

				return session;
			}
		}

		private abstract class ManagerTask<T> : AsyncTask<T> {
			protected override void validate_operation () throws Error {
				if (manager.service == null)
					throw new IOError.FAILED ("invalid operation (manager is closed)");
			}
		}

		protected async Zed.HostSession ensure_host_session_is_available () throws IOError {
			if (local_session == null) {
				service = new Zed.HostSessionService.with_local_backend_only ();

				service.provider_available.connect ((p) => {
					local_provider = p;
				});
				yield service.start ();

				/* HACK */
				while (local_provider == null) {
					var timeout = new TimeoutSource (10);
					timeout.set_callback (() => {
						ensure_host_session_is_available.callback ();
						return false;
					});
					timeout.attach (MainContext.get_thread_default ());
					yield;
				}

				local_session = yield local_provider.create ();
			}

			return local_session;
		}
	}

	public class Session : Object {
		private weak SessionManager manager;

		public uint pid {
			get;
			private set;
		}

		private Zed.AgentSession session;

		public signal void glog_message (string domain, uint level, string message);

		public Session (SessionManager manager, uint pid, Zed.AgentSession session) {
			this.manager = manager;
			this.pid = pid;
			this.session = session;
			session.glog_message.connect ((domain, level, message) => glog_message (domain, level, message));
		}

		public void close () {
			try {
				(create<CloseTask> () as CloseTask).start_and_wait_for_completion ();
			} catch (Error e) {
				assert_not_reached ();
			}
		}

		public void add_glog_pattern (string pattern, uint levels) throws Error {
			var task = create<AddGLogPatternTask> () as AddGLogPatternTask;
			task.pattern = pattern;
			task.levels = levels;
			task.start_and_wait_for_completion ();
		}

		public void clear_glog_patterns () throws Error {
			(create<ClearGLogPatternsTask> () as ClearGLogPatternsTask).start_and_wait_for_completion ();
		}

		public void set_gmain_watchdog_enabled (bool enable) throws Error {
			var task = create<SetGMainWatchdogEnabledTask> () as SetGMainWatchdogEnabledTask;
			task.enable = enable;
			task.start_and_wait_for_completion ();
		}

		private Object create<T> () {
			return Object.new (typeof (T), manager: manager, parent: this);
		}

		private class CloseTask : SessionTask<void> {
			protected override void validate_operation () throws Error {
			}

			protected override async void perform_operation () throws Error {
				if (parent.session == null)
					return;

				try {
					yield parent.session.close ();
				} catch (IOError ignored_error) {
				}
				parent.session = null;

				manager._release_session (parent);
			}
		}

		private class AddGLogPatternTask : SessionTask<void> {
			public string pattern;
			public uint levels;

			protected override async void perform_operation () throws Error {
				yield parent.session.add_glog_pattern (pattern, levels);
			}
		}

		private class ClearGLogPatternsTask : SessionTask<void> {
			protected override async void perform_operation () throws Error {
				yield parent.session.clear_glog_patterns ();
			}
		}

		private class SetGMainWatchdogEnabledTask : SessionTask<void> {
			public bool enable;

			protected override async void perform_operation () throws Error {
				yield parent.session.set_gmain_watchdog_enabled (enable);
			}
		}

		private abstract class SessionTask<T> : AsyncTask<T> {
			public weak Session parent {
				get;
				construct;
			}

			protected override void validate_operation () throws Error {
				if (parent.session == null)
					throw new IOError.FAILED ("invalid operation (session is closed)");
			}
		}
	}

	private abstract class AsyncTask<T> : Object {
		public weak SessionManager manager {
			get;
			construct;
		}

		private bool completed;
		private Mutex mutex = new Mutex ();
		private Cond cond = new Cond ();

		private T result;
		private Error error;

		public T start_and_wait_for_completion () throws Error {
			var source = new IdleSource ();
			source.set_callback (() => {
				do_perform_operation ();
				return false;
			});
			source.attach (manager.main_context);

			mutex.lock ();
			while (!completed)
				cond.wait (mutex);
			mutex.unlock ();

			if (error != null)
				throw error;

			return result;
		}

		private async void do_perform_operation () {
			try {
				validate_operation ();
				result = yield perform_operation ();
			} catch (Error e) {
				error = new IOError.FAILED (e.message);
			}

			mutex.lock ();
			completed = true;
			cond.signal ();
			mutex.unlock ();
		}

		protected abstract void validate_operation () throws Error;
		protected abstract async T perform_operation () throws Error;
	}
}
