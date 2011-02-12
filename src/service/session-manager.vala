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

		private Gee.HashMap<uint, weak Session> session_by_pid = new Gee.HashMap<uint, weak Session> ();

		public SessionManager (MainContext main_context) {
			this.main_context = main_context;
		}

		public Session obtain_session_for (uint pid) throws Error {
			var attach = new ObtainSessionTask (this, pid);
			return attach.wait_for_completion ();
		}

		public void _release_session (Session session) {
			var session_did_exist = session_by_pid.unset (session.pid);
			assert (session_did_exist);
		}

		private class ObtainSessionTask : AsyncTask<Session> {
			private uint pid;

			public ObtainSessionTask (SessionManager manager, uint pid) {
				base (manager);

				this.pid = pid;
			}

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
		private unowned SessionManager manager;

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

		~Session () {
			var task = new CloseTask (manager, this);
			task.wait_for_completion ();
		}

		public void add_glog_pattern (string pattern, uint levels) throws Error {
			var task = new AddGLogPatternTask (manager, session, pattern, levels);
			task.wait_for_completion ();
		}

		public void clear_glog_patterns () throws Error {
			var task = new ClearGLogPatternsTask (manager, session);
			task.wait_for_completion ();
		}

		public void set_gmain_watchdog_enabled (bool enable) throws Error {
			var task = new SetGMainWatchdogEnabledTask (manager, session, enable);
			task.wait_for_completion ();
		}

		private class CloseTask : AsyncTask<void> {
			private weak Session parent;

			public CloseTask (SessionManager manager, Session parent) {
				base (manager);

				this.parent = parent;
			}

			protected override async void perform_operation () throws Error {
				try {
					yield parent.session.close ();
				} catch (IOError ignored_error) {
				}
				parent.session = null;

				manager._release_session (parent);
			}
		}

		private class AddGLogPatternTask : AsyncTask<void> {
			private weak Zed.AgentSession session;
			private string pattern;
			private uint levels;

			public AddGLogPatternTask (SessionManager manager, Zed.AgentSession session, string pattern, uint levels) {
				base (manager);

				this.session = session;
				this.pattern = pattern;
				this.levels = levels;
			}

			protected override async void perform_operation () throws Error {
				yield session.add_glog_pattern (pattern, levels);
			}
		}

		private class ClearGLogPatternsTask : AsyncTask<void> {
			private weak Zed.AgentSession session;

			public ClearGLogPatternsTask (SessionManager manager, Zed.AgentSession session) {
				base (manager);

				this.session = session;
			}

			protected override async void perform_operation () throws Error {
				yield session.clear_glog_patterns ();
			}
		}

		private class SetGMainWatchdogEnabledTask : AsyncTask<void> {
			private weak Zed.AgentSession session;
			private bool enable;

			public SetGMainWatchdogEnabledTask (SessionManager manager, Zed.AgentSession session, bool enable) {
				base (manager);

				this.session = session;
				this.enable = enable;
			}

			protected override async void perform_operation () throws Error {
				yield session.set_gmain_watchdog_enabled (enable);
			}
		}
	}

	private abstract class AsyncTask<T> : GLib.Object {
		public weak SessionManager manager {
			get;
			construct;
		}

		private bool completed;
		private Mutex mutex = new Mutex ();
		private Cond cond = new Cond ();

		private T result;
		private Error error;

		public AsyncTask (SessionManager manager) {
			GLib.Object (manager: manager);
		}

		public T wait_for_completion () throws Error {
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
				result = yield perform_operation ();
			} catch (Error e) {
				error = new IOError.FAILED (e.message);
			}

			mutex.lock ();
			completed = true;
			cond.signal ();
			mutex.unlock ();
		}

		protected abstract async T perform_operation () throws Error;
	}
}
