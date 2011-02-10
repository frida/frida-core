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

		private Gee.HashMap<uint, Zed.AgentSession> agent_session_by_process_id = new Gee.HashMap<uint, Zed.AgentSession> ();
		private Gee.HashMap<uint, Session> session_by_pid = new Gee.HashMap<uint, Session> ();

		public SessionManager (MainContext main_context) {
			this.main_context = main_context;
		}

		public Session attach_to (uint pid) throws Error {
			var attach = new AttachTask (this, pid);
			var session = attach.wait_for_completion ();
			session_by_pid[pid] = session;
			return session;
		}

		protected async Zed.HostSession obtain_host_session () throws IOError {
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
						obtain_host_session.callback ();
						return false;
					});
					timeout.attach (MainContext.get_thread_default ());
					yield;
				}

				local_session = yield local_provider.create ();
			}

			return local_session;
		}

		protected async Zed.AgentSession obtain_agent_session (uint pid) throws IOError {
			yield obtain_host_session ();

			var agent_session = agent_session_by_process_id[pid];
			if (agent_session == null) {
				var agent_session_id = yield local_session.attach_to (pid);
				agent_session = yield local_provider.obtain_agent_session (agent_session_id);
				agent_session_by_process_id[pid] = agent_session;
			}

			return agent_session;
		}

		private class AttachTask : AsyncTask<Session> {
			private uint pid;

			public AttachTask (SessionManager parent, uint pid) {
				base (parent);

				this.pid = pid;
			}

			protected override async Session perform_operation () throws Error {
				var agent_session = yield parent.obtain_agent_session (pid);

				return new Session (parent, agent_session);
			}
		}
	}

	public class Session : Object {
		public signal void glog_message (string domain, uint level, string message);

		private SessionManager parent;
		private Zed.AgentSession session;

		public Session (SessionManager parent, Zed.AgentSession session) {
			this.parent = parent;
			this.session = session;
			session.glog_message.connect ((domain, level, message) => glog_message (domain, level, message));
		}

		public void add_glog_pattern (string pattern, uint levels) throws Error {
			var task = new AddGLogPatternTask (parent, session, pattern, levels);
			task.wait_for_completion ();
		}

		public void clear_glog_patterns () throws Error {
			var task = new ClearGLogPatternsTask (parent, session);
			task.wait_for_completion ();
		}

		public void set_gmain_watchdog_enabled (bool enable) throws Error {
			var task = new SetGMainWatchdogEnabledTask (parent, session, enable);
			task.wait_for_completion ();
		}

		private class AddGLogPatternTask : AsyncTask<void> {
			private Zed.AgentSession session;
			private string pattern;
			private uint levels;

			public AddGLogPatternTask (SessionManager parent, Zed.AgentSession session, string pattern, uint levels) {
				base (parent);

				this.session = session;
				this.pattern = pattern;
				this.levels = levels;
			}

			protected override async void perform_operation () throws Error {
				yield session.add_glog_pattern (pattern, levels);
			}
		}

		private class ClearGLogPatternsTask : AsyncTask<void> {
			private Zed.AgentSession session;

			public ClearGLogPatternsTask (SessionManager parent, Zed.AgentSession session) {
				base (parent);

				this.session = session;
			}

			protected override async void perform_operation () throws Error {
				yield session.clear_glog_patterns ();
			}
		}

		private class SetGMainWatchdogEnabledTask : AsyncTask<void> {
			private Zed.AgentSession session;
			private bool enable;

			public SetGMainWatchdogEnabledTask (SessionManager parent, Zed.AgentSession session, bool enable) {
				base (parent);

				this.session = session;
				this.enable = enable;
			}

			protected override async void perform_operation () throws Error {
				yield session.set_gmain_watchdog_enabled (enable);
			}
		}
	}

	private abstract class AsyncTask<T> : GLib.Object {
		public SessionManager parent {
			get;
			construct;
		}

		private bool completed;
		private Mutex mutex = new Mutex ();
		private Cond cond = new Cond ();

		private T result;
		private Error error;

		public AsyncTask (SessionManager parent) {
			GLib.Object (parent: parent);
		}

		public T wait_for_completion () throws Error {
			var source = new IdleSource ();
			source.set_callback (() => {
				do_perform_operation ();
				return false;
			});
			source.attach (parent.main_context);

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
