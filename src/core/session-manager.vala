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
		private Gee.HashMap<uint, Session> session_by_handle = new Gee.HashMap<uint, Session> ();

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

			uint handle = 0;
			foreach (var entry in session_by_handle.entries) {
				if (entry.value == session)
					handle = entry.key;
			}
			assert (handle != 0);
			session_by_handle.unset (handle);
		}

		private Object create<T> () {
			return Object.new (typeof (T), main_context: main_context, parent: this);
		}

		private class CloseTask : ManagerTask<void> {
			protected override void validate_operation () throws Error {
			}

			protected override async void perform_operation () throws Error {
				var service = parent.service;
				if (service == null)
					return;

				foreach (var session in parent.session_by_pid.values.to_array ())
					yield session._do_close (true);

				yield service.stop ();
				parent.service = null;

				parent.local_provider = null;
				parent.local_session = null;

				parent.session_by_pid = null;
				parent.session_by_handle = null;
			}
		}

		private class ObtainSessionTask : ManagerTask<Session> {
			public uint pid;

			protected override async Session perform_operation () throws Error {
				var session = parent.session_by_pid[pid];
				if (session == null) {
					yield parent.ensure_host_session_is_available ();

					var agent_session_id = yield parent.local_session.attach_to (pid);
					var agent_session = yield parent.local_provider.obtain_agent_session (agent_session_id);
					session = new Session (parent, pid, agent_session);
					parent.session_by_pid[pid] = session;
					parent.session_by_handle[agent_session_id.handle] = session;
				}

				return session;
			}
		}

		private abstract class ManagerTask<T> : AsyncTask<T> {
			public weak SessionManager parent {
				get;
				construct;
			}

			protected override void validate_operation () throws Error {
				if (parent.service == null)
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
				local_provider.agent_session_closed.connect (on_agent_session_closed);

				local_session = yield local_provider.create ();
			}

			return local_session;
		}

		private void on_agent_session_closed (Zed.AgentSessionId id, Error? error) {
			var session = session_by_handle[id.handle];
			if (session != null)
				session._do_close (false);
		}
	}

	public class Session : Object {
		private weak SessionManager manager;

		public uint pid {
			get;
			private set;
		}

		public Zed.AgentSession internal_session {
			get;
			private set;
		}

		public MainContext main_context {
			get;
			private set;
		}

		private Gee.HashMap<uint, Script> script_by_id = new Gee.HashMap<uint, Script> ();

		public signal void closed ();

		public Session (SessionManager manager, uint pid, Zed.AgentSession agent_session) {
			this.manager = manager;
			this.pid = pid;
			this.internal_session = agent_session;
			this.main_context = manager.main_context;

			internal_session.message_from_script.connect (on_message_from_script);
		}

		public void close () {
			try {
				(create<CloseTask> () as CloseTask).start_and_wait_for_completion ();
			} catch (Error e) {
				assert_not_reached ();
			}
		}

		public Script create_script (string source) throws Error {
			var task = create<CreateScriptTask> () as CreateScriptTask;
			task.source = source;
			return task.start_and_wait_for_completion ();
		}

		private void on_message_from_script (Zed.AgentScriptId sid, string msg) {
			var script = script_by_id[sid.handle];
			if (script != null)
				script.message (msg);
		}

		public void _release_script (Zed.AgentScriptId sid) {
			var script_did_exist = script_by_id.unset (sid.handle);
			assert (script_did_exist);
		}

		private Object create<T> () {
			return Object.new (typeof (T), main_context: main_context, parent: this);
		}

		private class CloseTask : SessionTask<void> {
			protected override void validate_operation () throws Error {
			}

			protected override async void perform_operation () throws Error {
				yield parent._do_close (true);
			}
		}

		public async void _do_close (bool may_block) {
			if (manager == null)
				return;

			manager._release_session (this);
			manager = null;

			foreach (var script in script_by_id.values.to_array ())
				yield script._do_unload (may_block);

			if (may_block) {
				try {
					yield internal_session.close ();
				} catch (IOError ignored_error) {
				}
			}
			internal_session = null;

			closed ();
		}

		private class CreateScriptTask : SessionTask<Script> {
			public string source;

			protected override async Script perform_operation () throws Error {
				var sid = yield parent.internal_session.create_script (source);
				var script = new Script (parent, sid);
				parent.script_by_id[sid.handle] = script;
				return script;
			}
		}

		private abstract class SessionTask<T> : AsyncTask<T> {
			public weak Session parent {
				get;
				construct;
			}

			protected override void validate_operation () throws Error {
				if (parent.manager == null)
					throw new IOError.FAILED ("invalid operation (session is closed)");
			}
		}
	}

	public class Script : Object {
		private weak Session session;

		private Zed.AgentScriptId script_id;

		private MainContext main_context;

		public signal void message (string msg);

		public Script (Session session, Zed.AgentScriptId script_id) {
			this.session = session;
			this.script_id = script_id;
			this.main_context = session.main_context;
		}

		public void load () throws Error {
			(create<LoadTask> () as LoadTask).start_and_wait_for_completion ();
		}

		public void unload () throws Error {
			(create<UnloadTask> () as UnloadTask).start_and_wait_for_completion ();
		}

		public void post_message (string msg) throws Error {
			var task = create<PostMessageTask> () as PostMessageTask;
			task.msg = msg;
			task.start_and_wait_for_completion ();
		}

		private Object create<T> () {
			return Object.new (typeof (T), main_context: main_context, parent: this);
		}

		private class LoadTask : ScriptTask<void> {
			protected override async void perform_operation () throws Error {
				yield parent.session.internal_session.load_script (parent.script_id);
			}
		}

		private class UnloadTask : ScriptTask<void> {
			protected override async void perform_operation () throws Error {
				yield parent._do_unload (true);
			}
		}

		private class PostMessageTask : ScriptTask<void> {
			public string msg;

			protected override async void perform_operation () throws Error {
				yield parent.session.internal_session.post_message_to_script (parent.script_id, msg);
			}
		}

		public async void _do_unload (bool may_block) {
			var s = session;
			session = null;

			var sid = script_id;

			s._release_script (sid);

			if (may_block) {
				try {
					yield s.internal_session.destroy_script (sid);
				} catch (IOError ignored_error) {
				}
			}
		}

		private abstract class ScriptTask<T> : AsyncTask<T> {
			public weak Script parent {
				get;
				construct;
			}

			protected override void validate_operation () throws Error {
				if (parent.session == null)
					throw new IOError.FAILED ("invalid operation (script is destroyed)");
			}
		}
	}

	private abstract class AsyncTask<T> : Object {
		public MainContext main_context {
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
			source.attach (main_context);

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
