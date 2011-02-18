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
			foreach (var pair in session_by_handle) {
				if (pair.value == session)
					handle = pair.key;
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
		public signal void glog_message (uint64 timestamp, string domain, uint level, string message);

		public Session (SessionManager manager, uint pid, Zed.AgentSession agent_session) {
			this.manager = manager;
			this.pid = pid;
			this.internal_session = agent_session;
			this.main_context = manager.main_context;

			internal_session.message_from_script.connect (on_message_from_script);
			internal_session.glog_message.connect ((timestamp, domain, level, message) => glog_message (timestamp, domain, level, message));
		}

		public void close () {
			try {
				(create<CloseTask> () as CloseTask).start_and_wait_for_completion ();
			} catch (Error e) {
				assert_not_reached ();
			}
		}

		public Script compile_script (string text) throws Error {
			var task = create<CompileScriptTask> () as CompileScriptTask;
			task.text = text;
			return task.start_and_wait_for_completion ();
		}

		private void on_message_from_script (Zed.AgentScriptId sid, Variant msg) {
			var script = script_by_id[sid.handle];
			if (script != null)
				script.message (msg);
		}

		public void _release_script (Zed.AgentScriptId sid) {
			var script_did_exist = script_by_id.unset (sid.handle);
			assert (script_did_exist);
		}

		public uint64 resolve_module_base (string module_name) throws Error {
			var task = create<ResolveModuleBaseTask> () as ResolveModuleBaseTask;
			task.module_name = module_name;
			return task.start_and_wait_for_completion ();
		}

		public uint64 resolve_module_export (string module_name, string symbol_name) throws Error {
			var task = create<ResolveModuleExportTask> () as ResolveModuleExportTask;
			task.module_name = module_name;
			task.symbol_name = symbol_name;
			return task.start_and_wait_for_completion ();
		}

		public uint64[] scan_module_for_code_pattern (string module_name, string pattern) throws Error {
			var task = create<ScanModuleForCodePatternTask> () as ScanModuleForCodePatternTask;
			task.module_name = module_name;
			task.pattern = pattern;
			task.start_and_wait_for_completion ();
			return task.matches;
		}

		public void invoke_function (uint64 address, string arguments) throws Error {
			var task = create<InvokeFunctionTask> () as InvokeFunctionTask;
			task.address = address;
			task.arguments = arguments;
			task.start_and_wait_for_completion ();
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

		public void enable_gmain_watchdog (double max_duration) throws Error {
			var task = create<EnableGMainWatchdogTask> () as EnableGMainWatchdogTask;
			task.max_duration = max_duration;
			task.start_and_wait_for_completion ();
		}

		public void disable_gmain_watchdog () throws Error {
			(create<DisableGMainWatchdogTask> () as DisableGMainWatchdogTask).start_and_wait_for_completion ();
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
				yield script._do_destroy (may_block);

			if (may_block) {
				try {
					yield internal_session.close ();
				} catch (IOError ignored_error) {
				}
			}
			internal_session = null;

			closed ();
		}

		private class CompileScriptTask : SessionTask<Script> {
			public string text;

			protected override async Script perform_operation () throws Error {
				var info = yield parent.internal_session.compile_script (text);
				var script = new Script (parent, info);
				parent.script_by_id[info.sid.handle] = script;
				return script;
			}
		}

		private class ResolveModuleBaseTask : SessionTask<uint64> {
			public string module_name;

			protected override async uint64 perform_operation () throws Error {
				return yield parent.internal_session.resolve_module_base (module_name);
			}
		}

		private class ResolveModuleExportTask : SessionTask<uint64> {
			public string module_name;
			public string symbol_name;

			protected override async uint64 perform_operation () throws Error {
				return yield parent.internal_session.resolve_module_export (module_name, symbol_name);
			}
		}

		private class ScanModuleForCodePatternTask : SessionTask<void> {
			public string module_name;
			public string pattern;

			public uint64[] matches;

			protected override async void perform_operation () throws Error {
				matches = yield parent.internal_session.scan_module_for_code_pattern (module_name, pattern);
			}
		}

		private class InvokeFunctionTask : SessionTask<void> {
			public uint64 address;
			public string arguments;

			protected override async void perform_operation () throws Error {
				yield parent.internal_session.invoke_function (address, arguments);
			}
		}

		private class AddGLogPatternTask : SessionTask<void> {
			public string pattern;
			public uint levels;

			protected override async void perform_operation () throws Error {
				yield parent.internal_session.add_glog_pattern (pattern, levels);
			}
		}

		private class ClearGLogPatternsTask : SessionTask<void> {
			protected override async void perform_operation () throws Error {
				yield parent.internal_session.clear_glog_patterns ();
			}
		}

		private class EnableGMainWatchdogTask : SessionTask<void> {
			public double max_duration;

			protected override async void perform_operation () throws Error {
				yield parent.internal_session.enable_gmain_watchdog (max_duration);
			}
		}

		private class DisableGMainWatchdogTask : SessionTask<void> {
			protected override async void perform_operation () throws Error {
				yield parent.internal_session.disable_gmain_watchdog ();
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

		private Zed.AgentScriptInfo info;

		private MainContext main_context;

		public signal void message (Variant msg);

		public Script (Session session, Zed.AgentScriptInfo info) {
			this.session = session;
			this.info = info;
			this.main_context = session.main_context;
		}

		public void destroy () throws Error {
			(create<DestroyTask> () as DestroyTask).start_and_wait_for_completion ();
		}

		public void attach_to (uint64 address) throws Error {
			var task = create<AttachToTask> () as AttachToTask;
			task.address = address;
			task.start_and_wait_for_completion ();
		}

		private Object create<T> () {
			return Object.new (typeof (T), main_context: main_context, parent: this);
		}

		private class DestroyTask : ScriptTask<void> {
			protected override async void perform_operation () throws Error {
				parent._do_destroy (true);
			}
		}

		public async void _do_destroy (bool may_block) {
			var s = session;
			session = null;

			var sid = info.sid;

			s._release_script (sid);

			if (may_block) {
				try {
					yield s.internal_session.destroy_script (sid);
				} catch (IOError ignored_error) {
				}
			}
		}

		private class AttachToTask : ScriptTask<void> {
			public uint64 address;

			protected override async void perform_operation () throws Error {
				yield parent.session.internal_session.attach_script_to (parent.info.sid, address);
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
