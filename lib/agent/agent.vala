namespace Frida.Agent {
	public void main (string pipe_address, ref Frida.UnloadPolicy unload_policy, Gum.MemoryRange? mapped_range) {
		if (Runner.shared_instance == null)
			Runner.create_and_run (pipe_address, ref unload_policy, mapped_range);
#if !WINDOWS
		else
			Runner.resume_after_fork (ref unload_policy);
#endif
	}

	private enum StopReason {
		UNLOAD,
		FORK
	}

	private class Runner : Object, AgentSessionProvider, ForkHandler {
		public static Runner shared_instance = null;
		public static Mutex shared_mutex;

		public string pipe_address {
			get;
			construct;
		}

		public StopReason stop_reason {
			default = UNLOAD;
			get;
			set;
		}

		private void * agent_pthread;

		private MainContext main_context;
		private MainLoop main_loop;
		private DBusConnection connection;
		private AgentController controller;
		private bool unloading = false;
		private uint filter_id = 0;
		private uint registration_id = 0;
		private uint pending_calls = 0;
		private Gee.Promise<bool> pending_close;
		private Gee.HashSet<AgentClient> clients = new Gee.HashSet<AgentClient> ();

		private Gum.ScriptBackend script_backend;
		private Gum.Exceptor exceptor;
		private bool jit_enabled = false;
		protected Gum.MemoryRange agent_range;

		private uint child_gating_subscriber_count = 0;
#if !WINDOWS
		private ForkListener? fork_listener;
#if LINUX
		private ThreadListCloaker? thread_list_cloaker;
#endif
		private ThreadIgnoreScope fork_ignore_scope;
		private uint fork_parent_pid;
		private uint fork_child_pid;
		private HostChildId fork_child_id;
		private uint fork_parent_injectee_id;
		private uint fork_child_injectee_id;
		private Socket fork_child_socket;
		private ForkRecoveryState fork_recovery_state;
		private Mutex fork_mutex;
		private Cond fork_cond;
#endif

		private enum ForkRecoveryState {
			RECOVERING,
			RECOVERED
		}

		private enum ForkActor {
			PARENT,
			CHILD
		}

		public static void create_and_run (string pipe_address, ref Frida.UnloadPolicy unload_policy, Gum.MemoryRange? mapped_range) {
			Environment._init ();

			{
				var agent_range = memory_range (mapped_range);
				Gum.Cloak.add_range (agent_range);

				var ignore_scope = new ThreadIgnoreScope ();

				shared_instance = new Runner (pipe_address, agent_range);

				try {
					shared_instance.run ();
				} catch (Error e) {
					printerr ("Unable to start agent: %s\n", e.message);
				}

				if (shared_instance.stop_reason == FORK) {
					unload_policy = DEFERRED;
					return;
				} else {
					release_shared_instance ();
				}

				ignore_scope = null;
			}

			Environment._deinit ();
		}

#if !WINDOWS
		public static void resume_after_fork (ref Frida.UnloadPolicy unload_policy) {
			{
				var ignore_scope = new ThreadIgnoreScope ();

				shared_instance.run_after_fork ();

				if (shared_instance.stop_reason == FORK) {
					unload_policy = DEFERRED;
					return;
				} else {
					release_shared_instance ();
				}

				ignore_scope = null;
			}

			Environment._deinit ();
		}
#endif

		private static void release_shared_instance () {
			shared_mutex.lock ();
			var instance = shared_instance;
			shared_instance = null;
			shared_mutex.unlock ();

			instance = null;
		}

		private Runner (string pipe_address, Gum.MemoryRange agent_range) {
			Object (pipe_address: pipe_address);

			this.agent_range = agent_range;
		}

		construct {
			agent_pthread = Environment._get_current_pthread ();

			main_context = new MainContext ();
			main_loop = new MainLoop (main_context);

			exceptor = Gum.Exceptor.obtain ();
		}

		~Runner () {
			disable_child_gating ();
		}

		private void run () throws Error {
			main_context.push_thread_default ();

			setup_connection_with_pipe_address.begin (pipe_address);

			main_loop.run ();

			main_context.pop_thread_default ();
		}

#if !WINDOWS
		private void run_after_fork () {
			fork_mutex.lock ();
			fork_mutex.unlock ();

			stop_reason = UNLOAD;
			agent_pthread = Environment._get_current_pthread ();

			main_context.push_thread_default ();
			main_loop.run ();
			main_context.pop_thread_default ();
		}

		private void prepare_to_fork () {
			fork_ignore_scope = new ThreadIgnoreScope ();

			schedule_idle (() => {
				do_prepare_to_fork.begin ();
				return false;
			});
			Environment._join_pthread (agent_pthread);

			GumJS.prepare_to_fork ();
			Gum.prepare_to_fork ();
			GIOFork.prepare_to_fork ();
			GLibFork.prepare_to_fork ();
		}

		private async void do_prepare_to_fork () {
			stop_reason = FORK;

			try {
				fork_parent_pid = Posix.getpid ();
				fork_child_id = yield controller.prepare_to_fork (fork_parent_pid, out fork_parent_injectee_id, out fork_child_injectee_id, out fork_child_socket);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			main_loop.quit ();
		}

		private void recover_from_fork_in_parent () {
			recover_from_fork (ForkActor.PARENT);
		}

		private void recover_from_fork_in_child () {
			recover_from_fork (ForkActor.CHILD);
		}

		private void recover_from_fork (ForkActor actor) {
			if (actor == PARENT) {
				GLibFork.recover_from_fork_in_parent ();
				GIOFork.recover_from_fork_in_parent ();
				Gum.recover_from_fork_in_parent ();
				GumJS.recover_from_fork_in_parent ();
			} else if (actor == CHILD) {
				GLibFork.recover_from_fork_in_child ();
				GIOFork.recover_from_fork_in_child ();
				Gum.recover_from_fork_in_child ();
				GumJS.recover_from_fork_in_child ();

				fork_child_pid = Posix.getpid ();

				acquire_child_gating ();

				discard_connection ();
			}

			fork_mutex.lock ();

			fork_recovery_state = RECOVERING;

			schedule_idle (() => {
				recreate_agent_thread.begin (actor);
				return false;
			});

			main_context.push_thread_default ();
			main_loop.run ();
			main_context.pop_thread_default ();

			schedule_idle (() => {
				finish_recovery_from_fork.begin (actor);
				return false;
			});

			while (fork_recovery_state != RECOVERED)
				fork_cond.wait (fork_mutex);

			fork_mutex.unlock ();

			fork_ignore_scope = null;
		}

		private async void recreate_agent_thread (ForkActor actor) {
			uint pid, injectee_id;
			if (actor == PARENT) {
				pid = fork_parent_pid;
				injectee_id = fork_parent_injectee_id;
			} else if (actor == CHILD) {
				yield close_all_clients ();

				var stream = SocketConnection.factory_create_connection (fork_child_socket);
				yield setup_connection_with_stream (stream);

				pid = fork_child_pid;
				injectee_id = fork_child_injectee_id;
			} else {
				assert_not_reached ();
			}

			try {
				yield controller.recreate_agent_thread (pid, injectee_id);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			main_loop.quit ();
		}

		private async void finish_recovery_from_fork (ForkActor actor) {
			if (actor == CHILD) {
				var info = HostChildInfo (fork_child_pid, Environment.get_executable_path (), fork_parent_pid);
				try {
					yield controller.wait_for_permission_to_resume (fork_child_id, info);
				} catch (GLib.Error e) {
					// The connection will/did get closed and we will unload...
				}
			}

			fork_parent_pid = 0;
			fork_child_pid = 0;
			fork_child_id = HostChildId (0);
			fork_parent_injectee_id = 0;
			fork_child_injectee_id = 0;
			fork_child_socket = null;

			fork_mutex.lock ();
			fork_recovery_state = RECOVERED;
			fork_cond.signal ();
			fork_mutex.unlock ();

			if (actor == CHILD)
				release_child_gating ();
		}
#else
		private void prepare_to_fork () {
		}

		private void recover_from_fork_in_parent () {
		}

		private void recover_from_fork_in_child () {
		}
#endif

		private async void open (AgentSessionId id) throws Error {
			if (unloading)
				throw new Error.INVALID_OPERATION ("Agent is unloading");

			var client = new AgentClient (this, id);
			clients.add (client);
			client.closed.connect (on_client_closed);

			try {
				AgentSession session = client;
				client.registration_id = connection.register_object (ObjectPath.from_agent_session_id (id), session);
			} catch (IOError io_error) {
				assert_not_reached ();
			}

			opened (id);
		}

		private async void close_all_clients () {
			foreach (var client in clients.to_array ()) {
				try {
					yield client.close ();
				} catch (GLib.Error e) {
					assert_not_reached ();
				}
			}
			assert (clients.is_empty);
		}

		private void on_client_closed (AgentClient client) {
			closed (client.id);

			var id = client.registration_id;
			if (id != 0) {
				connection.unregister_object (id);
				client.registration_id = 0;
			}

			client.closed.disconnect (on_client_closed);
			clients.remove (client);
		}

		private async void unload () throws Error {
			if (unloading)
				throw new Error.INVALID_OPERATION ("Agent is already unloading");
			unloading = true;
			perform_unload.begin ();
		}

		private async void perform_unload () {
			Gee.Promise<bool> operation = null;

			lock (pending_calls) {
				if (pending_calls > 0) {
					pending_close = new Gee.Promise<bool> ();
					operation = pending_close;
				}
			}

			if (operation != null) {
				try {
					yield operation.future.wait_async ();
				} catch (Gee.FutureError e) {
					assert_not_reached ();
				}
			}

			yield close_all_clients ();

			yield teardown_connection ();

			schedule_idle (() => {
				main_loop.quit ();
				return false;
			});
		}

		public void acquire_child_gating () {
			child_gating_subscriber_count++;
			if (child_gating_subscriber_count == 1)
				enable_child_gating ();
		}

		public void release_child_gating () {
			child_gating_subscriber_count--;
			if (child_gating_subscriber_count == 0)
				disable_child_gating ();
		}

		private void enable_child_gating () {
#if !WINDOWS
			if (fork_listener != null)
				return;

			fork_listener = new ForkListener (this);

			var interceptor = Gum.Interceptor.obtain ();
			interceptor.begin_transaction ();

			interceptor.attach_listener ((void *) Posix.fork, fork_listener);
			interceptor.replace_function ((void *) Posix.vfork, (void *) Posix.fork);

#if LINUX
			thread_list_cloaker = new ThreadListCloaker ();
#endif

			interceptor.end_transaction ();
#endif
		}

		private void disable_child_gating () {
#if !WINDOWS
			if (fork_listener == null)
				return;

			var interceptor = Gum.Interceptor.obtain ();
			interceptor.begin_transaction ();

#if LINUX
			thread_list_cloaker = null;
#endif

			interceptor.revert_function ((void *) Posix.vfork);
			interceptor.detach_listener (fork_listener);

			interceptor.end_transaction ();

			fork_listener = null;
#endif
		}

		public ScriptEngine create_script_engine () {
			if (script_backend == null)
				script_backend = Environment._obtain_script_backend (jit_enabled);

			return new ScriptEngine (script_backend, agent_range);
		}

		public void enable_jit () throws Error {
			if (jit_enabled)
				return;

			if (script_backend != null)
				throw new Error.INVALID_OPERATION ("JIT may only be enabled before the first script is created");

			jit_enabled = true;
		}

		public void schedule_idle (owned SourceFunc function) {
			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (main_context);
		}

		public void schedule_timeout (uint delay, owned SourceFunc function) {
			var source = new TimeoutSource (delay);
			source.set_callback ((owned) function);
			source.attach (main_context);
		}

		private async void setup_connection_with_pipe_address (string pipe_address) {
			IOStream stream;
			try {
				stream = yield Pipe.open (pipe_address).future.wait_async ();
			} catch (Gee.FutureError e) {
				assert_not_reached ();
			}

			yield setup_connection_with_stream (stream);
		}

		private async void setup_connection_with_stream (IOStream stream) {
			try {
				connection = yield new DBusConnection (stream, null, AUTHENTICATION_CLIENT | DELAY_MESSAGE_PROCESSING);
			} catch (GLib.Error connection_error) {
				printerr ("Unable to create connection: %s\n", connection_error.message);
				return;
			}

			connection.on_closed.connect (on_connection_closed);
			filter_id = connection.add_filter (on_connection_message);

			try {
				AgentSessionProvider provider = this;
				registration_id = connection.register_object (ObjectPath.AGENT_SESSION_PROVIDER, provider);

				connection.start_message_processing ();
			} catch (IOError io_error) {
				assert_not_reached ();
			}

			try {
				controller = yield connection.get_proxy (null, ObjectPath.AGENT_CONTROLLER, DBusProxyFlags.NONE, null);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
		}

		private async void teardown_connection () {
			if (connection == null)
				return;

			connection.on_closed.disconnect (on_connection_closed);

			try {
				yield connection.flush ();
			} catch (GLib.Error e) {
			}

			try {
				yield connection.close ();
			} catch (GLib.Error e) {
			}

			unregister_connection ();

			connection = null;
		}

#if !WINDOWS
		private void discard_connection () {
			if (connection == null)
				return;

			connection.on_closed.disconnect (on_connection_closed);

			unregister_connection ();

			connection.dispose ();
			connection = null;
		}
#endif

		private void unregister_connection () {
			foreach (var client in clients) {
				connection.unregister_object (client.registration_id);
				client.registration_id = 0;
			}

			controller = null;

			if (registration_id != 0) {
				connection.unregister_object (registration_id);
				registration_id = 0;
			}

			if (filter_id != 0) {
				connection.remove_filter (filter_id);
				filter_id = 0;
			}
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			bool closed_by_us = (!remote_peer_vanished && error == null);
			if (!closed_by_us)
				unload.begin ();

			Gee.Promise<bool> operation = null;
			lock (pending_calls) {
				pending_calls = 0;
				operation = pending_close;
				pending_close = null;
			}
			if (operation != null)
				operation.set_value (true);
		}

		private GLib.DBusMessage on_connection_message (DBusConnection connection, owned DBusMessage message, bool incoming) {
			switch (message.get_message_type ()) {
				case DBusMessageType.METHOD_CALL:
					if (incoming) {
						lock (pending_calls) {
							pending_calls++;
						}
					}
					break;
				case DBusMessageType.METHOD_RETURN:
				case DBusMessageType.ERROR:
					if (!incoming) {
						lock (pending_calls) {
							pending_calls--;
							var operation = pending_close;
							if (pending_calls == 0 && operation != null) {
								pending_close = null;
								schedule_idle (() => {
									operation.set_value (true);
									return false;
								});
							}
						}
					}
					break;
				default:
					break;
			}

			return message;
		}
	}

	private class AgentClient : Object, AgentSession {
		public signal void closed (AgentClient client);

		public weak Runner runner {
			get;
			construct;
		}

		public AgentSessionId id {
			get;
			construct;
		}

		public uint registration_id {
			get;
			set;
		}

		private Gee.Promise<bool> close_request;

		private bool child_gating_enabled = false;
		private ScriptEngine script_engine;

		public AgentClient (Runner runner, AgentSessionId id) {
			Object (runner: runner, id: id);
		}

		public async void close () throws Error {
			if (close_request != null) {
				try {
					yield close_request.future.wait_async ();
				} catch (Gee.FutureError e) {
					assert_not_reached ();
				}
				return;
			}
			close_request = new Gee.Promise<bool> ();

			try {
				yield disable_child_gating ();
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			if (script_engine != null) {
				yield script_engine.shutdown ();
				script_engine = null;
			}

			closed (this);

			close_request.set_value (true);
		}

		public async void enable_child_gating () throws Error {
			if (child_gating_enabled)
				return;

			runner.acquire_child_gating ();

			child_gating_enabled = true;
		}

		public async void disable_child_gating () throws Error {
			if (!child_gating_enabled)
				return;

			runner.release_child_gating ();

			child_gating_enabled = false;
		}

		public async AgentScriptId create_script (string name, string source) throws Error {
			var engine = get_script_engine ();
			var instance = yield engine.create_script ((name != "") ? name : null, source, null);
			return instance.sid;
		}

		public async AgentScriptId create_script_from_bytes (uint8[] bytes) throws Error {
			var engine = get_script_engine ();
			var instance = yield engine.create_script (null, null, new Bytes (bytes));
			return instance.sid;
		}

		public async uint8[] compile_script (string name, string source) throws Error {
			var engine = get_script_engine ();
			var bytes = yield engine.compile_script ((name != "") ? name : null, source);
			return bytes.get_data ();
		}

		public async void destroy_script (AgentScriptId sid) throws Error {
			var engine = get_script_engine ();
			yield engine.destroy_script (sid);
		}

		public async void load_script (AgentScriptId sid) throws Error {
			var engine = get_script_engine ();
			yield engine.load_script (sid);
		}

		public async void post_to_script (AgentScriptId sid, string message, bool has_data, uint8[] data) throws Error {
			get_script_engine ().post_to_script (sid, message, has_data ? new Bytes (data) : null);
		}

		public async void enable_debugger () throws Error {
			get_script_engine ().enable_debugger ();
		}

		public async void disable_debugger () throws Error {
			get_script_engine ().disable_debugger ();
		}

		public async void post_message_to_debugger (string message) throws Error {
			get_script_engine ().post_message_to_debugger (message);
		}

		public async void enable_jit () throws GLib.Error {
			runner.enable_jit ();
		}

		private ScriptEngine get_script_engine () throws Error {
			check_open ();

			if (script_engine == null) {
				script_engine = runner.create_script_engine ();
				script_engine.message_from_script.connect ((script_id, message, data) => {
					var has_data = data != null;
					var data_param = has_data ? data.get_data () : new uint8[0];
					this.message_from_script (script_id, message, has_data, data_param);
				});
				script_engine.message_from_debugger.connect ((message) => this.message_from_debugger (message));
			}

			return script_engine;
		}

		private void check_open () throws Error {
			if (close_request != null)
				throw new Error.INVALID_OPERATION ("Session is closing");
		}
	}

	private Gum.MemoryRange memory_range (Gum.MemoryRange? mapped_range) {
		Gum.MemoryRange? result = mapped_range;

		if (result == null) {
			Gum.Process.enumerate_modules ((details) => {
				if (details.name.index_of ("frida-agent") != -1) {
					result = details.range;
					return false;
				}
				return true;
			});
			assert (result != null);
		}

		return result;
	}

	private class ThreadIgnoreScope {
		private Gum.Interceptor interceptor;

		private Gum.ThreadId thread_id;

		private uint num_ranges;
		private Gum.MemoryRange ranges[2];

		public ThreadIgnoreScope () {
			interceptor = Gum.Interceptor.obtain ();
			interceptor.ignore_current_thread ();

			thread_id = Gum.Process.get_current_thread_id ();
			Gum.Cloak.add_thread (thread_id);

			num_ranges = Gum.Thread.try_get_ranges (ranges);
			for (var i = 0; i != num_ranges; i++)
				Gum.Cloak.add_range (ranges[i]);
		}

		~ThreadIgnoreScope () {
			for (var i = 0; i != num_ranges; i++)
				Gum.Cloak.remove_range (ranges[i]);

			Gum.Cloak.remove_thread (thread_id);

			interceptor.unignore_current_thread ();
		}
	}

	private class ForkListener : Object, Gum.InvocationListener {
		public weak ForkHandler handler {
			get;
			construct;
		}

		public ForkListener (ForkHandler handler) {
			Object (handler: handler);
		}

		public void on_enter (Gum.InvocationContext context) {
			handler.prepare_to_fork ();
		}

		public void on_leave (Gum.InvocationContext context) {
			int result = (int) context.get_return_value ();
			if (result != 0)
				handler.recover_from_fork_in_parent ();
			else
				handler.recover_from_fork_in_child ();
		}
	}

	public interface ForkHandler : Object {
		public abstract void prepare_to_fork ();
		public abstract void recover_from_fork_in_parent ();
		public abstract void recover_from_fork_in_child ();
	}

#if LINUX
	private class ThreadListCloaker : Object {
		private Gee.HashSet<Gum.InvocationListener> listeners = new Gee.HashSet<Gum.InvocationListener> ();
		private Gee.HashSet<Posix.Dir> tracked_handles = new Gee.HashSet<unowned Posix.Dir> ();

		construct {
			var interceptor = Gum.Interceptor.obtain ();

			var libc_name = detect_libc_name ();

			var open_listener = new OpenDirListener (this);
			listeners.add (open_listener);
			interceptor.attach_listener (Gum.Module.find_export_by_name (libc_name, "opendir"), open_listener);

			var close_listener = new CloseDirListener (this);
			listeners.add (close_listener);
			interceptor.attach_listener (Gum.Module.find_export_by_name (libc_name, "closedir"), close_listener);

			var readdir64_r = Gum.Module.find_export_by_name (libc_name, "readdir64_r");
			if (readdir64_r != null) {
				var listener = new ReadDirRListener (this, ANDROID);
				listeners.add (listener);
				interceptor.attach_listener (readdir64_r, listener);
			}
		}

		~ThreadListCloaker () {
			var interceptor = Gum.Interceptor.obtain ();

			foreach (var listener in listeners)
				interceptor.detach_listener (listener);
		}

		public void start_tracking (Posix.Dir handle) {
			lock (tracked_handles)
				tracked_handles.add (handle);
		}

		public void stop_tracking (Posix.Dir handle) {
			lock (tracked_handles)
				tracked_handles.remove (handle);
		}

		public bool is_tracking (Posix.Dir handle) {
			lock (tracked_handles)
				return tracked_handles.contains (handle);
		}

		private class OpenDirListener : Object, Gum.InvocationListener {
			public weak ThreadListCloaker parent {
				get;
				construct;
			}

			public OpenDirListener (ThreadListCloaker parent) {
				Object (parent: parent);
			}

			public void on_enter (Gum.InvocationContext context) {
				Invocation * invocation = context.get_listener_function_invocation_data (sizeof (Invocation));

				var path = (string *) context.get_nth_argument (0);
				invocation.is_for_our_task = (path == "/proc/self/task") || (path == "/proc/%u/task".printf (Posix.getpid ()));
			}

			public void on_leave (Gum.InvocationContext context) {
				Invocation * invocation = context.get_listener_function_invocation_data (sizeof (Invocation));
				if (!invocation.is_for_our_task)
					return;

				unowned Posix.Dir? handle = (Posix.Dir?) context.get_return_value ();
				if (handle != null)
					parent.start_tracking (handle);
			}

			private struct Invocation {
				public bool is_for_our_task;
			}
		}

		private class CloseDirListener : Object, Gum.InvocationListener {
			public weak ThreadListCloaker parent {
				get;
				construct;
			}

			public CloseDirListener (ThreadListCloaker parent) {
				Object (parent: parent);
			}

			public void on_enter (Gum.InvocationContext context) {
				unowned Posix.Dir? handle = (Posix.Dir?) context.get_nth_argument (0);
				if (handle != null)
					parent.stop_tracking (handle);
			}
		}

		private enum ReadDirRKind {
			POSIX,
			ANDROID
		}

		private class ReadDirRListener : Object, Gum.InvocationListener {
			public weak ThreadListCloaker parent {
				get;
				construct;
			}

			public ReadDirRKind kind {
				get;
				construct;
			}

			public ReadDirRListener (ThreadListCloaker parent, ReadDirRKind kind) {
				Object (parent: parent, kind: kind);
			}

			public void on_enter (Gum.InvocationContext context) {
				Invocation * invocation = context.get_listener_function_invocation_data (sizeof (Invocation));
				invocation.handle = (Posix.Dir?) context.get_nth_argument (0);
				invocation.entry = context.get_nth_argument (1);
				invocation.result = context.get_nth_argument (2);
			}

			public void on_leave (Gum.InvocationContext context) {
				var result = (int) context.get_return_value ();
				if (result != 0)
					return;

				Invocation * invocation = context.get_listener_function_invocation_data (sizeof (Invocation));
				if (*invocation.result == null)
					return;

				if (!parent.is_tracking (invocation.handle))
					return;

				string? name = null;
				if (kind == POSIX) {
					unowned Posix.DirEnt ent = (Posix.DirEnt) *invocation.result;
					name = (string) ent.d_name;
				} else if (kind == ANDROID) {
					unowned DirEnt64 ent = (DirEnt64) *invocation.result;
					name = (string) ent.d_name;
				}

				if (name == "." || name == "..")
					return;

				var tid = (Gum.ThreadId) uint64.parse (name);
				var is_cloaked = Gum.Cloak.has_thread (tid);
				debug ("tid=%u is_cloaked=%s", (uint) tid, is_cloaked.to_string ());
			}

			private struct Invocation {
				public unowned Posix.Dir? handle;
				public void * entry;
				public void ** result;
			}
		}

		[Compact]
		private class DirEnt64 {
			public uint64 d_ino;
			public int64 d_off;
			public uint16 d_reclen;
			public uint8 d_type;
			public char d_name[256];
		}

		private static string detect_libc_name () {
			string? libc_name = null;

			Gum.Address address_in_libc = (Gum.Address) Posix.opendir;
			Gum.Process.enumerate_modules ((details) => {
				var range = details.range;

				if (address_in_libc >= range.base_address && address_in_libc < range.base_address + range.size) {
					libc_name = details.path;
					return false;
				}

				return true;
			});

			assert (libc_name != null);

			return libc_name;
		}
	}
#endif

	namespace Environment {
		public extern void _init ();
		public extern void _deinit ();

		public extern unowned Gum.ScriptBackend _obtain_script_backend (bool jit_enabled);

		public string get_executable_path () {
			var path = _try_get_executable_path ();
			if (path != null)
				return path;

			Gum.Process.enumerate_modules ((details) => {
				path = details.name;
				return false;
			});
			assert (path != null);

			return path;
		}

		public extern string? _try_get_executable_path ();
		public extern void * _get_current_pthread ();
		public extern void _join_pthread (void * thread);
	}

	private Mutex gc_mutex;
	private uint gc_generation = 0;
	private bool gc_scheduled = false;

	public void _on_pending_garbage (void * data) {
		gc_mutex.lock ();
		gc_generation++;
		bool already_scheduled = gc_scheduled;
		gc_scheduled = true;
		gc_mutex.unlock ();

		if (already_scheduled)
			return;

		Runner.shared_mutex.lock ();
		var runner = Runner.shared_instance;
		Runner.shared_mutex.unlock ();

		if (runner == null)
			return;

		runner.schedule_timeout (50, () => {
			gc_mutex.lock ();
			uint generation = gc_generation;
			gc_mutex.unlock ();

			bool collected_everything = Thread.garbage_collect ();

			gc_mutex.lock ();
			bool same_generation = generation == gc_generation;
			bool repeat = !collected_everything || !same_generation;
			if (!repeat)
				gc_scheduled = false;
			gc_mutex.unlock ();

			return repeat;
		});
	}
}
