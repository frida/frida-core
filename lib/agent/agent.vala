namespace Frida.Agent {
	public void main (string pipe_address, ref Frida.UnloadPolicy unload_policy, void * injector_state) {
		if (Runner.shared_instance == null)
			Runner.create_and_run (pipe_address, ref unload_policy, injector_state);
#if !WINDOWS
		else
			Runner.resume_after_fork (ref unload_policy, injector_state);
#endif
	}

	private enum StopReason {
		UNLOAD,
		FORK
	}

	private class Runner : Object, AgentSessionProvider, ExitHandler, ForkHandler, SpawnHandler {
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
		private ExitMonitor exit_monitor;
		private Gum.Interceptor interceptor;
		private Gum.Exceptor exceptor;
		private bool jit_enabled = false;
		protected Gum.MemoryRange agent_range;

		private uint child_gating_subscriber_count = 0;
#if !WINDOWS
		private ForkMonitor? fork_monitor;
#if LINUX
		private ThreadListCloaker? thread_list_cloaker;
		private FDListCloaker? fd_list_cloaker;
#endif
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
		private SpawnMonitor spawn_monitor;

		private enum ForkRecoveryState {
			RECOVERING,
			RECOVERED
		}

		private enum ForkActor {
			PARENT,
			CHILD
		}

		public static void create_and_run (string pipe_address, ref Frida.UnloadPolicy unload_policy, void * opaque_injector_state) {
			Environment._init ();

			{
				Gum.MemoryRange? mapped_range = null;

#if DARWIN
				var injector_state = (DarwinInjectorState *) opaque_injector_state;
				if (injector_state != null)
					mapped_range = injector_state.mapped_range;
#endif

				var agent_range = memory_range (mapped_range);
				Gum.Cloak.add_range (agent_range);

#if LINUX
				var injector_state = (LinuxInjectorState *) opaque_injector_state;
				if (injector_state != null)
					Gum.Cloak.add_file_descriptor (injector_state.fifo_fd);
#endif

				var ignore_scope = new ThreadIgnoreScope ();

				shared_instance = new Runner (pipe_address, agent_range);

				try {
					shared_instance.run ();
				} catch (Error e) {
					printerr ("Unable to start agent: %s\n", e.message);
				}

				if (shared_instance.stop_reason == FORK) {
#if LINUX
					if (injector_state != null)
						Gum.Cloak.remove_file_descriptor (injector_state.fifo_fd);
#endif
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
		public static void resume_after_fork (ref Frida.UnloadPolicy unload_policy, void * opaque_injector_state) {
			{
#if LINUX
				var injector_state = (LinuxInjectorState *) opaque_injector_state;
				if (injector_state != null)
					Gum.Cloak.add_file_descriptor (injector_state.fifo_fd);
#endif

				var ignore_scope = new ThreadIgnoreScope ();

				shared_instance.run_after_fork ();

				if (shared_instance.stop_reason == FORK) {
#if LINUX
					if (injector_state != null)
						Gum.Cloak.remove_file_descriptor (injector_state.fifo_fd);
#endif
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

			main_context = MainContext.default ();
			main_loop = new MainLoop (main_context);

			var interceptor = Gum.Interceptor.obtain ();
			interceptor.begin_transaction ();

			exit_monitor = new ExitMonitor (this, main_context);

			this.interceptor = interceptor;
			this.exceptor = Gum.Exceptor.obtain ();

			interceptor.end_transaction ();
		}

		~Runner () {
			var interceptor = this.interceptor;
			interceptor.begin_transaction ();

			disable_child_gating ();

			exceptor = null;

			exit_monitor = null;

			interceptor.end_transaction ();
		}

		private void run () throws Error {
			main_context.push_thread_default ();

			setup_connection_with_pipe_address.begin (pipe_address);

			main_loop.run ();

			main_context.pop_thread_default ();
		}

		private async void prepare_to_exit () {
			yield prepare_for_termination ();
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
			recover_from_fork (ForkActor.PARENT, null);
		}

		private void recover_from_fork_in_child (string? identifier) {
			recover_from_fork (ForkActor.CHILD, identifier);
		}

		private void recover_from_fork (ForkActor actor, string? identifier) {
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
				finish_recovery_from_fork.begin (actor, identifier);
				return false;
			});

			while (fork_recovery_state != RECOVERED)
				fork_cond.wait (fork_mutex);

			fork_mutex.unlock ();
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

		private async void finish_recovery_from_fork (ForkActor actor, string? identifier) {
			if (actor == CHILD) {
				var identifier_value = (identifier != null) ? identifier : "";
				var path = Environment._get_executable_path ();
				var argv = new string[0];
				var envp = new string[0];
				var info = HostChildInfo (fork_child_pid, fork_parent_pid, identifier_value, path, argv, envp, HostChildOrigin.FORK);

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

		private void recover_from_fork_in_child (string? identifier) {
		}
#endif

		private async void prepare_to_exec (HostChildInfo * info) {
			yield prepare_for_termination ();

			if (controller == null)
				return;

			try {
				yield controller.prepare_to_exec (*info);
			} catch (GLib.Error e) {
			}
		}

		private async async void cancel_exec (uint pid) {
			if (controller == null)
				return;

			try {
				yield controller.cancel_exec (pid);
			} catch (GLib.Error e) {
			}
		}

		private async void acknowledge_spawn (HostChildInfo * info, SpawnStartState start_state) {
			if (controller == null)
				return;

			try {
				yield controller.acknowledge_spawn (*info, start_state);
			} catch (GLib.Error e) {
			}
		}

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
			if (spawn_monitor != null)
				return;

			var interceptor = Gum.Interceptor.obtain ();
			interceptor.begin_transaction ();

#if !WINDOWS
			fork_monitor = new ForkMonitor (this);
#endif

#if LINUX
			thread_list_cloaker = new ThreadListCloaker ();
			fd_list_cloaker = new FDListCloaker ();
#endif

			spawn_monitor = new SpawnMonitor (this, main_context);

			interceptor.end_transaction ();
		}

		private void disable_child_gating () {
			if (spawn_monitor == null)
				return;

			var interceptor = Gum.Interceptor.obtain ();
			interceptor.begin_transaction ();

			spawn_monitor = null;

#if LINUX
			fd_list_cloaker = null;
			thread_list_cloaker = null;
#endif

#if !WINDOWS
			fork_monitor = null;
#endif

			interceptor.end_transaction ();
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

		private async void prepare_for_termination () {
			foreach (var client in clients.to_array ())
				yield client.prepare_for_termination ();

			var connection = this.connection;
			if (connection != null) {
				try {
					yield connection.flush ();
				} catch (GLib.Error e) {
				}
			}
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

		public async void prepare_for_termination () {
			if (script_engine != null)
				yield script_engine.prepare_for_termination ();
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

	private class ExitMonitor : Object, Gum.InvocationListener {
		public weak ExitHandler handler {
			get;
			construct;
		}

		public MainContext main_context {
			get;
			construct;
		}

		public ExitMonitor (ExitHandler handler, MainContext main_context) {
			Object (handler: handler, main_context: main_context);
		}

		private PreparationState preparation_state = UNPREPARED;
		private Mutex mutex;
		private Cond cond;

		private enum PreparationState {
			UNPREPARED,
			PREPARING,
			PREPARED
		}

		construct {
			var interceptor = Gum.Interceptor.obtain ();

			Gum.InvocationListener listener = this;

#if WINDOWS
			interceptor.attach_listener (Gum.Module.find_export_by_name ("kernel32.dll", "ExitProcess"), listener);
#else
			interceptor.attach_listener ((void *) Posix.exit, listener);
			interceptor.attach_listener ((void *) Posix._exit, listener);
			interceptor.attach_listener ((void *) Posix.abort, listener);
#endif
		}

		public override void dispose () {
			var interceptor = Gum.Interceptor.obtain ();

			interceptor.detach_listener (this);

			base.dispose ();
		}

		private void on_enter (Gum.InvocationContext context) {
			if (context.get_depth () > 0)
				return;

			mutex.lock ();

			if (preparation_state == UNPREPARED) {
				preparation_state = PREPARING;

				var source = new IdleSource ();
				source.set_callback (() => {
					do_prepare.begin ();
					return false;
				});
				source.attach (main_context);
			}

			while (preparation_state != PREPARED)
				cond.wait (mutex);

			mutex.unlock ();
		}

		private void on_leave (Gum.InvocationContext context) {
		}

		private async void do_prepare () {
			yield handler.prepare_to_exit ();

			mutex.lock ();
			preparation_state = PREPARED;
			cond.broadcast ();
			mutex.unlock ();
		}
	}

	public interface ExitHandler : Object {
		public abstract async void prepare_to_exit ();
	}

#if !WINDOWS
	private class ForkMonitor : Object {
		public weak ForkHandler handler {
			get;
			construct;
		}

		private ForkListener fork_listener;
		private SetArgV0Listener set_argv0_listener;

		public ForkMonitor (ForkHandler handler) {
			Object (handler: handler);
		}

		construct {
			var interceptor = Gum.Interceptor.obtain ();

			var recover_child_late = false;

#if ANDROID
			if (Environment._get_executable_path ().has_prefix ("/system/bin/app_process")) {
				var set_argv0 = Gum.Module.find_export_by_name ("libandroid_runtime.so", "_Z27android_os_Process_setArgV0P7_JNIEnvP8_jobjectP8_jstring");
				if (set_argv0 != null) {
					set_argv0_listener = new SetArgV0Listener (handler);
					interceptor.attach_listener (set_argv0, set_argv0_listener);

					recover_child_late = true;
				}
			}
#endif

			fork_listener = new ForkListener (handler, recover_child_late);
			interceptor.attach_listener ((void *) Posix.fork, fork_listener);
			interceptor.replace_function ((void *) Posix.vfork, (void *) Posix.fork);
		}

		~ForkMonitor () {
			var interceptor = Gum.Interceptor.obtain ();

			if (set_argv0_listener != null)
				interceptor.detach_listener (set_argv0_listener);

			interceptor.revert_function ((void *) Posix.vfork);
			interceptor.detach_listener (fork_listener);
		}

		private class ForkListener : Object, Gum.InvocationListener {
			public weak ForkHandler handler {
				get;
				construct;
			}

			public bool recover_child_late {
				get;
				construct;
			}

			public ForkListener (ForkHandler handler, bool recover_child_late) {
				Object (handler: handler, recover_child_late: recover_child_late);
			}

			public void on_enter (Gum.InvocationContext context) {
				handler.prepare_to_fork ();
			}

			public void on_leave (Gum.InvocationContext context) {
				int result = (int) context.get_return_value ();
				if (result != 0)
					handler.recover_from_fork_in_parent ();
				else if (!recover_child_late)
					handler.recover_from_fork_in_child (null);
			}
		}

		private class SetArgV0Listener : Object, Gum.InvocationListener {
			public weak ForkHandler handler {
				get;
				construct;
			}

			public SetArgV0Listener (ForkHandler handler) {
				Object (handler: handler);
			}

			public void on_enter (Gum.InvocationContext context) {
				Invocation * invocation = context.get_listener_function_invocation_data (sizeof (Invocation));
				invocation.env = context.get_nth_argument (0);
				invocation.name_obj = context.get_nth_argument (2);
			}

			public void on_leave (Gum.InvocationContext context) {
				Invocation * invocation = context.get_listener_function_invocation_data (sizeof (Invocation));

				var env = invocation.env;
				var env_vtable = *env;

				var get_string_utf_chars = (GetStringUTFCharsFunc) env_vtable[169];
				var release_string_utf_chars = (ReleaseStringUTFCharsFunc) env_vtable[170];

				var name_obj = invocation.name_obj;
				var name_utf8 = get_string_utf_chars (env, name_obj);

				handler.recover_from_fork_in_child (name_utf8);

				release_string_utf_chars (env, name_obj, name_utf8);
			}

			private struct Invocation {
				public void *** env;
				public void * name_obj;
			}

			[CCode (has_target = false)]
			private delegate string * GetStringUTFCharsFunc (void * env, void * str_obj, out uint8 is_copy = null);

			[CCode (has_target = false)]
			private delegate string * ReleaseStringUTFCharsFunc (void * env, void * str_obj, string * str_utf8);

		}
	}
#endif

	public interface ForkHandler : Object {
		public abstract void prepare_to_fork ();
		public abstract void recover_from_fork_in_parent ();
		public abstract void recover_from_fork_in_child (string? identifier);
	}

	public class SpawnMonitor : Object, Gum.InvocationListener {
		public weak SpawnHandler handler {
			get;
			construct;
		}

		public MainContext main_context {
			get;
			construct;
		}

		private Mutex mutex;
		private Cond cond;

		public enum OperationStatus {
			QUEUED,
			COMPLETED
		}

#if DARWIN
		private PosixSpawnFunc posix_spawn;
		private PosixSpawnAttrInitFunc posix_spawnattr_init;
		private PosixSpawnAttrDestroyFunc posix_spawnattr_destroy;
		private PosixSpawnAttrGetFlagsFunc posix_spawnattr_getflags;
		private PosixSpawnAttrSetFlagsFunc posix_spawnattr_setflags;

		private void * execve;

		private Private posix_spawn_caller_is_internal = new Private ();
#endif

		public SpawnMonitor (SpawnHandler handler, MainContext main_context) {
			Object (handler: handler, main_context: main_context);
		}

		construct {
			var interceptor = Gum.Interceptor.obtain ();

#if WINDOWS
			interceptor.attach_listener (Gum.Module.find_export_by_name ("kernel32.dll", "CreateProcessW"), this);
#else
			var libc_name = detect_libc_name ();
#if DARWIN
			posix_spawn = (PosixSpawnFunc) Gum.Module.find_export_by_name (libc_name, "posix_spawn");
			posix_spawnattr_init = (PosixSpawnAttrInitFunc) Gum.Module.find_export_by_name (libc_name, "posix_spawnattr_init");
			posix_spawnattr_destroy = (PosixSpawnAttrDestroyFunc) Gum.Module.find_export_by_name (libc_name, "posix_spawnattr_destroy");
			posix_spawnattr_getflags = (PosixSpawnAttrSetFlagsFunc) Gum.Module.find_export_by_name (libc_name, "posix_spawnattr_getflags");
			posix_spawnattr_setflags = (PosixSpawnAttrSetFlagsFunc) Gum.Module.find_export_by_name (libc_name, "posix_spawnattr_setflags");

			execve = Gum.Module.find_export_by_name (libc_name, "execve");

			interceptor.attach_listener ((void *) posix_spawn, this);

			interceptor.replace_function (execve, (void *) replacement_execve, this);
#else
			interceptor.attach_listener (Gum.Module.find_export_by_name (libc_name, "execve"), this);
#endif
#endif
		}

		public override void dispose () {
			var interceptor = Gum.Interceptor.obtain ();

#if DARWIN
			interceptor.revert_function (execve);
#endif

			interceptor.detach_listener (this);

			base.dispose ();
		}

#if !WINDOWS
		private void on_exec_imminent (HostChildInfo * info) {
			mutex.lock ();

			OperationStatus status = QUEUED;

			var source = new IdleSource ();
			source.set_callback (() => {
				perform_prepare_to_exec.begin (info, &status);
				return false;
			});
			source.attach (main_context);

			while (status != COMPLETED)
				cond.wait (mutex);

			mutex.unlock ();
		}

		private async void perform_prepare_to_exec (HostChildInfo * info, OperationStatus * status) {
			yield handler.prepare_to_exec (info);

			notify_operation_completed (status);
		}

		private void on_exec_cancelled (uint pid) {
			mutex.lock ();

			OperationStatus status = QUEUED;

			var source = new IdleSource ();
			source.set_callback (() => {
				perform_cancel_exec.begin (pid, &status);
				return false;
			});
			source.attach (main_context);

			while (status != COMPLETED)
				cond.wait (mutex);

			mutex.unlock ();
		}

		private async void perform_cancel_exec (uint pid, OperationStatus * status) {
			yield handler.cancel_exec (pid);

			notify_operation_completed (status);
		}
#endif

#if WINDOWS || DARWIN
		private void on_spawn_created (HostChildInfo * info, SpawnStartState start_state) {
			mutex.lock ();

			OperationStatus status = QUEUED;

			var source = new IdleSource ();
			source.set_callback (() => {
				perform_acknowledge_spawn.begin (info, start_state, &status);
				return false;
			});
			source.attach (main_context);

			while (status != COMPLETED)
				cond.wait (mutex);

			mutex.unlock ();
		}

		private async void perform_acknowledge_spawn (HostChildInfo * info, SpawnStartState start_state, OperationStatus * status) {
			yield handler.acknowledge_spawn (info, start_state);

			notify_operation_completed (status);
		}
#endif

#if WINDOWS
		private void on_enter (Gum.InvocationContext context) {
			Invocation * invocation = context.get_listener_function_invocation_data (sizeof (Invocation));

			invocation.application_name = (string16?) context.get_nth_argument (0);
			invocation.command_line = (string16?) context.get_nth_argument (1);

			invocation.creation_flags = (uint32) context.get_nth_argument (5);
			context.replace_nth_argument (5, (void *) (invocation.creation_flags | CreateProcessFlags.CREATE_SUSPENDED));

			invocation.environment = context.get_nth_argument (6);

			invocation.process_info = context.get_nth_argument (9);
		}

		private void on_leave (Gum.InvocationContext context) {
			var success = (bool) context.get_return_value ();
			if (!success)
				return;

			Invocation * invocation = context.get_listener_function_invocation_data (sizeof (Invocation));

			string path = null;
			string[] argv;
			try {
				if (invocation.application_name != null)
					path = invocation.application_name.to_utf8 ();

				if (invocation.command_line != null) {
					Shell.parse_argv (invocation.command_line.to_utf8 (), out argv);
					if (path == null)
						path = argv[0];
				} else {
					argv = new string[0];
				}
			} catch (ConvertError e) {
				assert_not_reached ();
			} catch (ShellError e) {
				assert_not_reached ();
			}

			string[] envp;
			if (invocation.environment != null) {
				if ((invocation.creation_flags & CreateProcessFlags.CREATE_UNICODE_ENVIRONMENT) != 0)
					envp = _parse_unicode_environment (invocation.environment);
				else
					envp = _parse_ansi_environment (invocation.environment);
			} else {
				envp = _get_environment ();
			}

			var pid = invocation.process_info.process_id;
			var parent_pid = _get_current_process_id ();
			var no_identifier = "";
			var info = HostChildInfo (pid, parent_pid, no_identifier, path, argv, envp, HostChildOrigin.SPAWN);
			on_spawn_created (&info, SpawnStartState.SUSPENDED);

			if ((invocation.creation_flags & CreateProcessFlags.CREATE_SUSPENDED) == 0)
				_resume_thread (invocation.process_info.thread);

			(void) invocation.process_info.process;
			(void) invocation.process_info.thread_id;
		}

		private struct Invocation {
			public unowned string16? application_name;
			public unowned string16? command_line;

			public uint32 creation_flags;

			public void * environment;

			public CreateProcessInfo * process_info;
		}

		private struct CreateProcessInfo {
			public void * process;
			public void * thread;
			public uint32 process_id;
			public uint32 thread_id;
		}

		[Flags]
		private enum CreateProcessFlags {
			CREATE_SUSPENDED		= 0x00000004,
			CREATE_UNICODE_ENVIRONMENT	= 0x00000400,
		}

		public static extern uint32 _get_current_process_id ();
		public static extern uint32 _resume_thread (void * thread);
		public static extern string[] _get_environment ();
		public static extern string[] _parse_unicode_environment (void * env);
		public static extern string[] _parse_ansi_environment (void * env);
#elif DARWIN
		private void on_enter (Gum.InvocationContext context) {
			var caller_is_internal = (bool) posix_spawn_caller_is_internal.get ();
			if (caller_is_internal)
				return;

			Invocation * invocation = context.get_listener_function_invocation_data (sizeof (Invocation));

			invocation.pid = context.get_nth_argument (0);
			invocation.path = (string) context.get_nth_argument (1);

			posix_spawnattr_init (&invocation.attr_storage);

			posix_spawnattr_t * attr = context.get_nth_argument (3);
			if (attr == null) {
				attr = &invocation.attr_storage;
				context.replace_nth_argument (3, attr);
			}
			invocation.attr = attr;

			posix_spawnattr_getflags (attr, out invocation.flags);
			posix_spawnattr_setflags (attr, invocation.flags | PosixSpawnFlags.START_SUSPENDED);

			invocation.argv = parse_strv ((string **) context.get_nth_argument (4));
			invocation.envp = parse_strv ((string **) context.get_nth_argument (5));

			if ((invocation.flags & PosixSpawnFlags.SETEXEC) != 0) {
				var pid = Posix.getpid ();
				var no_identifier = "";
				var info = HostChildInfo (pid, pid, no_identifier, invocation.path, invocation.argv, invocation.envp, HostChildOrigin.EXEC);
				on_exec_imminent (&info);
			}
		}

		private void on_leave (Gum.InvocationContext context) {
			var caller_is_internal = (bool) posix_spawn_caller_is_internal.get ();
			if (caller_is_internal)
				return;

			Invocation * invocation = context.get_listener_function_invocation_data (sizeof (Invocation));

			int result = (int) context.get_return_value ();

			if ((invocation.flags & PosixSpawnFlags.SETEXEC) != 0) {
				on_exec_cancelled (Posix.getpid ());
			} else if (result == 0) {
				var pid = *(invocation.pid);
				var parent_pid = Posix.getpid ();
				var no_identifier = "";
				var info = HostChildInfo (pid, parent_pid, no_identifier, invocation.path, invocation.argv, invocation.envp, HostChildOrigin.SPAWN);

				SpawnStartState start_state = ((invocation.flags & PosixSpawnFlags.START_SUSPENDED) != 0)
					? SpawnStartState.SUSPENDED
					: SpawnStartState.RUNNING;

				on_spawn_created (&info, start_state);
			}

			posix_spawnattr_destroy (&invocation.attr_storage);
		}

		private static int replacement_execve (string path, string ** argv, string ** envp) {
			unowned Gum.InvocationContext context = Gum.Interceptor.get_current_invocation ();
			var monitor = (SpawnMonitor) context.get_replacement_function_data ();

			return monitor.handle_execve (path, argv, envp);
		}

		private int handle_execve (string path, string ** argv, string ** envp) {
			var pid = Posix.getpid ();
			var no_identifier = "";
			var info = HostChildInfo (pid, pid, no_identifier, path, parse_strv (argv), parse_strv (envp), HostChildOrigin.EXEC);
			on_exec_imminent (&info);

			Pid resulting_pid;

			posix_spawnattr_t attr;
			posix_spawnattr_init (&attr);
			posix_spawnattr_setflags (&attr, PosixSpawnFlags.SETEXEC | PosixSpawnFlags.START_SUSPENDED);

			posix_spawn_caller_is_internal.set ((void *) true);

			var result = posix_spawn (out resulting_pid, path, null, &attr, argv, envp);
			var spawn_errno = Posix.errno;

			posix_spawn_caller_is_internal.set ((void *) false);

			posix_spawnattr_destroy (&attr);

			on_exec_cancelled (pid);

			Posix.errno = spawn_errno;

			return result;
		}

		private struct Invocation {
			public Posix.pid_t * pid;
			public unowned string path;
			public posix_spawnattr_t * attr;
			public posix_spawnattr_t attr_storage;
			public uint16 flags;
			public unowned string[] argv;
			public unowned string[] envp;
		}

		[CCode (has_target = false)]
		private delegate int PosixSpawnFunc (out Pid pid, string path, void * file_actions, posix_spawnattr_t * attr, string ** argv, string ** envp);

		[CCode (has_target = false)]
		private delegate int PosixSpawnAttrInitFunc (posix_spawnattr_t * attr);

		[CCode (has_target = false)]
		private delegate int PosixSpawnAttrDestroyFunc (posix_spawnattr_t * attr);

		[CCode (has_target = false)]
		private delegate int PosixSpawnAttrGetFlagsFunc (posix_spawnattr_t * attr, out uint16 flags);

		[CCode (has_target = false)]
		private delegate int PosixSpawnAttrSetFlagsFunc (posix_spawnattr_t * attr, uint16 flags);

		[SimpleType]
		[IntegerType (rank = 9)]
		[CCode (cname = "posix_spawnattr_t", cheader_filename = "spawn.h", has_type_id = false)]
		private struct posix_spawnattr_t : size_t {
		}

		[Flags]
		private enum PosixSpawnFlags {
			SETEXEC		= 0x0040,
			START_SUSPENDED	= 0x0080,
		}
#else
		private void on_enter (Gum.InvocationContext context) {
			Invocation * invocation = context.get_listener_function_invocation_data (sizeof (Invocation));
			invocation.pid = Posix.getpid ();

			var no_identifier = "";
			unowned string path = (string) context.get_nth_argument (0);
			var argv = parse_strv ((string **) context.get_nth_argument (1));
			var envp = parse_strv ((string **) context.get_nth_argument (2));
			var info = HostChildInfo (invocation.pid, invocation.pid, no_identifier, path, argv, envp, HostChildOrigin.EXEC);
			on_exec_imminent (&info);
		}

		private void on_leave (Gum.InvocationContext context) {
			Invocation * invocation = context.get_listener_function_invocation_data (sizeof (Invocation));
			on_exec_cancelled (invocation.pid);
		}

		private struct Invocation {
			public uint pid;
		}
#endif

#if !WINDOWS
		private string[] empty_strv = new string[0];

		private unowned string[] parse_strv (string ** strv) {
			if (strv == null)
				return empty_strv;

			unowned string[] elements = (string[]) strv;
			return elements[0:strv_length (elements)];
		}
#endif

		private void notify_operation_completed (OperationStatus * status) {
			mutex.lock ();
			*status = COMPLETED;
			cond.broadcast ();
			mutex.unlock ();
		}
	}

	public interface SpawnHandler : Object {
		public abstract async void prepare_to_exec (HostChildInfo * info);
		public abstract async void cancel_exec (uint pid);
		public abstract async void acknowledge_spawn (HostChildInfo * info, SpawnStartState start_state);
	}

#if LINUX
	private class ThreadListCloaker : Object, DirListFilter {
		private string our_dir_by_pid;
		private DirListCloaker cloaker;

		construct {
			our_dir_by_pid = "/proc/%u/task".printf (Posix.getpid ());
			cloaker = new DirListCloaker (this);
		}

		private bool matches_directory (string path) {
			return path == "/proc/self/task" || path == our_dir_by_pid;
		}

		private bool matches_file (string name) {
			var tid = (Gum.ThreadId) uint64.parse (name);
			return Gum.Cloak.has_thread (tid);
		}
	}

	private class FDListCloaker : Object, DirListFilter {
		private string our_dir_by_pid;
		private DirListCloaker cloaker;

		construct {
			our_dir_by_pid = "/proc/%u/fd".printf (Posix.getpid ());
			cloaker = new DirListCloaker (this);
		}

		private bool matches_directory (string path) {
			return path == "/proc/self/fd" || path == our_dir_by_pid;
		}

		private bool matches_file (string name) {
			var fd = int.parse (name);
			return Gum.Cloak.has_file_descriptor (fd);
		}
	}

	public class DirListCloaker : Object {
		public weak DirListFilter filter {
			get;
			construct;
		}

		private Gee.HashSet<Gum.InvocationListener> listeners = new Gee.HashSet<Gum.InvocationListener> ();
		private Gee.HashSet<Posix.Dir> tracked_handles = new Gee.HashSet<unowned Posix.Dir> ();

		public DirListCloaker (DirListFilter filter) {
			Object (filter: filter);
		}

		construct {
			var interceptor = Gum.Interceptor.obtain ();

			var libc_name = detect_libc_name ();

			var open_listener = new OpenDirListener (this);
			listeners.add (open_listener);
			interceptor.attach_listener (Gum.Module.find_export_by_name (libc_name, "opendir"), open_listener);

			var close_listener = new CloseDirListener (this);
			listeners.add (close_listener);
			interceptor.attach_listener (Gum.Module.find_export_by_name (libc_name, "closedir"), close_listener);

			var readdir = Gum.Module.find_export_by_name (libc_name, "readdir");
			var readdir_listener = new ReadDirListener (this, LEGACY);
			listeners.add (readdir_listener);
			interceptor.attach_listener (readdir, readdir_listener);

			var readdir64 = Gum.Module.find_export_by_name (libc_name, "readdir64");
			if (readdir64 != null && readdir64 != readdir) {
				var listener = new ReadDirListener (this, MODERN);
				listeners.add (listener);
				interceptor.attach_listener (readdir64, listener);
			}

			var readdir_r = Gum.Module.find_export_by_name (libc_name, "readdir_r");
			var readdir_r_listener = new ReadDirRListener (this, LEGACY);
			listeners.add (readdir_r_listener);
			interceptor.attach_listener (readdir_r, readdir_r_listener);

			var readdir64_r = Gum.Module.find_export_by_name (libc_name, "readdir64_r");
			if (readdir64_r != null && readdir64_r != readdir_r) {
				var listener = new ReadDirRListener (this, MODERN);
				listeners.add (listener);
				interceptor.attach_listener (readdir64_r, listener);
			}
		}

		~DirListCloaker () {
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
			public weak DirListCloaker parent {
				get;
				construct;
			}

			public OpenDirListener (DirListCloaker parent) {
				Object (parent: parent);
			}

			public void on_enter (Gum.InvocationContext context) {
				Invocation * invocation = context.get_listener_function_invocation_data (sizeof (Invocation));

				invocation.path = (string *) context.get_nth_argument (0);
			}

			public void on_leave (Gum.InvocationContext context) {
				Invocation * invocation = context.get_listener_function_invocation_data (sizeof (Invocation));
				if (!parent.filter.matches_directory (invocation.path))
					return;

				unowned Posix.Dir? handle = (Posix.Dir?) context.get_return_value ();
				if (handle != null)
					parent.start_tracking (handle);
			}

			private struct Invocation {
				public string * path;
			}
		}

		private class CloseDirListener : Object, Gum.InvocationListener {
			public weak DirListCloaker parent {
				get;
				construct;
			}

			public CloseDirListener (DirListCloaker parent) {
				Object (parent: parent);
			}

			public void on_enter (Gum.InvocationContext context) {
				unowned Posix.Dir? handle = (Posix.Dir?) context.get_nth_argument (0);
				if (handle != null)
					parent.stop_tracking (handle);
			}
		}

		private class ReadDirListener : Object, Gum.InvocationListener {
			public weak DirListCloaker parent {
				get;
				construct;
			}

			public DirEntKind kind {
				get;
				construct;
			}

			public ReadDirListener (DirListCloaker parent, DirEntKind kind) {
				Object (parent: parent, kind: kind);
			}

			public void on_enter (Gum.InvocationContext context) {
				Invocation * invocation = context.get_listener_function_invocation_data (sizeof (Invocation));
				invocation.handle = (Posix.Dir?) context.get_nth_argument (0);
			}

			public void on_leave (Gum.InvocationContext context) {
				Invocation * invocation = context.get_listener_function_invocation_data (sizeof (Invocation));
				if (!parent.is_tracking (invocation.handle))
					return;

				var entry = context.get_return_value ();
				do {
					if (entry == null)
						return;

					var name = parse_dirent_name (entry, kind);

					if (name == "." || name == "..")
						return;

					if (!parent.filter.matches_file (name))
						return;

					var impl = (ReadDirFunc) context.function;
					entry = impl (invocation.handle);

					context.replace_return_value (entry);
				} while (true);
			}

			private struct Invocation {
				public unowned Posix.Dir? handle;
			}

			[CCode (has_target = false)]
			private delegate void * ReadDirFunc (Posix.Dir dir);
		}

		private class ReadDirRListener : Object, Gum.InvocationListener {
			public weak DirListCloaker parent {
				get;
				construct;
			}

			public DirEntKind kind {
				get;
				construct;
			}

			public ReadDirRListener (DirListCloaker parent, DirEntKind kind) {
				Object (parent: parent, kind: kind);
			}

			public void on_enter (Gum.InvocationContext context) {
				Invocation * invocation = context.get_listener_function_invocation_data (sizeof (Invocation));
				invocation.handle = (Posix.Dir?) context.get_nth_argument (0);
				invocation.entry = context.get_nth_argument (1);
				invocation.result = context.get_nth_argument (2);
			}

			public void on_leave (Gum.InvocationContext context) {
				Invocation * invocation = context.get_listener_function_invocation_data (sizeof (Invocation));
				if (!parent.is_tracking (invocation.handle))
					return;

				var result = (int) context.get_return_value ();
				do {
					if (result != 0)
						return;

					if (*invocation.result == null)
						return;

					var name = parse_dirent_name (*invocation.result, kind);

					if (name == "." || name == "..")
						return;

					if (!parent.filter.matches_file (name))
						return;

					var impl = (ReadDirRFunc) context.function;
					result = impl (invocation.handle, invocation.entry, invocation.result);

					context.replace_return_value ((void *) result);
				} while (true);
			}

			private struct Invocation {
				public unowned Posix.Dir? handle;
				public void * entry;
				public void ** result;
			}

			[CCode (has_target = false)]
			private delegate int ReadDirRFunc (Posix.Dir dir, void * entry, void ** result);
		}

		private static unowned string parse_dirent_name (void * entry, DirEntKind kind) {
			unowned string? name = null;

			if (kind == LEGACY) {
				unowned Posix.DirEnt ent = (Posix.DirEnt) entry;
				name = (string) ent.d_name;
			} else if (kind == MODERN) {
				unowned DirEnt64 ent = (DirEnt64) entry;
				name = (string) ent.d_name;
			}

			return name;
		}

		private enum DirEntKind {
			LEGACY,
			MODERN
		}

		[Compact]
		public class DirEnt64 {
			public uint64 d_ino;
			public int64 d_off;
			public uint16 d_reclen;
			public uint8 d_type;
			public char d_name[256];
		}
	}

	public interface DirListFilter : Object {
		public abstract bool matches_directory (string path);
		public abstract bool matches_file (string name);
	}
#endif

#if !WINDOWS
	private static Once<string> libc_name_value;

	private static string detect_libc_name () {
		return libc_name_value.once (_detect_libc_name);
	}

	private static string _detect_libc_name () {
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
#endif

	namespace Environment {
		public extern void _init ();
		public extern void _deinit ();

		public extern unowned Gum.ScriptBackend _obtain_script_backend (bool jit_enabled);

		public string _get_executable_path () {
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
