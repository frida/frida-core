namespace Frida.Agent {
	public void main (string agent_parameters, ref Frida.UnloadPolicy unload_policy, void * injector_state) {
		if (Runner.shared_instance == null)
			Runner.create_and_run (agent_parameters, ref unload_policy, injector_state);
		else
			Runner.resume_after_fork (ref unload_policy, injector_state);
	}

	private enum StopReason {
		UNLOAD,
		FORK
	}

	private class Runner : Object, ProcessInvader, AgentSessionProvider, ExitHandler, ForkHandler, SpawnHandler {
		public static Runner shared_instance = null;
		public static Mutex shared_mutex;

		public string agent_parameters {
			get;
			construct;
		}

		public string? agent_path {
			get;
			construct;
		}

		public StopReason stop_reason {
			get;
			set;
			default = UNLOAD;
		}

		public bool is_eternal {
			get {
				return _is_eternal;
			}
		}
		private bool _is_eternal = false;

		private bool stop_thread_on_unload = true;

		private void * agent_pthread;
		private Thread<bool> agent_gthread;

		private MainContext main_context;
		private MainContext? dbus_context;
		private MainLoop main_loop;
		private DBusConnection connection;
		private AgentController controller;
		private AgentMessageSink message_sink;
		private bool unloading = false;
		private uint filter_id = 0;
		private uint registration_id = 0;
		private uint pending_calls = 0;
		private Promise<bool> pending_close;
		private Gee.HashMap<AgentSessionId?, LiveAgentSession> sessions =
			new Gee.HashMap<AgentSessionId?, LiveAgentSession> (AgentSessionId.hash, AgentSessionId.equal);
		private Gee.HashMap<DBusConnection, DirectConnection> direct_connections =
			new Gee.HashMap<DBusConnection, DirectConnection> ();
		private Gee.Map<PortalMembershipId?, PortalClient> portal_clients =
			new Gee.HashMap<PortalMembershipId?, PortalClient> (PortalMembershipId.hash, PortalMembershipId.equal);
		private uint next_portal_membership_id = 1;
		private Gee.ArrayList<Gum.Script> eternalized_scripts = new Gee.ArrayList<Gum.Script> ();
		private Gee.HashMap<AgentSessionId?, uint> emulated_session_registrations = new Gee.HashMap<AgentSessionId?, uint> ();

		private Gum.MemoryRange agent_range;
		private Gum.ScriptBackend? qjs_backend;
		private Gum.ScriptBackend? v8_backend;
		private ExitMonitor? exit_monitor;
		private Gum.Interceptor interceptor;
		private Gum.Exceptor exceptor;

		private uint child_gating_subscriber_count = 0;
		private ForkMonitor? fork_monitor;
		private FileDescriptorGuard fd_guard;
		private ThreadListCloaker? thread_list_cloaker;
		private FDListCloaker? fd_list_cloaker;
		private uint fork_parent_pid;
		private uint fork_child_pid;
		private HostChildId fork_child_id;
		private uint fork_parent_injectee_id;
		private uint fork_child_injectee_id;
		private Socket fork_child_socket;
		private ForkRecoveryState fork_recovery_state;
		private Mutex fork_mutex;
		private Cond fork_cond;
		private SpawnMonitor? spawn_monitor;
		private ThreadSuspendMonitor? thread_suspend_monitor;

		private delegate void CompletionNotify ();

		private enum ForkRecoveryState {
			RECOVERING,
			RECOVERED
		}

		private enum ForkActor {
			PARENT,
			CHILD
		}

		public static void create_and_run (string agent_parameters, ref Frida.UnloadPolicy unload_policy,
				void * opaque_injector_state) {
			Environment._init ();

			{
				Gum.MemoryRange? mapped_range = null;

#if DARWIN
				var injector_state = (DarwinInjectorState *) opaque_injector_state;
				if (injector_state != null)
					mapped_range = injector_state.mapped_range;
#endif

				string? agent_path;
				var agent_range = detect_own_range_and_path (mapped_range, out agent_path);
				Gum.Cloak.add_range (agent_range);

				var fdt_padder = FileDescriptorTablePadder.obtain ();

#if LINUX
				var injector_state = (LinuxInjectorState *) opaque_injector_state;
				if (injector_state != null) {
					fdt_padder.move_descriptor_if_needed (ref injector_state.fifo_fd);
					Gum.Cloak.add_file_descriptor (injector_state.fifo_fd);
				}
#endif

				var ignore_scope = new ThreadIgnoreScope ();

				shared_instance = new Runner (agent_parameters, agent_path, agent_range);

				try {
					shared_instance.run ((owned) fdt_padder);
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
				} else if (shared_instance.is_eternal) {
					unload_policy = RESIDENT;
					shared_instance.keep_running_eternalized ();
					return;
				} else {
					release_shared_instance ();
				}

				ignore_scope = null;
			}

			Environment._deinit ();
		}

		public static void resume_after_fork (ref Frida.UnloadPolicy unload_policy, void * opaque_injector_state) {
			{
#if LINUX
				var injector_state = (LinuxInjectorState *) opaque_injector_state;
				if (injector_state != null) {
					FileDescriptorTablePadder.obtain ().move_descriptor_if_needed (ref injector_state.fifo_fd);
					Gum.Cloak.add_file_descriptor (injector_state.fifo_fd);
				}
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
				} else if (shared_instance.is_eternal) {
					unload_policy = RESIDENT;
					shared_instance.keep_running_eternalized ();
					return;
				} else {
					release_shared_instance ();
				}

				ignore_scope = null;
			}

			Environment._deinit ();
		}

		private static void release_shared_instance () {
			shared_mutex.lock ();
			var instance = shared_instance;
			shared_instance = null;
			shared_mutex.unlock ();

			instance = null;
		}

		private Runner (string agent_parameters, string? agent_path, Gum.MemoryRange agent_range) {
			Object (agent_parameters: agent_parameters, agent_path: agent_path);

			this.agent_range = agent_range;
		}

		construct {
			agent_pthread = get_current_pthread ();

			main_context = MainContext.default ();
			main_loop = new MainLoop (main_context);
		}

		~Runner () {
			var interceptor = this.interceptor;
			interceptor.begin_transaction ();

			disable_child_gating ();

			thread_suspend_monitor = null;

			exceptor = null;

			exit_monitor = null;

			interceptor.end_transaction ();
		}

		private void run (owned FileDescriptorTablePadder padder) throws Error {
			main_context.push_thread_default ();

			start.begin ((owned) padder);

			main_loop.run ();

			main_context.pop_thread_default ();
		}

		private async void start (owned FileDescriptorTablePadder padder) {
			string[] tokens = agent_parameters.split ("|");
			unowned string transport_uri = tokens[0];
			bool enable_exit_monitor = true;
			foreach (unowned string option in tokens[1:]) {
				if (option == "eternal")
					ensure_eternalized ();
				else if (option == "sticky")
					stop_thread_on_unload = false;
				else if (option == "exit-monitor:off")
					enable_exit_monitor = false;
			}

			{
				var interceptor = Gum.Interceptor.obtain ();
				interceptor.begin_transaction ();

				if (enable_exit_monitor)
					exit_monitor = new ExitMonitor (this, main_context);
				thread_suspend_monitor = new ThreadSuspendMonitor (this);

				this.interceptor = interceptor;
				this.exceptor = Gum.Exceptor.obtain ();

				interceptor.end_transaction ();
			}

			yield setup_connection_with_transport_uri (transport_uri);

			Gum.ScriptBackend.get_scheduler ().push_job_on_js_thread (Priority.DEFAULT, () => {
				schedule_idle (start.callback);
			});
			yield;

			padder = null;
		}

		private void keep_running_eternalized () {
			agent_gthread = new Thread<bool> ("frida-eternal-agent", () => {
				var ignore_scope = new ThreadIgnoreScope ();

				main_context.push_thread_default ();
				main_loop.run ();
				main_context.pop_thread_default ();

				ignore_scope = null;

				return true;
			});
		}

		private async void prepare_to_exit () {
			yield prepare_for_termination (TerminationReason.EXIT);
		}

		private void run_after_fork () {
			fork_mutex.lock ();
			fork_mutex.unlock ();

			stop_reason = UNLOAD;
			agent_pthread = get_current_pthread ();

			main_context.push_thread_default ();
			main_loop.run ();
			main_context.pop_thread_default ();
		}

		private void prepare_to_fork () {
			var fdt_padder = FileDescriptorTablePadder.obtain ();

			schedule_idle (() => {
				do_prepare_to_fork.begin ();
				return false;
			});
			if (agent_gthread != null) {
				agent_gthread.join ();
				agent_gthread = null;
			} else {
				join_pthread (agent_pthread);
			}
			agent_pthread = null;

#if !WINDOWS
			GumJS.prepare_to_fork ();
			Gum.prepare_to_fork ();
			GIOFork.prepare_to_fork ();
			GLibFork.prepare_to_fork ();

#endif

			fdt_padder = null;
		}

		private async void do_prepare_to_fork () {
			stop_reason = FORK;

#if !WINDOWS
			if (controller != null) {
				try {
					fork_parent_pid = get_process_id ();
					fork_child_id = yield controller.prepare_to_fork (fork_parent_pid, null,
						out fork_parent_injectee_id, out fork_child_injectee_id, out fork_child_socket);
				} catch (GLib.Error e) {
#if ANDROID
					error ("Oops, SELinux rule probably missing for your system. Symptom: %s", e.message);
#else
					error ("%s", e.message);
#endif
				}
			}
#endif

			main_loop.quit ();
		}

		private void recover_from_fork_in_parent () {
			recover_from_fork (ForkActor.PARENT, null);
		}

		private void recover_from_fork_in_child (string? identifier) {
			recover_from_fork (ForkActor.CHILD, identifier);
		}

		private void recover_from_fork (ForkActor actor, string? identifier) {
			var fdt_padder = FileDescriptorTablePadder.obtain ();

			if (actor == PARENT) {
#if !WINDOWS
				GLibFork.recover_from_fork_in_parent ();
				GIOFork.recover_from_fork_in_parent ();
				Gum.recover_from_fork_in_parent ();
				GumJS.recover_from_fork_in_parent ();
#endif
			} else if (actor == CHILD) {
#if !WINDOWS
				GLibFork.recover_from_fork_in_child ();
				GIOFork.recover_from_fork_in_child ();
				Gum.recover_from_fork_in_child ();
				GumJS.recover_from_fork_in_child ();
#endif

				fork_child_pid = get_process_id ();

				try {
					acquire_child_gating ();
				} catch (Error e) {
					assert_not_reached ();
				}

				discard_connections ();
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

			fdt_padder = null;
		}

		private async void recreate_agent_thread (ForkActor actor) {
			uint pid, injectee_id;
			if (actor == PARENT) {
				pid = fork_parent_pid;
				injectee_id = fork_parent_injectee_id;
			} else if (actor == CHILD) {
				yield flush_all_sessions ();

				if (fork_child_socket != null) {
					var stream = SocketConnection.factory_create_connection (fork_child_socket);
					yield setup_connection_with_stream (stream);
				}

				pid = fork_child_pid;
				injectee_id = fork_child_injectee_id;
			} else {
				assert_not_reached ();
			}

			if (controller != null) {
				try {
					yield controller.recreate_agent_thread (pid, injectee_id, null);
				} catch (GLib.Error e) {
					assert_not_reached ();
				}
			} else {
				agent_gthread = new Thread<bool> ("frida-eternal-agent", () => {
					var ignore_scope = new ThreadIgnoreScope ();
					run_after_fork ();
					ignore_scope = null;

					return true;
				});
			}

			main_loop.quit ();
		}

		private async void finish_recovery_from_fork (ForkActor actor, string? identifier) {
			if (actor == CHILD && controller != null) {
				var info = HostChildInfo (fork_child_pid, fork_parent_pid, ChildOrigin.FORK);
				if (identifier != null)
					info.identifier = identifier;

				var controller_proxy = controller as DBusProxy;
				var previous_timeout = controller_proxy.get_default_timeout ();
				controller_proxy.set_default_timeout (int.MAX);
				try {
					yield controller.wait_for_permission_to_resume (fork_child_id, info, null);
				} catch (GLib.Error e) {
					// The connection will/did get closed and we will unload...
				}
				controller_proxy.set_default_timeout (previous_timeout);
			}

			if (actor == CHILD)
				release_child_gating ();

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
		}

		private async void prepare_to_exec (HostChildInfo * info) {
			yield prepare_for_termination (TerminationReason.EXEC);

			if (controller == null)
				return;

			try {
				yield controller.prepare_to_exec (*info, null);
			} catch (GLib.Error e) {
			}
		}

		private async void cancel_exec (uint pid) {
			unprepare_for_termination ();

			if (controller == null)
				return;

			try {
				yield controller.cancel_exec (pid, null);
			} catch (GLib.Error e) {
			}
		}

		private async void acknowledge_spawn (HostChildInfo * info, SpawnStartState start_state) {
			if (controller == null)
				return;

			try {
				yield controller.acknowledge_spawn (*info, start_state, null);
			} catch (GLib.Error e) {
			}
		}

		public SpawnStartState query_current_spawn_state () {
			return RUNNING;
		}

		public Gum.MemoryRange get_memory_range () {
			return agent_range;
		}

		public Gum.ScriptBackend get_script_backend (ScriptRuntime runtime) throws Error {
			switch (runtime) {
				case DEFAULT:
					break;
				case QJS:
					if (qjs_backend == null) {
						qjs_backend = Gum.ScriptBackend.obtain_qjs ();
						if (qjs_backend == null) {
							throw new Error.NOT_SUPPORTED (
								"QuickJS runtime not available due to build configuration");
						}
					}
					return qjs_backend;
				case V8:
					if (v8_backend == null) {
						v8_backend = Gum.ScriptBackend.obtain_v8 ();
						if (v8_backend == null) {
							throw new Error.NOT_SUPPORTED (
								"V8 runtime not available due to build configuration");
						}
					}
					return v8_backend;
			}

			try {
				return get_script_backend (QJS);
			} catch (Error e) {
			}
			return get_script_backend (V8);
		}

		public Gum.ScriptBackend? get_active_script_backend () {
			return (v8_backend != null) ? v8_backend : qjs_backend;
		}

		private async void open (AgentSessionId id, AgentSessionOptions options, Cancellable? cancellable) throws Error, IOError {
			if (unloading)
				throw new Error.INVALID_OPERATION ("Agent is unloading");

			var opts = SessionOptions._deserialize (options.data);
			if (opts.realm == EMULATED) {
				AgentSessionProvider emulated_provider = yield get_emulated_provider (cancellable);

				var emulated_opts = new SessionOptions ();
				emulated_opts.persist_timeout = opts.persist_timeout;

				var raw_emulated_opts = AgentSessionOptions ();
				raw_emulated_opts.data = emulated_opts._serialize ().get_data ();

				try {
					yield emulated_provider.open (id, raw_emulated_opts, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}

				var emulated_connection = ((DBusProxy) emulated_provider).get_connection ();

				string path = ObjectPath.from_agent_session_id (id);

				AgentSession emulated_session = yield emulated_connection.get_proxy (null, path, DBusProxyFlags.NONE,
					cancellable);

				var registration_id = connection.register_object (path, emulated_session);
				emulated_session_registrations[id] = registration_id;

				return;
			}

			var session = new LiveAgentSession (this, id, message_sink, dbus_context);
			sessions[id] = session;
			session.closed.connect (on_session_closed);
			session.script_eternalized.connect (on_script_eternalized);

			try {
				session.registration_id = connection.register_object (ObjectPath.from_agent_session_id (id),
					(AgentSession) session);
			} catch (IOError io_error) {
				assert_not_reached ();
			}

			// Ensure DBusConnection gets the signal first, as we will unregister the object right after.
			session.migrated.connect (on_session_migrated);

			opened (id);
		}

		private async void close_all_sessions () {
			uint pending = 1;

			CompletionNotify on_complete = () => {
				pending--;
				if (pending == 0)
					schedule_idle (close_all_sessions.callback);
			};

			foreach (var session in sessions.values.to_array ()) {
				pending++;
				close_session.begin (session, on_complete);
			}

			on_complete ();

			yield;

			assert (sessions.is_empty);
		}

		private async void close_session (LiveAgentSession session, CompletionNotify on_complete) {
			try {
				yield session.close (null);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			on_complete ();
		}

		private async void flush_all_sessions () {
			uint pending = 1;

			CompletionNotify on_complete = () => {
				pending--;
				if (pending == 0)
					schedule_idle (flush_all_sessions.callback);
			};

			foreach (var session in sessions.values.to_array ()) {
				pending++;
				flush_session.begin (session, on_complete);
			}

			on_complete ();

			yield;
		}

		private async void flush_session (LiveAgentSession session, CompletionNotify on_complete) {
			yield session.flush ();

			on_complete ();
		}

		private void on_session_closed (BaseAgentSession base_session) {
			LiveAgentSession session = (LiveAgentSession) base_session;

			closed (session.id);

			unregister_session (session);

			session.migrated.disconnect (on_session_migrated);
			session.script_eternalized.disconnect (on_script_eternalized);
			session.closed.disconnect (on_session_closed);
			sessions.unset (session.id);

			foreach (var dc in direct_connections.values) {
				if (dc.session == session) {
					detach_and_steal_direct_dbus_connection (dc.connection);
					break;
				}
			}
		}

		private void on_session_migrated (AgentSession abstract_session) {
			LiveAgentSession session = (LiveAgentSession) abstract_session;

			unregister_session (session);
		}

		private void unregister_session (LiveAgentSession session) {
			var id = session.registration_id;
			if (id != 0) {
				connection.unregister_object (id);
				session.registration_id = 0;
			}
		}

		private void on_script_eternalized (Gum.Script script) {
			eternalized_scripts.add (script);
			ensure_eternalized ();
		}

#if !WINDOWS
		private async void migrate (AgentSessionId id, Socket to_socket, Cancellable? cancellable) throws Error, IOError {
			if (emulated_session_registrations.has_key (id)) {
				AgentSessionProvider emulated_provider = yield get_emulated_provider (cancellable);
				try {
					yield emulated_provider.migrate (id, to_socket, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
				return;
			}

			if (!sessions.has_key (id))
				throw new Error.INVALID_ARGUMENT ("Invalid session ID");
			var session = sessions[id];

			var dc = new DirectConnection (session);

			DBusConnection connection;
			try {
				connection = yield new DBusConnection (SocketConnection.factory_create_connection (to_socket),
					ServerGuid.AGENT_SESSION, DELAY_MESSAGE_PROCESSING, null, cancellable);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("%s", e.message);
			}
			dc.connection = connection;

			try {
				dc.registration_id = connection.register_object (ObjectPath.AGENT_SESSION, (AgentSession) session);
			} catch (IOError io_error) {
				assert_not_reached ();
			}

			connection.start_message_processing ();

			this.connection.unregister_object (session.registration_id);
			session.registration_id = 0;

			direct_connections[connection] = dc;
			connection.on_closed.connect (on_direct_connection_closed);
		}
#endif

		private void on_direct_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			var dc = detach_and_steal_direct_dbus_connection (connection);

			dc.session.close.begin (null);
		}

		private DirectConnection detach_and_steal_direct_dbus_connection (DBusConnection connection) {
			connection.on_closed.disconnect (on_direct_connection_closed);

			DirectConnection dc;
			bool found = direct_connections.unset (connection, out dc);
			assert (found);

			connection.unregister_object (dc.registration_id);

			return dc;
		}

		private async void unload (Cancellable? cancellable) throws Error, IOError {
			if (unloading)
				throw new Error.INVALID_OPERATION ("Agent is already unloading");
			unloading = true;
			perform_unload.begin ();
		}

		private async void perform_unload () {
			Promise<bool> operation = null;

			AgentSessionProvider? emulated_provider;
			try {
				emulated_provider = yield try_get_emulated_provider (null);
			} catch (IOError e) {
				assert_not_reached ();
			}
			if (emulated_provider != null)
				emulated_provider.unload.begin (null);

			lock (pending_calls) {
				if (pending_calls > 0) {
					pending_close = new Promise<bool> ();
					operation = pending_close;
				}
			}

			if (operation != null) {
				try {
					yield operation.future.wait_async (null);
				} catch (GLib.Error e) {
					assert_not_reached ();
				}
			}

			yield close_all_sessions ();

			yield teardown_connection ();

			if (!is_eternal)
				teardown_emulated_provider ();

			if (stop_thread_on_unload) {
				schedule_idle (() => {
					main_loop.quit ();
					return false;
				});
			}
		}

		private void ensure_eternalized () {
			if (!_is_eternal) {
				_is_eternal = true;
				eternalized ();
			}
		}

		public void acquire_child_gating () throws Error {
			child_gating_subscriber_count++;
			if (child_gating_subscriber_count == 1)
				enable_child_gating ();
			child_gating_changed (child_gating_subscriber_count);
		}

		public void release_child_gating () {
			child_gating_subscriber_count--;
			if (child_gating_subscriber_count == 0)
				disable_child_gating ();
			child_gating_changed (child_gating_subscriber_count);
		}

		private void enable_child_gating () {
			if (spawn_monitor != null)
				return;

			var interceptor = Gum.Interceptor.obtain ();
			interceptor.begin_transaction ();

			fork_monitor = new ForkMonitor (this);
			fd_guard = new FileDescriptorGuard (agent_range);

			thread_list_cloaker = new ThreadListCloaker ();
			fd_list_cloaker = new FDListCloaker ();

			spawn_monitor = new SpawnMonitor (this, main_context);

			interceptor.end_transaction ();
		}

		private void disable_child_gating () {
			if (spawn_monitor == null)
				return;

			var interceptor = Gum.Interceptor.obtain ();
			interceptor.begin_transaction ();

			spawn_monitor = null;

			fd_list_cloaker = null;
			thread_list_cloaker = null;

			fd_guard = null;
			fork_monitor = null;

			interceptor.end_transaction ();
		}

		public async PortalMembershipId join_portal (SocketConnectable connectable, PortalOptions options,
				Cancellable? cancellable) throws Error, IOError {
			string executable_path = get_executable_path ();
			string identifier = executable_path; // TODO: Detect app ID
			string name = Path.get_basename (executable_path); // TODO: Detect app name
			uint pid = get_process_id ();
			var no_icon = ImageData.empty ();
			var app_info = HostApplicationInfo (identifier, name, pid, no_icon, no_icon);

			var client = new PortalClient (this, connectable, options.certificate, options.token, app_info);
			client.kill.connect (on_kill);
			yield client.start (cancellable);

			var id = PortalMembershipId (next_portal_membership_id++);
			portal_clients[id] = client;

			ensure_eternalized ();

			return id;
		}

		public async void leave_portal (PortalMembershipId membership_id, Cancellable? cancellable) throws Error, IOError {
			PortalClient client;
			if (!portal_clients.unset (membership_id, out client))
				throw new Error.INVALID_ARGUMENT ("Invalid membership ID");

			yield client.stop (cancellable);
		}

		private void on_kill () {
			kill_process (get_process_id ());
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

		private async void setup_connection_with_transport_uri (string transport_uri) {
			IOStream stream;
			try {
				if (transport_uri.has_prefix ("socket:")) {
					var socket = new Socket.from_fd (int.parse (transport_uri[7:]));
					stream = SocketConnection.factory_create_connection (socket);
				} else if (transport_uri.has_prefix ("pipe:")) {
					stream = yield Pipe.open (transport_uri, null).wait_async (null);
				} else {
					error ("Invalid transport URI: %s", transport_uri);
				}
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			yield setup_connection_with_stream (stream);
		}

		private async void setup_connection_with_stream (IOStream stream) {
			try {
				connection = yield new DBusConnection (stream, null, DELAY_MESSAGE_PROCESSING);
			} catch (GLib.Error connection_error) {
				printerr ("Unable to create connection: %s\n", connection_error.message);
				return;
			}

			Promise<MainContext> dbus_context_request = detect_dbus_context (connection);

			connection.on_closed.connect (on_connection_closed);
			filter_id = connection.add_filter (on_connection_message);

			try {
				AgentSessionProvider provider = this;
				registration_id = connection.register_object (ObjectPath.AGENT_SESSION_PROVIDER, provider);

				connection.start_message_processing ();

				controller = yield connection.get_proxy (null, ObjectPath.AGENT_CONTROLLER, DBusProxyFlags.NONE, null);
				message_sink = yield connection.get_proxy (null, ObjectPath.AGENT_MESSAGE_SINK, DBusProxyFlags.NONE, null);

				dbus_context = yield dbus_context_request.future.wait_async (null);
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

		private void discard_connections () {
			foreach (var dc in direct_connections.values.to_array ()) {
				detach_and_steal_direct_dbus_connection (dc.connection);

				dc.connection.dispose ();
			}

			if (connection == null)
				return;

			connection.on_closed.disconnect (on_connection_closed);

			unregister_connection ();

			connection.dispose ();
			connection = null;
		}

		private void unregister_connection () {
			foreach (var id in emulated_session_registrations.values)
				connection.unregister_object (id);
			emulated_session_registrations.clear ();

			foreach (var session in sessions.values) {
				var id = session.registration_id;
				if (id != 0)
					connection.unregister_object (id);
				session.registration_id = 0;
			}

			message_sink = null;
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
				unload.begin (null);

			Promise<bool> operation = null;
			lock (pending_calls) {
				pending_calls = 0;
				operation = pending_close;
				pending_close = null;
			}
			if (operation != null)
				operation.resolve (true);
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
									operation.resolve (true);
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

		private async void prepare_for_termination (TerminationReason reason) {
			foreach (var session in sessions.values.to_array ())
				yield session.prepare_for_termination (reason);

			var connection = this.connection;
			if (connection != null) {
				try {
					yield connection.flush ();
				} catch (GLib.Error e) {
				}
			}
		}

		private void unprepare_for_termination () {
			foreach (var session in sessions.values.to_array ())
				session.unprepare_for_termination ();
		}

#if ANDROID && (X86 || X86_64)
		private Promise<AgentSessionProvider>? get_emulated_request;
		private AgentSessionProvider? cached_emulated_provider;
		private NativeBridgeApi? nb_api;
		private void * emulated_agent;
		private NBOnLoadFunc? emulated_entrypoint;
		private Socket? emulated_socket;
		private BridgeState? emulated_bridge_state;
		private Thread<void>? emulated_worker;

		private async AgentSessionProvider? try_get_emulated_provider (Cancellable? cancellable) throws IOError {
			if (get_emulated_request == null)
				return null;

			try {
				return yield get_emulated_provider (cancellable);
			} catch (Error e) {
				return null;
			}
		}

		private async AgentSessionProvider get_emulated_provider (Cancellable? cancellable) throws Error, IOError {
			while (get_emulated_request != null) {
				try {
					return yield get_emulated_request.future.wait_async (cancellable);
				} catch (Error e) {
					throw e;
				} catch (IOError e) {
					assert (e is IOError.CANCELLED);
					cancellable.set_error_if_cancelled ();
				}
			}
			var request = new Promise<AgentSessionProvider> ();
			get_emulated_request = request;

			try {
				if (nb_api == null)
					nb_api = NativeBridgeApi.open ();

				string parent_path = Path.get_dirname (agent_path);
				string emulated_agent_path = Path.build_filename (parent_path,
					sizeof (void *) == 8 ? "frida-agent-arm64.so" : "frida-agent-arm.so");
				if (!FileUtils.test (emulated_agent_path, EXISTS))
					throw new Error.NOT_SUPPORTED ("Unable to handle emulated processes due to build configuration");

				if (nb_api.load_library_ext != null && nb_api.flavor == LEGACY) {
					/*
					 * FIXME: We should be using LoadLibraryExt() on modern systems also, but we need to figure out
					 *        how to get the namespace pointer for the namespace named “classloader-namespace”.
					 */
					var classloader_namespace = (void *) 3;
					emulated_agent = nb_api.load_library_ext (emulated_agent_path, RTLD_LAZY, classloader_namespace);
				} else {
					emulated_agent = nb_api.load_library (emulated_agent_path, RTLD_LAZY);
				}
				if (emulated_agent == null)
					throw new Error.NOT_SUPPORTED ("Process is not using emulation");

				/*
				 * We name our entrypoint “JNI_OnLoad” so that the NativeBridge implementation
				 * recognizes its name and we don't have to register it.
				 */
				emulated_entrypoint = (NBOnLoadFunc) nb_api.get_trampoline (emulated_agent, "JNI_OnLoad");

				var fds = new int[2];
				if (Posix.socketpair (Posix.AF_UNIX, Posix.SOCK_STREAM, 0, fds) != 0)
					throw new Error.NOT_SUPPORTED ("Unable to allocate socketpair");

				Socket local_socket, remote_socket;
				try {
					local_socket = new Socket.from_fd (fds[0]);
					remote_socket = new Socket.from_fd (fds[1]);
				} catch (GLib.Error e) {
					assert_not_reached ();
				}

				IOStream stream = SocketConnection.factory_create_connection (local_socket);
				emulated_socket = remote_socket;

				var parameters = new StringBuilder.sized (64);
				parameters.append_printf ("socket:%d", emulated_socket.fd);
				if (nb_api.unload_library == null)
					parameters.append ("|eternal|sticky");
				/*
				 * Disable ExitMonitor to work around a bug in Android's libndk_translation.so on Android 11.
				 * We need to avoid modifying libc.so ranges that the translator potentially depends on, to
				 * avoid blowing up when Interceptor's CPU cache flush results in the translated code being
				 * discarded, which seems like an edge-case the translator doesn't handle.
				 */
				parameters.append ("|exit-monitor:off");

				emulated_bridge_state = new BridgeState (parameters.str);

				emulated_worker = new Thread<void> ("frida-agent-emulated", run_emulated_agent);

				var connection = yield new DBusConnection (stream, ServerGuid.HOST_SESSION_SERVICE,
					DBusConnectionFlags.NONE, null, cancellable);

				AgentSessionProvider provider = yield connection.get_proxy (null, ObjectPath.AGENT_SESSION_PROVIDER,
					DBusProxyFlags.NONE, cancellable);

				cached_emulated_provider = provider;
				provider.opened.connect (on_emulated_session_opened);
				provider.closed.connect (on_emulated_session_closed);
				provider.eternalized.connect (on_emulated_provider_eternalized);
				provider.child_gating_changed.connect (on_emulated_child_gating_changed);

				if (nb_api.unload_library == null)
					ensure_eternalized ();

				request.resolve (provider);
				return provider;
			} catch (GLib.Error raw_error) {
				DBusError.strip_remote_error (raw_error);

				teardown_emulated_provider ();

				GLib.Error e;
				if (raw_error is Error || raw_error is IOError.CANCELLED)
					e = raw_error;
				else
					e = new Error.TRANSPORT ("%s", raw_error.message);

				request.reject (e);
				throw_api_error (e);
			}
		}

		private void teardown_emulated_provider () {
			get_emulated_request = null;

			if (cached_emulated_provider != null) {
				var provider = cached_emulated_provider;
				provider.opened.disconnect (on_emulated_session_opened);
				provider.closed.disconnect (on_emulated_session_closed);
				provider.eternalized.disconnect (on_emulated_provider_eternalized);
				provider.child_gating_changed.disconnect (on_emulated_child_gating_changed);
				cached_emulated_provider = null;
			}

			if (emulated_worker != null) {
				emulated_worker.join ();
				emulated_worker = null;
			}

			emulated_socket = null;

			if (emulated_agent != null) {
				if (nb_api.unload_library != null)
					nb_api.unload_library (emulated_agent);
				emulated_agent = null;
			}
		}

		private void run_emulated_agent () {
			emulated_entrypoint (nb_api.vm, emulated_bridge_state);
		}

		private void on_emulated_session_opened (AgentSessionId id) {
			opened (id);
		}

		private void on_emulated_session_closed (AgentSessionId id) {
			uint registration_id;
			if (emulated_session_registrations.unset (id, out registration_id))
				connection.unregister_object (registration_id);

			closed (id);
		}

		private void on_emulated_provider_eternalized () {
			ensure_eternalized ();
		}

		private void on_emulated_child_gating_changed (uint subscriber_count) {
			// TODO: Wire up remainder of the child gating logic.
			child_gating_changed (subscriber_count);
		}

		private class NativeBridgeApi {
			public Flavor flavor;
			public NBLoadLibraryFunc load_library;
			public NBLoadLibraryExtFunc? load_library_ext;
			public NBUnloadLibraryFunc? unload_library;
			public NBGetTrampolineFunc get_trampoline;
			public void * vm;

			public enum Flavor {
				MODERN,
				LEGACY
			}

			public static NativeBridgeApi open () throws Error {
				string? nb_mod = null;
				string? vm_mod = null;
				Gum.Process.enumerate_modules ((details) => {
					if (/\/lib(64)?\/libnativebridge.so$/.match (details.path))
						nb_mod = details.path;
					else if (/^lib(art|dvm).so$/.match (details.name) && !/\/system\/fake-libs/.match (details.path))
						vm_mod = details.path;
					bool carry_on = nb_mod == null || vm_mod == null;
					return carry_on;
				});
				if (nb_mod == null)
					throw new Error.NOT_SUPPORTED ("NativeBridge API is not available on this system");
				if (vm_mod == null)
					throw new Error.NOT_SUPPORTED ("Unable to locate Java VM");

				Flavor flavor;
				NBLoadLibraryFunc load;
				NBLoadLibraryExtFunc? load_ext;
				NBUnloadLibraryFunc? unload;
				NBGetTrampolineFunc get_trampoline;

				load = (NBLoadLibraryFunc) Gum.Module.find_export_by_name (nb_mod, "NativeBridgeLoadLibrary");;
				if (load != null) {
					flavor = MODERN;
					load_ext = (NBLoadLibraryExtFunc) Gum.Module.find_export_by_name (nb_mod, "NativeBridgeLoadLibraryExt");
					// XXX: NativeBridgeUnloadLibrary() is only a stub as of Android 11 w/ libndk_translation.so
					unload = null;
					get_trampoline = (NBGetTrampolineFunc) Gum.Module.find_export_by_name (nb_mod,
						"NativeBridgeGetTrampoline");
				} else {
					flavor = LEGACY;
					load = (NBLoadLibraryFunc) Gum.Module.find_export_by_name (nb_mod,
						"_ZN7android23NativeBridgeLoadLibraryEPKci");
					load_ext = (NBLoadLibraryExtFunc) Gum.Module.find_export_by_name (nb_mod,
						"_ZN7android26NativeBridgeLoadLibraryExtEPKciPNS_25native_bridge_namespace_tE");
					// XXX: Unload implementation seems to be unreliable.
					unload = null;
					get_trampoline = (NBGetTrampolineFunc) Gum.Module.find_export_by_name (nb_mod,
						"_ZN7android25NativeBridgeGetTrampolineEPvPKcS2_j");
				}
				if (load == null || get_trampoline == null)
					throw new Error.NOT_SUPPORTED ("NativeBridge API is not available on this system");

				var get_vms = (JNIGetCreatedJavaVMsFunc) Gum.Module.find_export_by_name (vm_mod, "JNI_GetCreatedJavaVMs");
				if (get_vms == null)
					throw new Error.NOT_SUPPORTED ("Unable to locate Java VM");

				var vms = new void *[] { null };
				int num_vms;
				if (get_vms (vms, out num_vms) != JNI_OK || num_vms < 1)
					throw new Error.NOT_SUPPORTED ("No Java VM loaded");

				return new NativeBridgeApi (flavor, load, load_ext, unload, get_trampoline, vms[0]);
			}

			private NativeBridgeApi (Flavor flavor, NBLoadLibraryFunc load_library, NBLoadLibraryExtFunc? load_library_ext,
					NBUnloadLibraryFunc? unload_library, NBGetTrampolineFunc get_trampoline, void * vm) {
				this.flavor = flavor;
				this.load_library = load_library;
				this.load_library_ext = load_library_ext;
				this.unload_library = unload_library;
				this.get_trampoline = get_trampoline;
				this.vm = vm;
			}
		}

		private const int JNI_OK = 0;
		private const int RTLD_LAZY = 1;

		[CCode (has_target = false)]
		private delegate void * NBLoadLibraryFunc (string path, int flags);

		[CCode (has_target = false)]
		private delegate void * NBLoadLibraryExtFunc (string path, int flags, void * ns);

		[CCode (has_target = false)]
		private delegate int NBUnloadLibraryFunc (void * handle);

		[CCode (has_target = false)]
		private delegate void * NBGetTrampolineFunc (void * handle, string name, string? shorty = null, uint32 len = 0);

		[CCode (has_target = false)]
		private delegate int NBOnLoadFunc (void * vm, void * reserved);

		[CCode (has_target = false)]
		private delegate int JNIGetCreatedJavaVMsFunc (void *[] vms, out int num_vms);
#else
		private async AgentSessionProvider? try_get_emulated_provider (Cancellable? cancellable) throws IOError {
			return null;
		}

		private async AgentSessionProvider get_emulated_provider (Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Emulated realm is not supported on this OS");
		}

		private void teardown_emulated_provider () {
		}
#endif
	}

#if ANDROID
	public class BridgeState {
		public string agent_parameters;
		public UnloadPolicy unload_policy;
		public LinuxInjectorState * injector_state;

		public BridgeState (string agent_parameters) {
			this.agent_parameters = agent_parameters;
			this.unload_policy = IMMEDIATE;
		}
	}
#endif

	private class LiveAgentSession : BaseAgentSession {
		public uint registration_id {
			get;
			set;
		}

		public LiveAgentSession (ProcessInvader invader, AgentSessionId id, AgentMessageSink sink, MainContext dbus_context) {
			Object (
				invader: invader,
				id: id,
				message_sink: sink,
				frida_context: MainContext.ref_thread_default (),
				dbus_context: dbus_context
			);
		}
	}

	private class DirectConnection {
		public LiveAgentSession session;

		public DBusConnection connection;
		public uint registration_id;

		public DirectConnection (LiveAgentSession session) {
			this.session = session;
		}
	}

	namespace Environment {
		public extern void _init ();
		public extern void _deinit ();
	}

	private Mutex gc_mutex;
	private uint gc_generation = 0;
	private bool gc_scheduled = false;

	public void _on_pending_thread_garbage (void * data) {
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
