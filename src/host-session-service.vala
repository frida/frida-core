namespace Frida {
	public class HostSessionService : Object {
		private Gee.ArrayList<HostSessionBackend> backends = new Gee.ArrayList<HostSessionBackend> ();

		public signal void provider_available (HostSessionProvider provider);
		public signal void provider_unavailable (HostSessionProvider provider);

		private delegate void NotifyCompleteFunc ();

		public HostSessionService.with_default_backends () {
			add_local_backends ();
			add_backend (new FruityHostSessionBackend ());
			add_backend (new DroidyHostSessionBackend ());
			add_backend (new TcpHostSessionBackend ());
		}

		public HostSessionService.with_local_backend_only () {
			add_local_backends ();
		}

		public HostSessionService.with_tcp_backend_only () {
			add_backend (new TcpHostSessionBackend ());
		}

		private void add_local_backends () {
#if WINDOWS
			add_backend (new WindowsHostSessionBackend ());
#endif
#if DARWIN
			add_backend (new DarwinHostSessionBackend ());
#endif
#if LINUX
			add_backend (new LinuxHostSessionBackend ());
#endif
#if QNX
			add_backend (new QnxHostSessionBackend ());
#endif
		}

		public async void start () {
			var remaining = backends.size;

			NotifyCompleteFunc on_complete = () => {
				remaining--;
				if (remaining == 0)
					start.callback ();
			};

			foreach (var backend in backends)
				perform_start.begin (backend, on_complete);

			yield;
		}

		public async void stop () {
			var remaining = backends.size;

			NotifyCompleteFunc on_complete = () => {
				remaining--;
				if (remaining == 0)
					stop.callback ();
			};

			foreach (var backend in backends)
				perform_stop.begin (backend, on_complete);

			yield;
		}

		private async void perform_start (HostSessionBackend backend, NotifyCompleteFunc on_complete) {
			yield backend.start ();
			on_complete ();
		}

		private async void perform_stop (HostSessionBackend backend, NotifyCompleteFunc on_complete) {
			yield backend.stop ();
			on_complete ();
		}

		public void add_backend (HostSessionBackend backend) {
			backends.add (backend);
			backend.provider_available.connect ((provider) => {
				provider_available (provider);
			});
			backend.provider_unavailable.connect ((provider) => {
				provider_unavailable (provider);
			});
		}

		public void remove_backend (HostSessionBackend backend) {
			backends.remove (backend);
		}
	}

	public interface HostSessionProvider : Object {
		public abstract string id {
			get;
		}

		public abstract string name {
			get;
		}

		public abstract Image? icon {
			get;
		}

		public abstract HostSessionProviderKind kind {
			get;
		}

		public abstract async HostSession create (string? location = null) throws Error;
		public abstract async void destroy (HostSession session) throws Error;
		public signal void host_session_closed (HostSession session);

		public abstract async AgentSession obtain_agent_session (HostSession host_session, AgentSessionId agent_session_id) throws Error;
		public signal void agent_session_closed (AgentSessionId id, SessionDetachReason reason, string? crash_report);
	}

	public enum HostSessionProviderKind {
		LOCAL,
		REMOTE,
		USB
	}

	public interface HostSessionBackend : Object {
		public signal void provider_available (HostSessionProvider provider);
		public signal void provider_unavailable (HostSessionProvider provider);

		public abstract async void start ();
		public abstract async void stop ();
	}

	public abstract class BaseDBusHostSession : Object, HostSession, AgentController {
		public signal void agent_session_opened (AgentSessionId id, AgentSession session);
		public signal void agent_session_closed (AgentSessionId id, AgentSession session, SessionDetachReason reason, string? crash_report);

		private Gee.HashMap<uint, Gee.Promise<AgentEntry>> agent_entries = new Gee.HashMap<uint, Gee.Promise<AgentEntry>> ();

		private Gee.HashMap<uint, AgentSession> agent_sessions = new Gee.HashMap<uint, AgentSession> ();
		private uint next_agent_session_id = 1;

		private Gee.HashMap<uint, ChildEntry> child_entries = new Gee.HashMap<uint, ChildEntry> ();
#if !WINDOWS
		private uint next_host_child_id = 1;
#endif
		private Gee.HashMap<uint, HostChildInfo?> pending_children = new Gee.HashMap<uint, HostChildInfo?> ();
		private Gee.HashMap<uint, SpawnAckRequest> pending_acks = new Gee.HashMap<uint, SpawnAckRequest> ();
		private Gee.Promise<bool> pending_children_gc_request;
		private Source pending_children_gc_timer;

		protected Injector injector;
		protected Gee.HashMap<uint, uint> injectee_by_pid = new Gee.HashMap<uint, uint> ();

		public virtual async void close () {
			if (pending_children_gc_timer != null) {
				pending_children_gc_timer.destroy ();
				pending_children_gc_timer = null;
			}

			if (pending_children_gc_request != null)
				yield garbage_collect_pending_children ();

			foreach (var ack_request in pending_acks)
				ack_request.complete ();
			pending_acks.clear ();

			while (!agent_entries.is_empty) {
				var iterator = agent_entries.values.iterator ();
				iterator.next ();
				var entry_request = iterator.get ();
				try {
					var entry = yield entry_request.future.wait_async ();

					var resume_request = entry.resume_request;
					if (resume_request != null) {
						resume_request.set_value (true);
						entry.resume_request = null;
					}

					yield destroy (entry, SessionDetachReason.APPLICATION_REQUESTED);
				} catch (Gee.FutureError e) {
				}
			}
		}

		protected abstract async AgentSessionProvider create_system_session_provider (out DBusConnection connection) throws Error;

		public abstract async HostApplicationInfo get_frontmost_application () throws Error;

		public abstract async HostApplicationInfo[] enumerate_applications () throws Error;

		public abstract async HostProcessInfo[] enumerate_processes () throws Error;

		public abstract async void enable_spawn_gating () throws Error;

		public abstract async void disable_spawn_gating () throws Error;

		public abstract async HostSpawnInfo[] enumerate_pending_spawn () throws Error;

		public async HostChildInfo[] enumerate_pending_children () throws Error {
			var result = new HostChildInfo[pending_children.size];
			var index = 0;
			foreach (var child in pending_children.values)
				result[index++] = child;
			return result;
		}

		public abstract async uint spawn (string program, HostSpawnOptions options) throws Error;

		protected virtual bool try_handle_child (HostChildInfo info) {
			return false;
		}

		protected virtual void notify_child_resumed (uint pid) {
		}

		protected virtual void notify_child_gating_changed (uint pid, uint subscriber_count) {
		}

		protected virtual async void prepare_exec_transition (uint pid) throws Error {
		}

		protected virtual async void await_exec_transition (uint pid) throws Error {
			throw new Error.NOT_SUPPORTED ("Not supported on this OS");
		}

		protected virtual async void cancel_exec_transition (uint pid) throws Error {
			throw new Error.NOT_SUPPORTED ("Not supported on this OS");
		}

		protected abstract bool process_is_alive (uint pid);

		public abstract async void input (uint pid, uint8[] data) throws Error;

		public async void resume (uint pid) throws Error {
			if (yield try_resume_child (pid))
				return;

			yield perform_resume (pid);
		}

		private async bool try_resume_child (uint pid) throws Error {
			HostChildInfo? info;
			if (pending_children.unset (pid, out info))
				child_removed (info);

			SpawnAckRequest ack_request;
			if (pending_acks.unset (pid, out ack_request)) {
				try {
					if (ack_request.start_state == RUNNING)
						yield perform_resume (pid);
				} finally {
					ack_request.complete ();
				}

				notify_child_resumed (pid);

				return true;
			}

			var entry_request = agent_entries[pid];
			if (entry_request == null)
				return false;

			var entry_future = entry_request.future;
			if (!entry_future.ready)
				return false;

			var entry = entry_future.value;

			var resume_request = entry.resume_request;
			if (resume_request == null)
				return false;

			resume_request.set_value (true);
			entry.resume_request = null;

			if (entry.sessions.is_empty) {
				unload_and_destroy.begin (entry, SessionDetachReason.APPLICATION_REQUESTED);
			}

			notify_child_resumed (pid);

			return true;
		}

		protected abstract async void perform_resume (uint pid) throws Error;

		public abstract async void kill (uint pid) throws Error;

		public async Frida.AgentSessionId attach_to (uint pid) throws Error {
			var entry = yield establish (pid);

			var id = AgentSessionId (next_agent_session_id++);
			var raw_id = id.handle;
			AgentSession session;

			entry.sessions.add (raw_id);

			try {
				yield entry.provider.open (id);

				session = yield entry.connection.get_proxy (null, ObjectPath.from_agent_session_id (id), DBusProxyFlags.NONE, null);
			} catch (GLib.Error e) {
				entry.sessions.remove (raw_id);

				throw new Error.PROTOCOL (e.message);
			}

			agent_sessions[raw_id] = session;

			agent_session_opened (id, session);
			log_event ("agent_session_opened(id=%u, pid=%u)", raw_id, pid);

			return id;
		}

		private async AgentEntry establish (uint pid) throws Error {
			var promise = agent_entries[pid];
			if (promise != null) {
				var future = promise.future;
				try {
					return yield future.wait_async ();
				} catch (Gee.FutureError e) {
					throw (Error) future.exception;
				}
			}
			promise = new Gee.Promise<AgentEntry> ();
			agent_entries[pid] = promise;

			AgentEntry entry;
			try {
				DBusConnection connection;
				AgentSessionProvider provider;

				if (pid == 0) {
					provider = yield create_system_session_provider (out connection);
					entry = new AgentEntry (pid, null, connection, provider);
				} else {
					Object transport;
					var stream_request = yield perform_attach_to (pid, out transport);

					IOStream stream;
					try {
						stream = yield stream_request.future.wait_async ();
					} catch (Gee.FutureError e) {
						throw new Error.TRANSPORT (e.message);
					}

					var cancellable = new Cancellable ();
					var timeout_source = new TimeoutSource.seconds (10);
					timeout_source.set_callback (() => {
						cancellable.cancel ();
						return false;
					});
					timeout_source.attach (MainContext.get_thread_default ());

					uint controller_registration_id;
					try {
						connection = yield new DBusConnection (stream, ServerGuid.HOST_SESSION_SERVICE, AUTHENTICATION_SERVER | AUTHENTICATION_ALLOW_ANONYMOUS | DELAY_MESSAGE_PROCESSING, null, cancellable);

						AgentController controller = this;
						controller_registration_id = connection.register_object (ObjectPath.AGENT_CONTROLLER, controller);

						connection.start_message_processing ();

						provider = yield connection.get_proxy (null, ObjectPath.AGENT_SESSION_PROVIDER, DBusProxyFlags.NONE, cancellable);
					} catch (GLib.Error establish_error) {
						if (establish_error is IOError.CANCELLED)
							throw new Error.PROCESS_NOT_RESPONDING ("Timed out while waiting for session to establish");
						else
							throw new Error.PROCESS_NOT_RESPONDING (establish_error.message);
					}
					if (cancellable.is_cancelled ())
						throw new Error.PROCESS_NOT_RESPONDING ("Timed out while waiting for session to establish");

					timeout_source.destroy ();

					entry = new AgentEntry (pid, transport, connection, provider, controller_registration_id);
				}

				connection.on_closed.connect (on_agent_connection_closed);
				provider.closed.connect (on_agent_session_provider_closed);
				entry.child_gating_changed.connect (on_child_gating_changed);

				promise.set_value (entry);
			} catch (Error e) {
				agent_entries.unset (pid);

				promise.set_exception (e);
				throw e;
			}

			return entry;
		}

		protected abstract async Gee.Promise<IOStream> perform_attach_to (uint pid, out Object? transport) throws Error;

		public async AgentSession obtain_agent_session (AgentSessionId id) throws Error {
			var session = agent_sessions[id.handle];
			if (session == null)
				throw new Error.INVALID_ARGUMENT ("Invalid session ID");
			return session;
		}

		private void on_agent_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			bool closed_by_us = (!remote_peer_vanished && error == null);
			if (closed_by_us)
				return;

			AgentEntry entry_to_remove = null;
			foreach (var promise in agent_entries.values) {
				var future = promise.future;

				if (!future.ready)
					continue;

				var entry = future.value;
				if (entry.connection == connection) {
					entry_to_remove = entry;
					break;
				}
			}
			assert (entry_to_remove != null);

			destroy.begin (entry_to_remove, entry_to_remove.disconnect_reason);
		}

		private void on_agent_session_provider_closed (AgentSessionId id) {
			var raw_id = id.handle;

			AgentSession session;
			var closed_after_opening = agent_sessions.unset (raw_id, out session);
			if (!closed_after_opening)
				return;
			var reason = SessionDetachReason.APPLICATION_REQUESTED;
			string? crash_report = null;
			agent_session_closed (id, session, reason, crash_report);
			agent_session_destroyed (id, reason);

			foreach (var promise in agent_entries.values) {
				var future = promise.future;

				if (!future.ready)
					continue;

				var entry = future.value;

				var sessions = entry.sessions;
				if (sessions.remove (raw_id)) {
					if (sessions.is_empty) {
						var is_system_session = entry.pid == 0;
						if (!is_system_session)
							unload_and_destroy.begin (entry, reason);
					}

					break;
				}
			}
		}

		private void on_child_gating_changed (AgentEntry entry, uint subscriber_count) {
			var pid = entry.pid;

			if (subscriber_count == 0) {
				foreach (var child in pending_children.values.to_array ()) {
					if (child.parent_pid == pid)
						resume.begin (child.pid);
				}
			}

			notify_child_gating_changed (pid, subscriber_count);
		}

		private async void unload_and_destroy (AgentEntry entry, SessionDetachReason reason) {
			if (!prepare_teardown (entry))
				return;

			try {
				yield entry.provider.unload ();
			} catch (GLib.Error e) {
			}

			yield teardown (entry, reason);
		}

		private async void destroy (AgentEntry entry, SessionDetachReason reason) {
			if (!prepare_teardown (entry))
				return;

			yield teardown (entry, reason);
		}

		private bool prepare_teardown (AgentEntry entry) {
			if (!agent_entries.unset (entry.pid))
				return false;

			entry.child_gating_changed.disconnect (on_child_gating_changed);
			entry.provider.closed.disconnect (on_agent_session_provider_closed);
			entry.connection.on_closed.disconnect (on_agent_connection_closed);

			return true;
		}

		private async void teardown (AgentEntry entry, SessionDetachReason reason) {
			string? crash_report = null;
			if (reason == PROCESS_TERMINATED)
				crash_report = yield try_collect_crash_report (entry.pid);

			foreach (var raw_id in entry.sessions) {
				var id = AgentSessionId (raw_id);

				AgentSession session;
				if (agent_sessions.unset (raw_id, out session)) {
					log_event ("agent_session_closed(id=%u, reason=%s)", raw_id, reason.to_string ());
					agent_session_closed (id, session, reason, crash_report);
					if (crash_report != null)
						agent_session_crashed (id, crash_report);
					agent_session_destroyed (id, reason);
				}
			}

			yield entry.close ();
		}

		protected virtual async string? try_collect_crash_report (uint pid) {
			return null;
		}

		public async InjectorPayloadId inject_library_file (uint pid, string path, string entrypoint, string data) throws Error {
			var raw_id = yield injector.inject_library_file (pid, path, entrypoint, data);
			return InjectorPayloadId (raw_id);
		}

		public async InjectorPayloadId inject_library_blob (uint pid, uint8[] blob, string entrypoint, string data) throws Error {
			var blob_bytes = new Bytes (blob);
			var raw_id = yield injector.inject_library_blob (pid, blob_bytes, entrypoint, data);
			return InjectorPayloadId (raw_id);
		}

#if !WINDOWS
		public async HostChildId prepare_to_fork (uint parent_pid, out uint parent_injectee_id, out uint child_injectee_id, out GLib.Socket child_socket) throws Error {
			var id = HostChildId (next_host_child_id++);

			if (!injectee_by_pid.has_key (parent_pid))
				throw new Error.INVALID_ARGUMENT ("No injectee found for PID %u", parent_pid);
			parent_injectee_id = injectee_by_pid[parent_pid];
			child_injectee_id = yield injector.demonitor_and_clone_state (parent_injectee_id);

			var fds = new int[2];
			Posix.socketpair (Posix.AF_UNIX, Posix.SOCK_STREAM, 0, fds);

			Socket local_socket, remote_socket;
			try {
				local_socket = new Socket.from_fd (fds[0]);
				remote_socket = new Socket.from_fd (fds[1]);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			start_child_connection.begin (id, local_socket);

			child_socket = remote_socket;

			return id;
		}

		private async void start_child_connection (HostChildId id, Socket local_socket) {
			DBusConnection connection;
			uint controller_registration_id;
			try {
				var stream = SocketConnection.factory_create_connection (local_socket);
				connection = yield new DBusConnection (stream, ServerGuid.HOST_SESSION_SERVICE, AUTHENTICATION_SERVER | AUTHENTICATION_ALLOW_ANONYMOUS | DELAY_MESSAGE_PROCESSING, null, null);

				AgentController controller = this;
				controller_registration_id = connection.register_object (ObjectPath.AGENT_CONTROLLER, controller);

				connection.start_message_processing ();
			} catch (GLib.Error e) {
				return;
			}

			var entry = new ChildEntry (connection, controller_registration_id);
			child_entries[id.handle] = entry;
			connection.on_closed.connect (on_child_connection_closed);
		}
#endif

		private void on_child_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			ChildEntry entry_to_remove = null;
			uint child_id = 0;
			foreach (var e in child_entries.entries) {
				var entry = e.value;
				if (entry.connection == connection) {
					entry_to_remove = entry;
					child_id = e.key;
					break;
				}
			}
			assert (entry_to_remove != null);

			connection.on_closed.disconnect (on_child_connection_closed);
			child_entries.unset (child_id);

			entry_to_remove.close.begin ();
		}

		public async void recreate_agent_thread (uint pid, uint injectee_id) throws Error {
			injectee_by_pid[pid] = injectee_id;

			yield injector.recreate_thread (pid, injectee_id);
		}

		public async void wait_for_permission_to_resume (HostChildId id, HostChildInfo info) throws Error {
			var raw_id = id.handle;

			var child_entry = child_entries[raw_id];
			if (child_entry == null)
				throw new Error.INVALID_ARGUMENT ("Invalid ID");

			var pid = info.pid;
			var connection = child_entry.connection;

			var promise = new Gee.Promise<AgentEntry> ();
			agent_entries[pid] = promise;

			AgentSessionProvider provider;
			try {
				provider = yield connection.get_proxy (null, ObjectPath.AGENT_SESSION_PROVIDER, DBusProxyFlags.NONE, null);
			} catch (GLib.Error e) {
				agent_entries.unset (pid);
				promise.set_exception (new Error.TRANSPORT (e.message));

				child_entry.close_soon ();

				return;
			}

			connection.on_closed.disconnect (on_child_connection_closed);
			child_entries.unset (raw_id);

			var resume_request = new Gee.Promise<bool> ();

			var agent_entry = new AgentEntry (pid, null, connection, provider, child_entry.controller_registration_id);
			agent_entry.resume_request = resume_request;
			promise.set_value (agent_entry);

			connection.on_closed.connect (on_agent_connection_closed);
			provider.closed.connect (on_agent_session_provider_closed);
			agent_entry.child_gating_changed.connect (on_child_gating_changed);

			if (!try_handle_child (info))
				add_pending_child (info);

			try {
				yield resume_request.future.wait_async ();
			} catch (Gee.FutureError e) {
				assert_not_reached ();
			}
		}

		public async void prepare_to_exec (HostChildInfo info) throws Error {
			var pid = info.pid;

			AgentEntry? entry_to_wait_for = null;
			var entry_promise = agent_entries[pid];
			if (entry_promise != null) {
				try {
					var entry = yield entry_promise.future.wait_async ();
					entry.disconnect_reason = PROCESS_REPLACED;
					entry_to_wait_for = entry;
				} catch (Gee.FutureError e) {
				}
			}

			yield prepare_exec_transition (pid);

			wait_for_exec_and_deliver.begin (info, entry_to_wait_for);
		}

		private async void wait_for_exec_and_deliver (HostChildInfo info, AgentEntry? entry_to_wait_for) {
			var pid = info.pid;

			try {
				yield await_exec_transition (pid);
			} catch (Error e) {
				return;
			}

			if (entry_to_wait_for != null)
				yield entry_to_wait_for.wait_until_closed ();

			add_pending_child (info);
		}

		public async void cancel_exec (uint pid) throws Error {
			yield cancel_exec_transition (pid);

			var entry_promise = agent_entries[pid];
			if (entry_promise != null) {
				try {
					var entry = yield entry_promise.future.wait_async ();
					entry.disconnect_reason = PROCESS_TERMINATED;
				} catch (Gee.FutureError e) {
				}
			}
		}

		public async void acknowledge_spawn (HostChildInfo info, SpawnStartState start_state) throws Error {
			var pid = info.pid;

			var request = new SpawnAckRequest (start_state);

			pending_acks[pid] = request;

			add_pending_child (info);

			yield request.await ();
		}

		private void add_pending_child (HostChildInfo info) {
			pending_children[info.pid] = info;
			child_added (info);

			garbage_collect_pending_children_soon ();
		}

		private void garbage_collect_pending_children_soon () {
			if (pending_children_gc_timer != null || pending_children_gc_request != null)
				return;

			var timer = new TimeoutSource.seconds (1);
			timer.set_callback (() => {
				pending_children_gc_timer = null;
				garbage_collect_pending_children.begin ();
				return false;
			});
			timer.attach (MainContext.get_thread_default ());
			pending_children_gc_timer = timer;
		}

		private async void garbage_collect_pending_children () {
			if (pending_children_gc_request != null) {
				try {
					yield pending_children_gc_request.future.wait_async ();
				} catch (Gee.FutureError e) {
					assert_not_reached ();
				}
				return;
			}
			pending_children_gc_request = new Gee.Promise<bool> ();

			foreach (var pid in pending_children.keys.to_array ()) {
				if (!process_is_alive (pid)) {
					try {
						yield resume (pid);
					} catch (GLib.Error e) {
					}
				}
			}

			pending_children_gc_request.set_value (true);
			pending_children_gc_request = null;

			if (!pending_children.is_empty)
				garbage_collect_pending_children_soon ();
		}

		private class AgentEntry : Object {
			public signal void child_gating_changed (uint subscriber_count);

			public uint pid {
				get;
				construct;
			}

			public Object? transport {
				get;
				construct;
			}

			public DBusConnection? connection {
				get;
				construct;
			}

			public AgentSessionProvider provider {
				get;
				construct;
			}

			public uint controller_registration_id {
				get;
				construct;
			}

			public Gee.HashSet<uint> sessions {
				get;
				construct;
			}

			public SessionDetachReason disconnect_reason {
				get;
				set;
				default = PROCESS_TERMINATED;
			}

			public Gee.Promise<bool>? resume_request {
				get;
				set;
			}

			private bool closing = false;
			private Gee.Promise<bool> close_request = new Gee.Promise<bool> ();

			public AgentEntry (uint pid, Object? transport, DBusConnection? connection, AgentSessionProvider provider, uint controller_registration_id = 0) {
				Object (
					pid: pid,
					transport: transport,
					connection: connection,
					provider: provider,
					controller_registration_id: controller_registration_id,
					sessions: new Gee.HashSet<uint> ()
				);
			}

			construct {
				provider.child_gating_changed.connect (on_child_gating_changed);
			}

			public async void close () {
				if (closing) {
					yield wait_until_closed ();
					return;
				}
				closing = true;

				provider.child_gating_changed.disconnect (on_child_gating_changed);

				if (connection != null) {
					try {
						yield connection.close ();
					} catch (GLib.Error e) {
					}
				}

				var id = controller_registration_id;
				if (id != 0) {
					connection.unregister_object (id);
				}

				close_request.set_value (true);
			}

			public async void wait_until_closed () {
				try {
					yield close_request.future.wait_async ();
				} catch (Gee.FutureError e) {
					assert_not_reached ();
				}
			}

			private void on_child_gating_changed (uint subscriber_count) {
				child_gating_changed (subscriber_count);
			}
		}

		private class ChildEntry : Object {
			public DBusConnection connection {
				get;
				construct;
			}

			public uint controller_registration_id {
				get;
				construct;
			}

			private Gee.Promise<bool> close_request;

			public ChildEntry (DBusConnection connection, uint controller_registration_id = 0) {
				Object (
					connection: connection,
					controller_registration_id: controller_registration_id
				);
			}

			public async void close () {
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
					yield connection.close ();
				} catch (GLib.Error e) {
				}

				var id = controller_registration_id;
				if (id != 0) {
					connection.unregister_object (id);
				}

				close_request.set_value (true);
			}

			public void close_soon () {
				var source = new IdleSource ();
				source.set_priority (Priority.LOW);
				source.set_callback (() => {
					close.begin ();
					return false;
				});
				source.attach (MainContext.get_thread_default ());
			}
		}

		private class SpawnAckRequest : Object {
			public SpawnStartState start_state {
				get;
				construct;
			}

			private Gee.Promise<bool> promise = new Gee.Promise<bool> ();

			public SpawnAckRequest (SpawnStartState start_state) {
				Object (start_state: start_state);
			}

			public async void await () {
				try {
					yield promise.future.wait_async ();
				} catch (Gee.FutureError e) {
					assert_not_reached ();
				}
			}

			public void complete () {
				promise.set_value (true);
			}
		}
	}

	public abstract class InternalAgent : Object {
		public signal void unloaded ();

		public BaseDBusHostSession host_session {
			get;
			construct;
		}

		public string? script_source {
			get;
			construct;
		}

		public bool enable_jit {
			get;
			construct;
			default = false;
		}

		private Gee.Promise<bool> ensure_request;
		private Gee.Promise<bool> _unloaded = new Gee.Promise<bool> ();

		protected AgentSession session;
		private AgentScriptId script;

		private Gee.HashMap<string, PendingResponse> pending = new Gee.HashMap<string, PendingResponse> ();
		private int64 next_request_id = 1;

		construct {
			host_session.agent_session_closed.connect (on_agent_session_closed);
		}

		~InternalAgent () {
			host_session.agent_session_closed.disconnect (on_agent_session_closed);
		}

		public async void close () {
			if (ensure_request != null) {
				try {
					yield ensure_loaded ();
				} catch (Error e) {
				}
			}

			yield ensure_unloaded ();
		}

		protected abstract async uint get_target_pid () throws Error;

		protected virtual void on_event (string type, Json.Array event) {
		}

		protected async Json.Node call (string method, Json.Node[] args) throws Error {
			yield ensure_loaded ();

			var request_id = next_request_id++;

			var builder = new Json.Builder ();
			builder
			.begin_array ()
			.add_string_value ("frida:rpc")
			.add_int_value (request_id)
			.add_string_value ("call")
			.add_string_value (method)
			.begin_array ();
			foreach (var arg in args)
				builder.add_value (arg);
			builder
			.end_array ()
			.end_array ();

			var generator = new Json.Generator ();
			generator.set_root (builder.get_root ());
			size_t length;
			var request = generator.to_data (out length);

			var response = new PendingResponse (() => call.callback ());
			pending[request_id.to_string ()] = response;

			post_call_request.begin (request, response, session, script);

			yield;

			if (response.error != null)
				throw response.error;

			return response.result;
		}

		private async void post_call_request (string request, PendingResponse response, AgentSession session, AgentScriptId script) {
			try {
				yield session.post_to_script (script, request, false, new uint8[0]);
			} catch (GLib.Error e) {
				response.complete_with_error (Marshal.from_dbus (e));
			}
		}

		protected async void ensure_loaded () throws Error {
			if (ensure_request != null) {
				var future = ensure_request.future;
				try {
					yield future.wait_async ();
				} catch (Gee.FutureError e) {
					throw (Error) future.exception;
				}
				return;
			}
			ensure_request = new Gee.Promise<bool> ();

			uint target_pid;
			try {
				target_pid = yield get_target_pid ();
			} catch (Error e) {
				ensure_request.set_exception (e);
				ensure_request = null;

				throw e;
			}

			try {
				var id = yield host_session.attach_to (target_pid);

				session = yield host_session.obtain_agent_session (id);
				session.message_from_script.connect (on_message_from_script);

				if (enable_jit) {
					yield session.enable_jit ();
				}

				if (script_source != null) {
					script = yield session.create_script ("internal-agent", script_source);
					yield session.load_script (script);
				}

				ensure_request.set_value (true);
			} catch (GLib.Error raw_error) {
				yield ensure_unloaded ();

				var error = Marshal.from_dbus (raw_error);
				ensure_request.set_exception (error);
				ensure_request = null;

				throw error;
			}
		}

		private async void ensure_unloaded () {
			if (script.handle != 0) {
				try {
					yield session.destroy_script (script);
				} catch (GLib.Error e) {
				}
				script = AgentScriptId (0);
			}

			if (session != null) {
				try {
					yield session.close ();
				} catch (GLib.Error e) {
				}
				session.message_from_script.disconnect (on_message_from_script);
				session = null;
			}
		}

		protected async void wait_for_unload () {
			try {
				yield _unloaded.future.wait_async ();
			} catch (Gee.FutureError e) {
				assert_not_reached ();
			}
		}

		private void on_agent_session_closed (AgentSessionId id, AgentSession session) {
			if (session != this.session)
				return;

			_unloaded.set_value (true);
			unloaded ();
		}

		private void on_message_from_script (AgentScriptId sid, string raw_message, bool has_data, uint8[] data) {
			if (sid != script)
				return;

			var parser = new Json.Parser ();
			try {
				parser.load_from_data (raw_message);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
			var message = parser.get_root ().get_object ();
			var type = message.get_string_member ("type");
			if (type == "send") {
				var event = message.get_array_member ("payload");
				var event_type = event.get_string_element (0);
				if (event_type == "frida:rpc") {
					var request_id = event.get_int_element (1);
					PendingResponse response;
					pending.unset (request_id.to_string (), out response);
					var status = event.get_string_element (2);
					if (status == "ok")
						response.complete_with_result (event.get_element (3));
					else
						response.complete_with_error (new Error.NOT_SUPPORTED (event.get_string_element (3)));
				} else {
					on_event (event_type, event);
				}
			} else if (type == "log") {
				var text = message.get_string_member ("payload");
				log_event ("%s", text);
			} else {
				log_event ("%s", raw_message);
			}
		}

		private class PendingResponse {
			public delegate void CompletionHandler ();
			private CompletionHandler handler;

			public Json.Node? result {
				get;
				private set;
			}

			public Error? error {
				get;
				private set;
			}

			public PendingResponse (owned CompletionHandler handler) {
				this.handler = (owned) handler;
			}

			public void complete_with_result (Json.Node r) {
				result = r;
				handler ();
			}

			public void complete_with_error (Error e) {
				error = e;
				handler ();
			}
		}
	}

	private static Timer last_event_timer = null;

	public void log_event (string format, ...) {
		var builder = new StringBuilder ();

		if (last_event_timer == null) {
			last_event_timer = new Timer ();
		}

		builder.append_printf ("[+%u ms] ", (uint) (last_event_timer.elapsed () * 1000.0));

		var args = va_list ();
		builder.append_vprintf (format, args);

		builder.append_c ('\n');

		stderr.write (builder.str.data);
	}
}
