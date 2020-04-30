namespace Frida {
	public class HostSessionService : Object {
		private Gee.ArrayList<HostSessionBackend> backends = new Gee.ArrayList<HostSessionBackend> ();

		public signal void provider_available (HostSessionProvider provider);
		public signal void provider_unavailable (HostSessionProvider provider);

		private delegate void NotifyCompleteFunc ();

		public HostSessionService.with_default_backends () {
			add_local_backends ();
#if !IOS && !ANDROID
			add_backend (new FruityHostSessionBackend ());
			add_backend (new DroidyHostSessionBackend ());
#endif
			add_backend (new SocketHostSessionBackend ());
		}

		public HostSessionService.with_local_backend_only () {
			add_local_backends ();
		}

		public HostSessionService.with_socket_backend_only () {
			add_backend (new SocketHostSessionBackend ());
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

		public async void start (Cancellable? cancellable = null) throws IOError {
			var remaining = backends.size;

			NotifyCompleteFunc on_complete = () => {
				remaining--;
				if (remaining == 0)
					start.callback ();
			};

			foreach (var backend in backends)
				perform_start.begin (backend, cancellable, on_complete);

			yield;
		}

		public async void stop (Cancellable? cancellable = null) throws IOError {
			var remaining = backends.size;

			NotifyCompleteFunc on_complete = () => {
				remaining--;
				if (remaining == 0)
					stop.callback ();
			};

			foreach (var backend in backends)
				perform_stop.begin (backend, cancellable, on_complete);

			yield;
		}

		private async void perform_start (HostSessionBackend backend, Cancellable? cancellable, NotifyCompleteFunc on_complete) {
			try {
				yield backend.start (cancellable);
			} catch (IOError e) {
			}

			on_complete ();
		}

		private async void perform_stop (HostSessionBackend backend, Cancellable? cancellable, NotifyCompleteFunc on_complete) {
			try {
				yield backend.stop (cancellable);
			} catch (IOError e) {
			}

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

		public abstract async HostSession create (string? location = null, Cancellable? cancellable = null) throws Error, IOError;
		public abstract async void destroy (HostSession session, Cancellable? cancellable = null) throws Error, IOError;
		public signal void host_session_closed (HostSession session);

		public abstract async AgentSession obtain_agent_session (HostSession host_session, AgentSessionId agent_session_id, Cancellable? cancellable = null) throws Error, IOError;
		public signal void agent_session_closed (AgentSessionId id, SessionDetachReason reason, CrashInfo? crash);
	}

	public enum HostSessionProviderKind {
		LOCAL,
		REMOTE,
		USB
	}

	public interface ChannelProvider : Object {
		public abstract async IOStream open_channel (string address, Cancellable? cancellable = null) throws Error, IOError;
	}

	public interface HostSessionBackend : Object {
		public signal void provider_available (HostSessionProvider provider);
		public signal void provider_unavailable (HostSessionProvider provider);

		public abstract async void start (Cancellable? cancellable = null) throws IOError;
		public abstract async void stop (Cancellable? cancellable = null) throws IOError;
	}

	public abstract class BaseDBusHostSession : Object, HostSession, AgentController {
		public signal void agent_session_opened (AgentSessionId id, AgentSession session);
		public signal void agent_session_closed (AgentSessionId id, AgentSession session, SessionDetachReason reason, CrashInfo? crash);

		private Gee.HashMap<uint, Future<AgentEntry>> agent_entries = new Gee.HashMap<uint, Future<AgentEntry>> ();

		private Gee.HashMap<AgentSessionId?, AgentSession> agent_sessions =
			new Gee.HashMap<AgentSessionId?, AgentSession> (AgentSessionId.hash, AgentSessionId.equal);
		private uint next_agent_session_id = 1;

		private Gee.HashMap<HostChildId?, ChildEntry> child_entries =
			new Gee.HashMap<HostChildId?, ChildEntry> (HostChildId.hash, HostChildId.equal);
#if !WINDOWS
		private uint next_host_child_id = 1;
#endif
		private Gee.HashMap<uint, HostChildInfo?> pending_children = new Gee.HashMap<uint, HostChildInfo?> ();
		private Gee.HashMap<uint, SpawnAckRequest> pending_acks = new Gee.HashMap<uint, SpawnAckRequest> ();
		private Promise<bool> pending_children_gc_request;
		private Source pending_children_gc_timer;

		protected Injector injector;
		protected Gee.HashMap<uint, uint> injectee_by_pid = new Gee.HashMap<uint, uint> ();

		protected Cancellable io_cancellable = new Cancellable ();

		public virtual async void preload (Cancellable? cancellable) throws Error, IOError {
		}

		public virtual async void close (Cancellable? cancellable) throws IOError {
			if (pending_children_gc_timer != null) {
				pending_children_gc_timer.destroy ();
				pending_children_gc_timer = null;
			}

			if (pending_children_gc_request != null)
				yield garbage_collect_pending_children (cancellable);

			foreach (var ack_request in pending_acks)
				ack_request.complete ();
			pending_acks.clear ();

			while (!agent_entries.is_empty) {
				var iterator = agent_entries.values.iterator ();
				iterator.next ();
				var entry_future = iterator.get ();
				try {
					var entry = yield entry_future.wait_async (cancellable);

					var resume_request = entry.resume_request;
					if (resume_request != null) {
						resume_request.resolve (true);
						entry.resume_request = null;
					}

					yield destroy (entry, APPLICATION_REQUESTED, cancellable);
				} catch (Error e) {
				}
			}

			io_cancellable.cancel ();
		}

		protected abstract async AgentSessionProvider create_system_session_provider (Cancellable? cancellable,
			out DBusConnection connection) throws Error, IOError;

		public abstract async HostApplicationInfo get_frontmost_application (Cancellable? cancellable) throws Error, IOError;

		public abstract async HostApplicationInfo[] enumerate_applications (Cancellable? cancellable) throws Error, IOError;

		public abstract async HostProcessInfo[] enumerate_processes (Cancellable? cancellable) throws Error, IOError;

		public abstract async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError;

		public abstract async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError;

		public abstract async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws Error, IOError;

		public async HostChildInfo[] enumerate_pending_children (Cancellable? cancellable) throws Error, IOError {
			var result = new HostChildInfo[pending_children.size];
			var index = 0;
			foreach (var child in pending_children.values)
				result[index++] = child;
			return result;
		}

		public abstract async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError;

		protected virtual bool try_handle_child (HostChildInfo info) {
			return false;
		}

		protected virtual void notify_child_resumed (uint pid) {
		}

		protected virtual void notify_child_gating_changed (uint pid, uint subscriber_count) {
		}

		protected virtual async void prepare_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
		}

		protected virtual async void await_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not supported on this OS");
		}

		protected virtual async void cancel_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not supported on this OS");
		}

		protected abstract bool process_is_alive (uint pid);

		public abstract async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError;

		public async void resume (uint pid, Cancellable? cancellable) throws Error, IOError {
			if (yield try_resume_child (pid, cancellable))
				return;

			yield perform_resume (pid, cancellable);
		}

		private async bool try_resume_child (uint pid, Cancellable? cancellable) throws Error, IOError {
			HostChildInfo? info;
			if (pending_children.unset (pid, out info))
				child_removed (info);

			SpawnAckRequest ack_request;
			if (pending_acks.unset (pid, out ack_request)) {
				try {
					if (ack_request.start_state == RUNNING)
						yield perform_resume (pid, cancellable);
				} finally {
					ack_request.complete ();
				}

				notify_child_resumed (pid);

				return true;
			}

			var entry_future = agent_entries[pid];
			if (entry_future == null || !entry_future.ready)
				return false;

			var entry = entry_future.value;

			var resume_request = entry.resume_request;
			if (resume_request == null)
				return false;

			resume_request.resolve (true);
			entry.resume_request = null;

			if (entry.sessions.is_empty) {
				unload_and_destroy.begin (entry, APPLICATION_REQUESTED);
			}

			notify_child_resumed (pid);

			return true;
		}

		protected abstract async void perform_resume (uint pid, Cancellable? cancellable) throws Error, IOError;

		protected bool still_attached_to (uint pid) {
			return agent_entries.has_key (pid);
		}

		public abstract async void kill (uint pid, Cancellable? cancellable) throws Error, IOError;

		public async Frida.AgentSessionId attach_to (uint pid, Cancellable? cancellable) throws Error, IOError {
			var entry = yield establish (pid, cancellable);

			var id = AgentSessionId (next_agent_session_id++);
			AgentSession session;

			entry.sessions.add (id);

			try {
				yield entry.provider.open (id, cancellable);

				session = yield entry.connection.get_proxy (null, ObjectPath.from_agent_session_id (id),
					DBusProxyFlags.NONE, cancellable);
			} catch (GLib.Error e) {
				entry.sessions.remove (id);

				throw new Error.PROTOCOL ("%s", e.message);
			}

			agent_sessions[id] = session;

			agent_session_opened (id, session);

			return id;
		}

		private async AgentEntry establish (uint pid, Cancellable? cancellable) throws Error, IOError {
			while (agent_entries.has_key (pid)) {
				var future = agent_entries[pid];
				try {
					return yield future.wait_async (cancellable);
				} catch (Error e) {
					throw e;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}
			var promise = new Promise<AgentEntry> ();
			agent_entries[pid] = promise.future;

			AgentEntry entry;
			try {
				DBusConnection connection;
				AgentSessionProvider provider;

				if (pid == 0) {
					provider = yield create_system_session_provider (cancellable, out connection);
					entry = new AgentEntry (pid, null, connection, provider);
				} else {
					Object transport;
					var stream_request = yield perform_attach_to (pid, cancellable, out transport);

					IOStream stream = yield stream_request.wait_async (cancellable);

					uint controller_registration_id;
					try {
						connection = yield new DBusConnection (stream, ServerGuid.HOST_SESSION_SERVICE,
							AUTHENTICATION_SERVER | AUTHENTICATION_ALLOW_ANONYMOUS | DELAY_MESSAGE_PROCESSING,
							null, cancellable);

						AgentController controller = this;
						controller_registration_id = connection.register_object (ObjectPath.AGENT_CONTROLLER,
							controller);

						connection.start_message_processing ();

						provider = yield connection.get_proxy (null, ObjectPath.AGENT_SESSION_PROVIDER,
							DBusProxyFlags.NONE, cancellable);
					} catch (GLib.Error e) {
						throw new Error.PROCESS_NOT_RESPONDING ("%s", e.message);
					}

					entry = new AgentEntry (pid, transport, connection, provider, controller_registration_id);
				}

				connection.on_closed.connect (on_agent_connection_closed);
				provider.closed.connect (on_agent_session_provider_closed);
				provider.eternalized.connect (on_agent_session_provider_eternalized);
				entry.child_gating_changed.connect (on_child_gating_changed);

				promise.resolve (entry);
			} catch (GLib.Error e) {
				agent_entries.unset (pid);

				promise.reject (e);
				throw_api_error (e);
			}

			return entry;
		}

		protected abstract async Future<IOStream> perform_attach_to (uint pid, Cancellable? cancellable, out Object? transport)
			throws Error, IOError;

		public AgentSession obtain_agent_session (AgentSessionId id) throws Error {
			var session = agent_sessions[id];
			if (session == null)
				throw new Error.INVALID_ARGUMENT ("Invalid session ID");
			return session;
		}

		public AgentSessionProvider obtain_session_provider (AgentSessionId id) throws Error {
			foreach (var future in agent_entries.values) {
				if (!future.ready)
					continue;

				var entry = future.value;
				if (entry.sessions.contains (id))
					return entry.provider;
			}

			throw new Error.INVALID_ARGUMENT ("Invalid session ID");
		}

		private void on_agent_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			bool closed_by_us = (!remote_peer_vanished && error == null);
			if (closed_by_us)
				return;

			AgentEntry entry_to_remove = null;
			foreach (var future in agent_entries.values) {
				if (!future.ready)
					continue;

				var entry = future.value;
				if (entry.connection == connection) {
					entry_to_remove = entry;
					break;
				}
			}
			assert (entry_to_remove != null);

			destroy.begin (entry_to_remove, entry_to_remove.disconnect_reason, io_cancellable);
		}

		private void on_agent_session_provider_closed (AgentSessionId id) {
			AgentSession session;
			var closed_after_opening = agent_sessions.unset (id, out session);
			if (!closed_after_opening)
				return;
			var reason = SessionDetachReason.APPLICATION_REQUESTED;
			agent_session_closed (id, session, reason, null);
			agent_session_destroyed (id, reason);

			foreach (var future in agent_entries.values) {
				if (!future.ready)
					continue;

				var entry = future.value;

				var sessions = entry.sessions;
				if (sessions.remove (id)) {
					if (sessions.is_empty) {
						var is_system_session = entry.pid == 0;
						if (!is_system_session && !entry.eternalized)
							unload_and_destroy.begin (entry, reason);
					}

					break;
				}
			}
		}

		private void on_agent_session_provider_eternalized (AgentSessionProvider provider) {
			foreach (var future in agent_entries.values) {
				if (!future.ready)
					continue;

				var entry = future.value;
				if (entry.provider == provider) {
					entry.eternalized = true;
					break;
				}
			}
		}

		private void on_child_gating_changed (AgentEntry entry, uint subscriber_count) {
			var pid = entry.pid;

			if (subscriber_count == 0) {
				foreach (var child in pending_children.values.to_array ()) {
					if (child.parent_pid == pid)
						resume.begin (child.pid, null);
				}
			}

			notify_child_gating_changed (pid, subscriber_count);
		}

		private async void unload_and_destroy (AgentEntry entry, SessionDetachReason reason) throws IOError {
			if (!prepare_teardown (entry))
				return;

			try {
				yield entry.provider.unload (io_cancellable);
			} catch (GLib.Error e) {
				if (e is IOError.CANCELLED)
					return;
			}

			yield teardown (entry, reason, io_cancellable);
		}

		private async void destroy (AgentEntry entry, SessionDetachReason reason, Cancellable? cancellable) throws IOError {
			if (!prepare_teardown (entry))
				return;

			yield teardown (entry, reason, cancellable);
		}

		private bool prepare_teardown (AgentEntry entry) {
			if (!agent_entries.unset (entry.pid))
				return false;

			entry.child_gating_changed.disconnect (on_child_gating_changed);
			entry.provider.closed.disconnect (on_agent_session_provider_closed);
			entry.provider.eternalized.disconnect (on_agent_session_provider_eternalized);
			entry.connection.on_closed.disconnect (on_agent_connection_closed);

			return true;
		}

		private async void teardown (AgentEntry entry, SessionDetachReason reason, Cancellable? cancellable) throws IOError {
			CrashInfo? crash = null;
			if (reason == PROCESS_TERMINATED)
				crash = yield try_collect_crash (entry.pid, cancellable);

			foreach (var id in entry.sessions) {
				AgentSession session;
				if (agent_sessions.unset (id, out session)) {
					agent_session_closed (id, session, reason, crash);
					if (crash != null)
						agent_session_crashed (id, crash);
					agent_session_destroyed (id, reason);
				}
			}

			yield entry.close (cancellable);
		}

		protected virtual async CrashInfo? try_collect_crash (uint pid, Cancellable? cancellable) throws IOError {
			return null;
		}

		public async InjectorPayloadId inject_library_file (uint pid, string path, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			var raw_id = yield injector.inject_library_file (pid, path, entrypoint, data, cancellable);
			return InjectorPayloadId (raw_id);
		}

		public async InjectorPayloadId inject_library_blob (uint pid, uint8[] blob, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			var blob_bytes = new Bytes (blob);
			var raw_id = yield injector.inject_library_blob (pid, blob_bytes, entrypoint, data, cancellable);
			return InjectorPayloadId (raw_id);
		}

#if !WINDOWS
		public async HostChildId prepare_to_fork (uint parent_pid, Cancellable? cancellable, out uint parent_injectee_id,
				out uint child_injectee_id, out GLib.Socket child_socket) throws Error, IOError {
			var id = HostChildId (next_host_child_id++);

			if (!injectee_by_pid.has_key (parent_pid))
				throw new Error.INVALID_ARGUMENT ("No injectee found for PID %u", parent_pid);
			parent_injectee_id = injectee_by_pid[parent_pid];
			child_injectee_id = yield injector.demonitor_and_clone_state (parent_injectee_id, cancellable);

			var fds = new int[2];
			Posix.socketpair (Posix.AF_UNIX, Posix.SOCK_STREAM, 0, fds);

			Socket local_socket, remote_socket;
			try {
				local_socket = new Socket.from_fd (fds[0]);
				remote_socket = new Socket.from_fd (fds[1]);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			start_child_connection.begin (id, local_socket, cancellable);

			child_socket = remote_socket;

			return id;
		}

		private async void start_child_connection (HostChildId id, Socket local_socket, Cancellable? cancellable) throws IOError {
			DBusConnection connection;
			uint controller_registration_id;
			try {
				var stream = SocketConnection.factory_create_connection (local_socket);
				connection = yield new DBusConnection (stream, ServerGuid.HOST_SESSION_SERVICE,
					AUTHENTICATION_SERVER | AUTHENTICATION_ALLOW_ANONYMOUS | DELAY_MESSAGE_PROCESSING,
					null, cancellable);

				AgentController controller = this;
				controller_registration_id = connection.register_object (ObjectPath.AGENT_CONTROLLER, controller);

				connection.start_message_processing ();
			} catch (GLib.Error e) {
				return;
			}

			var entry = new ChildEntry (connection, controller_registration_id);
			child_entries[id] = entry;
			connection.on_closed.connect (on_child_connection_closed);
		}
#endif

		private void on_child_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			ChildEntry entry_to_remove = null;
			HostChildId? child_id = null;
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

			entry_to_remove.close.begin (io_cancellable);
		}

		public async void recreate_agent_thread (uint pid, uint injectee_id, Cancellable? cancellable) throws Error, IOError {
			injectee_by_pid[pid] = injectee_id;

			yield injector.recreate_thread (pid, injectee_id, cancellable);
		}

		public async void wait_for_permission_to_resume (HostChildId id, HostChildInfo info, Cancellable? cancellable)
				throws Error, IOError {
			var child_entry = child_entries[id];
			if (child_entry == null)
				throw new Error.INVALID_ARGUMENT ("Invalid ID");

			var pid = info.pid;
			var connection = child_entry.connection;

			var promise = new Promise<AgentEntry> ();
			agent_entries[pid] = promise.future;

			AgentSessionProvider provider;
			try {
				provider = yield connection.get_proxy (null, ObjectPath.AGENT_SESSION_PROVIDER, DBusProxyFlags.NONE,
					cancellable);
			} catch (GLib.Error e) {
				agent_entries.unset (pid);
				promise.reject (new Error.TRANSPORT (e.message));

				child_entry.close_soon ();

				return;
			}

			connection.on_closed.disconnect (on_child_connection_closed);
			child_entries.unset (id);

			var resume_request = new Promise<bool> ();

			var agent_entry = new AgentEntry (pid, null, connection, provider, child_entry.controller_registration_id);
			agent_entry.resume_request = resume_request;
			promise.resolve (agent_entry);

			connection.on_closed.connect (on_agent_connection_closed);
			provider.closed.connect (on_agent_session_provider_closed);
			provider.eternalized.connect (on_agent_session_provider_eternalized);
			agent_entry.child_gating_changed.connect (on_child_gating_changed);

			if (!try_handle_child (info))
				add_pending_child (info);

			yield resume_request.future.wait_async (cancellable);
		}

		public async void prepare_to_exec (HostChildInfo info, Cancellable? cancellable) throws Error, IOError {
			var pid = info.pid;

			AgentEntry? entry_to_wait_for = null;
			var entry_future = agent_entries[pid];
			if (entry_future != null) {
				try {
					var entry = yield entry_future.wait_async (cancellable);
					entry.disconnect_reason = PROCESS_REPLACED;
					entry_to_wait_for = entry;
				} catch (GLib.Error e) {
				}
			}

			yield prepare_exec_transition (pid, cancellable);

			wait_for_exec_and_deliver.begin (info, entry_to_wait_for, cancellable);
		}

		private async void wait_for_exec_and_deliver (HostChildInfo info, AgentEntry? entry_to_wait_for, Cancellable? cancellable)
				throws IOError {
			var pid = info.pid;

			try {
				yield await_exec_transition (pid, cancellable);
			} catch (GLib.Error e) {
				return;
			}

			if (entry_to_wait_for != null)
				yield entry_to_wait_for.wait_until_closed (cancellable);

			add_pending_child (info);
		}

		public async void cancel_exec (uint pid, Cancellable? cancellable) throws Error, IOError {
			yield cancel_exec_transition (pid, cancellable);

			var entry_future = agent_entries[pid];
			if (entry_future != null) {
				try {
					var entry = yield entry_future.wait_async (cancellable);
					entry.disconnect_reason = PROCESS_TERMINATED;
				} catch (GLib.Error e) {
				}
			}
		}

		public async void acknowledge_spawn (HostChildInfo info, SpawnStartState start_state, Cancellable? cancellable)
				throws Error, IOError {
			var pid = info.pid;

			var request = new SpawnAckRequest (start_state);

			pending_acks[pid] = request;

			add_pending_child (info);

			yield request.await (cancellable);
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
				garbage_collect_pending_children.begin (io_cancellable);
				return false;
			});
			timer.attach (MainContext.get_thread_default ());
			pending_children_gc_timer = timer;
		}

		private async void garbage_collect_pending_children (Cancellable? cancellable) throws IOError {
			while (pending_children_gc_request != null) {
				try {
					yield pending_children_gc_request.future.wait_async (cancellable);
					return;
				} catch (GLib.Error e) {
					assert (e is IOError.CANCELLED);
					cancellable.set_error_if_cancelled ();
				}
			}
			pending_children_gc_request = new Promise<bool> ();

			foreach (var pid in pending_children.keys.to_array ()) {
				if (!process_is_alive (pid)) {
					try {
						yield resume (pid, cancellable);
					} catch (GLib.Error e) {
					}
				}
			}

			pending_children_gc_request.resolve (true);
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

			public Gee.HashSet<AgentSessionId?> sessions {
				get;
				default = new Gee.HashSet<AgentSessionId?> (AgentSessionId.hash, AgentSessionId.equal);
			}

			public SessionDetachReason disconnect_reason {
				get;
				set;
				default = PROCESS_TERMINATED;
			}

			public Promise<bool>? resume_request {
				get;
				set;
			}

			public bool eternalized {
				get;
				set;
				default = false;
			}

			private bool closing = false;
			private Promise<bool> close_request = new Promise<bool> ();

			public AgentEntry (uint pid, Object? transport, DBusConnection? connection, AgentSessionProvider provider, uint controller_registration_id = 0) {
				Object (
					pid: pid,
					transport: transport,
					connection: connection,
					provider: provider,
					controller_registration_id: controller_registration_id
				);
			}

			construct {
				provider.child_gating_changed.connect (on_child_gating_changed);
			}

			public async void close (Cancellable? cancellable) throws IOError {
				if (closing) {
					yield wait_until_closed (cancellable);
					return;
				}
				closing = true;

				provider.child_gating_changed.disconnect (on_child_gating_changed);

				if (connection != null) {
					try {
						yield connection.close (cancellable);
					} catch (GLib.Error e) {
					}
				}

				var id = controller_registration_id;
				if (id != 0)
					connection.unregister_object (id);

				close_request.resolve (true);
			}

			public async void wait_until_closed (Cancellable? cancellable) throws IOError {
				try {
					yield close_request.future.wait_async (cancellable);
				} catch (Error e) {
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

			private Promise<bool> close_request;

			public ChildEntry (DBusConnection connection, uint controller_registration_id = 0) {
				Object (
					connection: connection,
					controller_registration_id: controller_registration_id
				);
			}

			public async void close (Cancellable? cancellable) throws IOError {
				while (close_request != null) {
					try {
						yield close_request.future.wait_async (cancellable);
						return;
					} catch (GLib.Error e) {
						assert (e is IOError.CANCELLED);
						cancellable.set_error_if_cancelled ();
					}
				}
				close_request = new Promise<bool> ();

				try {
					yield connection.close (cancellable);
				} catch (GLib.Error e) {
				}

				var id = controller_registration_id;
				if (id != 0) {
					connection.unregister_object (id);
				}

				close_request.resolve (true);
			}

			public void close_soon () {
				var source = new IdleSource ();
				source.set_priority (Priority.LOW);
				source.set_callback (() => {
					close.begin (null);
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

			private Promise<bool> promise = new Promise<bool> ();

			public SpawnAckRequest (SpawnStartState start_state) {
				Object (start_state: start_state);
			}

			public async void await (Cancellable? cancellable) throws IOError {
				try {
					yield promise.future.wait_async (cancellable);
				} catch (Error e) {
					assert_not_reached ();
				}
			}

			public void complete () {
				promise.resolve (true);
			}
		}
	}

	public abstract class InternalAgent : Object, RpcPeer {
		public signal void unloaded ();

		public weak BaseDBusHostSession host_session {
			get;
			construct;
		}

		public string? script_source {
			get;
			construct;
		}

		public ScriptRuntime script_runtime {
			get;
			construct;
			default = DEFAULT;
		}

		private Promise<bool> ensure_request;
		private Promise<bool> _unloaded = new Promise<bool> ();

		protected AgentSession session;
		protected AgentScriptId script;
		private RpcClient rpc_client;

		construct {
			rpc_client = new RpcClient (this);

			host_session.agent_session_closed.connect (on_agent_session_closed);
		}

		~InternalAgent () {
			host_session.agent_session_closed.disconnect (on_agent_session_closed);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			if (ensure_request != null) {
				try {
					yield ensure_loaded (cancellable);
				} catch (Error e) {
				}
			}

			yield ensure_unloaded (cancellable);
		}

		protected abstract async uint get_target_pid (Cancellable? cancellable) throws Error, IOError;

		protected virtual void on_event (string type, Json.Array event) {
		}

		protected async Json.Node call (string method, Json.Node[] args, Cancellable? cancellable) throws Error, IOError {
			yield ensure_loaded (cancellable);

			return yield rpc_client.call (method, args, cancellable);
		}

		protected async void ensure_loaded (Cancellable? cancellable) throws Error, IOError {
			while (ensure_request != null) {
				try {
					yield ensure_request.future.wait_async (cancellable);
					return;
				} catch (Error e) {
					throw e;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}
			ensure_request = new Promise<bool> ();

			try {
				yield ensure_unloaded (cancellable);

				uint target_pid = yield get_target_pid (cancellable);

				try {
					var id = yield host_session.attach_to (target_pid, cancellable);

					session = host_session.obtain_agent_session (id);
					session.message_from_script.connect (on_message_from_script);

					if (script_source != null) {
						var options = new ScriptOptions ();
						options.name = "internal-agent";
						options.runtime = script_runtime;

						var raw_options = AgentScriptOptions ();
						raw_options.data = options._serialize ().get_data ();

						script = yield session.create_script_with_options (script_source, raw_options, cancellable);

						yield session.load_script (script, cancellable);
					}
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}

				ensure_request.resolve (true);
			} catch (GLib.Error e) {
				ensure_request.reject (e);
			}

			var pending_error = ensure_request.future.error;
			if (pending_error != null) {
				try {
					yield ensure_unloaded (cancellable);
				} finally {
					ensure_request = null;
				}

				throw_api_error (pending_error);
			}
		}

		private async void ensure_unloaded (Cancellable? cancellable) throws IOError {
			if (script.handle != 0) {
				try {
					yield session.destroy_script (script, cancellable);
				} catch (GLib.Error e) {
					if (e is IOError.CANCELLED)
						return;
				}
				script = AgentScriptId (0);
			}

			if (session != null) {
				try {
					yield session.close (cancellable);
				} catch (GLib.Error e) {
					if (e is IOError.CANCELLED)
						return;
				}
				session.message_from_script.disconnect (on_message_from_script);
				session = null;
			}
		}

		protected async void wait_for_unload (Cancellable? cancellable) throws IOError {
			try {
				yield _unloaded.future.wait_async (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}
		}

		private void on_agent_session_closed (AgentSessionId id, AgentSession session) {
			if (session != this.session)
				return;

			_unloaded.resolve (true);
			unloaded ();
		}

		private void on_message_from_script (AgentScriptId script_id, string raw_message, bool has_data, uint8[] data) {
			if (script_id != script)
				return;

			bool handled = rpc_client.try_handle_message (raw_message);
			if (handled)
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
				on_event (event_type, event);

				handled = true;
			} else if (type == "log") {
				var text = message.get_string_member ("payload");
				printerr ("%s\n", text);

				handled = true;
			}

			if (!handled)
				printerr ("%s\n", raw_message);
		}

		private async void post_rpc_message (string raw_message, Cancellable? cancellable) throws Error, IOError {
			try {
				yield session.post_to_script (script, raw_message, false, new uint8[0], cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}
	}

	internal async void wait_for_uninject (Injector injector, Cancellable? cancellable, UninjectPredicate is_injected) throws IOError {
		if (!is_injected ())
			return;

		var uninjected_handler = injector.uninjected.connect ((id) => {
			wait_for_uninject.callback ();
		});

		var cancel_source = new CancellableSource (cancellable);
		cancel_source.set_callback (wait_for_uninject.callback);
		cancel_source.attach (MainContext.get_thread_default ());

		while (is_injected () && !cancellable.is_cancelled ())
			yield;

		cancel_source.destroy ();

		injector.disconnect (uninjected_handler);
	}

	internal delegate bool UninjectPredicate ();

	internal async AgentSession establish_direct_session (TransportBroker broker, AgentSessionId id, ChannelProvider channel_provider,
			Cancellable? cancellable) throws Error, IOError {
		uint16 port;
		string token;
		try {
			yield broker.open_tcp_transport (id, cancellable, out port, out token);
		} catch (GLib.Error e) {
			if (e is Error.NOT_SUPPORTED)
				throw (Error) e;
			if (e is DBusError.UNKNOWN_METHOD)
				throw new Error.NOT_SUPPORTED ("Not supported by the remote frida-server");
			throw new Error.TRANSPORT ("%s", e.message);
		}

		var stream = yield channel_provider.open_channel (("tcp:%" + uint16.FORMAT_MODIFIER + "u").printf (port), cancellable);

		try {
			size_t bytes_written;
			yield stream.output_stream.write_all_async (token.data, Priority.DEFAULT, cancellable, out bytes_written);

			var connection = yield new DBusConnection (stream, null, AUTHENTICATION_CLIENT, null, cancellable);

			AgentSession agent_session = yield connection.get_proxy (null, ObjectPath.AGENT_SESSION, DBusProxyFlags.NONE,
				cancellable);

			return agent_session;
		} catch (GLib.Error e) {
			throw new Error.TRANSPORT ("%s", e.message);
		}
	}
}
