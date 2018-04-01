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
		public signal void agent_session_closed (AgentSessionId id, SessionDetachReason reason);
	}

	public enum HostSessionProviderKind {
		LOCAL_SYSTEM,
		LOCAL_TETHER,
		REMOTE_SYSTEM
	}

	public interface HostSessionBackend : Object {
		public signal void provider_available (HostSessionProvider provider);
		public signal void provider_unavailable (HostSessionProvider provider);

		public abstract async void start ();
		public abstract async void stop ();
	}

	public abstract class BaseDBusHostSession : Object, HostSession, AgentController {
		public signal void agent_session_opened (AgentSessionId id, AgentSession session);
		public signal void agent_session_closed (AgentSessionId id, AgentSession session, SessionDetachReason reason);

		private Gee.HashMap<uint, Gee.Promise<AgentEntry>> agent_entries = new Gee.HashMap<uint, Gee.Promise<AgentEntry>> ();

		private Gee.HashMap<uint, AgentSession> agent_sessions = new Gee.HashMap<uint, AgentSession> ();
		private uint next_agent_session_id = 1;

		private Gee.HashMap<uint, ChildEntry> child_entries = new Gee.HashMap<uint, ChildEntry> ();
#if !WINDOWS
		private uint next_host_child_id = 1;
#endif
		private Gee.HashMap<uint, HostChildInfo?> pending_children = new Gee.HashMap<uint, HostChildInfo?> ();

		protected Injector injector;
		protected Gee.HashMap<uint, uint> injectee_by_pid = new Gee.HashMap<uint, uint> ();

		public virtual async void close () {
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

		public abstract async HostSpawnInfo[] enumerate_pending_spawns () throws Error;

		public async HostChildInfo[] enumerate_pending_children () throws Error {
			var result = new HostChildInfo[pending_children.size];
			var index = 0;
			foreach (var child in pending_children.values)
				result[index++] = child;
			return result;
		}

		public abstract async uint spawn (string path, string[] argv, string[] envp) throws Error;

		public abstract async void input (uint pid, uint8[] data) throws Error;

		public async void resume (uint pid) throws Error {
			if (try_resume_child (pid))
				return;

			yield perform_resume (pid);
		}

		private bool try_resume_child (uint pid) {
			if (!pending_children.unset (pid))
				return false;

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

			destroy.begin (entry_to_remove, SessionDetachReason.PROCESS_TERMINATED);
		}

		private void on_agent_session_provider_closed (AgentSessionId id) {
			var raw_id = id.handle;

			AgentSession session;
			var closed_after_opening = agent_sessions.unset (raw_id, out session);
			if (!closed_after_opening)
				return;
			var reason = SessionDetachReason.APPLICATION_REQUESTED;
			agent_session_closed (id, session, reason);
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

			entry.provider.closed.disconnect (on_agent_session_provider_closed);
			entry.connection.on_closed.disconnect (on_agent_connection_closed);

			return true;
		}

		private async void teardown (AgentEntry entry, SessionDetachReason reason) {
			yield entry.close ();

			foreach (var raw_id in entry.sessions) {
				var id = AgentSessionId (raw_id);

				AgentSession session;
				if (agent_sessions.unset (raw_id, out session)) {
					agent_session_closed (id, session, reason);
					agent_session_destroyed (id, reason);
				}
			}
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

			pending_children[pid] = info;
			delivered (info);

			try {
				yield resume_request.future.wait_async ();
			} catch (Gee.FutureError e) {
				assert_not_reached ();
			}
		}

		private class AgentEntry : Object {
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

			public Gee.Promise<bool>? resume_request {
				get;
				set;
			}

			private Gee.Promise<bool> close_request;

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
	}
}
