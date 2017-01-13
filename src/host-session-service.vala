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

		public abstract ImageData? icon {
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

	public abstract class BaseDBusHostSession : Object, HostSession {
		public signal void agent_session_opened (AgentSessionId id, AgentSession session);
		public signal void agent_session_closed (AgentSessionId id, AgentSession session, SessionDetachReason reason);

		private Gee.HashMap<uint, Gee.Promise<Entry>> entries = new Gee.HashMap<uint, Gee.Promise<Entry>> ();
		private Gee.HashMap<uint, AgentSession> sessions = new Gee.HashMap<uint, AgentSession> ();
		private uint next_session_id = 1;

		protected Injector injector;

		public virtual async void close () {
			while (!entries.is_empty) {
				var iterator = entries.values.iterator ();
				iterator.next ();
				var request = iterator.get ();
				try {
					var entry = yield request.future.wait_async ();
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

		public abstract async uint spawn (string path, string[] argv, string[] envp) throws Error;

		public abstract async void input (uint pid, uint8[] data) throws Error;

		public abstract async void resume (uint pid) throws Error;

		public abstract async void kill (uint pid) throws Error;

		public async Frida.AgentSessionId attach_to (uint pid) throws Error {
			var entry = yield establish (pid);

			var id = AgentSessionId (next_session_id++);
			var raw_id = id.handle;
			AgentSession session;

			try {
				yield entry.provider.open (id);
			} catch (GLib.Error e) {
				/*
				 * We might be attempting to open a new session on an agent that is about to unload,
				 * so if we fail here wait a bit and consider re-establishing.
				 */
				var timeout_source = new TimeoutSource (10);
				timeout_source.set_callback (() => {
					attach_to.callback ();
					return false;
				});
				timeout_source.attach (MainContext.get_thread_default ());

				yield;

				if (entries.has_key (pid))
					throw new Error.PROTOCOL (e.message);

				entry = yield establish (pid);

				try {
					yield entry.provider.open (id);
				} catch (GLib.Error e) {
					throw new Error.PROTOCOL (e.message);
				}
			}

			try {
				session = yield entry.connection.get_proxy (null, ObjectPath.from_agent_session_id (id), DBusProxyFlags.NONE, null);
			} catch (GLib.Error e) {
				throw new Error.PROTOCOL (e.message);
			}

			sessions[raw_id] = session;
			entry.sessions.add (raw_id);

			agent_session_opened (id, session);

			return id;
		}

		private async Entry establish (uint pid) throws Error {
			var promise = entries[pid];
			if (promise != null) {
				var future = promise.future;
				try {
					return yield future.wait_async ();
				} catch (Gee.FutureError e) {
					throw (Error) future.exception;
				}
			}
			promise = new Gee.Promise<Entry> ();
			entries[pid] = promise;

			Entry entry;
			try {
				DBusConnection connection;
				AgentSessionProvider provider;

				if (pid == 0) {
					provider = yield create_system_session_provider (out connection);
					entry = new Entry (pid, null, connection, provider);
				} else {
					Object transport;
					var stream = yield perform_attach_to (pid, out transport);

					var cancellable = new Cancellable ();
					var timeout_source = new TimeoutSource.seconds (10);
					timeout_source.set_callback (() => {
						cancellable.cancel ();
						return false;
					});
					timeout_source.attach (MainContext.get_thread_default ());

					try {
						connection = yield new DBusConnection (stream, null, DBusConnectionFlags.NONE, null, cancellable);
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

					entry = new Entry (pid, transport, connection, provider);
				}

				connection.closed.connect (on_connection_closed);
				provider.closed.connect (on_session_closed);

				promise.set_value (entry);
			} catch (Error e) {
				entries.unset (pid);

				promise.set_exception (e);
				throw e;
			}

			return entry;
		}

		protected abstract async IOStream perform_attach_to (uint pid, out Object? transport) throws Error;

		public async AgentSession obtain_agent_session (AgentSessionId id) throws Error {
			var session = sessions[id.handle];
			if (session == null)
				throw new Error.INVALID_ARGUMENT ("Invalid session ID");
			return session;
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			bool closed_by_us = (!remote_peer_vanished && error == null);
			if (closed_by_us)
				return;

			Entry entry_to_remove = null;
			foreach (var promise in entries.values) {
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

		private void on_session_closed (AgentSessionId id) {
			var raw_id = id.handle;

			AgentSession session;
			var found = sessions.unset (raw_id, out session);
			assert (found);
			agent_session_closed (id, session, SessionDetachReason.APPLICATION_REQUESTED);
			agent_session_destroyed (id);

			foreach (var promise in entries.values) {
				var future = promise.future;

				if (!future.ready)
					continue;

				var entry = future.value;

				var sessions = entry.sessions;
				sessions.remove (raw_id);
				if (sessions.is_empty) {
					var is_system_session = entry.pid == 0;
					if (!is_system_session)
						entry.provider.unload.begin ();
				}
			}
		}

		private async void destroy (Entry entry, SessionDetachReason reason) {
			if (!entries.unset (entry.pid))
				return;

			entry.provider.closed.disconnect (on_session_closed);
			entry.connection.closed.disconnect (on_connection_closed);

			yield entry.close ();

			foreach (var raw_id in entry.sessions) {
				var id = AgentSessionId (raw_id);

				AgentSession session;
				var found = sessions.unset (raw_id, out session);
				assert (found);

				agent_session_closed (id, session, reason);
				agent_session_destroyed (id);
			}
		}

		private class Entry : Object {
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

			public Gee.HashSet<uint> sessions {
				get;
				construct;
			}

			private Gee.Promise<bool> close_request;

			public Entry (uint pid, Object? transport, DBusConnection? connection, AgentSessionProvider provider) {
				Object (
					pid: pid,
					transport: transport,
					connection: connection,
					provider: provider,
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

				close_request.set_value (true);
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
	}
}
