namespace Frida {
	public class HostSessionService : Object {
		private Gee.ArrayList<HostSessionBackend> backends = new Gee.ArrayList<HostSessionBackend> ();

		public signal void provider_available (HostSessionProvider provider);
		public signal void provider_unavailable (HostSessionProvider provider);

		public HostSessionService.with_default_backends () {
			add_local_backends ();
#if !LINUX
			add_backend (new FruityHostSessionBackend ());
#endif
			add_backend (new TcpHostSessionBackend ());
		}

		public HostSessionService.with_local_backend_only () {
			add_local_backends ();
		}

		public HostSessionService.with_tcp_backend_only () {
			add_backend (new TcpHostSessionBackend ());
		}

		private void add_local_backends () {
#if LINUX
			add_backend (new LinuxHostSessionBackend ());
#endif
#if DARWIN
			add_backend (new DarwinHostSessionBackend ());
#endif
#if WINDOWS
			add_backend (new WindowsHostSessionBackend ());
#endif
		}

		public async void start () {
			foreach (var backend in backends)
				yield backend.start ();
		}

		public async void stop () {
			foreach (var backend in backends)
				yield backend.stop ();
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
		public abstract string name {
			get;
		}

		public abstract ImageData? icon {
			get;
		}

		public abstract HostSessionProviderKind kind {
			get;
		}

		public abstract async HostSession create () throws IOError;

		public abstract async AgentSession obtain_agent_session (AgentSessionId id) throws IOError;
		public signal void agent_session_closed (AgentSessionId id, Error? error);
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

	public abstract class BaseDBusHostSession : Object {
		public signal void agent_session_closed (AgentSessionId id, Error? error);

		private const string LISTEN_ADDRESS_TEMPLATE = "tcp:host=127.0.0.1,port=%u";
		private uint last_agent_port = 27043;
		private Gee.ArrayList<Entry> entries = new Gee.ArrayList<Entry> ();

		public virtual async void close () {
			foreach (var entry in entries.slice (0, entries.size))
				yield entry.close ();
			entries.clear ();
		}

		protected async AgentSessionId allocate_session (Object transport, IOStream stream) throws IOError {
			var cancellable = new Cancellable ();
			var cancelled = new IOError.CANCELLED ("");
			var timeout_source = new TimeoutSource (2000);
			timeout_source.set_callback (() => {
				cancellable.cancel ();
				return false;
			});
			timeout_source.attach (MainContext.get_thread_default ());

			DBusConnection connection;
			AgentSession session;
			try {
				connection = yield DBusConnection.new_for_stream (stream, null, DBusConnectionFlags.NONE, null, cancellable);
				session = yield connection.get_proxy (null, ObjectPath.AGENT_SESSION, DBusProxyFlags.NONE, cancellable);
			} catch (Error e) {
				if (e is IOError && e.code == cancelled.code)
					throw new IOError.TIMED_OUT ("timed out");
				else
					throw new IOError.FAILED (e.message);
			}
			if (cancellable.is_cancelled ())
				throw new IOError.TIMED_OUT ("timed out");

			bool found_available = false;
			var loopback = new InetAddress.loopback (SocketFamily.IPV4);
			var address_in_use = new IOError.ADDRESS_IN_USE ("");
			while (!found_available) {
				try {
					var socket = new Socket (SocketFamily.IPV4, SocketType.STREAM, SocketProtocol.TCP);
					socket.bind (new InetSocketAddress (loopback, (uint16) last_agent_port), false);
					socket.close ();
					found_available = true;
				} catch (Error probe_error) {
					if (probe_error.code == address_in_use.code)
						last_agent_port++;
					else
						found_available = true;
				}
			}
			var port = last_agent_port++;
			AgentSessionId id = AgentSessionId (port);

			var entry = new Entry (id, transport, connection, session);
			entries.add (entry);
			connection.closed.connect (on_connection_closed);

			try {
				entry.serve (LISTEN_ADDRESS_TEMPLATE.printf (port));
			} catch (Error serve_error) {
				try {
					yield connection.close ();
				} catch (Error cleanup_error) {
				}
				throw new IOError.FAILED (serve_error.message);
			}

			timeout_source.destroy ();

			return AgentSessionId (port);
		}

		public async AgentSession obtain_agent_session (AgentSessionId id) throws IOError {
			foreach (var entry in entries) {
				if (entry.id.handle == id.handle)
					return entry.agent_session;
			}
			throw new IOError.NOT_FOUND ("no such session");
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			Entry entry_to_remove = null;
			foreach (var entry in entries) {
				if (entry.agent_connection == connection) {
					entry_to_remove = entry;
					break;
				}
			}

			assert (entry_to_remove != null);
			entries.remove (entry_to_remove);

			agent_session_closed (entry_to_remove.id, error);
		}

		private class Entry : Object {
			public AgentSessionId id {
				get;
				private set;
			}

			public Object transport {
				get;
				private set;
			}

			public DBusConnection agent_connection {
				get;
				private set;
			}

			public AgentSession agent_session {
				get;
				private set;
			}

			private DBusServer server;
			private Gee.ArrayList<DBusConnection> client_connections = new Gee.ArrayList<DBusConnection> ();
			private Gee.HashMap<DBusConnection, uint> registration_id_by_connection = new Gee.HashMap<DBusConnection, uint> ();

			public Entry (AgentSessionId id, Object transport, DBusConnection agent_connection, AgentSession agent_session) {
				this.id = id;
				this.transport = transport;
				this.agent_connection = agent_connection;
				this.agent_session = agent_session;
			}

			public async void close () {
				if (server != null) {
					server.stop ();
					server = null;
				}

				foreach (var connection in client_connections.slice (0, client_connections.size)) {
					try {
						yield connection.close ();
					} catch (Error client_conn_error) {
					}
				}
				client_connections.clear ();
				registration_id_by_connection.clear ();

				agent_session = null;

				try {
					yield agent_connection.close ();
				} catch (Error agent_conn_error) {
				}
				agent_connection = null;
			}

			public void serve (string listen_address) throws Error {
				server = new DBusServer.sync (listen_address, DBusServerFlags.AUTHENTICATION_ALLOW_ANONYMOUS, DBus.generate_guid ());
				server.new_connection.connect ((connection) => {
					connection.closed.connect (on_client_connection_closed);

					try {
						var registration_id = connection.register_object (Frida.ObjectPath.AGENT_SESSION, agent_session);
						registration_id_by_connection[connection] = registration_id;
					} catch (IOError e) {
						printerr ("failed to register object: %s\n", e.message);
						close ();
						return false;
					}

					client_connections.add (connection);
					return true;
				});
				server.start ();
			}

			private void on_client_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
				uint registration_id;
				if (registration_id_by_connection.unset (connection, out registration_id))
					connection.unregister_object (registration_id);
				client_connections.remove (connection);
			}
		}
	}
}
