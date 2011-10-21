namespace Zed {
	public class HostSessionService : Object {
		private Gee.ArrayList<HostSessionBackend> backends = new Gee.ArrayList<HostSessionBackend> ();

		public signal void provider_available (HostSessionProvider provider);
		public signal void provider_unavailable (HostSessionProvider provider);

		public HostSessionService.with_default_backends () {
			add_local_backends ();
			add_backend (new FruityHostSessionBackend ());
			add_backend (new TcpHostSessionBackend ());
		}

		public HostSessionService.with_local_backend_only () {
			add_local_backends ();
		}

		private void add_local_backends () {
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
			foreach (var entry in entries)
				yield entry.close ();
			entries.clear ();
		}

		protected Session allocate_session () {
			var port = last_agent_port++;
			return new Session (AgentSessionId (port), LISTEN_ADDRESS_TEMPLATE.printf (port));
		}

		public async AgentSession obtain_agent_session (AgentSessionId id) throws IOError {
			var address = LISTEN_ADDRESS_TEMPLATE.printf (id.handle);

			DBusConnection connection = null;

			for (int i = 1; connection == null; i++) {
				try {
					connection = yield DBusConnection.new_for_address (address, DBusConnectionFlags.AUTHENTICATION_CLIENT);
				} catch (Error connect_error) {
					if (i != 40) {
						var source = new TimeoutSource (50);
						source.set_callback (() => {
							obtain_agent_session.callback ();
							return false;
						});
						source.attach (MainContext.get_thread_default ());
						yield;
					} else {
						break;
					}
				}
			}

			if (connection == null)
				throw new IOError.TIMED_OUT ("timed out");

			AgentSession session = connection.get_proxy_sync (null, ObjectPath.AGENT_SESSION);

			var entry = new Entry (id, connection, session);
			entries.add (entry);

			connection.closed.connect (on_connection_closed);

			return session;
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			bool closed_by_us = (!remote_peer_vanished && error == null);
			if (closed_by_us)
				return;

			Entry entry_to_remove = null;
			foreach (var entry in entries) {
				if (entry.connection == connection) {
					entry_to_remove = entry;
					break;
				}
			}

			assert (entry_to_remove != null);
			entries.remove (entry_to_remove);

			agent_session_closed (entry_to_remove.id, error);
		}

		protected class Session {
			public AgentSessionId id;
			public string listen_address;

			public Session (AgentSessionId id, string listen_address) {
				this.id = id;
				this.listen_address = listen_address;
			}
		}

		private class Entry : Object {
			public AgentSessionId id {
				get;
				private set;
			}

			public DBusConnection connection {
				get;
				private set;
			}

			public Object proxy {
				get;
				private set;
			}

			public Entry (AgentSessionId id, DBusConnection connection, Object proxy) {
				this.id = id;
				this.connection = connection;
				this.proxy = proxy;
			}

			public async void close () {
				proxy = null;

				try {
					yield connection.close ();
				} catch (Error conn_error) {
				}
				connection = null;
			}
		}
	}
}
