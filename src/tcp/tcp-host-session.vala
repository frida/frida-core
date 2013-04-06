namespace Frida {
	public class TcpHostSessionBackend : Object, HostSessionBackend {
		private TcpHostSessionProvider provider;

		public async void start () {
			provider = new TcpHostSessionProvider ();
			provider_available (provider);
		}

		public async void stop () {
			provider_unavailable (provider);
			yield provider.close ();
			provider = null;
		}
	}

	public class TcpHostSessionProvider : Object, HostSessionProvider {
		public string name {
			get { return _name; }
		}
		private string _name = "Local TCP";

		public ImageData? icon {
			get { return _icon; }
		}
		private ImageData? _icon = ImageData (0, 0, 0, "");

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.REMOTE_SYSTEM; }
		}

		private const string DEFAULT_SERVER_ADDRESS = "tcp:host=127.0.0.1,port=27042";
		private const string AGENT_ADDRESS_TEMPLATE = "tcp:host=127.0.0.1,port=%u";

		private string server_address;
		private Gee.ArrayList<Entry> entries = new Gee.ArrayList<Entry> ();

		public TcpHostSessionProvider () {
			server_address = DEFAULT_SERVER_ADDRESS;
		}

		public TcpHostSessionProvider.for_address (string address) {
			server_address = address;
		}

		public async void close () {
			foreach (var entry in entries)
				yield entry.close ();
			entries.clear ();
		}

		public async HostSession create () throws IOError {
			DBusConnection connection = null;
			IOError error = null;
			for (int i = 1; connection == null && error == null; i++) {
				try {
					connection = yield DBusConnection.new_for_address (server_address, DBusConnectionFlags.AUTHENTICATION_CLIENT);
				} catch (Error e) {
					var refused = new IOError.CONNECTION_REFUSED ("Connection refused");
					if (e.domain == refused.domain && e.code == refused.code) {
						if (i != 2 * 20) {
							var source = new TimeoutSource (50);
							source.set_callback (() => {
								create.callback ();
								return false;
							});
							source.attach (MainContext.get_thread_default ());
							yield;
						} else {
							error = new IOError.TIMED_OUT ("timed out");
						}
					} else {
						error = new IOError.FAILED (e.message);
					}
				}
			}

			if (error != null)
				throw error;

			HostSession session = yield connection.get_proxy (null, ObjectPath.HOST_SESSION);

			var entry = new Entry (0, connection, session);
			entries.add (entry);

			connection.closed.connect (on_connection_closed);

			return session;
		}

		public async AgentSession obtain_agent_session (AgentSessionId id) throws IOError {
			var address = AGENT_ADDRESS_TEMPLATE.printf (id.handle);

			DBusConnection connection;
			try {
				connection = yield DBusConnection.new_for_address (address, DBusConnectionFlags.AUTHENTICATION_CLIENT);
			} catch (Error connection_error) {
				throw new IOError.FAILED (connection_error.message);
			}

			AgentSession session = yield connection.get_proxy (null, ObjectPath.AGENT_SESSION);

			var entry = new Entry (id.handle, connection, session);
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

			if (entry_to_remove.id != 0) /* otherwise it's a HostSession */
				agent_session_closed (AgentSessionId (entry_to_remove.id), error);
		}

		private class Entry : Object {
			public uint id {
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

			public Entry (uint id, DBusConnection connection, Object proxy) {
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

