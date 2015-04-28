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
		private ImageData? _icon = ImageData (16, 16, 16 * 4, "AAAAAAAAAAAAAAAAOjo6Dzo6OhQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOjo6TZCHbvlycnL4Ojo6iTo6OhMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOjo6aa6fdv7878f/+/Te/93d3f9xcXH3Ojo6gTo6Og8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOjo6F4KAfv//5Hn//fHK//r6+v/39/f/9/f3/9LS0v9kZGTzOjo6eDo6OgsAAAAAAAAAAAAAAAAAAAAAAAAAADo6Og6Tk5P/zc3N//z8/P/6+vr/8PDw/+7u7v/p6en/9PT0/8jIyP9XV1f2Ojo6SgAAAAAAAAAAAAAAAAAAAAA6OjoIb29v/8HBwf+5ubn/9/f3/+/v7//p6en/+Pj4/+np6f/o6Oj/4ODg/z09PcsAAAAAAAAAAAAAAAAAAAAAAAAAAjMzM1p8fHz/wsLC/7CwsP/x8fH/8/P0/9zc3f/09PT/+vr6/8vLy/9AQEDFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALS0tV2pqav7BwcH/rq6u/+bm5v/09PT/s7Oz/93d3f/R0dL/VVVVygAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjIyNRWlpa+7+/v/+wsLD/oaGh/4iIiP9NTU7/VVVW/0BAQf89PT61Pj4/BgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABsbG09NTU32urq6/4yMjP9ycnL/Pj4//1BQUf9tbW7/XFxd/z4+P8M+Pj8PAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAExMTTD09PfBzc3P/LCwsvDAwMbVEREX/f3+A/6ioqf9tbW7zPj4/lAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANDQ0vGRkZggAAAAAAAAAAJycnh0NDRP2GhojujIyP4EtLS4k/Pz8YAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjIyRoRUVFq21tbp5TU1ZUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACkpK10AAAAWAAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==");

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

		public async HostSession create () throws Error {
			DBusConnection connection = null;
			Error connection_error = null;
			for (int i = 1; connection == null && connection_error == null; i++) {
				try {
					connection = yield DBusConnection.new_for_address (server_address, DBusConnectionFlags.AUTHENTICATION_CLIENT);
				} catch (GLib.Error e) {
					if (e is IOError.CONNECTION_REFUSED) {
						if (i != 2 * 20) {
							var source = new TimeoutSource (50);
							source.set_callback (() => {
								create.callback ();
								return false;
							});
							source.attach (MainContext.get_thread_default ());
							yield;
						} else {
							connection_error = new Error.SERVER_NOT_RUNNING ("timed out");
						}
					} else {
						connection_error = new Error.SERVER_NOT_RUNNING (e.message);
					}
				}
			}

			if (connection_error != null)
				throw connection_error;

			HostSession session;
			try {
				session = yield connection.get_proxy (null, ObjectPath.HOST_SESSION);
			} catch (IOError proxy_error) {
				throw new Error.PROTOCOL (proxy_error.message);
			}

			var entry = new Entry (0, connection, session);
			entries.add (entry);

			connection.closed.connect (on_connection_closed);

			return session;
		}

		public async AgentSession obtain_agent_session (AgentSessionId id) throws Error {
			var address = AGENT_ADDRESS_TEMPLATE.printf (id.handle);

			DBusConnection connection;
			try {
				connection = yield DBusConnection.new_for_address (address, DBusConnectionFlags.AUTHENTICATION_CLIENT);
			} catch (GLib.Error connection_error) {
				throw new Error.PROCESS_NOT_RESPONDING (connection_error.message);
			}

			AgentSession session;
			try {
				session = yield connection.get_proxy (null, ObjectPath.AGENT_SESSION);
			} catch (IOError proxy_error) {
				throw new Error.PROTOCOL (proxy_error.message);
			}

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
				agent_session_closed (AgentSessionId (entry_to_remove.id));
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
				} catch (GLib.Error conn_error) {
				}
				connection = null;
			}
		}
	}
}

