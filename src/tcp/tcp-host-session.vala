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
		public string id {
			get { return "tcp"; }
		}

		public string name {
			get { return _name; }
		}
		private string _name = "Local TCP";

		public Image? icon {
			get { return _icon; }
		}
		private Image _icon = new Image (ImageData (16, 16, 16 * 4, "AAAAAAAAAAAAAAAAOjo6Dzo6OhQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOjo6TZCHbvlycnL4Ojo6iTo6OhMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOjo6aa6fdv7878f/+/Te/93d3f9xcXH3Ojo6gTo6Og8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOjo6F4KAfv//5Hn//fHK//r6+v/39/f/9/f3/9LS0v9kZGTzOjo6eDo6OgsAAAAAAAAAAAAAAAAAAAAAAAAAADo6Og6Tk5P/zc3N//z8/P/6+vr/8PDw/+7u7v/p6en/9PT0/8jIyP9XV1f2Ojo6SgAAAAAAAAAAAAAAAAAAAAA6OjoIb29v/8HBwf+5ubn/9/f3/+/v7//p6en/+Pj4/+np6f/o6Oj/4ODg/z09PcsAAAAAAAAAAAAAAAAAAAAAAAAAAjMzM1p8fHz/wsLC/7CwsP/x8fH/8/P0/9zc3f/09PT/+vr6/8vLy/9AQEDFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALS0tV2pqav7BwcH/rq6u/+bm5v/09PT/s7Oz/93d3f/R0dL/VVVVygAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjIyNRWlpa+7+/v/+wsLD/oaGh/4iIiP9NTU7/VVVW/0BAQf89PT61Pj4/BgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABsbG09NTU32urq6/4yMjP9ycnL/Pj4//1BQUf9tbW7/XFxd/z4+P8M+Pj8PAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAExMTTD09PfBzc3P/LCwsvDAwMbVEREX/f3+A/6ioqf9tbW7zPj4/lAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANDQ0vGRkZggAAAAAAAAAAJycnh0NDRP2GhojujIyP4EtLS4k/Pz8YAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjIyRoRUVFq21tbp5TU1ZUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACkpK10AAAAWAAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="));

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.REMOTE; }
		}

		private const string DEFAULT_SERVER_ADDRESS = "127.0.0.1";
		private const uint16 DEFAULT_SERVER_PORT = 27042;

		private Gee.ArrayList<Entry> entries = new Gee.ArrayList<Entry> ();

		public async void close () {
			foreach (var entry in entries)
				yield destroy_entry (entry, SessionDetachReason.APPLICATION_REQUESTED);
			entries.clear ();
		}

		public async HostSession create (string? location = null) throws Error {
			string address;
			try {
				var raw_address = (location != null) ? location : DEFAULT_SERVER_ADDRESS;
				var enumerator = NetworkAddress.parse (raw_address, DEFAULT_SERVER_PORT).enumerate ();
				var socket_address = yield enumerator.next_async ();
				if (socket_address is InetSocketAddress) {
					var inet_socket_address = socket_address as InetSocketAddress;
					var inet_address = inet_socket_address.get_address ();
					var family = (inet_address.get_family () == SocketFamily.IPV6) ? "ipv6" : "ipv4";
					address = "tcp:family=%s,host=%s,port=%hu".printf (family, inet_address.to_string (), inet_socket_address.get_port ());
				} else {
					throw new Error.INVALID_ARGUMENT ("Invalid server address");
				}
			} catch (GLib.Error e) {
				throw new Error.INVALID_ARGUMENT (e.message);
			}

			foreach (var entry in entries) {
				if (entry.address == address)
					throw new Error.INVALID_ARGUMENT ("Invalid server address: already created");
			}

			DBusConnection connection;
			try {
				connection = yield new DBusConnection.for_address (address, DBusConnectionFlags.AUTHENTICATION_CLIENT);
			} catch (GLib.Error e) {
				if (e is IOError.CONNECTION_REFUSED)
					throw new Error.SERVER_NOT_RUNNING ("Unable to connect to remote frida-server");
				else
					throw new Error.SERVER_NOT_RUNNING ("Unable to connect to remote frida-server: " + e.message);
			}

			HostSession host_session;
			try {
				host_session = yield connection.get_proxy (null, ObjectPath.HOST_SESSION);
			} catch (IOError e) {
				throw new Error.PROTOCOL ("Incompatible frida-server version");
			}

			var entry = new Entry (address, connection, host_session);
			entry.agent_session_closed.connect (on_agent_session_closed);
			entries.add (entry);

			connection.on_closed.connect (on_connection_closed);

			return host_session;
		}

		public async void destroy (HostSession host_session) throws Error {
			foreach (var entry in entries) {
				if (entry.host_session == host_session) {
					entries.remove (entry);
					yield destroy_entry (entry, SessionDetachReason.APPLICATION_REQUESTED);
					return;
				}
			}
			throw new Error.INVALID_ARGUMENT ("Invalid host session");
		}

		public async AgentSession obtain_agent_session (HostSession host_session, AgentSessionId agent_session_id) throws Error {
			foreach (var entry in entries) {
				if (entry.host_session == host_session)
					return yield entry.obtain_agent_session (agent_session_id);
			}
			throw new Error.INVALID_ARGUMENT ("Invalid host session");
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
			destroy_entry.begin (entry_to_remove, SessionDetachReason.SERVER_TERMINATED);
		}

		private void on_agent_session_closed (AgentSessionId id, SessionDetachReason reason, string? crash_report) {
			agent_session_closed (id, reason, crash_report);
		}

		private async void destroy_entry (Entry entry, SessionDetachReason reason) {
			entry.connection.on_closed.disconnect (on_connection_closed);
			yield entry.destroy (reason);
			entry.agent_session_closed.disconnect (on_agent_session_closed);
			host_session_closed (entry.host_session);
		}

		private class Entry : Object {
			public signal void agent_session_closed (AgentSessionId id, SessionDetachReason reason, string? crash_report);

			public string address {
				get;
				construct;
			}

			public DBusConnection connection {
				get;
				construct;
			}

			public HostSession host_session {
				get;
				construct;
			}

			private Gee.HashMap<AgentSessionId?, AgentSession> agent_session_by_id = new Gee.HashMap<AgentSessionId?, AgentSession> ();

			public Entry (string address, DBusConnection connection, HostSession host_session) {
				Object (address: address, connection: connection, host_session: host_session);

				host_session.agent_session_destroyed.connect (on_agent_session_destroyed);
				host_session.agent_session_crashed.connect (on_agent_session_crashed);
			}

			public async void destroy (SessionDetachReason reason) {
				host_session.agent_session_crashed.disconnect (on_agent_session_crashed);
				host_session.agent_session_destroyed.disconnect (on_agent_session_destroyed);

				foreach (var agent_session_id in agent_session_by_id.keys)
					agent_session_closed (agent_session_id, reason, null);
				agent_session_by_id.clear ();

				try {
					yield connection.close ();
				} catch (GLib.Error e) {
				}
			}

			public async AgentSession obtain_agent_session (AgentSessionId id) throws Error {
				AgentSession session = agent_session_by_id[id];
				if (session == null) {
					try {
						session = yield connection.get_proxy (null, ObjectPath.from_agent_session_id (id));
						agent_session_by_id[id] = session;
					} catch (IOError proxy_error) {
						throw new Error.INVALID_ARGUMENT (proxy_error.message);
					}
				}
				return session;
			}

			private void on_agent_session_destroyed (AgentSessionId id, SessionDetachReason reason) {
				if (agent_session_by_id.unset (id))
					agent_session_closed (id, reason, null);
			}

			private void on_agent_session_crashed (AgentSessionId id, string crash_report) {
				agent_session_by_id.unset (id);
				agent_session_closed (id, PROCESS_TERMINATED, crash_report);
			}
		}
	}
}

