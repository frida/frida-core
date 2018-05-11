namespace Frida {
	public class FruityRemoteProvider : Object, HostSessionProvider {
		public string id {
			get { return device_details.udid.raw_value; }
		}

		public string name {
			get { return device_name; }
		}

		public Image? icon {
			get { return device_icon; }
		}

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.USB; }
		}

		public string device_name {
			get;
			construct;
		}

		public Image? device_icon {
			get;
			construct;
		}

		public Fruity.DeviceDetails device_details {
			get;
			construct;
		}

		private Gee.HashSet<Entry> entries = new Gee.HashSet<Entry> ();

		private const uint16 DEFAULT_SERVER_PORT = 27042;

		public FruityRemoteProvider (string name, Image? icon, Fruity.DeviceDetails details) {
			Object (
				device_name: name,
				device_icon: icon,
				device_details: details
			);
		}

		public async void close () {
			while (!entries.is_empty) {
				var iterator = entries.iterator ();
				iterator.next ();
				var entry = iterator.get ();

				entries.remove (entry);

				yield destroy_entry (entry, SessionDetachReason.APPLICATION_REQUESTED);
			}
		}

		public async HostSession create (string? location = null) throws Error {
			uint16 port = (location != null) ? (uint16) int.parse (location) : DEFAULT_SERVER_PORT;
			foreach (var entry in entries) {
				if (entry.port == port)
					throw new Error.INVALID_ARGUMENT ("Invalid location: already created");
			}

			Fruity.UsbmuxClient client;
			DBusConnection connection;
			try {
				client = yield Fruity.UsbmuxClient.open ();
				yield client.connect_to_port (device_details.id, port);
				connection = yield new DBusConnection (client.connection, null, DBusConnectionFlags.AUTHENTICATION_CLIENT);
			} catch (GLib.Error e) {
				if (e is IOError.CONNECTION_REFUSED)
					throw new Error.SERVER_NOT_RUNNING ("Unable to connect to remote frida-server");
				else
					throw new Error.SERVER_NOT_RUNNING ("Unable to connect to remote frida-server: " + e.message);
			}

			HostSession session;
			try {
				session = yield connection.get_proxy (null, ObjectPath.HOST_SESSION);
			} catch (IOError e) {
				throw new Error.PROTOCOL ("Incompatible frida-server version");
			}

			var entry = new Entry (port, client, connection, session);
			entry.agent_session_closed.connect (on_agent_session_closed);
			entries.add (entry);

			connection.on_closed.connect (on_connection_closed);

			return session;
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

		private void on_agent_session_closed (AgentSessionId id, SessionDetachReason reason, CrashInfo? crash) {
			agent_session_closed (id, reason, crash);
		}

		private async void destroy_entry (Entry entry, SessionDetachReason reason) {
			entry.connection.on_closed.disconnect (on_connection_closed);
			yield entry.destroy (reason);
			entry.agent_session_closed.disconnect (on_agent_session_closed);
			host_session_closed (entry.host_session);
		}

		private class Entry : Object {
			public signal void agent_session_closed (AgentSessionId id, SessionDetachReason reason, CrashInfo? crash);

			public uint16 port {
				get;
				construct;
			}

			public Fruity.UsbmuxClient client {
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

			private Gee.HashMap<AgentSessionId?, AgentSession> agent_session_by_id =
				new Gee.HashMap<AgentSessionId?, AgentSession> (AgentSessionId.hash, AgentSessionId.equal);

			public Entry (uint16 port, Fruity.UsbmuxClient client, DBusConnection connection, HostSession host_session) {
				Object (port: port, client: client, connection: connection, host_session: host_session);

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

			private void on_agent_session_crashed (AgentSessionId id, CrashInfo crash) {
				agent_session_by_id.unset (id);
				agent_session_closed (id, PROCESS_TERMINATED, crash);
			}
		}
	}
}
