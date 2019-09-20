namespace Frida {
	public class FruityRemoteProvider : Object, HostSessionProvider, ChannelProvider {
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
		private Cancellable io_cancellable = new Cancellable ();

		private Promise<Fruity.LockdownClient>? lockdown_client_request;

		private const uint16 DEFAULT_SERVER_PORT = 27042;

		public FruityRemoteProvider (string name, Image? icon, Fruity.DeviceDetails details) {
			Object (
				device_name: name,
				device_icon: icon,
				device_details: details
			);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			while (!entries.is_empty) {
				var iterator = entries.iterator ();
				iterator.next ();
				var entry = iterator.get ();

				entries.remove (entry);

				yield destroy_entry (entry, APPLICATION_REQUESTED, cancellable);
			}

			io_cancellable.cancel ();
		}

		public async HostSession create (string? location, Cancellable? cancellable) throws Error, IOError {
			uint16 port = (location != null) ? (uint16) int.parse (location) : DEFAULT_SERVER_PORT;
			foreach (var entry in entries) {
				if (entry.port == port)
					throw new Error.INVALID_ARGUMENT ("Invalid location: already created");
			}

			Fruity.UsbmuxClient client = null;
			DBusConnection connection;
			try {
				client = yield Fruity.UsbmuxClient.open (cancellable);
				yield client.connect_to_port (device_details.id, port, cancellable);

				connection = yield new DBusConnection (client.connection, null, AUTHENTICATION_CLIENT, null, cancellable);
			} catch (GLib.Error e) {
				if (client != null)
					client.close.begin ();

				if (e is IOError.CONNECTION_REFUSED)
					throw new Error.SERVER_NOT_RUNNING ("Unable to connect to remote frida-server");
				else
					throw new Error.SERVER_NOT_RUNNING ("Unable to connect to remote frida-server: %s", e.message);
			}

			HostSession session;
			try {
				session = yield connection.get_proxy (null, ObjectPath.HOST_SESSION, DBusProxyFlags.NONE, cancellable);
			} catch (IOError e) {
				throw new Error.PROTOCOL ("Incompatible frida-server version");
			}

			var entry = new Entry (port, client, connection, session);
			entry.agent_session_closed.connect (on_agent_session_closed);
			entries.add (entry);

			connection.on_closed.connect (on_connection_closed);

			return session;
		}

		public async void destroy (HostSession host_session, Cancellable? cancellable) throws Error, IOError {
			foreach (var entry in entries) {
				if (entry.host_session == host_session) {
					entries.remove (entry);
					yield destroy_entry (entry, APPLICATION_REQUESTED, cancellable);
					return;
				}
			}
			throw new Error.INVALID_ARGUMENT ("Invalid host session");
		}

		public async AgentSession obtain_agent_session (HostSession host_session, AgentSessionId agent_session_id,
				Cancellable? cancellable) throws Error, IOError {
			foreach (var entry in entries) {
				if (entry.host_session == host_session)
					return yield entry.obtain_agent_session (agent_session_id, cancellable);
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
			destroy_entry.begin (entry_to_remove, SERVER_TERMINATED, io_cancellable);
		}

		private void on_agent_session_closed (AgentSessionId id, SessionDetachReason reason, CrashInfo? crash) {
			agent_session_closed (id, reason, crash);
		}

		private async void destroy_entry (Entry entry, SessionDetachReason reason, Cancellable? cancellable) throws IOError {
			entry.connection.on_closed.disconnect (on_connection_closed);
			yield entry.destroy (reason, cancellable);
			entry.agent_session_closed.disconnect (on_agent_session_closed);
			host_session_closed (entry.host_session);
		}

		public async IOStream open_channel (string address, Cancellable? cancellable = null) throws Error, IOError {
			if (address.has_prefix ("tcp:")) {
				ulong raw_port;
				if (!ulong.try_parse (address.substring (4), out raw_port) || raw_port == 0 || raw_port > uint16.MAX)
					throw new Error.INVALID_ARGUMENT ("Invalid TCP port");
				uint16 port = (uint16) raw_port;

				Fruity.UsbmuxClient client = null;
				try {
					client = yield Fruity.UsbmuxClient.open (cancellable);

					yield client.connect_to_port (device_details.id, port, cancellable);

					return client.connection;
				} catch (GLib.Error e) {
					if (client != null)
						client.close.begin ();

					throw new Error.TRANSPORT ("%s", e.message);
				}
			}

			if (address.has_prefix ("lockdown:")) {
				string service_name = address.substring (9);

				var client = yield get_lockdown_client (cancellable);

				try {
					return yield client.start_service (service_name, cancellable);
				} catch (GLib.Error e) {
					throw new Error.TRANSPORT ("%s", e.message);
				}
			}

			throw new Error.NOT_SUPPORTED ("Unsupported channel address");
		}

		private async Fruity.LockdownClient get_lockdown_client (Cancellable? cancellable) throws Error, IOError {
			while (lockdown_client_request != null) {
				try {
					return yield lockdown_client_request.future.wait_async (cancellable);
				} catch (Error e) {
					throw e;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}
			lockdown_client_request = new Promise<Fruity.LockdownClient> ();

			try {
				var client = yield Fruity.LockdownClient.open (device_details, cancellable);

				lockdown_client_request.resolve (client);

				return client;
			} catch (GLib.Error e) {
				var api_error = new Error.NOT_SUPPORTED ("%s", e.message);

				lockdown_client_request.reject (api_error);
				lockdown_client_request = null;

				throw_api_error (api_error);
			}
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

			public async void destroy (SessionDetachReason reason, Cancellable? cancellable) throws IOError {
				host_session.agent_session_crashed.disconnect (on_agent_session_crashed);
				host_session.agent_session_destroyed.disconnect (on_agent_session_destroyed);

				foreach (var agent_session_id in agent_session_by_id.keys)
					agent_session_closed (agent_session_id, reason, null);
				agent_session_by_id.clear ();

				try {
					yield connection.close (cancellable);
				} catch (GLib.Error e) {
				}
			}

			public async AgentSession obtain_agent_session (AgentSessionId id, Cancellable? cancellable) throws Error, IOError {
				AgentSession session = agent_session_by_id[id];
				if (session == null) {
					try {
						session = yield connection.get_proxy (null, ObjectPath.from_agent_session_id (id),
							DBusProxyFlags.NONE, cancellable);
						agent_session_by_id[id] = session;
					} catch (IOError e) {
						throw new Error.INVALID_ARGUMENT ("%s", e.message);
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
