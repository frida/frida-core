namespace Frida {
	public class DroidyHostSessionBackend : Object, HostSessionBackend {
		private Droidy.DeviceTracker tracker = new Droidy.DeviceTracker ();
		private Gee.HashMap<string, DroidyHostSessionProvider> provider_by_serial = new Gee.HashMap<string, DroidyHostSessionProvider> ();

		public async void start () {
			tracker.device_attached.connect ((serial, name) => {
				var provider = new DroidyHostSessionProvider (this, serial, name);
				provider_by_serial[serial] = provider;
				provider_available (provider);
			});
			tracker.device_detached.connect ((serial) => {
				DroidyHostSessionProvider provider;
				provider_by_serial.unset (serial, out provider);
				provider_unavailable (provider);
			});

			try {
				yield tracker.open ();
			} catch (Error e) {
				stderr.printf ("ERROR: %s\n", e.message);
			}
		}

		public async void stop () {
			yield tracker.close ();

			foreach (var provider in provider_by_serial.values) {
				provider_unavailable (provider);
				yield provider.close ();
			}
			provider_by_serial.clear ();
		}
	}

	public class DroidyHostSessionProvider : Object, HostSessionProvider {
		public string id {
			get { return device_serial; }
		}

		public string name {
			get { return device_name; }
		}

		public ImageData? icon {
			get { return _icon; }
		}
		private ImageData? _icon = ImageData (16, 16, 16 * 4, "AAAAAAAAAAAAAAAAOjo6Dzo6OhQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOjo6TZCHbvlycnL4Ojo6iTo6OhMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOjo6aa6fdv7878f/+/Te/93d3f9xcXH3Ojo6gTo6Og8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOjo6F4KAfv//5Hn//fHK//r6+v/39/f/9/f3/9LS0v9kZGTzOjo6eDo6OgsAAAAAAAAAAAAAAAAAAAAAAAAAADo6Og6Tk5P/zc3N//z8/P/6+vr/8PDw/+7u7v/p6en/9PT0/8jIyP9XV1f2Ojo6SgAAAAAAAAAAAAAAAAAAAAA6OjoIb29v/8HBwf+5ubn/9/f3/+/v7//p6en/+Pj4/+np6f/o6Oj/4ODg/z09PcsAAAAAAAAAAAAAAAAAAAAAAAAAAjMzM1p8fHz/wsLC/7CwsP/x8fH/8/P0/9zc3f/09PT/+vr6/8vLy/9AQEDFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALS0tV2pqav7BwcH/rq6u/+bm5v/09PT/s7Oz/93d3f/R0dL/VVVVygAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjIyNRWlpa+7+/v/+wsLD/oaGh/4iIiP9NTU7/VVVW/0BAQf89PT61Pj4/BgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABsbG09NTU32urq6/4yMjP9ycnL/Pj4//1BQUf9tbW7/XFxd/z4+P8M+Pj8PAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAExMTTD09PfBzc3P/LCwsvDAwMbVEREX/f3+A/6ioqf9tbW7zPj4/lAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANDQ0vGRkZggAAAAAAAAAAJycnh0NDRP2GhojujIyP4EtLS4k/Pz8YAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjIyRoRUVFq21tbp5TU1ZUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACkpK10AAAAWAAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==");

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.LOCAL_TETHER; }
		}

		public DroidyHostSessionBackend backend {
			get;
			construct;
		}

		public string device_serial {
			get;
			construct;
		}

		public string device_name {
			get;
			construct;
		}

		private Gee.ArrayList<Entry> entries = new Gee.ArrayList<Entry> ();

		private const uint DEFAULT_SERVER_PORT = 27042;

		public DroidyHostSessionProvider (DroidyHostSessionBackend backend, string device_serial, string device_name) {
			Object (backend: backend, device_serial: device_serial, device_name: device_name);
		}

		public async void close () {
			foreach (var entry in entries)
				yield destroy_entry (entry);
			entries.clear ();
		}

		public async HostSession create (string? location = null) throws Error {
			uint port = (location != null) ? (uint) int.parse (location) : DEFAULT_SERVER_PORT;
			foreach (var entry in entries) {
				if (entry.port == port)
					throw new Error.INVALID_ARGUMENT ("Invalid location: already created");
			}

			Droidy.Client client = new Droidy.Client ();
			DBusConnection connection;
			try {
				yield client.request ("host:transport:" + device_serial);
				yield client.request_protocol_change ("tcp:%u".printf (port));
				connection = yield DBusConnection.new (client.connection, null, DBusConnectionFlags.AUTHENTICATION_CLIENT);
			} catch (GLib.Error e) {
				client.close.begin ();
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

			connection.closed.connect (on_connection_closed);

			return session;
		}

		public async void destroy (HostSession host_session) throws Error {
			foreach (var entry in entries) {
				if (entry.host_session == host_session) {
					entries.remove (entry);
					yield destroy_entry (entry);
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
			destroy_entry.begin (entry_to_remove);
		}

		private void on_agent_session_closed (AgentSessionId id) {
			agent_session_closed (id);
		}

		private async void destroy_entry (Entry entry) {
			yield entry.destroy ();
			entry.agent_session_closed.disconnect (on_agent_session_closed);
		}

		private class Entry : Object {
			public signal void agent_session_closed (AgentSessionId id);

			public uint port {
				get;
				construct;
			}

			public Droidy.Client client {
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

			public Entry (uint port, Droidy.Client client, DBusConnection connection, HostSession host_session) {
				Object (port: port, client: client, connection: connection, host_session: host_session);

				host_session.agent_session_destroyed.connect (on_agent_session_destroyed);
			}

			public async void destroy () {
				host_session.agent_session_destroyed.disconnect (on_agent_session_destroyed);

				foreach (var agent_session_id in agent_session_by_id.keys)
					agent_session_closed (agent_session_id);
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

			private void on_agent_session_destroyed (AgentSessionId id) {
				agent_session_by_id.unset (id);
				agent_session_closed (id);
			}
		}
	}
}
