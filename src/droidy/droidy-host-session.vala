namespace Frida {
	public class DroidyHostSessionBackend : Object, HostSessionBackend {
		private Droidy.DeviceTracker tracker;
		private Gee.HashMap<string, DroidyHostSessionProvider> provider_by_serial = new Gee.HashMap<string, DroidyHostSessionProvider> ();

		private Promise<bool> start_request;
		private Cancellable start_cancellable;
		private SourceFunc on_start_completed;

		public async void start (Cancellable? cancellable) throws IOError {
			start_request = new Promise<bool> ();
			start_cancellable = new Cancellable ();
			on_start_completed = start.callback;

			var main_context = MainContext.get_thread_default ();

			var timeout_source = new TimeoutSource (500);
			timeout_source.set_callback (start.callback);
			timeout_source.attach (main_context);

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (start.callback);
			cancel_source.attach (main_context);

			do_start.begin ();

			yield;

			cancel_source.destroy ();
			timeout_source.destroy ();
			on_start_completed = null;
		}

		private async void do_start () {
			bool success = true;

			tracker = new Droidy.DeviceTracker ();
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
				yield tracker.open (start_cancellable);
			} catch (GLib.Error e) {
				success = false;
			}

			start_request.resolve (success);

			if (on_start_completed != null)
				on_start_completed ();
		}

		public async void stop (Cancellable? cancellable) throws IOError {
			start_cancellable.cancel ();

			try {
				yield start_request.future.wait_async (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}

			if (tracker != null) {
				yield tracker.close (cancellable);
				tracker = null;
			}

			foreach (var provider in provider_by_serial.values) {
				provider_unavailable (provider);
				yield provider.close (cancellable);
			}
			provider_by_serial.clear ();
		}
	}

	public class DroidyHostSessionProvider : Object, HostSessionProvider, ChannelProvider {
		public string id {
			get { return device_serial; }
		}

		public string name {
			get { return device_name; }
		}

		public Image? icon {
			get { return _icon; }
		}
		private Image _icon = new Image (ImageData (16, 16, 16 * 4, "AAAAAAAAAAAAAAAAAAAAAP///0DS4pz/////MP///0D///9A////MNflqP////9AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD///8QzN6Q/7vTa/+vy1L/r8tS/7vTa//O4JXv////EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1eSkz6TEOf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/9XkpM8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8vfjcKrIRf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/6TEOf+qyEX/8PXeYAAAAAAAAAAAAAAAAAAAAAAAAAAA////QNLinL+kxDn/pMQ5/6TEOf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/97qt6////9AAAAAAAAAAAAAAAAA2eatv7vTa//G2oP/pMQ5/6TEOf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/6TEOf/M3pD/u9Nr/9nmrb8AAAAAAAAAANLinP+kxDn/u9Nr/6TEOf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/6TEOf+kxDn/u9Nr/6TEOf/S4pz/AAAAAAAAAADS4pz/pMQ5/7vTa/+kxDn/pMQ5/6TEOf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/7vTa/+kxDn/0uKc/wAAAAAAAAAA0uKc/6TEOf+702v/pMQ5/6TEOf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/6TEOf+702v/pMQ5/9LinP8AAAAAAAAAANLinP+kxDn/u9Nr/6TEOf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/6TEOf+kxDn/u9Nr/6TEOf/S4pz/AAAAAAAAAADO4JXvpMQ5/8DWd/+kxDn/pMQ5/6TEOf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/8DWd/+kxDn/zuCV7wAAAAAAAAAA7fPXUNLinIDl7sbfpMQ5/6TEOf+kxDn/pMQ5/6TEOf+kxDn/pMQ5/6TEOf/l7sbf0uKcgO3z11AAAAAAAAAAAAAAAAAAAAAA8PXeYMDWd/+qyEX/pMQ5/6/LUv+vy1L/pMQ5/6rIRf/A1nf/7fPXUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAu9Nr/6TEOf/C2Hu/wth7v6TEOf+702v/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALvTa/+kxDn/wth7v8LYe7+kxDn/u9Nr/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADc6LPPu9Nr/+HrvY/h672Pu9Nr/9nmrb8AAAAAAAAAAAAAAAAAAAAAAAAAAA=="));

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.USB; }
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
		private Cancellable io_cancellable = new Cancellable ();

		private const uint16 DEFAULT_SERVER_PORT = 27042;

		public DroidyHostSessionProvider (DroidyHostSessionBackend backend, string device_serial, string device_name) {
			Object (backend: backend, device_serial: device_serial, device_name: device_name);
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

			Droidy.Client client = null;
			DBusConnection connection;
			try {
				client = yield Droidy.Client.open (cancellable);
				yield client.request ("host:transport:" + device_serial, cancellable);
				yield client.request_protocol_change ("tcp:%u".printf (port), cancellable);

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

			TransportBroker transport_broker = yield connection.get_proxy (null, ObjectPath.TRANSPORT_BROKER,
				DBusProxyFlags.NONE, cancellable);

			var entry = new Entry (port, client, connection, session, transport_broker);
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
					return yield entry.obtain_agent_session (agent_session_id, this, cancellable);
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
			if (address.contains (":")) {
				Droidy.Client client = null;
				try {
					client = yield Droidy.Client.open (cancellable);
					yield client.request ("host:transport:" + device_serial, cancellable);
					yield client.request_protocol_change (address, cancellable);
					return client.connection;
				} catch (GLib.Error e) {
					if (client != null)
						client.close.begin ();

					throw new Error.TRANSPORT ("%s", e.message);
				}
			}

			throw new Error.NOT_SUPPORTED ("Unsupported channel address");
		}

		private class Entry : Object {
			public signal void agent_session_closed (AgentSessionId id, SessionDetachReason reason, CrashInfo? crash);

			public uint16 port {
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

			public TransportBroker? transport_broker {
				get;
				set;
			}

			private Gee.HashMap<AgentSessionId?, AgentSession> agent_session_by_id =
				new Gee.HashMap<AgentSessionId?, AgentSession> (AgentSessionId.hash, AgentSessionId.equal);

			public Entry (uint16 port, Droidy.Client client, DBusConnection connection, HostSession host_session,
					TransportBroker transport_broker) {
				Object (
					port: port,
					client: client,
					connection: connection,
					host_session: host_session,
					transport_broker: transport_broker
				);

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

			public async AgentSession obtain_agent_session (AgentSessionId id, ChannelProvider channel_provider,
					Cancellable? cancellable) throws Error, IOError {
				AgentSession session = agent_session_by_id[id];
				if (session == null) {
					try {
						session = yield connection.get_proxy (null, ObjectPath.from_agent_session_id (id),
							DBusProxyFlags.NONE, cancellable);
						agent_session_by_id[id] = session;
					} catch (IOError e) {
						throw new Error.INVALID_ARGUMENT ("%s", e.message);
					}

					if (transport_broker != null) {
						try {
							session = yield establish_direct_session (transport_broker, id, channel_provider,
								cancellable);
							agent_session_by_id[id] = session;
						} catch (Error e) {
							if (e is Error.NOT_SUPPORTED)
								transport_broker = null;
						}
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
