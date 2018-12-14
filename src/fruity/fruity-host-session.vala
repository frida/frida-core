namespace Frida {
	public class FruityHostSessionBackend : Object, HostSessionBackend {
		private Fruity.Client control_client;
		private Gee.HashMap<uint, FruityHostSessionProvider> provider_by_device_id = new Gee.HashMap<uint, FruityHostSessionProvider> ();
		private Gee.Promise<bool> start_request;
		private StartedHandler started_handler;
		private delegate void StartedHandler ();
		private bool has_probed_protocol_version = false;
		private uint protocol_version = 1;

		public async void start () {
			started_handler = () => start.callback ();
			var timeout_source = new TimeoutSource (100);
			timeout_source.set_callback (() => {
				start.callback ();
				return false;
			});
			timeout_source.attach (MainContext.get_thread_default ());
			do_start.begin ();
			yield;
			started_handler = null;
			timeout_source.destroy ();
		}

		private async void do_start () {
			start_request = new Gee.Promise<bool> ();

			bool success = true;

			control_client = yield create_client ();
			control_client.device_attached.connect ((id, product_id, udid) => {
				if (provider_by_device_id.has_key (id))
					return;

				var provider = new FruityHostSessionProvider (this, id, product_id, udid);
				provider_by_device_id[id] = provider;
				open_provider.begin (provider);
			});
			control_client.device_detached.connect ((id) => {
				if (!provider_by_device_id.has_key (id))
					return;

				FruityHostSessionProvider provider;
				provider_by_device_id.unset (id, out provider);

				if (provider.is_open)
					provider_unavailable (provider);
			});

			try {
				yield control_client.establish ();
				yield control_client.enable_listen_mode ();
			} catch (IOError e) {
				success = false;
			}

			if (success) {
				/* perform a dummy-request to flush out any pending device attach notifications */
				try {
					yield control_client.connect_to_port (uint.MAX, uint.MAX);
					assert_not_reached ();
				} catch (IOError expected_error) {
				}
			}

			start_request.set_value (success);

			if (!success)
				yield stop ();

			if (started_handler != null)
				started_handler ();
		}

		public async void stop () {
			try {
				yield start_request.future.wait_async ();
			} catch (Gee.FutureError e) {
				assert_not_reached ();
			}

			if (control_client != null) {
				try {
					yield control_client.close ();
				} catch (IOError e) {
				}
				control_client = null;
			}

			foreach (var provider in provider_by_device_id.values) {
				if (provider.is_open)
					provider_unavailable (provider);
				yield provider.close ();
			}
			provider_by_device_id.clear ();
		}

		public async Fruity.Client create_client () {
			if (!has_probed_protocol_version) {
				bool service_is_present = false;

				var client = new Fruity.ClientV1 ();
				try {
					yield client.establish ();
					service_is_present = true;
				} catch (IOError establish_error) {
				}

				if (service_is_present) {
					try {
						yield client.enable_listen_mode ();
						protocol_version = 1;
					} catch (IOError listen_error) {
						protocol_version = 2;
					}

					has_probed_protocol_version = true;
				}
			}

			if (protocol_version == 1)
				return new Fruity.ClientV1 ();
			else
				return new Fruity.ClientV2 ();
		}

		private async void open_provider (FruityHostSessionProvider provider) {
			try {
				yield provider.open ();

				provider_available (provider);
			} catch (Error e) {
				provider_by_device_id.unset (provider.device_id);
			}
		}
	}

	public class FruityHostSessionProvider : Object, HostSessionProvider {
		public string id {
			get { return device_udid; }
		}

		public string name {
			get { return _name; }
		}
		private string _name = "iOS Device";

		public Image? icon {
			get { return _icon; }
		}
		private Image? _icon = null;

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.USB; }
		}

		public FruityHostSessionBackend backend {
			get;
			construct;
		}

		public uint device_id {
			get;
			construct;
		}

		public int device_product_id {
			get;
			construct;
		}

		public string device_udid {
			get;
			construct;
		}

		public bool is_open {
			get;
			private set;
		}

		private Gee.ArrayList<Entry> entries = new Gee.ArrayList<Entry> ();

		private const uint DEFAULT_SERVER_PORT = 27042;

		public FruityHostSessionProvider (FruityHostSessionBackend backend, uint device_id, int device_product_id, string device_udid) {
			Object (backend: backend, device_id: device_id, device_product_id: device_product_id, device_udid: device_udid);
		}

		public async void open () throws Error {
			bool got_details = false;
			for (int i = 1; !got_details; i++) {
				try {
					ImageData? icon_data;
					_extract_details_for_device (device_product_id, device_udid, out _name, out icon_data);
					_icon = Image.from_data (icon_data);
					got_details = true;
				} catch (Error e) {
					if (i != 60) {
						var source = new TimeoutSource.seconds (1);
						source.set_callback (() => {
							open.callback ();
							return false;
						});
						source.attach (MainContext.get_thread_default ());
						yield;
					} else {
						break;
					}
				}
			}

			if (!got_details)
				throw new Error.TIMED_OUT ("Timed out while waiting for USB device to appear");

			is_open = true;
		}

		public async void close () {
			foreach (var entry in entries)
				yield destroy_entry (entry, SessionDetachReason.APPLICATION_REQUESTED);
			entries.clear ();
		}

		public async HostSession create (string? location = null) throws Error {
			uint port = (location != null) ? (uint) int.parse (location) : DEFAULT_SERVER_PORT;
			foreach (var entry in entries) {
				if (entry.port == port)
					throw new Error.INVALID_ARGUMENT ("Invalid location: already created");
			}

			Fruity.Client client = yield backend.create_client ();
			DBusConnection connection;
			try {
				yield client.establish ();
				yield client.connect_to_port (device_id, port);
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

		public extern static void _extract_details_for_device (int product_id, string udid, out string name, out ImageData? icon) throws Error;

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

			public uint port {
				get;
				construct;
			}

			public Fruity.Client client {
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

			public Entry (uint port, Fruity.Client client, DBusConnection connection, HostSession host_session) {
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
