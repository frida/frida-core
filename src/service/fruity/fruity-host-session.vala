namespace Zed.Service {
	public class FruityHostSessionBackend : Object, HostSessionBackend {
		private Fruity.Client control_client;
		private Gee.HashMap<uint, FruityHostSessionProvider> provider_by_device_id = new Gee.HashMap<uint, FruityHostSessionProvider> ();

		public async void start () {
			control_client = new Fruity.Client ();
			control_client.device_connected.connect ((device_id, device_udid) => {
				if (provider_by_device_id.has_key (device_id))
					return;

				var provider = new FruityHostSessionProvider (device_id, device_udid);
				provider_by_device_id[device_id] = provider;
				open_provider (provider);
			});
			control_client.device_disconnected.connect ((device_id) => {
				if (!provider_by_device_id.has_key (device_id))
					return;

				FruityHostSessionProvider provider;
				provider_by_device_id.unset (device_id, out provider);

				if (provider.is_open)
					provider_unavailable (provider);
			});

			try {
				yield control_client.establish ();
				yield control_client.enable_monitor_mode ();
			} catch (Error e) {
				debug ("failed to establish: %s", e.message);
			}
		}

		public async void stop () {
			try {
				yield control_client.close ();
			} catch (IOError e) {
			}
			control_client = null;

			foreach (var provider in provider_by_device_id.values) {
				if (provider.is_open)
					provider_unavailable (provider);
				yield provider.close ();
			}
			provider_by_device_id.clear ();
		}

		private async void open_provider (FruityHostSessionProvider provider) {
			try {
				yield provider.open ();

				provider_available (provider);
			} catch (IOError e) {
				provider_by_device_id.unset (provider.device_id);
			}
		}
	}

	public class FruityHostSessionProvider : Object, HostSessionProvider {
		public string name {
			get { return _name; }
		}
		private string _name = "Apple Mobile Device";

		public ImageData? icon {
			get { return _icon; }
		}
		private ImageData? _icon = null;

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.LOCAL_TETHER; }
		}

		public uint device_id {
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

		private const uint ZID_SERVER_PORT = 27042;

		public FruityHostSessionProvider (uint device_id, string device_udid) {
			Object (device_id: device_id, device_udid: device_udid);
		}

		public async void open () throws IOError {
			bool got_details = false;
			for (int i = 0; !got_details; i++) {
				try {
					_extract_details_for_device_with_udid (device_udid, out _name, out _icon);
					got_details = true;
				} catch (IOError e) {
					if (i != 60 - 1) {
						Timeout.add (1000, () => {
							open.callback ();
							return false;
						});
						yield;
					} else {
						break;
					}
				}
			}

			if (!got_details)
				throw new IOError.TIMED_OUT ("timed out");

			is_open = true;
		}

		public async void close () {
			foreach (var entry in entries) {
				try {
					yield entry.connection.close ();
				} catch (IOError first_close_error) {
				}

				/* FIXME: close again to make sure things are shut down, needs further investigation */
				try {
					yield entry.connection.close ();
				} catch (IOError second_close_error) {
				}

				try {
					yield entry.client.close ();
				} catch (IOError client_error) {
				}
			}
			entries.clear ();
		}

		public async HostSession create () throws IOError {
			var client = new Fruity.Client ();
			yield client.establish ();
			yield client.connect_to_port (device_id, ZID_SERVER_PORT);

			DBusConnection connection;
			try {
				connection = yield DBusConnection.new_for_stream (client.connection, null, DBusConnectionFlags.AUTHENTICATION_CLIENT);
			} catch (Error e) {
				throw new IOError.FAILED (e.message);
			}

			HostSession session = connection.get_proxy_sync (null, ObjectPath.HOST_SESSION);

			var entry = new Entry (0, client, connection, session);
			entries.add (entry);

			connection.closed.connect (on_connection_closed);

			return session;
		}

		public async AgentSession obtain_agent_session (AgentSessionId id) throws IOError {
			Fruity.Client client = null;

			bool connected = false;
			for (int i = 0; !connected; i++) {
				client = new Fruity.Client ();
				yield client.establish ();

				try {
					yield client.connect_to_port (device_id, id.handle);
					connected = true;
				} catch (IOError client_error) {
					if (i != 10 - 1) {
						Timeout.add (200, () => {
							obtain_agent_session.callback ();
							return false;
						});
						yield;
					} else {
						break;
					}
				}
			}

			if (!connected)
				throw new IOError.TIMED_OUT ("timed out");

			DBusConnection connection;
			try {
				connection = yield DBusConnection.new_for_stream (client.connection, null, DBusConnectionFlags.AUTHENTICATION_CLIENT);
			} catch (Error dbus_error) {
				throw new IOError.FAILED (dbus_error.message);
			}

			AgentSession session = connection.get_proxy_sync (null, ObjectPath.AGENT_SESSION);

			var entry = new Entry (id.handle, client, connection, session);
			entries.add (entry);

			connection.closed.connect (on_connection_closed);

			return session;
		}

		public static extern void _extract_details_for_device_with_udid (string udid, out string name, out ImageData? icon) throws IOError;

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

			public Fruity.Client client {
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

			public Entry (uint id, Fruity.Client client, DBusConnection connection, Object proxy) {
				this.id = id;
				this.client = client;
				this.connection = connection;
				this.proxy = proxy;
			}
		}
	}
}