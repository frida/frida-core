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

		private const uint SERVER_PORT = 27042;

		public FruityHostSessionProvider (FruityHostSessionBackend backend, uint device_id, int device_product_id, string device_udid) {
			Object (backend: backend, device_id: device_id, device_product_id: device_product_id, device_udid: device_udid);
		}

		public async void open () throws Error {
			bool got_details = false;
			for (int i = 1; !got_details; i++) {
				try {
					_extract_details_for_device (device_product_id, device_udid, out _name, out _icon);
					got_details = true;
				} catch (Error e) {
					if (i != 60) {
						var source = new TimeoutSource (1000);
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
				yield entry.close ();
			entries.clear ();
		}

		public async HostSession create () throws Error {
			Fruity.Client client = yield backend.create_client ();
			DBusConnection connection;
			try {
				yield client.establish ();
				yield client.connect_to_port (device_id, SERVER_PORT);
				connection = yield DBusConnection.new (client.connection, null, DBusConnectionFlags.AUTHENTICATION_CLIENT);
			} catch (GLib.Error connection_error) {
				throw new Error.SERVER_NOT_RUNNING (connection_error.message);
			}

			HostSession session;
			try {
				session = yield connection.get_proxy (null, ObjectPath.HOST_SESSION);
			} catch (IOError proxy_error) {
				throw new Error.PROTOCOL (proxy_error.message);
			}

			var entry = new Entry (0, client, connection, session);
			entries.add (entry);

			connection.closed.connect (on_connection_closed);

			return session;
		}

		public async AgentSession obtain_agent_session (AgentSessionId id) throws Error {
			Fruity.Client client = yield backend.create_client ();
			DBusConnection connection;
			try {
				yield client.establish ();
				yield client.connect_to_port (device_id, id.handle);
				connection = yield DBusConnection.new (client.connection, null, DBusConnectionFlags.AUTHENTICATION_CLIENT);
			} catch (GLib.Error connection_error) {
				throw new Error.PROCESS_NOT_RESPONDING (connection_error.message);
			}

			AgentSession session;
			try {
				session = yield connection.get_proxy (null, ObjectPath.AGENT_SESSION);
			} catch (IOError proxy_error) {
				throw new Error.PROTOCOL (proxy_error.message);
			}

			var entry = new Entry (id.handle, client, connection, session);
			entries.add (entry);

			connection.closed.connect (on_connection_closed);

			return session;
		}

		public static extern void _extract_details_for_device (int product_id, string udid, out string name, out ImageData? icon) throws Error;

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

			if (entry_to_remove.id != 0) {
				/* otherwise it's a HostSession */
				Error e = null;
				if (error != null)
					e = new Error.PROCESS_GONE (error.message);
				agent_session_closed (AgentSessionId (entry_to_remove.id), e);
			}
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

			public async void close () {
				proxy = null;

				try {
					yield connection.close ();
				} catch (GLib.Error conn_error) {
				}
				connection = null;

				try {
					yield client.close ();
				} catch (IOError client_error) {
				}
				client = null;
			}
		}
	}
}
