namespace Zed.Service {
	public class FruityHostSessionBackend : Object, HostSessionBackend {
		private Fruity.Client control_client;
		private Gee.HashMap<uint, FruityHostSessionProvider> provider_by_device_id = new Gee.HashMap<uint, FruityHostSessionProvider> ();

		public async void start () {
			control_client = new Fruity.Client ();
			control_client.device_connected.connect ((device_id) => {
				if (provider_by_device_id.has_key (device_id))
					return;

				var provider = new FruityHostSessionProvider (device_id);
				provider_by_device_id[device_id] = provider;

				provider_available (provider);
			});
			control_client.device_disconnected.connect ((device_id) => {
				if (!provider_by_device_id.has_key (device_id))
					return;

				FruityHostSessionProvider provider;
				provider_by_device_id.unset (device_id, out provider);
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
		}
	}

	public class FruityHostSessionProvider : Object, HostSessionProvider {
		public string name {
			get { return "Apple Mobile Device"; }
		}

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.LOCAL_TETHER; }
		}

		public uint device_id {
			get;
			construct;
		}

		private Gee.ArrayList<Entry> entries = new Gee.ArrayList<Entry> ();

		private const uint ZID_SERVER_PORT = 27042;

		public FruityHostSessionProvider (uint device_id) {
			Object (device_id: device_id);
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

			HostSession session = Bus.get_proxy_for_connection_sync (connection, null, ObjectPath.HOST_SESSION);

			var entry = new Entry (client, connection, session);
			entries.add (entry);

			return entry.session;
		}

		public async AgentSession obtain_agent_session (AgentSessionId id) throws IOError {
			throw new IOError.FAILED ("not yet implemented");
		}

		private class Entry {
			public Fruity.Client client {
				get;
				private set;
			}

			public DBusConnection connection {
				get;
				private set;
			}

			public HostSession session {
				get;
				private set;
			}

			public Entry (Fruity.Client client, DBusConnection connection, HostSession session) {
				this.client = client;
				this.connection = connection;
				this.session = session;
			}
		}
	}

	namespace Fruity {
		public class Client : Object {
			public SocketConnection connection {
				get;
				private set;
			}
			private InputStream input;
			private OutputStream output;

			private bool running;
			private uint last_tag;
			private uint mode_switch_tag;
			private Gee.ArrayList<PendingResponse> pending_responses;

			private const uint16 USBMUX_SERVER_PORT = 27015;

			public signal void device_connected (uint device_id);
			public signal void device_disconnected (uint device_id);

			public Client () {
				reset ();
			}

			private void reset () {
				connection = null;
				input = null;
				output = null;

				running = false;
				last_tag = 1;
				mode_switch_tag = 0;
				pending_responses = new Gee.ArrayList<PendingResponse> ();
			}

			public async void establish () throws IOError {
				assert (!running);

				var client = new SocketClient ();

				try {
					connection = yield client.connect_to_host_async ("127.0.0.1", USBMUX_SERVER_PORT);
					input = connection.get_input_stream ();
					output = connection.get_output_stream ();

					running = true;

					process_incoming_messages ();
				} catch (Error e) {
					reset ();
					throw new IOError.FAILED (e.message);
				}
			}

			public async void enable_monitor_mode () throws Error {
				assert (running);

				var result = yield send_request_and_receive_response (MessageType.HELLO);
				if (result != ResultCode.SUCCESS)
					throw new IOError.FAILED ("handshake failed, result %d", result);
			}

			public async void connect_to_port (uint device_id, uint port) throws IOError {
				assert (running);

				uint8[] connect_body = new uint8[8];

				uint32 * p = (void *) connect_body;
				p[0] = device_id.to_little_endian ();
				p[1] = ((uint32) port << 16).to_big_endian ();

				try {
					int result = yield send_request_and_receive_response (MessageType.CONNECT, connect_body, true);
					switch (result) {
						case ResultCode.SUCCESS:
							break;
						case ResultCode.CONNECTION_REFUSED:
							throw new IOError.FAILED ("connect failed (connection refused)");
						case ResultCode.INVALID_REQUEST:
							throw new IOError.FAILED ("connect failed (invalid request)");
						default:
							throw new IOError.FAILED ("connect failed (error code: %d)", result);
					}
				} catch (Error e) {
					throw new IOError.FAILED (e.message);
				}
			}

			private async int send_request_and_receive_response (MessageType type, uint8[]? body = null, bool is_mode_switch_request = false) throws Error {
				uint32 tag = last_tag++;

				if (is_mode_switch_request)
					mode_switch_tag = tag;

				var request = create_message (type, tag, body);
				var pending = new PendingResponse (tag, () => send_request_and_receive_response.callback ());
				pending_responses.add (pending);
				yield write_message (request);
				yield;

				return pending.result;
			}

			private async void process_incoming_messages () {
				while (running) {
					try {
						var message_blob = yield read_message ();

						uint32 * header = (void *) message_blob;
						MessageType type = (MessageType) uint.from_little_endian (header[0]);
						uint32 tag = uint.from_little_endian (header[1]);

						uint32 body_size = message_blob.length - 8;
						int32 * body_i32 = (int32 *) header + 2;
						uint32 * body_u32 = (uint32 *) header + 2;

						switch (type) {
							case MessageType.RESULT:
								if (body_size != 4)
									throw new IOError.FAILED ("unexpected payload size for RESULT");
								int result = body_i32[0];

								PendingResponse match = null;
								foreach (var pending in pending_responses) {
									if (pending.tag == tag) {
										match = pending;
										break;
									}
								}

								if (match == null)
									throw new IOError.FAILED ("response to unknown tag");
								pending_responses.remove (match);
								match.complete (result);

								if (tag == mode_switch_tag) {
									if (result == ResultCode.SUCCESS)
										return;
									else
										mode_switch_tag = 0;
								}

								break;

							case MessageType.DEVICE_CONNECTED:
								if (body_size < 4)
									throw new IOError.FAILED ("unexpected payload size for CONNECTED");
								uint conn_device_id = body_u32[0];
								device_connected (conn_device_id);
								break;

							case MessageType.DEVICE_DISCONNECTED:
								if (body_size != 4)
									throw new IOError.FAILED ("unexpected payload size for DISCONNECTED");
								uint disc_device_id = body_u32[0];
								device_disconnected (disc_device_id);
								break;

							default:
								throw new IOError.FAILED ("unexpected message type: %u", (uint) type);
						}

					} catch (Error e) {
						debug ("read error: %s", e.message);
						reset ();
					}
				}
			}

			private async uint8[] read_message () throws Error {
				uint32[] u32_buf = new uint32[1];
				ssize_t len;

				/* total size */
				len = yield input.read_async (u32_buf, 4);
				if (len != 4)
					throw new IOError.FAILED ("short read of size (len = %d)", (int) len);

				uint size = uint.from_little_endian (u32_buf[0]);
				if (size < 16 || size > 1024)
					throw new IOError.FAILED ("protocol error: invalid size");

				/* ignore the next 4 bytes (reserved) */
				len = yield input.read_async (u32_buf, 4);
				if (len != 4)
					throw new IOError.FAILED ("short read of reserved");

				/* body */
				uint body_size = size - 8;
				uint8[] body_buf = new uint8[body_size];
				len = yield input.read_async (body_buf, body_size);
				if (len != body_size)
					throw new IOError.FAILED ("short read of body");
				return body_buf;
			}

			private async void write_message (uint8[] blob) throws Error {
				var len = yield output.write_async (blob, blob.length);
				if (len != blob.length)
					throw new IOError.FAILED ("short write");
			}

			private uint8[] create_message (MessageType type, uint32 tag, uint8[]? body = null) {
				uint body_size = 0;
				if (body != null)
					body_size = body.length;

				uint8[] blob = new uint8[16 + body_size];

				uint32 * p = (void *) blob;
				p[0] = blob.length;
				p[1] = 0;
				p[2] = ((uint) type).to_little_endian ();
				p[3] = tag.to_little_endian ();

				if (body_size != 0) {
					uint8 * blob_start = (void *) blob;
					Memory.copy (blob_start + 16, body, body_size);
				}

				return blob;
			}

			private class PendingResponse {
				public uint32 tag {
					get;
					private set;
				}

				public delegate void CompletionHandler ();
				private CompletionHandler handler;

				public int result {
					get;
					private set;
				}

				public PendingResponse (uint32 tag, CompletionHandler handler) {
					this.tag = tag;
					this.handler = handler;
				}

				public void complete (int result) {
					this.result = result;
					handler ();
				}
			}
		}

		private enum MessageType {
			RESULT		    = 1,
			CONNECT		    = 2,
			HELLO		    = 3,
			DEVICE_CONNECTED    = 4,
			DEVICE_DISCONNECTED = 5
		}

		private enum ResultCode {
			SUCCESS		    = 0,
			CONNECTION_REFUSED  = 3,
			INVALID_REQUEST	    = 5
		}
	}
}

