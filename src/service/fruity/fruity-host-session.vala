namespace Zed.Service {
	public class FruityHostSessionBackend : Object, HostSessionBackend {
		private Fruity.Client control_client;
		private Gee.HashMap<uint, FruityHostSessionProvider> provider_by_device_id = new Gee.HashMap<uint, FruityHostSessionProvider> ();

		public void start () {
			control_client = new Fruity.Client ();
			control_client.device_connected.connect ((device_id) => {
				assert (!provider_by_device_id.has_key (device_id));

				debug ("device %u connected!", device_id);

				var provider = new FruityHostSessionProvider (device_id);
				provider_by_device_id[device_id] = provider;

				provider_available (provider);
			});
			control_client.device_disconnected.connect ((device_id) => {
				assert (provider_by_device_id.has_key (device_id));

				debug ("device %u disconnected!", device_id);

				FruityHostSessionProvider provider;
				provider_by_device_id.unset (device_id, out provider);
				provider_unavailable (provider);
			});

			do_establish ();
		}

		private async void do_establish () {
			try {
				yield control_client.establish ();
			} catch (Error e) {
				debug ("failed to establish: %s", e.message);
			}
		}

	}

	public class FruityHostSessionProvider : Object, HostSessionProvider {
		public uint device_id {
			get;
			construct;
		}

		public FruityHostSessionProvider (uint device_id) {
			Object (device_id: device_id);
		}

		public async HostSession create () throws IOError {
			return new FruityHostSession ();
		}
	}

	public class FruityHostSession : Object, HostSession {
		public async HostProcessInfo[] enumerate_processes () throws IOError {
			throw new IOError.FAILED ("not implemented");
		}
	}

	namespace Fruity {
		private class Client : Object {
			private SocketConnection connection;
			private InputStream input;
			private OutputStream output;

			private bool running = false;
			private uint last_tag = 1;
			private Gee.ArrayList<PendingResponse> pending_responses = new Gee.ArrayList<PendingResponse> ();

			public signal void device_connected (uint device_id);
			public signal void device_disconnected (uint device_id);

			public async void establish () throws Error {
				assert (!running);
				running = true;

				var client = new SocketClient ();

				try {
					connection = yield client.connect_to_host_async ("127.0.0.1", 27015);
				} catch (Error e) {
					running = false;
					return;
				}

				input = new BufferedInputStream (connection.get_input_stream ());
				output = connection.get_output_stream ();

				process_incoming_messages ();

				yield perform_handshake ();
			}

			private async void perform_handshake () throws Error {
				var result = yield send_request_and_receive_response (MessageType.HELLO);
				if (result != ResultCode.SUCCESS)
					throw new IOError.FAILED ("handshake failed, result %d", result);
			}

			private async int send_request_and_receive_response (MessageType type) throws Error {
				uint32 tag = last_tag++;
				var request = create_message (type, tag);
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

						debug ("read message of size %d: type=%s, tag=%u", message_blob.length, type.to_string (), tag);

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
						running = false;
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

			private uint8[] create_message (MessageType type, uint32 tag) {
				uint8[] blob = new uint8[16];
				uint32 * p = (void *) blob;
				p[0] = blob.length;
				p[1] = 0;
				p[2] = ((uint) type).to_little_endian ();
				p[3] = tag.to_little_endian ();
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
			SUCCESS		    = 0
		}
	}
}

