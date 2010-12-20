namespace Zed.Service.Fruity {
	public class ClientV1 : Client {
		public override uint protocol_version {
			get { return 0; }
		}

		public override async void enable_listen_mode () throws IOError {
			assert (is_processing_messages);

			var result = yield query (MessageType.LISTEN);
			if (result != ResultCode.SUCCESS)
				throw new IOError.FAILED ("failed to enable listen mode, result %d", result);
		}

		public override async void connect_to_port (uint device_id, uint port) throws IOError {
			assert (is_processing_messages);

			uint8[] connect_body = new uint8[8];

			uint32 * p = (void *) connect_body;
			p[0] = device_id.to_little_endian ();
			p[1] = ((uint32) port << 16).to_big_endian ();

			int result = yield query (MessageType.CONNECT, connect_body, true);
			handle_connect_result (result);
		}

		protected override void dispatch_message (Client.Message msg) throws IOError {
			int32 * body_i32 = (int32 *) msg.body;
			uint32 * body_u32 = (uint32 *) msg.body;

			switch (msg.type) {
				case MessageType.RESULT:
					if (msg.body_size != 4)
						throw new IOError.FAILED ("unexpected payload size for RESULT");
					int result = body_i32[0];
					handle_result_message (msg, result);
					break;

				case MessageType.DEVICE_ATTACHED:
					if (msg.body_size < 4)
						throw new IOError.FAILED ("unexpected payload size for ATTACHED");
					uint attached_id = body_u32[0];
					unowned string attached_udid = (string) (msg.body + 6);
					device_attached (attached_id, attached_udid);
					break;

				case MessageType.DEVICE_DETACHED:
					if (msg.body_size != 4)
						throw new IOError.FAILED ("unexpected payload size for DETACHED");
					uint detached_id = body_u32[0];
					device_detached (detached_id);
					break;

				default:
					throw new IOError.FAILED ("unexpected message type: %u", (uint) msg.type);
			}
		}
	}

	public class ClientV2 : Client {
		public override uint protocol_version {
			get { return 1; }
		}

		public override async void enable_listen_mode () throws IOError {
			assert (is_processing_messages);

			var result = yield query_with_plist (create_plist ("Listen"));
			if (result != ResultCode.SUCCESS)
				throw new IOError.FAILED ("failed to enable listen mode, result %d", result);
		}

		public override async void connect_to_port (uint device_id, uint port) throws IOError {
			assert (is_processing_messages);

			var plist = create_plist ("Connect");
			plist.set_int ("DeviceID", (int) device_id);
			plist.set_int ("PortNumber", (int) port);

			var result = yield query_with_plist (plist);
			handle_connect_result (result);
		}

		protected override void dispatch_message (Client.Message msg) throws IOError {
			if (msg.type != MessageType.PROPERTY_LIST)
				throw new IOError.FAILED ("unexpected message type: %u", (uint) msg.type);
			else if (msg.body_size == 0)
				throw new IOError.FAILED ("message has empty body");

			unowned string xml = (string) msg.body;
			var plist = new PropertyList.from_xml (xml);
			var message_type = plist.get_string ("MessageType");
			if (message_type == "Result") {
				int result = plist.get_int ("Number");
				handle_result_message (msg, result);
			} else if (message_type == "Attached") {
				uint attached_id = (uint) plist.get_int ("DeviceID");
				var props = plist.get_plist ("Properties");
				string attached_udid = props.get_string ("SerialNumber");
				device_attached (attached_id, attached_udid);
			} else if (message_type == "Detached") {
				uint detached_id = (uint) plist.get_int ("DeviceID");
				device_detached (detached_id);
			} else {
				throw new IOError.FAILED ("unexpected message type: %s", message_type);
			}
		}

		private PropertyList create_plist (string message_type) {
			var plist = new PropertyList ();
			plist.set_string ("BundleID", "com.apple.iTunes");
			plist.set_string ("ClientVersionString", "usbmuxd-??? built for ???");
			plist.set_string ("MessageType", message_type);
			return plist;
		}

		protected async int query_with_plist (PropertyList plist, bool is_mode_switch_request = false) throws IOError {
			var xml = plist.to_xml ();
			var size = xml.size ();
			var body = new uint8[size];
			Memory.copy (body, xml, size);
			var result = yield query (MessageType.PROPERTY_LIST, body, is_mode_switch_request);
			return result;
		}
	}

	public abstract class Client : Object {
		public abstract uint protocol_version {
			get;
		}

		public SocketConnection connection {
			get;
			private set;
		}
		private InputStream input;
		private OutputStream output;

		protected bool is_processing_messages;
		private uint last_tag;
		private uint mode_switch_tag;
		private Gee.ArrayList<PendingResponse> pending_responses;

		private const uint16 USBMUX_SERVER_PORT = 27015;
		private const uint16 MAX_MESSAGE_SIZE = 2048;

		public signal void device_attached (uint device_id, string device_udid);
		public signal void device_detached (uint device_id);

		construct {
			reset ();
		}

		private void reset () {
			connection = null;
			input = null;
			output = null;

			is_processing_messages = false;
			last_tag = 1;
			mode_switch_tag = 0;
			pending_responses = new Gee.ArrayList<PendingResponse> ();
		}

		public async void establish () throws IOError {
			assert (!is_processing_messages);

			var client = new SocketClient ();

			try {
				connection = yield client.connect_to_host_async ("127.0.0.1", USBMUX_SERVER_PORT);
				input = connection.get_input_stream ();
				output = connection.get_output_stream ();

				is_processing_messages = true;

				process_incoming_messages ();
			} catch (Error e) {
				reset ();
				throw new IOError.FAILED (e.message);
			}
		}

		public abstract async void enable_listen_mode () throws IOError;
		public abstract async void connect_to_port (uint device_id, uint port) throws IOError;

		public async void close () throws IOError {
			if (!is_processing_messages)
				throw new IOError.FAILED ("not processing messages");
			is_processing_messages = false;

			try {
				var conn = this.connection;
				yield conn.close_async (Priority.DEFAULT);
			} catch (Error e) {
			}
			connection = null;
			input = null;
			output = null;
		}

		protected async int query (MessageType type, uint8[]? body = null, bool is_mode_switch_request = false) throws IOError {
			uint32 tag = last_tag++;

			if (is_mode_switch_request)
				mode_switch_tag = tag;

			var request = create_message (type, tag, body);
			var pending = new PendingResponse (tag, () => query.callback ());
			pending_responses.add (pending);
			yield write_message (request);
			yield;

			return pending.result;
		}

		private async void process_incoming_messages () {
			while (is_processing_messages) {
				try {
					var msg = yield read_message ();
					dispatch_message (msg);
				} catch (IOError e) {
					foreach (var pending_response in pending_responses)
						pending_response.complete (ResultCode.PROTOCOL_ERROR);
					reset ();
				}
			}
		}

		protected abstract void dispatch_message (Message msg) throws IOError;

		protected void handle_result_message (Message msg, int result) throws IOError {
			PendingResponse match = null;
			foreach (var pending in pending_responses) {
				if (pending.tag == msg.tag) {
					match = pending;
					break;
				}
			}

			if (match == null)
				throw new IOError.FAILED ("response to unknown tag");
			pending_responses.remove (match);
			match.complete (result);

			if (msg.tag == mode_switch_tag) {
				if (result == ResultCode.SUCCESS)
					is_processing_messages = false;
				else
					mode_switch_tag = 0;
			}
		}

		protected void handle_connect_result (int result) throws IOError {
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
		}

		private async Message read_message () throws IOError {
			uint32 size = 0;
			yield read (&size, 4);
			size = uint.from_little_endian (size);
			if (size < 16 || size > MAX_MESSAGE_SIZE)
				throw new IOError.FAILED ("protocol error: invalid size");

			uint32 protocol_version;
			yield read (&protocol_version, 4);

			var msg = new Message ();
			msg.size = size - 8;
			msg.data = malloc (msg.size + 1);
			msg.data[msg.size] = 0;
			msg.body = msg.data + 8;
			msg.body_size = msg.size - 8;
			yield read (msg.data, msg.size);

			uint32 * header = (void *) msg.data;
			msg.type = (MessageType) uint.from_little_endian (header[0]);
			msg.tag = uint.from_little_endian (header[1]);

			return msg;
		}

		private async void write_message (uint8[] blob) throws IOError {
			yield write (blob, blob.length);
		}

		private async void read (void * buffer, size_t count) throws IOError {
			try {
				uint8 * p = buffer;
				size_t remaining = count;
				do {
					ssize_t len = yield input.read_async (p, remaining);
					p += len;
					remaining -= len;
				} while (remaining != 0);
			} catch (Error e) {
				throw new IOError.FAILED (e.message);
			}
		}

		private async void write (void * buffer, size_t count) throws IOError {
			try {
				uint8 * p = buffer;
				size_t remaining = count;
				do {
					ssize_t len = yield output.write_async (p, remaining);
					p += len;
					remaining -= len;
				} while (remaining != 0);
			} catch (Error e) {
				throw new IOError.FAILED (e.message);
			}
		}

		private uint8[] create_message (MessageType type, uint32 tag, uint8[]? body = null) {
			uint body_size = 0;
			if (body != null)
				body_size = body.length;

			uint8[] blob = new uint8[16 + body_size];

			uint32 * p = (void *) blob;
			p[0] = blob.length.to_little_endian ();
			p[1] = protocol_version.to_little_endian ();
			p[2] = ((uint) type).to_little_endian ();
			p[3] = tag.to_little_endian ();

			if (body_size != 0) {
				uint8 * blob_start = (void *) blob;
				Memory.copy (blob_start + 16, body, body_size);
			}

			return blob;
		}

		protected class Message {
			public MessageType type;
			public uint8 * body;
			public uint body_size;
			public uint32 tag;

			public uint8 * data;
			public uint size;

			~Message () {
				free (data);
			}
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

	public enum MessageType {
		RESULT		= 1,
		CONNECT		= 2,
		LISTEN		= 3,
		DEVICE_ATTACHED	= 4,
		DEVICE_DETACHED	= 5,
		PROPERTY_LIST	= 8
	}

	public enum ResultCode {
		PROTOCOL_ERROR      = -1,
		SUCCESS		    = 0,
		CONNECTION_REFUSED  = 3,
		INVALID_REQUEST	    = 5
	}
}
