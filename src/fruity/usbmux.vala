namespace Frida.Fruity {
	public class UsbmuxClient : Object, AsyncInitable {
		public SocketConnection connection {
			get;
			private set;
		}
		private InputStream input;
		private OutputStream output;
		private Cancellable cancellable = new Cancellable ();

		private bool is_processing_messages;
		private uint last_tag;
		private uint mode_switch_tag;
		private Gee.ArrayList<PendingResponse> pending_responses;

		private const uint16 USBMUX_SERVER_PORT = 27015;
		private const uint USBMUX_PROTOCOL_VERSION = 1;
		private const uint32 MAX_MESSAGE_SIZE = 128 * 1024;

		public signal void device_attached (DeviceDetails details);
		public signal void device_detached (DeviceId id);

		public static async UsbmuxClient open (Cancellable? cancellable = null) throws UsbmuxError {
			var client = new UsbmuxClient ();

			try {
				yield client.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				assert (e is UsbmuxError);
				throw (UsbmuxError) e;
			}

			return client;
		}

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

		private async bool init_async (int io_priority, Cancellable? cancellable) throws UsbmuxError {
			assert (!is_processing_messages);

			var client = new SocketClient ();

			SocketConnectable connectable;
#if WINDOWS
			connectable = new InetSocketAddress (new InetAddress.loopback (SocketFamily.IPV4), USBMUX_SERVER_PORT);
#else
			connectable = new UnixSocketAddress ("/var/run/usbmuxd");
#endif

			try {
				connection = yield client.connect_async (connectable, cancellable);
				input = connection.get_input_stream ();
				output = connection.get_output_stream ();

				is_processing_messages = true;
				process_incoming_messages.begin ();
			} catch (GLib.Error e) {
				reset ();
				throw new UsbmuxError.DAEMON_NOT_RUNNING ("%s", e.message);
			}

			return true;
		}

		public async void close () {
			if (!is_processing_messages)
				return;
			is_processing_messages = false;

			cancellable.cancel ();

			var source = new IdleSource ();
			source.set_priority (Priority.LOW);
			source.set_callback (() => {
				close.callback ();
				return false;
			});
			source.attach (MainContext.get_thread_default ());
			yield;

			try {
				var conn = this.connection;
				if (conn != null)
					yield conn.close_async (Priority.DEFAULT);
			} catch (GLib.Error e) {
			}
			connection = null;
			input = null;
			output = null;
		}

		public async void enable_listen_mode () throws UsbmuxError {
			assert (is_processing_messages);

			var response = yield query (create_request ("Listen"));
			try {
				if (response.get_string ("MessageType") != "Result")
					throw new UsbmuxError.PROTOCOL ("Unexpected response message type");

				var result = (int) response.get_integer ("Number");
				if (result != ResultCode.SUCCESS)
					throw new UsbmuxError.FAILED ("Unexpected result while trying to enable listen mode: %d", result);
			} catch (PlistError e) {
				throw new UsbmuxError.PROTOCOL ("Unexpected response: %s", e.message);
			}
		}

		public async void connect_to_port (DeviceId device_id, uint16 port) throws UsbmuxError {
			assert (is_processing_messages);

			var request = create_request ("Connect");
			request.set_integer ("DeviceID", device_id.raw_value);
			request.set_integer ("PortNumber", ((uint32) port << 16).to_big_endian ());

			var response = yield query (request, true);
			try {
				if (response.get_string ("MessageType") != "Result")
					throw new UsbmuxError.PROTOCOL ("Unexpected response message type");

				var result = (int) response.get_integer ("Number");
				switch (result) {
					case ResultCode.SUCCESS:
						break;
					case ResultCode.CONNECTION_REFUSED:
						throw new UsbmuxError.CONNECTION_REFUSED ("Unable to connect (connection refused)");
					case ResultCode.INVALID_REQUEST:
						throw new UsbmuxError.INVALID_ARGUMENT ("Unable to connect (invalid argument)");
					default:
						throw new UsbmuxError.FAILED ("Unable to connect (error code: %d)", result);
				}
			} catch (PlistError e) {
				throw new UsbmuxError.PROTOCOL ("Unexpected response: %s", e.message);
			}
		}

		public async Plist read_pair_record (Udid udid) throws UsbmuxError {
			var request = create_request ("ReadPairRecord");
			request.set_string ("PairRecordID", udid.raw_value);

			var response = yield query (request);
			try {
				if (response.has ("MessageType")) {
					if (response.get_string ("MessageType") != "Result")
						throw new UsbmuxError.PROTOCOL ("Unexpected ReadPairRecord response");
					var result = (int) response.get_integer ("Number");
					if (result != 0)
						throw new UsbmuxError.FAILED ("Unexpected result while trying to read pair record: %d", result);
				}

				var raw_record = response.get_bytes ("PairRecordData");
				unowned string record_xml_unterminated = (string) raw_record.get_data ();
				string record_xml = record_xml_unterminated[0:raw_record.length];
				return new Plist.from_xml (record_xml);
			} catch (PlistError e) {
				throw new UsbmuxError.PROTOCOL ("Unexpected response: %s", e.message);
			}
		}

		private async Plist query (Plist request, bool is_mode_switch_request = false) throws UsbmuxError {
			uint32 tag = last_tag++;

			if (is_mode_switch_request)
				mode_switch_tag = tag;

			var body_xml = request.to_xml ();
			unowned uint8[] body = ((uint8[]) body_xml)[0:body_xml.length];

			var msg = create_message (MessageType.PROPERTY_LIST, tag, body);
			var pending = new PendingResponse (tag, () => query.callback ());
			pending_responses.add (pending);
			write_message.begin (msg);
			yield;

			var response = pending.response;
			if (response == null)
				throw pending.error;

			return response;
		}

		private Plist create_request (string message_type) {
			var request = new Plist ();
			request.set_string ("ClientVersionString", "usbmuxd-423.50.204");
			request.set_string ("ProgName", "Xcode");
			request.set_string ("BundleID", "com.apple.dt.Xcode");
			request.set_string ("MessageType", message_type);
			return request;
		}

		private async void process_incoming_messages () {
			while (is_processing_messages) {
				try {
					var msg = yield read_message ();
					dispatch_message (msg);
				} catch (UsbmuxError error) {
					foreach (var pending_response in pending_responses)
						pending_response.complete_with_error (error);
					reset ();
				}
			}
		}

		private void dispatch_message (UsbmuxClient.Message msg) throws UsbmuxError {
			if (msg.type != MessageType.PROPERTY_LIST)
				throw new UsbmuxError.PROTOCOL ("Unexpected message type %u, was expecting a property list", (uint) msg.type);
			else if (msg.body_size == 0)
				throw new UsbmuxError.PROTOCOL ("Unexpected message with empty body");

			unowned string body_xml = (string) msg.body;
			try {
				var body = new Plist.from_xml (body_xml);
				if (msg.tag != 0) {
					handle_response_message (msg.tag, body);
				} else {
					var message_type = body.get_string ("MessageType");
					if (message_type == "Attached") {
						var props = body.get_dict ("Properties");
						var details = new DeviceDetails (
							DeviceId ((uint) body.get_integer ("DeviceID")),
							ProductId ((int) props.get_integer ("ProductID")),
							Udid (props.get_string ("SerialNumber"))
						);
						device_attached (details);
					} else if (message_type == "Detached") {
						device_detached (DeviceId ((uint) body.get_integer ("DeviceID")));
					} else {
						throw new UsbmuxError.PROTOCOL ("Unexpected message type: %s", message_type);
					}
				}
			} catch (PlistError e) {
				throw new UsbmuxError.PROTOCOL ("Malformed usbmux message body: %s", e.message);
			}
		}

		private void handle_response_message (uint32 tag, Plist response) throws UsbmuxError {
			PendingResponse match = null;
			foreach (var pending in pending_responses) {
				if (pending.tag == tag) {
					match = pending;
					break;
				}
			}
			if (match == null)
				throw new UsbmuxError.PROTOCOL ("Unexpected response with unknown tag");

			pending_responses.remove (match);
			match.complete_with_response (response);

			if (tag == mode_switch_tag) {
				int64 result;
				try {
					result = response.get_integer ("Number");
				} catch (PlistError e) {
					throw new UsbmuxError.PROTOCOL ("Malformed response: %s", e.message);
				}
				if (result == ResultCode.SUCCESS)
					is_processing_messages = false;
				else
					mode_switch_tag = 0;
			}
		}

		private uint8[] create_message (MessageType type, uint32 tag, uint8[]? body = null) {
			uint body_size = 0;
			if (body != null)
				body_size = body.length;

			uint8[] blob = new uint8[16 + body_size];

			uint32 * p = (void *) blob;
			p[0] = blob.length.to_little_endian ();
			p[1] = USBMUX_PROTOCOL_VERSION.to_little_endian ();
			p[2] = ((uint) type).to_little_endian ();
			p[3] = tag.to_little_endian ();

			if (body_size != 0) {
				uint8 * blob_start = (void *) blob;
				Memory.copy (blob_start + 16, body, body_size);
			}

			return blob;
		}

		private async Message read_message () throws UsbmuxError {
			var header_buf = new uint8[16];
			yield read (header_buf);
			var header = (uint32 *) header_buf;

			uint32 size = uint32.from_little_endian (header[0]);
			MessageType type = (MessageType) uint32.from_little_endian (header[2]);
			uint32 tag = uint32.from_little_endian (header[3]);

			if (size < 16 || size > MAX_MESSAGE_SIZE)
				throw new UsbmuxError.PROTOCOL ("Invalid message size");

			var body_size = size - 16;
			var msg = new Message (type, tag, body_size);

			if (body_size > 0) {
				unowned uint8[] body_buf = ((uint8 []) msg.body)[0:body_size];
				yield read (body_buf);
			}

			return msg;
		}

		private async void read (uint8[] buffer) throws UsbmuxError {
			size_t bytes_read;
			try {
				yield input.read_all_async (buffer, Priority.DEFAULT, cancellable, out bytes_read);
			} catch (GLib.Error e) {
				throw new UsbmuxError.CONNECTION_CLOSED ("%s", e.message);
			}
			if (bytes_read == 0)
				throw new UsbmuxError.CONNECTION_CLOSED ("Connection closed");
		}

		private async void write_message (uint8[] blob) throws UsbmuxError {
			try {
				size_t bytes_written;
				yield output.write_all_async (blob, Priority.DEFAULT, cancellable, out bytes_written);
			} catch (GLib.Error e) {
				throw new UsbmuxError.CONNECTION_CLOSED ("%s", e.message);
			}
		}

		private enum MessageType {
			RESULT		= 1,
			CONNECT		= 2,
			LISTEN		= 3,
			DEVICE_ATTACHED	= 4,
			DEVICE_DETACHED	= 5,
			PROPERTY_LIST	= 8
		}

		private enum ResultCode {
			PROTOCOL_ERROR      = -1,
			SUCCESS		    = 0,
			CONNECTION_REFUSED  = 3,
			INVALID_REQUEST	    = 5
		}

		private class Message {
			public MessageType type;
			public uint32 tag;
			public uint8 * body;
			public uint32 body_size;

			public Message (MessageType type, uint32 tag, uint32 body_size) {
				this.type = type;
				this.tag = tag;
				this.body = malloc (body_size + 1);
				this.body[body_size] = 0;
				this.body_size = body_size;
			}

			~Message () {
				free (body);
			}
		}

		private class PendingResponse {
			public uint32 tag {
				get;
				private set;
			}

			public delegate void CompletionHandler ();
			private CompletionHandler handler;

			public Plist? response {
				get;
				private set;
			}

			public UsbmuxError? error {
				get;
				private set;
			}

			public PendingResponse (uint32 tag, owned CompletionHandler handler) {
				this.tag = tag;
				this.handler = (owned) handler;
			}

			public void complete_with_response (Plist? response) {
				this.response = response;
				handler ();
			}

			public void complete_with_error (UsbmuxError? error) {
				this.error = error;
				handler ();
			}
		}
	}

	public errordomain UsbmuxError {
		FAILED,
		DAEMON_NOT_RUNNING,
		CONNECTION_CLOSED,
		CONNECTION_REFUSED,
		INVALID_ARGUMENT,
		PROTOCOL
	}

	public class DeviceDetails : Object {
		public DeviceId id {
			get;
			construct;
		}

		public ProductId product_id {
			get;
			construct;
		}

		public Udid udid {
			get;
			construct;
		}

		public DeviceDetails (DeviceId id, ProductId product_id, Udid udid) {
			Object (id: id, product_id: product_id, udid: udid);
		}
	}

	public struct DeviceId {
		public uint raw_value {
			get;
			private set;
		}

		public DeviceId (uint raw_value) {
			this.raw_value = raw_value;
		}
	}

	public struct ProductId {
		public int raw_value {
			get;
			private set;
		}

		public ProductId (int raw_value) {
			this.raw_value = raw_value;
		}
	}

	public struct Udid {
		public string raw_value {
			get;
			private set;
		}

		public Udid (string raw_value) {
			this.raw_value = raw_value;
		}
	}
}
