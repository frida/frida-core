namespace Frida.Droidy {
	public class DeviceTracker : Object {
		public signal void device_attached (string serial, string name);
		public signal void device_detached (string serial);

		private Client client = new Client ();
		private Gee.HashMap<string, DeviceInfo> devices = new Gee.HashMap<string, DeviceInfo> ();

		construct {
			client.message.connect (on_message);
		}

		public async void open () throws Error {
			var devices_encoded = yield client.request_data ("host:track-devices");
			yield update_devices (devices_encoded);
		}

		public async void close () {
			yield client.close ();
		}

		private void on_message (string devices_encoded) {
			update_devices.begin (devices_encoded);
		}

		private async void update_devices (string devices_encoded) {
			var detached = new Gee.ArrayList<DeviceInfo> ();
			var attached = new Gee.ArrayList<DeviceInfo> ();

			var current = new Gee.HashSet<string> ();
			foreach (var line in devices_encoded.split ("\n")) {
				if (line.length == 0)
					continue;
				var tokens = line.split ("\t", 2);
				var serial = tokens[0];
				var status = tokens[1];
				if (status == "device")
					current.add (serial);
			}
			foreach (var entry in devices.entries) {
				var serial = entry.key;
				var info = entry.value;
				if (!current.contains (serial))
					detached.add (info);
			}
			foreach (var serial in current) {
				if (!devices.has_key (serial))
					attached.add (new DeviceInfo (serial));
			}

			foreach (var info in detached)
				devices.unset (info.serial);
			foreach (var info in attached)
				devices[info.serial] = info;

			foreach (var info in detached) {
				if (info.announced)
					device_detached (info.serial);
			}
			foreach (var info in attached)
				yield announce_device (info);
		}

		private async void announce_device (DeviceInfo info) {
			var serial = info.serial;
			uint port = 0;
			serial.scanf ("emulator-%u", out port);
			if (port != 0) {
				info.name = "Android Emulator %u".printf (port);
			} else {
				try {
					var manufacturer = yield get_manufacturer (info.serial);
					var model = yield get_model (info.serial);
					info.name = manufacturer + " " + model;
				} catch (Error e) {
					info.name = "Android Device";
				}
			}

			var still_attached = devices.has_key (info.serial);
			if (still_attached) {
				info.announced = true;
				device_attached (info.serial, info.name);
			}
		}

		private async string get_manufacturer (string device_serial) throws Error {
			var command = new ShellCommand ("getprop ro.product.manufacturer");
			var output = yield command.run (device_serial);
			var manifacturer = output.strip ();
			return manifacturer.get_char (0).toupper ().to_string () + manifacturer.substring (manifacturer.index_of_nth_char (1));
		}

		private async string get_model (string device_serial) throws Error {
			var command = new ShellCommand ("getprop ro.product.model");
			var output = yield command.run (device_serial);
			return output.strip ();
		}

		private class DeviceInfo {
			public string serial {
				get;
				private set;
			}

			public string name {
				get;
				set;
			}

			public bool announced {
				get;
				set;
			}

			public DeviceInfo (string serial) {
				this.serial = serial;
			}
		}
	}

	public class ShellCommand : Object {
		public string command {
			get;
			construct;
		}

		private const int CHUNK_SIZE = 4096;

		public ShellCommand (string command) {
			Object (command: command);
		}

		public async string run (string device_serial) throws Error {
			var client = new Client ();
			try {
				yield client.request ("host:transport:" + device_serial);
				yield client.request_protocol_change ("shell:" + command);

				var input = client.connection.get_input_stream ();
				var buf = new uint8[CHUNK_SIZE];
				var offset = 0;
				while (true) {
					var capacity = buf.length - offset;
					if (capacity < CHUNK_SIZE)
						buf.resize (buf.length + CHUNK_SIZE - capacity);
					ssize_t n;
					try {
						n = yield input.read_async (buf[offset:buf.length - 1]);
					} catch (IOError e) {
						throw new Error.TRANSPORT (e.message);
					}
					if (n == 0)
						break;
					offset += (int) n;
				}
				buf[offset] = '\0';

				char * chars = buf;
				return (string) chars;
			} finally {
				client.close.begin ();
			}
		}
	}

	public class Client : Object {
		public signal void message (string payload);

		public SocketConnection connection {
			get;
			private set;
		}
		private Gee.Promise<bool> open_request;
		private InputStream input;
		private Cancellable input_cancellable = new Cancellable ();
		private OutputStream output;
		private Cancellable output_cancellable = new Cancellable ();

		protected bool is_processing_messages;
		private Gee.ArrayQueue<PendingResponse> pending_responses;

		private enum RequestType {
			ACK,
			DATA,
			PROTOCOL_CHANGE
		}

		private const uint16 ADB_SERVER_PORT = 5037;
		private const uint16 MAX_MESSAGE_LENGTH = 1024;

		construct {
			reset ();
		}

		private void reset () {
			connection = null;
			input = null;
			output = null;

			is_processing_messages = false;
			pending_responses = new Gee.ArrayQueue<PendingResponse> ();
		}

		private async void ensure_open () throws Error {
			if (open_request != null) {
				var future = open_request.future;
				try {
					yield open_request.future.wait_async ();
				} catch (Gee.FutureError e) {
					throw (Error) future.exception;
				}
				return;
			}
			open_request = new Gee.Promise<bool> ();

			var client = new SocketClient ();

			SocketConnectable connectable;
			connectable = new InetSocketAddress (new InetAddress.loopback (SocketFamily.IPV4), ADB_SERVER_PORT);

			try {
				connection = yield client.connect_async (connectable);
				input = connection.get_input_stream ();
				output = connection.get_output_stream ();

				is_processing_messages = true;

				process_incoming_messages.begin ();

				open_request.set_value (true);
			} catch (GLib.Error e) {
				reset ();
				var error = new Error.NOT_SUPPORTED (e.message);
				open_request.set_exception (error);
				open_request = null;
				throw error;
			}
		}

		public async void close () {
			if (open_request != null) {
				try {
					yield ensure_open ();
				} catch (Error e) {
					return;
				}
			}

			if (is_processing_messages) {
				is_processing_messages = false;

				input_cancellable.cancel ();
				output_cancellable.cancel ();

				var source = new IdleSource ();
				source.set_priority (Priority.LOW);
				source.set_callback (() => {
					close.callback ();
					return false;
				});
				source.attach (MainContext.get_thread_default ());
				yield;
			}

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

		public async void request (string message) throws Error {
			yield request_with_type (message, RequestType.ACK);
		}

		public async string request_data (string message) throws Error {
			return yield request_with_type (message, RequestType.DATA);
		}

		public async void request_protocol_change (string message) throws Error {
			yield request_with_type (message, RequestType.PROTOCOL_CHANGE);
		}

		private async string request_with_type (string message, RequestType request_type) throws Error {
			yield ensure_open ();

			var waiting = false;
			var pending = new PendingResponse (request_type, () => {
				if (waiting)
					request_with_type.callback ();
			});
			pending_responses.offer_tail (pending);
			var message_str = "%04x%s".printf (message.length, message);
			unowned uint8[] message_buf = (uint8[]) message_str;
			size_t bytes_written;
			try {
				yield output.write_all_async (message_buf[0:message_str.length], Priority.DEFAULT, output_cancellable, out bytes_written);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("Unable to write message: " + e.message);
			}
			if (bytes_written != message_str.length) {
				pending_responses.remove (pending);
				throw new Error.TRANSPORT ("Unable to write message");
			}
			if (!pending.completed) {
				waiting = true;
				yield;
				waiting = false;
			}
			if (pending.error != null)
				throw pending.error;
			return pending.result;
		}

		private async void process_incoming_messages () {
			while (is_processing_messages) {
				try {
					var command_or_length = yield read_fixed_string (4);
					switch (command_or_length) {
						case "OKAY":
						case "FAIL":
							var pending = pending_responses.poll_head ();
							if (pending != null) {
								var success = command_or_length == "OKAY";
								if (success) {
									string result;
									if (pending.request_type == RequestType.DATA)
										result = yield read_string ();
									else
										result = "";
									pending.complete_with_result (result);

									if (pending.request_type == RequestType.PROTOCOL_CHANGE) {
										is_processing_messages = false;
										return;
									}
								} else {
									var error_message = yield read_string ();
									pending.complete_with_error (new Error.NOT_SUPPORTED (error_message));
								}
							} else {
								throw new Error.PROTOCOL ("Reply to unknown request");
							}
							break;

						case "SYNC":
						case "CNXN":
						case "AUTH":
						case "OPEN":
						case "CLSE":
						case "WRTE":
							throw new Error.PROTOCOL ("Unexpected command");

						default:
							var length = parse_length (command_or_length);
							var payload = yield read_fixed_string (length);
							message (payload);
							break;
					}
				} catch (Error e) {
					foreach (var pending_response in pending_responses)
						pending_response.complete_with_error (e);
					reset ();
				}
			}
		}

		private async string read_string () throws Error {
			var length_str = yield read_fixed_string (4);
			var length = parse_length (length_str);
			return yield read_fixed_string (length);
		}

		private async string read_fixed_string (size_t length) throws Error {
			var buf = new uint8[length + 1];
			size_t bytes_read;
			try {
				yield input.read_all_async (buf[0:length], Priority.DEFAULT, input_cancellable, out bytes_read);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("Unable to read string: " + e.message);
			}
			if (bytes_read != length)
				throw new Error.TRANSPORT ("Unable to read string");
			buf[length] = '\0';
			char * chars = buf;
			return (string) chars;
		}

		private size_t parse_length (string str) throws Error {
			int length = 0;
			str.scanf ("%04x", out length);
			if (length < 0 || length > MAX_MESSAGE_LENGTH)
				throw new Error.PROTOCOL ("Invalid message length");
			return length;
		}

		private class PendingResponse {
			public delegate void CompletionHandler ();
			private CompletionHandler handler;

			public RequestType request_type {
				get;
				private set;
			}

			public bool completed {
				get {
					return result != null || error != null;
				}
			}

			public string? result {
				get;
				private set;
			}

			public Error? error {
				get;
				private set;
			}

			public PendingResponse (RequestType request_type, owned CompletionHandler handler) {
				this.request_type = request_type;
				this.handler = (owned) handler;
			}

			public void complete_with_result (string r) {
				result = r;
				handler ();
			}

			public void complete_with_error (Error e) {
				error = e;
				handler ();
			}
		}
	}
}
