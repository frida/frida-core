namespace Frida.Droidy {
	public class DeviceTracker : Object {
		public signal void device_attached (DeviceDetails details);
		public signal void device_detached (string serial);

		private Client? client;
		private Gee.HashMap<string, DeviceEntry> devices = new Gee.HashMap<string, DeviceEntry> ();
		private Cancellable io_cancellable = new Cancellable ();

		public async void open (Cancellable? cancellable = null) throws Error, IOError {
			client = yield Client.open (cancellable);
			client.message.connect (on_message);

			try {
				try {
					var devices_encoded = yield client.request_data ("host:track-devices-l", cancellable);
					yield update_devices (devices_encoded, cancellable);
				} catch (Error.NOT_SUPPORTED e) {
					client.message.disconnect (on_message);
					client = null;

					client = yield Client.open (cancellable);
					var devices_encoded = yield client.request_data ("host:track-devices", cancellable);
					yield update_devices (devices_encoded, cancellable);
				}
			} catch (GLib.Error e) {
				if (client != null)
					yield client.close (cancellable);
			}
		}

		public async void close (Cancellable? cancellable = null) throws IOError {
			if (client == null)
				return;

			io_cancellable.cancel ();

			yield client.close (cancellable);
		}

		private void on_message (string devices_encoded) {
			update_devices.begin (devices_encoded, io_cancellable);
		}

		private async void update_devices (string devices_encoded, Cancellable? cancellable) throws IOError {
			var detached = new Gee.ArrayList<DeviceEntry> ();
			var attached = new Gee.ArrayList<DeviceEntry> ();

			var current = new Gee.HashMap<string, string?> ();
			foreach (var line in devices_encoded.split ("\n")) {
				MatchInfo info;
				if (!/^(\S+)\s+(\S+)( (.+))?$/m.match (line, 0, out info)) {
					continue;
				}

				string serial = info.fetch (1);

				string type = info.fetch (2);
				if (type != "device")
					continue;

				string? name = null;
				if (info.get_match_count () == 5) {
					string[] details = info.fetch (4).split (" ");
					foreach (unowned string pair in details) {
						if (pair.has_prefix ("model:")) {
							name = pair.substring (6).replace ("_", " ");
							break;
						}
					}
				}

				current[serial] = name;
			}
			foreach (var e in devices.entries) {
				var serial = e.key;
				if (!current.has_key (serial))
					detached.add (e.value);
			}
			foreach (var entry in current.entries) {
				unowned string serial = entry.key;
				if (!devices.has_key (serial))
					attached.add (new DeviceEntry (serial, entry.value));
			}

			foreach (var entry in detached)
				devices.unset (entry.serial);
			foreach (var entry in attached)
				devices[entry.serial] = entry;

			foreach (var entry in detached) {
				if (entry.announced)
					device_detached (entry.serial);
			}
			foreach (var entry in attached)
				yield announce_device (entry, cancellable);
		}

		private async void announce_device (DeviceEntry entry, Cancellable? cancellable) throws IOError {
			var serial = entry.serial;

			uint port = 0;
			serial.scanf ("emulator-%u", out port);
			if (port != 0) {
				entry.name = "Android Emulator %u".printf (port);
			} else if (entry.name == null) {
				try {
					entry.name = yield detect_name (entry.serial, cancellable);
				} catch (Error e) {
					entry.name = "Android Device";
				}
			}

			var still_attached = devices.has_key (entry.serial);
			if (still_attached) {
				entry.announced = true;
				device_attached (new DeviceDetails (entry.serial, entry.name));
			}
		}

		private async string detect_name (string device_serial, Cancellable? cancellable) throws Error, IOError {
			var output = yield ShellCommand.run ("getprop ro.product.model", device_serial, cancellable);
			return output.chomp ();
		}

		private class DeviceEntry {
			public string serial {
				get;
				private set;
			}

			public string? name {
				get;
				set;
			}

			public bool announced {
				get;
				set;
			}

			public DeviceEntry (string serial, string? name) {
				this.serial = serial;
				this.name = name;
			}
		}
	}

	public class DeviceDetails : Object {
		public string serial {
			get;
			construct;
		}

		public string name {
			get;
			construct;
		}

		public DeviceDetails (string serial, string name) {
			Object (serial: serial, name: name);
		}
	}

	namespace ShellCommand {
		private const int CHUNK_SIZE = 4096;

		public static async string run (string command, string device_serial, Cancellable? cancellable = null) throws Error, IOError {
			var client = yield Client.open (cancellable);

			try {
				yield client.request ("host:transport:" + device_serial, cancellable);
				yield client.request_protocol_change ("shell:" + command, cancellable);

				var input = client.stream.get_input_stream ();
				var buf = new uint8[CHUNK_SIZE];
				var offset = 0;
				while (true) {
					var capacity = buf.length - offset;
					if (capacity < CHUNK_SIZE)
						buf.resize (buf.length + CHUNK_SIZE - capacity);

					ssize_t n;
					try {
						n = yield input.read_async (buf[offset:buf.length - 1], Priority.DEFAULT, cancellable);
					} catch (IOError e) {
						throw new Error.TRANSPORT ("%s", e.message);
					}

					if (n == 0)
						break;

					offset += (int) n;
				}
				buf[offset] = '\0';

				char * chars = buf;
				return (string) chars;
			} finally {
				client.close.begin (cancellable);
			}
		}
	}

	namespace FileSync {
		private const size_t MAX_DATA_SIZE = 65536;

		public static async void send (InputStream content, FileMetadata metadata, string remote_path, string device_serial,
				Cancellable? cancellable = null) throws Error, IOError {
			var client = yield Client.open (cancellable);

			try {
				yield client.request ("host:transport:" + device_serial, cancellable);

				var session = yield client.request_sync_session (cancellable);

				var cmd_buf = new MemoryOutputStream.resizable ();
				var cmd = new DataOutputStream (cmd_buf);
				cmd.byte_order = LITTLE_ENDIAN;

				string raw_mode = "%u".printf (metadata.mode);

				cmd.put_string ("SEND");
				cmd.put_uint32 (remote_path.length + 1 + raw_mode.length);
				cmd.put_string (remote_path);
				cmd.put_string (",");
				cmd.put_string (raw_mode);

				while (true) {
					Bytes chunk = yield content.read_bytes_async (MAX_DATA_SIZE, Priority.DEFAULT, cancellable);
					size_t size = chunk.get_size ();
					if (size == 0)
						break;

					cmd.put_string ("DATA");
					cmd.put_uint32 ((uint32) size);
					cmd.write_bytes (chunk);

					cmd_buf.close ();
					yield session.send (cmd_buf.steal_as_bytes (), cancellable);

					cmd_buf = new MemoryOutputStream.resizable ();
					cmd = new DataOutputStream (cmd_buf);
					cmd.byte_order = LITTLE_ENDIAN;
				}

				cmd.put_string ("DONE");
				cmd.put_uint32 ((uint32) metadata.time_modified.to_unix ());

				cmd_buf.close ();
				yield session.finish (cmd_buf.steal_as_bytes (), cancellable);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("%s", e.message);
			} finally {
				client.close.begin (cancellable);
			}
		}
	}

	public class FileMetadata : Object {
		public uint32 mode {
			get;
			set;
			default = 0100644;
		}

		public DateTime time_modified {
			get;
			set;
			default = new DateTime.now_local ();
		}
	}

	public class JDWPTracker : Object {
		public signal void debugger_attached (uint pid);
		public signal void debugger_detached (uint pid);

		private Client? client;
		private Gee.HashSet<uint> debugger_pids = new Gee.HashSet<uint> ();
		private Cancellable io_cancellable = new Cancellable ();

		public async void open (string device_serial, Cancellable? cancellable = null) throws Error, IOError {
			client = yield Client.open (cancellable);
			client.message.connect (on_message);

			try {
				yield client.request ("host:transport:" + device_serial, cancellable);
				string? pids_encoded = yield client.request_data ("track-jdwp", cancellable);
				update_pids (pids_encoded, cancellable);
			} catch (GLib.Error e) {
				yield client.close (cancellable);
			}
		}

		public async void close (Cancellable? cancellable = null) throws IOError {
			if (client == null)
				return;

			io_cancellable.cancel ();

			yield client.close (cancellable);
		}

		private void on_message (string pids_encoded) {
			try {
				update_pids (pids_encoded, io_cancellable);
			} catch (IOError e) {
			}
		}

		private void update_pids (string pids_encoded, Cancellable? cancellable) throws IOError {
			var detached = new Gee.ArrayList<uint> ();
			var attached = new Gee.ArrayList<uint> ();

			var current = new Gee.HashSet<uint> ();
			foreach (var line in pids_encoded.chomp ().split ("\n")) {
				uint pid = uint.parse (line);
				current.add (pid);
			}
			foreach (var pid in debugger_pids) {
				if (!current.contains (pid))
					detached.add (pid);
			}
			foreach (var pid in current) {
				if (!debugger_pids.contains (pid))
					attached.add (pid);
			}

			foreach (var pid in detached) {
				debugger_pids.remove (pid);
				debugger_detached (pid);
			}
			foreach (var pid in attached) {
				debugger_pids.add (pid);
				debugger_attached (pid);
			}
		}
	}

	public class Client : Object {
		public signal void closed ();
		public signal void message (string payload);

		public IOStream stream {
			get;
			construct;
		}
		private InputStream input;
		private OutputStream output;
		private Cancellable io_cancellable = new Cancellable ();

		protected bool is_processing_messages;
		private Gee.ArrayQueue<PendingResponse> pending_responses = new Gee.ArrayQueue<PendingResponse> ();

		public enum RequestType {
			COMMAND,
			SYNC,
			DATA,
			PROTOCOL_CHANGE
		}

		private const uint16 ADB_SERVER_PORT = 5037;
		private const uint16 MAX_MESSAGE_LENGTH = 1024;

		public static async Client open (Cancellable? cancellable = null) throws Error, IOError {
			IOStream stream;
			try {
				var client = new SocketClient ();
				var connection = yield client.connect_async (new NetworkAddress.loopback (ADB_SERVER_PORT), cancellable);

				Tcp.enable_nodelay (connection.socket);

				stream = connection;
			} catch (GLib.Error e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}

			return new Client (stream);
		}

		public Client (IOStream stream) {
			Object (stream: stream);
		}

		construct {
			input = stream.get_input_stream ();
			output = stream.get_output_stream ();

			is_processing_messages = true;

			process_incoming_messages.begin ();
		}

		public async void close (Cancellable? cancellable = null) throws IOError {
			if (is_processing_messages) {
				is_processing_messages = false;

				io_cancellable.cancel ();

				var source = new IdleSource ();
				source.set_priority (Priority.LOW);
				source.set_callback (close.callback);
				source.attach (MainContext.get_thread_default ());
				yield;
			}

			try {
				yield this.stream.close_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				if (e is IOError.CANCELLED)
					throw (IOError) e;
			}
		}

		public async void request (string message, Cancellable? cancellable = null) throws Error, IOError {
			yield request_with_type (message, RequestType.COMMAND, cancellable);
		}

		public async string request_data (string message, Cancellable? cancellable = null) throws Error, IOError {
			return yield request_with_type (message, RequestType.DATA, cancellable);
		}

		public async void request_protocol_change (string message, Cancellable? cancellable = null) throws Error, IOError {
			yield request_with_type (message, RequestType.PROTOCOL_CHANGE, cancellable);
		}

		public async SyncSession request_sync_session (Cancellable? cancellable = null) throws Error, IOError {
			yield request ("sync:", cancellable);

			var session = new SyncSession (this);

			PendingResponse pending = null;
			pending = new PendingResponse (RequestType.SYNC, () => {
				session._end (pending.error);
			});
			pending_responses.offer_tail (pending);

			return session;
		}

		private async string? request_with_type (string message, RequestType request_type, Cancellable? cancellable)
				throws Error, IOError {
			Bytes response_bytes = yield request_with_bytes (new Bytes (message.data), request_type, cancellable);
			if (response_bytes == null)
				return null;
			return (string) response_bytes.get_data ();
		}

		public async Bytes? request_with_bytes (Bytes message, RequestType request_type, Cancellable? cancellable) throws Error, IOError {
			bool waiting = false;

			var pending = new PendingResponse (request_type, () => {
				if (waiting)
					request_with_bytes.callback ();
			});
			pending_responses.offer_tail (pending);

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (() => {
				pending.complete_with_error (new IOError.CANCELLED ("Operation was cancelled"));
				return false;
			});
			cancel_source.attach (MainContext.get_thread_default ());

			try {
				size_t bytes_written;
				try {
					if (request_type == SYNC) {
						yield output.write_all_async (message.get_data (), Priority.DEFAULT, cancellable, out bytes_written);
					} else {
						var message_size = message.get_size ();
						var message_buf = new uint8[4 + message_size];
						var length_str = "%04x".printf (message.length);
						Memory.copy (message_buf, length_str, 4);
						Memory.copy ((uint8 *) message_buf + 4, message.get_data (), message_size);

						yield output.write_all_async (message_buf, Priority.DEFAULT, cancellable, out bytes_written);
					}
				} catch (GLib.Error e) {
					throw new Error.TRANSPORT ("Unable to write message: %s", e.message);
				}

				if (!pending.completed) {
					waiting = true;
					yield;
					waiting = false;
				}
			} finally {
				cancel_source.destroy ();
			}

			cancellable.set_error_if_cancelled ();

			if (pending.error != null)
				throw_api_error (pending.error);

			return pending.result;
		}

		internal async void write_subcommand_chunk (Bytes chunk, Cancellable? cancellable) throws Error, IOError {
			try {
				size_t bytes_written;
				yield output.write_all_async (chunk.get_data (), Priority.DEFAULT, cancellable, out bytes_written);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("Unable to write subcommand chunk: %s", e.message);
			}
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
									Bytes? result;
									if (pending.request_type == RequestType.DATA)
										result = yield read_bytes ();
									else
										result = null;
									pending.complete_with_result (result);

									if (pending.request_type == RequestType.PROTOCOL_CHANGE) {
										is_processing_messages = false;
										return;
									}
								} else {
									var error_message = yield read_string (pending.request_type);
									pending.complete_with_error (
										new Error.NOT_SUPPORTED (error_message));
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
					is_processing_messages = false;
				}
			}
		}

		private async string read_string (RequestType type) throws Error {
			size_t length;
			if (type == SYNC) {
				length = yield read_u32 ();
			} else {
				var length_str = yield read_fixed_string (4);
				length = parse_length (length_str);
			}

			return yield read_fixed_string (length);
		}

		private async string read_fixed_string (size_t length) throws Error {
			var buf = new uint8[length + 1];
			size_t bytes_read;
			try {
				yield input.read_all_async (buf[0:length], Priority.DEFAULT, io_cancellable, out bytes_read);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("Unable to read string: %s", e.message);
			}
			if (bytes_read == 0)
				closed ();
			if (bytes_read != length)
				throw new Error.TRANSPORT ("Unable to read string");
			buf[length] = '\0';
			char * chars = buf;
			return (string) chars;
		}

		private async uint32 read_u32 () throws Error {
			uint32 result = 0;

			unowned uint8[] buf = (uint8[]) &result;
			size_t bytes_read;
			try {
				yield input.read_all_async (buf[0:sizeof (uint32)], Priority.DEFAULT, io_cancellable, out bytes_read);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("Unable to read: %s", e.message);
			}
			if (bytes_read != sizeof (uint32))
				throw new Error.TRANSPORT ("Unable to read");

			return result;
		}

		private async Bytes read_bytes () throws Error {
			var length_str = yield read_fixed_string (4);
			var length = parse_length (length_str);

			var buf = new uint8[length + 1];
			if (length > 0) {
				size_t bytes_read;
				try {
					yield input.read_all_async (buf[0:length], Priority.DEFAULT, io_cancellable, out bytes_read);
				} catch (GLib.Error e) {
					throw new Error.TRANSPORT ("Unable to read: %s", e.message);
				}
				if (bytes_read != length)
					throw new Error.TRANSPORT ("Unable to read");
			}
			buf[length] = '\0';
			buf.length = (int) length;

			return new Bytes.take ((owned) buf);
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
				get;
				private set;
			}

			public Bytes? result {
				get;
				private set;
			}

			public GLib.Error? error {
				get;
				private set;
			}

			public PendingResponse (RequestType request_type, owned CompletionHandler handler) {
				this.request_type = request_type;
				this.handler = (owned) handler;
			}

			public void complete_with_result (Bytes? val) {
				if (handler == null)
					return;
				completed = true;
				result = val;
				handler ();
				handler = null;
			}

			public void complete_with_error (GLib.Error e) {
				if (handler == null)
					return;
				completed = true;
				error = e;
				handler ();
				handler = null;
			}
		}
	}

	public class SyncSession : Object {
		public Client client {
			get;
			construct;
		}

		private Promise<bool> io_request = new Promise<bool> ();

		public SyncSession (Client client) {
			Object (client: client);
		}

		public async void send (Bytes chunk, Cancellable? cancellable = null) throws Error, IOError {
			var future = io_request.future;
			if (future.ready) {
				if (future.error != null)
					throw (Error) future.error;
				else
					throw new Error.PROTOCOL ("Sync session terminated unexpectedly");
			}

			yield client.write_subcommand_chunk (chunk, cancellable);
		}

		public async void finish (Bytes chunk, Cancellable? cancellable = null) throws Error, IOError {
			yield send (chunk, cancellable);

			yield io_request.future.wait_async (cancellable);
		}

		internal void _end (GLib.Error? error) {
			if (error == null)
				io_request.resolve (true);
			else
				io_request.reject (error);
		}
	}
}
