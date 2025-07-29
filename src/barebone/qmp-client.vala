[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	public sealed class QmpClient : Object, AsyncInitable {
		public signal void event (string name, Json.Node? data);

		public string address {
			get;
			construct;
		}

		public uint16 port {
			get;
			construct;
		}

		private IOStream stream;
		private DataInputStream input;
		private OutputStream output;

		private bool is_connected = false;
		private Promise<bool> close_request = new Promise<bool> ();

		private Gee.Map<uint, Promise<Json.Node>> pending_requests = new Gee.HashMap<uint, Promise<Json.Node>> ();
		private uint next_request_id = 1;

		private Cancellable io_cancellable = new Cancellable ();

		private const int COMMAND_TIMEOUT_MS = 30000;

		public QmpClient (string? address = null, uint16 port = 0) {
			Object (
				address: address ?? "localhost",
				port: port != 0 ? port : 4444
			);
		}

		public static async QmpClient open (string? address = null, uint16 port = 0, Cancellable? cancellable = null)
				throws Error, IOError {
			var client = new QmpClient (address, port);

			try {
				yield client.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return client;
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			var connectable = parse_socket_address (address, port, "localhost", 4444);

			SocketConnection connection;
			try {
				var client = new SocketClient ();
				connection = yield client.connect_async (connectable, cancellable);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("Unable to connect to QMP server: %s", e.message);
			}

			var socket = connection.socket;
			if (socket.get_family () != UNIX)
				Tcp.enable_nodelay (socket);

			stream = connection;
			input = new DataInputStream (stream.get_input_stream ());
			input.set_newline_type (DataStreamNewlineType.LF);
			output = stream.get_output_stream ();

			bool started_message_processing = false;
			try {
				is_connected = true;

				string? greeting_line = yield input.read_line_async (Priority.DEFAULT, cancellable);
				if (greeting_line == null)
					throw new Error.TRANSPORT ("Connection closed during QMP greeting");

				process_incoming_messages.begin ();
				started_message_processing = true;

				yield execute_command ("qmp_capabilities", null, cancellable);

				return true;
			} catch (GLib.Error e) {
				is_connected = false;
				if (!started_message_processing)
					close_request.resolve (true);

				if (e is Error)
					throw_api_error (e);
				else
					throw new Error.TRANSPORT ("%s", e.message);
			}
		}

		public async void close (Cancellable? cancellable = null) throws IOError {
			io_cancellable.cancel ();

			try {
				yield close_request.future.wait_async (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}
		}

		public async Json.Node execute_command (string command, Json.Node? arguments = null, Cancellable? cancellable = null)
				throws Error, IOError {
			if (!is_connected)
				throw new Error.INVALID_OPERATION ("QMP client is not connected");

			var b = new Json.Builder ();
			b
				.begin_object ()
				.set_member_name ("execute")
				.add_string_value (command);

			if (arguments != null) {
				b
					.set_member_name ("arguments")
					.add_value (arguments);
			}

			uint request_id = next_request_id++;
			b
				.set_member_name ("id")
				.add_int_value ((int64) request_id);

			Json.Node message = b
				.end_object ()
				.get_root ();

			var promise = new Promise<Json.Node> ();
			pending_requests[request_id] = promise;

			try {
				string line = Json.to_string (message, false) + "\n";
				printerr (">>> %s\n\n", line);
				try {
					yield output.write_all_async (line.data, Priority.DEFAULT, cancellable, null);
				} catch (GLib.Error e) {
					throw new Error.TRANSPORT ("%s", e.message);
				}

				var timeout_source = new TimeoutSource (COMMAND_TIMEOUT_MS);
				timeout_source.set_callback (() => {
					Promise<Json.Node>? p;
					if (pending_requests.unset (request_id, out p))
						p.reject (new Error.TIMED_OUT ("QMP command timed out"));
					return Source.REMOVE;
				});
				timeout_source.attach (MainContext.get_thread_default ());

				try {
					return yield promise.future.wait_async (cancellable);
				} finally {
					timeout_source.destroy ();
				}
			} catch (GLib.Error e) {
				pending_requests.unset (request_id);
				throw_api_error (e);
			}
		}

		private async void process_incoming_messages () {
			try {
				while (is_connected) {
					string? line = yield input.read_line_async (Priority.DEFAULT, io_cancellable);
					if (line == null)
						break;
					printerr ("<<< %s\n\n", line);

					handle_message (Json.from_string (line));
				}
			} catch (GLib.Error e) {
				if (!(e is IOError.CANCELLED))
					printerr ("QMP: Error reading messages: %s\n\n", e.message);
			} finally {
				is_connected = false;

				foreach (var promise in pending_requests.values)
					promise.reject (new Error.TRANSPORT ("QMP connection closed"));
				pending_requests.clear ();
			}

			io_cancellable.cancel ();

			var source = new IdleSource ();
			source.set_callback (process_incoming_messages.callback);
			source.attach (MainContext.get_thread_default ());
			yield;

			try {
				yield stream.close_async ();
			} catch (GLib.Error e) {
			}

			close_request.resolve (true);
		}

		private void handle_message (Json.Node message) throws Error {
			var r = new Json.Reader (message);

			bool is_response = r.read_member ("id");
			uint id = 0;
			if (is_response) {
				id = (uint) r.get_int_value ();
				GLib.Error? e = r.get_error ();
				if (e != null)
					throw new Error.PROTOCOL ("Malformed message: %s", e.message);
			}
			r.end_member ();

			if (is_response)
				handle_response (id, r);
			else
				handle_event (r);
		}

		private void handle_response (uint request_id, Json.Reader r) throws Error {
			Promise<Json.Node>? promise;
			if (!pending_requests.unset (request_id, out promise))
				return;

			if (r.read_member ("error")) {
				r.read_member ("desc");
				string? description = r.get_string_value ();
				if (description == null)
					throw new Error.PROTOCOL ("Malformed message: %s", r.get_error ().message);
				r.end_member ();

				promise.reject (new Error.NOT_SUPPORTED ("%s", description));
				return;
			}
			r.end_member ();

			r.read_member ("return");
			if (!r.is_object ())
				throw new Error.PROTOCOL ("Malformed event message: 'return' must be an object");
			promise.resolve (r.get_current_node ());
		}

		private void handle_event (Json.Reader r) throws Error {
			r.read_member ("event");
			string? name = r.get_string_value ();
			if (name == null)
				throw new Error.PROTOCOL ("Malformed event message: missing 'event' property");
			r.end_member ();

			Json.Node? data = null;
			if (r.read_member ("data")) {
				if (!r.is_object ())
					throw new Error.PROTOCOL ("Malformed event message: 'data' must be an object");
				data = r.get_current_node ();
			}
			r.end_member ();

			event (name, data);
		}
	}
}
