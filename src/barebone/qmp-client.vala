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

		private SocketConnection connection;
		private DataInputStream input;
		private OutputStream output;

		private bool is_connected = false;
		private Promise<bool> close_request = new Promise<bool> ();

		private Gee.Map<uint, Promise<Json.Node>> pending_requests = new Gee.HashMap<uint, Promise<Json.Node>> ();
		private uint next_request_id = 1;

		private Cancellable io_cancellable = new Cancellable ();

		private const int REQUEST_TIMEOUT_MS = 30000;

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

			try {
				var client = new SocketClient ();
				connection = yield client.connect_async (connectable, cancellable);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("Unable to connect to QMP server: %s", e.message);
			}

			var socket = connection.socket;
			if (socket.get_family () != UNIX)
				Tcp.enable_nodelay (socket);

			input = new DataInputStream (connection.get_input_stream ());
			input.set_newline_type (DataStreamNewlineType.LF);
			output = connection.get_output_stream ();

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

		public async Hostlink open_hostlink (Cancellable? cancellable = null) throws Error, IOError {
#if WINDOWS
			throw new Error.NOT_SUPPORTED ("Missing open_hostlink() for Windows");
#else
			uint64 mmio = (uint64) yield get_qom_property_int ("/machine", "hostlink-mmio", cancellable);
			uint irq = (uint) yield get_qom_property_int ("/machine", "hostlink-irq", cancellable);
			string bus = yield get_qom_property_string ("/machine", "hostlink-bus", cancellable);

			int fds[2];
			if (Posix.socketpair (Posix.AF_UNIX, Posix.SOCK_STREAM, 0, fds) != 0)
				throw new Error.NOT_SUPPORTED ("Unable to allocate socketpair");

			Socket local_sock, remote_sock;
			try {
				local_sock = new Socket.from_fd (fds[0]);
				remote_sock = new Socket.from_fd (fds[1]);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("%s", e.message);
			}

			string fd_name = "appfd";
			yield getfd (fd_name, fds[1], cancellable);

			string chardev = "vserial0";
			yield add_chardev_from_fd (chardev, fd_name, cancellable);

			yield add_serial_port (chardev, bus, "re.frida.hostlink", "hostlink.port", 1, cancellable);

			return new Hostlink () {
				connection = SocketConnection.factory_create_connection (local_sock),
				mmio = mmio,
				irq = irq,
			};
#endif
		}

		public class Hostlink {
			public SocketConnection connection;
			public uint64 mmio;
			public uint irq;
		}

		private async int64 get_qom_property_int (string path, string property, Cancellable? cancellable) throws Error, IOError {
			var val = yield get_qom_property (path, property, cancellable);
			if (val.get_value_type () != typeof (int64))
				throw new Error.PROTOCOL ("Expected '%s' property on %s to be an integer", property, path);
			return val.get_int ();
		}

		private async string get_qom_property_string (string path, string property, Cancellable? cancellable)
				throws Error, IOError {
			var val = yield get_qom_property (path, property, cancellable);
			if (val.get_value_type () != typeof (string))
				throw new Error.PROTOCOL ("Expected '%s' property on %s to be a string", property, path);
			return val.get_string ();
		}

		private async Json.Node get_qom_property (string path, string property, Cancellable? cancellable) throws Error, IOError {
			var args = new Json.Builder ();
			args
				.begin_object ()
					.set_member_name ("path")
					.add_string_value (path)
					.set_member_name ("property")
					.add_string_value (property)
				.end_object ();
			return yield execute_command ("qom-get", args.get_root (), cancellable);
		}

		private async void getfd (string name, int fd, Cancellable? cancellable) throws Error, IOError {
			var args = new Json.Builder ();
			args
				.begin_object ()
					.set_member_name ("fdname")
					.add_string_value (name)
				.end_object ();
			yield execute_command_with_file_descriptor ("getfd", args.get_root (), fd, cancellable);
		}

		private async void add_chardev_from_fd (string id, string fd_name, Cancellable? cancellable) throws Error, IOError {
			var args = new Json.Builder ();
			args
				.begin_object ()
					.set_member_name ("id")
					.add_string_value (id)
					.set_member_name ("backend")
					.begin_object ()
						.set_member_name ("type")
						.add_string_value ("socket")
						.set_member_name ("data")
						.begin_object ()
							.set_member_name ("server")
							.add_boolean_value (false)
							.set_member_name ("addr")
							.begin_object ()
								.set_member_name ("type")
								.add_string_value ("fd")
								.set_member_name ("data")
								.begin_object ()
									.set_member_name ("str")
									.add_string_value (fd_name)
								.end_object ()
							.end_object ()
						.end_object ()
					.end_object ()
				.end_object ();
			yield execute_command ("chardev-add", args.get_root (), cancellable);
		}

		private async void add_serial_port (string chardev, string bus, string name, string id, uint nr, Cancellable? cancellable)
				throws Error, IOError {
			var args = new Json.Builder ();
			args
				.begin_object ()
					.set_member_name ("driver")
					.add_string_value ("virtserialport")
					.set_member_name ("chardev")
					.add_string_value (chardev)
					.set_member_name ("bus")
					.add_string_value (bus)
					.set_member_name ("name")
					.add_string_value (name)
					.set_member_name ("id")
					.add_string_value (id)
					.set_member_name ("nr")
					.add_int_value ((int64) nr)
				.end_object ();
			yield execute_command ("device_add", args.get_root (), cancellable);
		}

		public async Json.Node execute_command (string command, Json.Node? arguments = null, Cancellable? cancellable = null)
				throws Error, IOError {
			check_connected ();

			Request request = begin_request (command, arguments);

			try {
				yield output.write_all_async (request.json.data, Priority.DEFAULT, cancellable, null);
			} catch (GLib.Error e) {
				cancel_request (request);
				throw new Error.TRANSPORT ("%s", e.message);
			}

			return yield join_request (request, cancellable);
		}

		public async Json.Node execute_command_with_file_descriptor (string command, Json.Node? arguments = null, int fd,
				Cancellable? cancellable = null) throws Error, IOError {
			check_connected ();

#if WINDOWS
			throw new Error.NOT_SUPPORTED ("Executing command with SocketControlMessage is not supported on Windows");
#else
			Request request = begin_request (command, arguments);

			var scm = new UnixFDMessage ();
			try {
				scm.append_fd (fd);
			} catch (GLib.Error e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}

			Socket s = connection.get_socket ();

			unowned uint8[] raw_command = request.json.data;

			OutputVector vectors[1] = {
				OutputVector () {
					buffer = raw_command,
					size = raw_command.length,
				},
			};
			SocketControlMessage scms[1] = { scm };

			ssize_t n;
			try {
				n = s.send_message (null, vectors, scms, 0, cancellable);
			} catch (GLib.Error e) {
				cancel_request (request);
				throw new Error.TRANSPORT ("%s", e.message);
			}

			if (n != raw_command.length) {
				try {
					yield output.write_all_async (raw_command[n:], Priority.DEFAULT, cancellable, null);
				} catch (GLib.Error e) {
					cancel_request (request);
					throw new Error.TRANSPORT ("%s", e.message);
				}
			}

			return yield join_request (request, cancellable);
#endif
		}

		private Request begin_request (string command, Json.Node? arguments) {
			uint id = next_request_id++;

			var promise = new Promise<Json.Node> ();
			pending_requests[id] = promise;

			string json = build_request (command, id, arguments);

			return new Request () {
				promise = promise,
				json = json,
				id = id,
			};
		}

		private static string build_request (string command, uint id, Json.Node? arguments) {
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

			b
				.set_member_name ("id")
				.add_int_value ((int64) id);

			Json.Node message = b.end_object ().get_root ();

			return Json.to_string (message, false) + "\n";
		}

		private async Json.Node join_request (Request request, Cancellable? cancellable) throws Error, IOError {
			var timeout_source = new TimeoutSource (REQUEST_TIMEOUT_MS);
			timeout_source.set_callback (() => {
				Promise<Json.Node>? p;
				if (pending_requests.unset (request.id, out p))
					p.reject (new Error.TIMED_OUT ("QMP command timed out"));
				return Source.REMOVE;
			});
			timeout_source.attach (MainContext.get_thread_default ());

			try {
				return yield request.promise.future.wait_async (cancellable);
			} finally {
				timeout_source.destroy ();
			}
		}

		private void cancel_request (Request r) {
			pending_requests.unset (r.id);
		}

		private class Request {
			public Promise<Json.Node> promise;
			public string json;
			public uint id;
		}

		private void check_connected () throws Error {
			if (!is_connected)
				throw new Error.INVALID_OPERATION ("QMP client is not connected");
		}

		private async void process_incoming_messages () {
			try {
				while (is_connected) {
					string? line = yield input.read_line_async (Priority.DEFAULT, io_cancellable);
					if (line == null)
						break;

					handle_message (Json.from_string (line));
				}
			} catch (GLib.Error e) {
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
				yield connection.close_async ();
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
