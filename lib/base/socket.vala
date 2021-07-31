namespace Frida {
	public const uint16 DEFAULT_CONTROL_PORT = 27042;
	public const uint16 DEFAULT_CLUSTER_PORT = 27052;

	public SocketConnectable parse_control_address (string? address, uint16 port = 0) throws Error {
		return parse_socket_address (address, port, "127.0.0.1", DEFAULT_CONTROL_PORT);
	}

	public SocketConnectable parse_cluster_address (string? address, uint16 port = 0) throws Error {
		return parse_socket_address (address, port, "127.0.0.1", DEFAULT_CLUSTER_PORT);
	}

	public SocketConnectable parse_socket_address (string? address, uint16 port, string default_address,
			uint16 default_port) throws Error {
		if (address == null)
			address = default_address;
		if (port == 0)
			port = default_port;

#if !WINDOWS
		if (address.has_prefix ("unix:")) {
			string path = address.substring (5);

			UnixSocketAddressType type = UnixSocketAddress.abstract_names_supported ()
				? UnixSocketAddressType.ABSTRACT
				: UnixSocketAddressType.PATH;

			return new UnixSocketAddress.with_type (path, -1, type);
		}
#endif

		try {
			return NetworkAddress.parse (address, port);
		} catch (GLib.Error e) {
			throw new Error.INVALID_ARGUMENT ("%s", e.message);
		}
	}

	namespace Tcp {
		public extern void enable_nodelay (Socket socket);
	}

	public class EndpointParameters : Object {
		public string? address {
			get;
			construct;
		}

		public uint16 port {
			get;
			construct;
		}

		public TlsCertificate? certificate {
			get;
			construct;
		}

		public string? origin {
			get;
			construct;
		}

		public AuthenticationService? auth_service {
			get;
			construct;
		}

		public File? asset_root {
			get;
			set;
		}

		public EndpointParameters (string? address = null, uint16 port = 0, TlsCertificate? certificate = null,
				string? origin = null, AuthenticationService? auth_service = null, File? asset_root = null) {
			Object (
				address: address,
				port: port,
				certificate: certificate,
				origin: origin,
				auth_service: auth_service,
				asset_root: asset_root
			);
		}
	}

	public async IOStream negotiate_connection (IOStream stream, WebServiceTransport transport, string host, string? origin,
			Cancellable? cancellable) throws Error, IOError {
		var input = (DataInputStream) Object.new (typeof (DataInputStream),
			"base-stream", stream.get_input_stream (),
			"close-base-stream", false,
			"newline-type", DataStreamNewlineType.CR_LF);
		OutputStream output = stream.get_output_stream ();

		var request = new StringBuilder.sized (256);
		request.append ("GET /ws HTTP/1.1\r\n");
		string protocol = (transport == TLS) ? "wss" : "ws";
		string canonical_host = canonicalize_host (host);
		string uri = protocol + "://" + canonical_host + "/ws";
		var msg = new Soup.Message ("GET", uri);
		Soup.websocket_client_prepare_handshake (msg, origin, null);
		msg.request_headers.replace ("Host", canonical_host);
		msg.request_headers.replace ("User-Agent", "Frida/" + _version_string ());
		msg.request_headers.foreach ((name, val) => {
			request.append (name + ": " + val + "\r\n");
		});
		request.append ("\r\n");

		var response = new StringBuilder.sized (256);
		try {
			size_t bytes_written;
			yield output.write_all_async (request.str.data, Priority.DEFAULT, cancellable, out bytes_written);

			string? line = null;
			do {
				size_t length;
				line = yield input.read_line_async (Priority.DEFAULT, cancellable, out length);
				if (line == null)
					throw new Error.TRANSPORT ("Connection closed");
				if (line != "")
					response.append (line + "\r\n");
			} while (line != "");
		} catch (GLib.Error e) {
			if (e is IOError.CANCELLED)
				throw (IOError) e;
			throw new Error.TRANSPORT ("%s", e.message);
		}

		var headers = new Soup.MessageHeaders (RESPONSE);
		Soup.HTTPVersion ver;
		uint status_code;
		string reason_phrase;
		if (!Soup.headers_parse_response (response.str, (int) response.len, headers, out ver, out status_code,
				out reason_phrase)) {
			throw new Error.PROTOCOL ("Invalid response");
		}

		if (status_code != Soup.Status.SWITCHING_PROTOCOLS) {
			if (status_code == Soup.Status.FORBIDDEN)
				throw new Error.INVALID_ARGUMENT ("Incorrect origin");
			else
				throw new Error.PROTOCOL ("%s", reason_phrase);
		}

		WebConnection connection = null;
		var frida_context = MainContext.ref_thread_default ();
		var dbus_context = yield get_dbus_context ();
		var dbus_source = new IdleSource ();
		dbus_source.set_callback (() => {
			var websocket = new Soup.WebsocketConnection (stream, msg.uri, CLIENT, origin, null);
			connection = new WebConnection (websocket);

			var frida_source = new IdleSource ();
			frida_source.set_callback (negotiate_connection.callback);
			frida_source.attach (frida_context);

			return false;
		});
		dbus_source.attach (dbus_context);
		yield;

		return connection;
	}

	private string canonicalize_host (string raw_host) {
		if (raw_host.has_suffix (":80") || raw_host.has_suffix (":443")) {
			string[] tokens = raw_host.split (":", 2);
			return tokens[0];
		}

		return raw_host;
	}

	public class WebService : Object {
		public signal void incoming (IOStream connection, SocketAddress remote_address);

		public EndpointParameters endpoint_params {
			get;
			construct;
		}

		public WebServiceFlavor flavor {
			get;
			construct;
		}

		public PortConflictBehavior on_port_conflict {
			get;
			construct;
			default = FAIL;
		}

		public SocketAddress? listen_address {
			get {
				return _listen_address;
			}
		}

		private Soup.Server? server;
		private SocketAddress? _listen_address;

		private Cancellable io_cancellable = new Cancellable ();

		private MainContext? frida_context;
		private MainContext? dbus_context;

		public WebService (EndpointParameters endpoint_params, WebServiceFlavor flavor,
				PortConflictBehavior on_port_conflict = FAIL) {
			Object (
				endpoint_params: endpoint_params,
				flavor: flavor,
				on_port_conflict: on_port_conflict
			);
		}

		public async void start (Cancellable? cancellable) throws Error, IOError {
			frida_context = MainContext.ref_thread_default ();
			dbus_context = yield get_dbus_context ();

			cancellable.set_error_if_cancelled ();

			var start_request = new Promise<SocketAddress> ();
			schedule_on_dbus_thread (() => {
				handle_start_request.begin (start_request, cancellable);
				return false;
			});

			_listen_address = yield start_request.future.wait_async (cancellable);
		}

		private async void handle_start_request (Promise<SocketAddress> start_request, Cancellable? cancellable) {
			try {
				SocketAddress effective_address = yield do_start (cancellable);
				schedule_on_frida_thread (() => {
					start_request.resolve (effective_address);
					return false;
				});
			} catch (GLib.Error e) {
				GLib.Error start_error = e;
				schedule_on_frida_thread (() => {
					start_request.reject (start_error);
					return false;
				});
			}
		}

		private async SocketAddress do_start (Cancellable? cancellable) throws Error, IOError {
			server = (Soup.Server) Object.new (typeof (Soup.Server),
				"tls-certificate", endpoint_params.certificate);

			server.add_websocket_handler ("/ws", endpoint_params.origin, null, on_websocket_opened);

			if (endpoint_params.asset_root != null)
				server.add_handler ("/", on_asset_request);

			SocketConnectable connectable = (flavor == CONTROL)
				? parse_control_address (endpoint_params.address, endpoint_params.port)
				: parse_cluster_address (endpoint_params.address, endpoint_params.port);

			Soup.ServerListenOptions listen_options = (endpoint_params.certificate != null)
				? Soup.ServerListenOptions.HTTPS
				: 0;

			SocketAddress? first_effective_address = null;
			var enumerator = connectable.enumerate ();
			while (true) {
				SocketAddress? address;
				try {
					address = yield enumerator.next_async (io_cancellable);
				} catch (GLib.Error e) {
					throw new Error.NOT_SUPPORTED ("%s", e.message);
				}
				if (address == null)
					break;

				SocketAddress? effective_address = null;
				InetSocketAddress? inet_address = address as InetSocketAddress;
				if (inet_address != null) {
					uint16 start_port = inet_address.get_port ();
					uint16 candidate_port = start_port;
					do {
						try {
							server.listen (inet_address, listen_options);
							effective_address = inet_address;
						} catch (GLib.Error e) {
							if (e is IOError.ADDRESS_IN_USE && on_port_conflict == PICK_NEXT) {
								candidate_port++;
								if (candidate_port == start_port)
									throw new Error.ADDRESS_IN_USE ("Unable to bind to any port");
								if (candidate_port == 0)
									candidate_port = 1024;
								inet_address = new InetSocketAddress (inet_address.get_address (),
									candidate_port);
							} else {
								throw_listen_error (e);
							}
						}
					} while (effective_address == null);
				} else {
					try {
						server.listen (address, listen_options);
						effective_address = address;
					} catch (GLib.Error e) {
						throw_listen_error (e);
					}
				}

				if (first_effective_address == null)
					first_effective_address = effective_address;
			}

			if (first_effective_address == null)
				throw new Error.NOT_SUPPORTED ("Unable to resolve listening address");

			return first_effective_address;
		}

		[NoReturn]
		private static void throw_listen_error (GLib.Error e) throws Error {
			if (e is IOError.ADDRESS_IN_USE)
				throw new Error.ADDRESS_IN_USE ("%s", e.message);

			if (e is IOError.PERMISSION_DENIED)
				throw new Error.PERMISSION_DENIED ("%s", e.message);

			throw new Error.NOT_SUPPORTED ("%s", e.message);
		}

		public void stop () {
			if (server != null)
				server.disconnect ();

			io_cancellable.cancel ();
		}

		private void on_websocket_opened (Soup.Server server, Soup.WebsocketConnection connection, string path,
				Soup.ClientContext client) {
			var peer = new WebConnection (connection);
			SocketAddress remote_address = client.get_remote_address ();

			schedule_on_frida_thread (() => {
				incoming (peer, remote_address);
				return false;
			});
		}

		private void on_asset_request (Soup.Server server, Soup.Message msg, string path, HashTable<string, string>? query,
				Soup.ClientContext client) {
			msg.response_headers.replace ("Server", "Frida/" + _version_string ());

			string method = msg.method;
			if (method != "GET" && method != "HEAD") {
				msg.set_status (Soup.Status.METHOD_NOT_ALLOWED);
				return;
			}

			File asset_root = endpoint_params.asset_root;

			File location = (path != "/")
				? asset_root.resolve_relative_path (path.next_char ())
				: asset_root.resolve_relative_path ("index.html");

			server.pause_message (msg);
			handle_asset_request.begin (location, msg);
		}

		private async void handle_asset_request (File file, Soup.Message msg) {
			int priority = Priority.DEFAULT;

			FileInputStream stream;
			FileInfo info;
			try {
				stream = yield file.read_async (priority, io_cancellable);
				info = yield stream.query_info_async (FileAttribute.STANDARD_SIZE, priority, io_cancellable);
			} catch (GLib.Error e) {
				msg.set_status (Soup.Status.NOT_FOUND);
				server.unpause_message (msg);
				return;
			}

			msg.set_status (Soup.Status.OK);

			var headers = msg.response_headers;
			headers.replace ("Content-Type", guess_mime_type_for (file.get_path ()));
			headers.replace ("Content-Length", info.get_size ().to_string ());

			if (msg.method == "HEAD") {
				server.unpause_message (msg);
				return;
			}

			var body = msg.response_body;
			body.set_accumulate (false);

			bool finished = false;
			bool waiting = false;
			ulong finished_handler = msg.finished.connect (() => {
				finished = true;
				if (waiting)
					handle_asset_request.callback ();
			});
			ulong write_handler = msg.wrote_body_data.connect (chunk => {
				if (waiting)
					handle_asset_request.callback ();
			});
			try {
				var buffer = new uint8[64 * 1024];
				while (true) {
					ssize_t n;
					try {
						n = yield stream.read_async (buffer, priority, io_cancellable);
					} catch (IOError e) {
						break;
					}
					if (n == 0 || finished)
						break;

					body.append_take (buffer[0:n]);

					server.unpause_message (msg);

					waiting = true;
					yield;
					waiting = false;

					if (finished)
						break;

					server.pause_message (msg);
				}
			} finally {
				msg.disconnect (write_handler);
				msg.disconnect (finished_handler);
				if (!finished)
					server.unpause_message (msg);
			}
		}

		private static string guess_mime_type_for (string path) {
			if (path.has_suffix (".html"))
				return "text/html";

			if (path.has_suffix (".js"))
				return "text/javascript";

			if (path.has_suffix (".json"))
				return "application/json";

			if (path.has_suffix (".css"))
				return "text/css";

			if (path.has_suffix (".jpeg") || path.has_suffix (".jpg"))
				return "image/jpeg";

			if (path.has_suffix (".png"))
				return "image/png";

			bool uncertain;
			return ContentType.guess (path, null, out uncertain);
		}

		private void schedule_on_frida_thread (owned SourceFunc function) {
			assert (frida_context != null);

			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (frida_context);
		}

		private void schedule_on_dbus_thread (owned SourceFunc function) {
			assert (dbus_context != null);

			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (dbus_context);
		}
	}

	public enum WebServiceTransport {
		PLAIN,
		TLS
	}

	public enum WebServiceFlavor {
		CONTROL,
		CLUSTER
	}

	public enum PortConflictBehavior {
		FAIL,
		PICK_NEXT
	}

	public extern static unowned string _version_string ();

	private class WebConnection : IOStream {
		public Soup.WebsocketConnection websocket {
			get;
			construct;
		}

		public override InputStream input_stream {
			get {
				return _input_stream;
			}
		}

		public override OutputStream output_stream {
			get {
				return _output_stream;
			}
		}

		public IOCondition pending_io {
			get {
				lock (state)
					return _pending_io;
			}
		}

		private WebInputStream _input_stream;
		private WebOutputStream _output_stream;

		private Soup.WebsocketState state;
		private IOCondition _pending_io;
		private ByteArray recv_queue = new ByteArray ();
		private ByteArray send_queue = new ByteArray ();

		private Gee.Map<unowned Source, IOCondition> sources = new Gee.HashMap<unowned Source, IOCondition> ();

		private MainContext main_context;

		public WebConnection (Soup.WebsocketConnection websocket) {
			Object (websocket: websocket);
		}

		construct {
			websocket.max_incoming_payload_size = (256 * 1024) + 1; // XXX: There's an off-by-one error in libsoup

			_input_stream = new WebInputStream (this);
			_output_stream = new WebOutputStream (this);

			state = websocket.state;
			_pending_io = (state == OPEN) ? IOCondition.OUT : IOCondition.IN;

			main_context = MainContext.ref_thread_default ();

			websocket.closed.connect (on_closed);
			websocket.message.connect (on_message);
		}

		~WebConnection () {
			websocket.message.disconnect (on_message);
			websocket.closed.disconnect (on_closed);
		}

		public override bool close (GLib.Cancellable? cancellable) throws IOError {
			_close ();
			return true;
		}

		public override async bool close_async (int io_priority, GLib.Cancellable? cancellable) throws IOError {
			_close ();
			return true;
		}

		private void _close () {
			if (main_context.is_owner ()) {
				do_close ();
			} else {
				var source = new IdleSource ();
				source.set_callback (() => {
					do_close ();
					return false;
				});
				source.attach (main_context);
			}
		}

		private void do_close () {
			if (websocket.state != OPEN)
				return;

			websocket.close (1000, "Closing");
		}

		public ssize_t recv (uint8[] buffer) throws IOError {
			size_t n;

			lock (state) {
				n = size_t.min (recv_queue.len, buffer.length);
				if (n == 0) {
					if (state == OPEN)
						throw new IOError.WOULD_BLOCK ("Resource temporarily unavailable");
					return 0;
				}

				Memory.copy (buffer, recv_queue.data, n);
				recv_queue.remove_range (0, (uint) n);

				recompute_pending_io_unlocked ();
			}

			return (ssize_t) n;
		}

		public ssize_t send (uint8[] buffer) {
			lock (state)
				send_queue.append (buffer);

			if (main_context.is_owner ()) {
				process_send_queue ();
			} else {
				var source = new IdleSource ();
				source.set_callback (() => {
					process_send_queue ();
					return false;
				});
				source.attach (main_context);
			}

			return buffer.length;
		}

		private void process_send_queue () {
			if (websocket.state != OPEN)
				return;

			size_t max_message_size = (size_t) websocket.max_incoming_payload_size - 1;

			while (true) {
				uint8[]? chunk = null;
				lock (state) {
					size_t n = size_t.min (send_queue.len, max_message_size);
					if (n == 0)
						return;
					chunk = send_queue.data[0:n];
					send_queue.remove_range (0, (uint) n);
				}

				websocket.send_binary (chunk);
			}
		}

		public void register_source (Source source, IOCondition condition) {
			lock (state)
				sources[source] = condition;
		}

		public void unregister_source (Source source) {
			lock (state)
				sources.unset (source);
		}

		private void on_closed () {
			lock (state) {
				state = websocket.state;
				recompute_pending_io_unlocked ();
			}
		}

		private void on_message (int type, Bytes message) {
			lock (state) {
				recv_queue.append (message.get_data ());
				recompute_pending_io_unlocked ();
			}
		}

		private void recompute_pending_io_unlocked () {
			IOCondition new_io = 0;
			if (recv_queue.len > 0 || state != OPEN)
				new_io |= IN;
			if (state == OPEN)
				new_io |= OUT;
			_pending_io = new_io;

			foreach (var entry in sources.entries) {
				Source source = entry.key;
				IOCondition c = entry.value;
				if ((new_io & c) != 0)
					source.set_ready_time (0);
			}
		}
	}

	private class WebInputStream : InputStream, PollableInputStream {
		public weak WebConnection connection {
			get;
			construct;
		}

		public WebInputStream (WebConnection connection) {
			Object (connection: connection);
		}

		public override bool close (Cancellable? cancellable) throws IOError {
			return true;
		}

		public override async bool close_async (int io_priority, Cancellable? cancellable) throws GLib.IOError {
			return close (cancellable);
		}

		public override ssize_t read (uint8[] buffer, Cancellable? cancellable) throws IOError {
			assert_not_reached ();
		}

		public bool can_poll () {
			return true;
		}

		public bool is_readable () {
			return (connection.pending_io & IOCondition.IN) != 0;
		}

		public PollableSource create_source (Cancellable? cancellable) {
			return new PollableSource.full (this, new WebIOSource (connection, IOCondition.IN), cancellable);
		}

		public ssize_t read_nonblocking_fn (uint8[] buffer) throws GLib.Error {
			return connection.recv (buffer);
		}
	}

	private class WebOutputStream : OutputStream, PollableOutputStream {
		public weak WebConnection connection {
			get;
			construct;
		}

		public WebOutputStream (WebConnection connection) {
			Object (connection: connection);
		}

		public override bool close (Cancellable? cancellable) throws IOError {
			return true;
		}

		public override async bool close_async (int io_priority, Cancellable? cancellable) throws GLib.IOError {
			return close (cancellable);
		}

		public override bool flush (GLib.Cancellable? cancellable) throws GLib.Error {
			return true;
		}

		public override async bool flush_async (int io_priority, GLib.Cancellable? cancellable) throws GLib.Error {
			return true;
		}

		public override ssize_t write (uint8[] buffer, Cancellable? cancellable) throws IOError {
			assert_not_reached ();
		}

		public bool can_poll () {
			return true;
		}

		public bool is_writable () {
			return (connection.pending_io & IOCondition.OUT) != 0;
		}

		public PollableSource create_source (Cancellable? cancellable) {
			return new PollableSource.full (this, new WebIOSource (connection, IOCondition.OUT), cancellable);
		}

		public ssize_t write_nonblocking_fn (uint8[]? buffer) throws GLib.Error {
			return connection.send (buffer);
		}

		public PollableReturn writev_nonblocking_fn (OutputVector[] vectors, out size_t bytes_written) throws GLib.Error {
			assert_not_reached ();
		}
	}

	private class WebIOSource : Source {
		public WebConnection connection;
		public IOCondition condition;

		public WebIOSource (WebConnection connection, IOCondition condition) {
			this.connection = connection;
			this.condition = condition;

			connection.register_source (this, condition);
		}

		~WebIOSource () {
			connection.unregister_source (this);
		}

		protected override bool prepare (out int timeout) {
			timeout = -1;
			return (connection.pending_io & condition) != 0;
		}

		protected override bool check () {
			return (connection.pending_io & condition) != 0;
		}

		protected override bool dispatch (SourceFunc? callback) {
			set_ready_time (-1);

			if (callback == null)
				return Source.REMOVE;

			return callback ();
		}

		protected static bool closure_callback (Closure closure) {
			var return_value = Value (typeof (bool));

			closure.invoke (ref return_value, {});

			return return_value.get_boolean ();
		}
	}
}
