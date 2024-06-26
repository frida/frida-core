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

	namespace UnixSocket {
		public extern void tune_buffer_sizes (int fd);
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
		Soup.websocket_client_prepare_handshake (msg, origin, null, null);
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
			var websocket = new Soup.WebsocketConnection (stream, msg.uri, CLIENT, origin, protocol,
				new List<Soup.WebsocketExtension> ());
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
				server.add_handler (null, on_asset_request);

			SocketConnectable connectable = (flavor == CONTROL)
				? parse_control_address (endpoint_params.address, endpoint_params.port)
				: parse_cluster_address (endpoint_params.address, endpoint_params.port);

			Soup.ServerListenOptions listen_options = (endpoint_params.certificate != null)
				? Soup.ServerListenOptions.HTTPS
				: 0;

			var prototype_enumerator = new EndpointEnumerator ();

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
			io_cancellable.cancel ();

			schedule_on_dbus_thread (() => {
				do_stop ();
				return false;
			});
		}

		private void do_stop () {
			if (server == null)
				return;

			if (endpoint_params.asset_root != null)
				server.remove_handler ("/");
			server.remove_handler ("/ws");

			server.disconnect ();
		}

		private void on_websocket_opened (Soup.Server server, Soup.ServerMessage msg, string path,
				Soup.WebsocketConnection connection) {
			var peer = new WebConnection (connection);

			IOStream soup_stream = connection.get_io_stream ();

			SocketConnection socket_stream;
			soup_stream.get ("base-iostream", out socket_stream);

			SocketAddress remote_address;
			try {
				remote_address = socket_stream.get_remote_address ();
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			schedule_on_frida_thread (() => {
				incoming (peer, remote_address);
				return false;
			});
		}

		private void on_asset_request (Soup.Server server, Soup.ServerMessage msg, string path, HashTable<string, string>? query) {
			msg.get_response_headers ().replace ("Server", "Frida/" + _version_string ());

			unowned string method = msg.get_method ();
			if (method != "GET" && method != "HEAD") {
				msg.set_status (Soup.Status.METHOD_NOT_ALLOWED, null);
				return;
			}

			File location = endpoint_params.asset_root.resolve_relative_path (path.next_char ());

			msg.pause ();
			handle_asset_request.begin (path, location, msg);
		}

		private async void handle_asset_request (string path, File file, Soup.ServerMessage msg) {
			int priority = Priority.DEFAULT;

			string attributes = FileAttribute.STANDARD_TYPE + "," + FileAttribute.STANDARD_SIZE;

			FileInfo info;
			FileInputStream? stream = null;
			try {
				info = yield file.query_info_async (attributes, FileQueryInfoFlags.NONE, priority, io_cancellable);

				FileType type = info.get_file_type ();
				if (type == DIRECTORY) {
					if (!path.has_suffix ("/")) {
						handle_misplaced_request (path + "/", msg);
						return;
					}

					File index_file = file.get_child ("index.html");
					try {
						var index_info = yield index_file.query_info_async (attributes, FileQueryInfoFlags.NONE,
							priority, io_cancellable);
						file = index_file;
						info = index_info;
						type = index_info.get_file_type ();
					} catch (GLib.Error e) {
					}
				}

				if (type != DIRECTORY)
					stream = yield file.read_async (priority, io_cancellable);
			} catch (GLib.Error e) {
				msg.set_status (Soup.Status.NOT_FOUND, null);
				msg.unpause ();
				return;
			}

			if (stream == null)
				yield handle_directory_request (path, file, msg);
			else
				yield handle_file_request (file, info, stream, msg);
		}

		private async void handle_directory_request (string path, File file, Soup.ServerMessage msg) {
			var listing = new StringBuilder.sized (1024);

			string escaped_path = Markup.escape_text (path);
			listing.append ("""<html>
<head><title>Index of %s</title></head>
<body>
<h1>Index of %s</h1><hr><pre>""".printf (escaped_path, escaped_path));

			if (path != "/")
				listing.append ("<a href=\"../\">../</a>");

			listing.append_c ('\n');

			string attributes =
				FileAttribute.STANDARD_DISPLAY_NAME + "," +
				FileAttribute.STANDARD_TYPE + "," +
				FileAttribute.TIME_MODIFIED + "," +
				FileAttribute.STANDARD_SIZE;
			int priority = Priority.DEFAULT;

			try {
				var enumerator = yield file.enumerate_children_async (attributes, FileQueryInfoFlags.NONE, priority,
					io_cancellable);

				List<FileInfo> files = yield enumerator.next_files_async (int.MAX, priority, io_cancellable);

				files.sort ((a, b) => {
					bool a_is_dir = a.get_file_type () == DIRECTORY;
					bool b_is_dir = b.get_file_type () == DIRECTORY;
					if (a_is_dir == b_is_dir)
						return strcmp (a.get_display_name (), b.get_display_name ());
					else if (a_is_dir)
						return -1;
					else
						return 1;
				});

				foreach (FileInfo info in files) {
					string display_name = info.get_display_name ();
					FileType type = info.get_file_type ();
					DateTime modified = info.get_modification_date_time ().to_local ();

					string link = Markup.escape_text (display_name);
					if (type == DIRECTORY)
						link += "/";

					listing
						.append ("<a href=\"")
						.append (link)
						.append ("\">")
						.append (link)
						.append ("</a>");

					int padding_needed = 50 - link.length;
					while (padding_needed > 0) {
						listing.append_c (' ');
						padding_needed--;
					}

					listing
						.append_c (' ')
						.append (modified.format ("%d-%b-%Y %H:%M"))
						.append ("            ");

					string size_info;
					if (type != DIRECTORY)
						size_info = info.get_size ().to_string ();
					else
						size_info = "-";
					listing.append_printf ("%8s\n", size_info);
				}
			} catch (GLib.Error e) {
				msg.set_status (Soup.Status.NOT_FOUND, null);
				msg.unpause ();
				return;
			}

			listing.append ("</pre><hr></body>\n</html>");

			msg.set_status (Soup.Status.OK, null);

			if (msg.get_method () == "HEAD") {
				var headers = msg.get_response_headers ();
				headers.replace ("Content-Type", "text/html");
				headers.replace ("Content-Length", listing.len.to_string ());
			} else {
				msg.set_response ("text/html", Soup.MemoryUse.COPY, listing.str.data);
			}

			msg.unpause ();
		}

		private async void handle_file_request (File file, FileInfo info, FileInputStream stream, Soup.ServerMessage msg) {
			msg.set_status (Soup.Status.OK, null);

			var headers = msg.get_response_headers ();
			headers.replace ("Content-Type", guess_mime_type_for (file.get_path ()));
			headers.replace ("Content-Length", info.get_size ().to_string ());

			if (msg.get_method () == "HEAD") {
				msg.unpause ();
				return;
			}

			var body = msg.get_response_body ();
			body.set_accumulate (false);

			bool finished = false;
			bool waiting = false;
			ulong finished_handler = msg.finished.connect (() => {
				finished = true;
				if (waiting)
					handle_file_request.callback ();
			});
			ulong write_handler = msg.wrote_body_data.connect (chunk => {
				if (waiting)
					handle_file_request.callback ();
			});
			try {
				var buffer = new uint8[64 * 1024];
				while (true) {
					ssize_t n;
					try {
						n = yield stream.read_async (buffer, Priority.DEFAULT, io_cancellable);
					} catch (IOError e) {
						break;
					}
					if (n == 0 || finished)
						break;

					body.append_take (buffer[0:n]);

					msg.unpause ();

					waiting = true;
					yield;
					waiting = false;

					if (finished)
						break;

					msg.pause ();
				}
			} finally {
				msg.disconnect (write_handler);
				msg.disconnect (finished_handler);
				if (!finished)
					msg.unpause ();
			}
		}

		private void handle_misplaced_request (string redirect_uri, Soup.ServerMessage msg) {
			msg.set_redirect (Soup.Status.MOVED_PERMANENTLY, redirect_uri);

			string body = """<html>
<head><title>301 Moved Permanently</title></head>
<body>
<center><h1>301 Moved Permanently</h1></center>
<hr><center>%s</center>
</body>
</html>""".printf ("Frida/" + _version_string ());

			if (msg.get_method () == "HEAD") {
				var headers = msg.get_response_headers ();
				headers.replace ("Content-Type", "text/html");
				headers.replace ("Content-Length", body.length.to_string ());
			} else {
				msg.set_response ("text/html", Soup.MemoryUse.COPY, body.data);
			}

			msg.unpause ();
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

			if (path.has_suffix (".gif"))
				return "image/gif";

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
			ssize_t n;
			lock (state) {
				n = ssize_t.min (recv_queue.len, buffer.length);
				if (n > 0) {
					Memory.copy (buffer, recv_queue.data, n);
					recv_queue.remove_range (0, (uint) n);

					recompute_pending_io_unlocked ();
				} else {
					if (state == OPEN)
						n = -1;
				}

			}

			if (n == -1)
				throw new IOError.WOULD_BLOCK ("Resource temporarily unavailable");

			return n;
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
				unowned Source source = entry.key;
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

#if DARWIN
	private class EndpointEnumerator : Object {
		private int necp;
		private uint8 client_id[16];

		private static NecpOpenFunc necp_open;
		private static NecpClientActionFunc necp_client_action;

		private enum NecpClientAction {
			ADD			= 1,
			REMOVE			= 2,
			COPY_PARAMETERS		= 3,
			COPY_RESULT		= 4,
			COPY_LIST		= 5,
			REQUEST_NEXUS_INSTANCE	= 6,
			AGENT			= 7,
			COPY_AGENT		= 8,
			COPY_INTERFACE		= 9,
			SET_STATISTICS		= 10,
			COPY_ROUTE_STATISTICS	= 11,
			AGENT_USE		= 12,
			MAP_SYSCTLS		= 13,
			UPDATE_CACHE		= 14,
			COPY_CLIENT_UPDATE	= 15,
			COPY_UPDATED_RESULT	= 16,
			ADD_FLOW		= 17,
			REMOVE_FLOW		= 18,
			CLAIM			= 19,
			SIGN			= 20,
			GET_INTERFACE_ADDRESS	= 21,
			ACQUIRE_AGENT_TOKEN	= 22,
			VALIDATE		= 23,
			GET_SIGNED_CLIENT_ID	= 24,
			SET_SIGNED_CLIENT_ID	= 25,
		}

		private enum NecpClientParameterType {
			APPLICATION			= 1,
			REAL_APPLICATION		= 2,
			DOMAIN				= 3,
			ACCOUNT				= 4,
			PID				= 6,
			UID				= 7,
			BOUND_INTERFACE			= 9,
			TRAFFIC_CLASS			= 10,
			IP_PROTOCOL			= 11,
			LOCAL_ADDRESS			= 12,
			REMOTE_ADDRESS			= 13,
			DOMAIN_OWNER			= 33,
			DOMAIN_CONTEXT			= 34,
			TRACKER_DOMAIN			= 35,
			ATTRIBUTED_BUNDLE_IDENTIFIER	= 36,
			SCHEME_PORT			= 37,
			APPLICATION_ID			= 41,
			URL				= 42,
			NEXUS_KEY			= 102,
			PROHIBIT_INTERFACE		= 100,
			PROHIBIT_IF_TYPE		= 101,
			PROHIBIT_AGENT			= 102,
			PROHIBIT_AGENT_TYPE		= 103,
			REQUIRE_IF_TYPE			= 111,
			REQUIRE_AGENT			= 112,
			REQUIRE_AGENT_TYPE		= 113,
			PREFER_AGENT			= 122,
			PREFER_AGENT_TYPE		= 123,
			AVOID_AGENT			= 124,
			AVOID_AGENT_TYPE		= 125,
			TRIGGER_AGENT			= 130,
			ASSERT_AGENT			= 131,
			UNASSERT_AGENT			= 132,
			AGENT_ADD_GROUP_MEMBERS		= 133,
			AGENT_REMOVE_GROUP_MEMBERS	= 134,
			REPORT_AGENT_ERROR		= 135,
			FALLBACK_MODE			= 140,
			PARENT_ID			= 150,
			LOCAL_ENDPOINT			= 200,
			REMOTE_ENDPOINT			= 201,
			BROWSE_DESCRIPTOR		= 202,
			RESOLVER_TAG			= 203,
			ADVERTISE_DESCRIPTOR		= 204,
			GROUP_DESCRIPTOR		= 205,
			DELEGATED_UPID			= 210,
			ETHERTYPE			= 220,
			TRANSPORT_PROTOCOL		= 221,
			LOCAL_ADDRESS_PREFERENCE	= 230,
			FLAGS				= 250,
			FLOW_DEMUX_PATTERN		= 251,
		}

		[Flags]
		private enum NecpClientParameterFlags {
			MULTIPATH			= 0x0001,
			BROWSE				= 0x0002,
			PROHIBIT_EXPENSIVE		= 0x0004,
			LISTENER			= 0x0008,
			DISCRETIONARY			= 0x0010,
			ECN_ENABLE			= 0x0020,
			ECN_DISABLE			= 0x0040,
			TFO_ENABLE			= 0x0080,
			ONLY_PRIMARY_REQUIRES_TYPE	= 0x0100,
			CUSTOM_ETHER			= 0x0200,
			CUSTOM_IP			= 0x0400,
			INTERPOSE			= 0x0800,
			PROHIBIT_CONSTRAINED		= 0x1000,
			FALLBACK_TRAFFIC		= 0x2000,
			INBOUND				= 0x4000,
			SYSTEM_PROXY			= 0x8000,
			KNOWN_TRACKER			= 0x10000,
			UNSAFE_SOCKET_ACCESS		= 0x20000,
			NON_APP_INITIATED		= 0x40000,
			THIRD_PARTY_WEB_CONTENT		= 0x80000,
			SILENT				= 0x100000,
			APPROVED_APP_DOMAIN		= 0x200000,
			NO_WAKE_FROM_SLEEP		= 0x400000,
			REUSE_LOCAL			= 0x800000,
			ENHANCED_PRIVACY		= 0x1000000,
			WEB_SEARCH_CONTENT		= 0x2000000,
		}

		private enum NecpClientResultType {
			CLIENT_ID			= 1,
			POLICY_RESULT			= 2,
			POLICY_RESULT_PARAMETER		= 3,
			FILTER_CONTROL_UNIT		= 4,
			INTERFACE_INDEX			= 5,
			NETAGENT			= 6,
			FLAGS				= 7,
			INTERFACE			= 8,
			INTERFACE_OPTION		= 9,
			EFFECTIVE_MTU			= 10,
			FLOW				= 11,
			PROTO_CTL_EVENT			= 12,
			TFO_COOKIE			= 13,
			TFO_FLAGS			= 14,
			RECOMMENDED_MSS			= 15,
			FLOW_ID				= 16,
			INTERFACE_TIME_DELTA		= 17,
			REASON				= 18,
			FLOW_DIVERT_AGGREGATE_UNIT	= 19,
			REQUEST_IN_PROCESS_FLOW_DIVERT	= 20,
			NEXUS_INSTANCE			= 100,
			NEXUS_PORT			= 101,
			NEXUS_KEY			= 102,
			NEXUS_PORT_FLOW_INDEX		= 103,
			NEXUS_FLOW_STATS		= 104,
			LOCAL_ENDPOINT			= 200,
			REMOTE_ENDPOINT			= 201,
			DISCOVERED_ENDPOINT		= 202,
			RESOLVED_ENDPOINT		= 203,
			LOCAL_ETHER_ADDR		= 204,
			REMOTE_ETHER_ADDR		= 205,
			EFFECTIVE_TRAFFIC_CLASS		= 210,
			TRAFFIC_MGMT_BG			= 211,
			GATEWAY				= 212,
			GROUP_MEMBER			= 213,
			NAT64				= 214,
			ESTIMATED_THROUGHPUT		= 215,
			AGENT_ERROR			= 216,
		}

		private struct NecpClientResultInterface {
			public uint32 generation;
			public uint32 index;
		}

		private struct NecpClientInterfaceOption {
			public uint32 index;
			public uint32 generation;
			public Bytes uuid;
		}

		private struct NecpInterfaceDetails {
			public char name[24];
			public uint32 index;
			public uint32 generation;
			public uint32 functional_type;
			public uint32 delegate_index;
			public uint32 flags;
			public uint32 mtu;
			public NecpInterfaceSignature ipv4_signature;
			public NecpInterfaceSignature ipv6_signature;
			public uint32 ipv4_netmask;
			public uint32 ipv4_broadcast;
			public uint32 tso_max_segment_size_v4;
			public uint32 tso_max_segment_size_v6;
			public uint32 hwcsum_flags;
			public uint8 radio_type;
			public uint8 radio_channel;
		}

		private struct NecpInterfaceSignature {
			public uint8 signature[20];
			public uint8 signature_len;
		}

		private enum InterfaceType {
			UNKNOWN		= 0,
			LOOPBACK	= 1,
			WIRED		= 2,
			WIFI_INFRA	= 3,
			WIFI_AWDL	= 4,
			CELLULAR	= 5,
			INTCOPROC	= 6,
			COMPANIONLINK	= 7,
			MANAGEMENT	= 8,
		}

		private const string LIBSYSTEM_KERNEL = "/usr/lib/system/libsystem_kernel.dylib";

		static construct {
			necp_open = (NecpOpenFunc) Gum.Module.find_export_by_name (LIBSYSTEM_KERNEL, "necp_open");
			necp_client_action = (NecpClientActionFunc) Gum.Module.find_export_by_name (LIBSYSTEM_KERNEL, "necp_client_action");
		}

		construct {
			for (int i = 0; i != 9; i++) {
				var iftype = (InterfaceType) i;
				printerr ("\n=== Trying %s\n", iftype.to_string ());

				necp = necp_open (0);

				var client_params = new NecpClientParametersBuilder ()
					.add_type (FLAGS)
					.add_flags (MULTIPATH) // MULTIPATH | ONLY_PRIMARY_REQUIRES_TYPE
					.add_type (REQUIRE_IF_TYPE)
					.add_interface_type (iftype)
					.build ();
				hexdump (client_params.get_data ());
				int res = necp_client_action (necp, ADD, client_id, client_params.get_data ());

				uint8 result[1536];
				var n = necp_client_action (necp, COPY_RESULT, client_id, result);
				var reader = new NecpClientResultReader (new Bytes (result[:n]));
				try {
					while (reader.has_next ()) {
						var type = reader.read_type ();
						printerr ("type: %s\n", type.to_string ());
						switch (type) {
							case INTERFACE: {
								var iface = reader.read_interface ();
								printerr ("\tgeneration=%u index=%u\n", iface.generation, iface.index);

								var details = NecpInterfaceDetails ();
								res = necp_client_action (necp, COPY_INTERFACE, (uint8[]) &iface.index, (uint8[]) &details);
								printerr ("\tCOPY_INTERFACE => %d\n", res);
								hexdump ((uint8[]) &details);

								break;
							}
							case INTERFACE_OPTION: {
								var iface = reader.read_interface_option ();
								printerr ("\tgeneration=%u index=%u\n", iface.generation, iface.index);

								var details = NecpInterfaceDetails ();
								res = necp_client_action (necp, COPY_INTERFACE, (uint8[]) &iface.index, (uint8[]) &details);
								printerr ("\tCOPY_INTERFACE => %d\n", res);
								hexdump ((uint8[]) &details);

								break;
							}
							default:
								reader.skip_value ();
						}
					}
				} catch (Error e) {
					printerr ("%s\n", e.message);
					assert_not_reached ();
				}

				//Posix.close (necp);
			}
		}

		private class NecpClientParametersBuilder {
			private BufferBuilder builder = new BufferBuilder ();

			public unowned NecpClientParametersBuilder add_type (NecpClientParameterType type) {
				builder.append_uint8 (type);

				return this;
			}

			public unowned NecpClientParametersBuilder add_flags (NecpClientParameterFlags flags) {
				builder
					.append_uint32 (4)
					.append_uint32 (flags);

				return this;
			}

			public unowned NecpClientParametersBuilder add_interface_type (InterfaceType type) {
				builder
					.append_uint32 (1)
					.append_uint8 (type);

				return this;
			}

			public Bytes build () {
				return builder.build ();
			}
		}

		private class NecpClientResultReader {
			private Buffer buffer;
			private size_t cursor = 0;
			private size_t end;

			public NecpClientResultReader (Bytes result) {
				buffer = new Buffer (result);
				end = buffer.bytes.get_size ();
			}

			public bool has_next () {
				return cursor != end;
			}

			public NecpClientResultType read_type () throws Error {
				check_available (sizeof (uint8));
				var type = buffer.read_uint8 (cursor);
				cursor++;
				return type;
			}

			public NecpClientResultInterface read_interface () throws Error {
				var size = read_uint32 ();
				if (size != 2 * sizeof (uint32))
					throw new Error.PROTOCOL ("Invalid necp_client_result_interface");
				return NecpClientResultInterface () {
					generation = read_uint32 (),
					index = read_uint32 (),
				};
			}

			public NecpClientInterfaceOption read_interface_option () throws Error {
				var size = read_uint32 ();
				if (size != 2 * sizeof (uint32) + 16)
					throw new Error.PROTOCOL ("Invalid necp_client_interface_option");
				return NecpClientInterfaceOption () {
					index = read_uint32 (),
					generation = read_uint32 (),
					uuid = read_uuid (),
				};
			}

			public void skip_value () throws Error {
				var size = read_uint32 ();
				check_available (size);
				cursor += size;
			}

			private uint32 read_uint32 () throws Error {
				check_available (sizeof (uint32));
				var v = buffer.read_uint32 (cursor);
				cursor += sizeof (uint32);
				return v;
			}

			private Bytes read_uuid () throws Error {
				check_available (16);
				var v = buffer.bytes[cursor:cursor + 16];
				cursor += 16;
				return v;
			}

			private void check_available (size_t n) throws Error {
				if (cursor + n > end)
					throw new Error.PROTOCOL ("Truncated NECP client result");
			}
		}

		[CCode (has_target = false)]
		private delegate int NecpOpenFunc (int flags);

		private delegate int NecpClientActionFunc (int necp_fd, NecpClientAction action,
			[CCode (array_length_type = "size_t")]
			uint8[] client_id,
			[CCode (array_length_type = "size_t")]
			uint8[] buffer);

		// https://gist.github.com/phako/96b36b5070beaf7eee27
		private static void hexdump (uint8[] data) {
			var builder = new StringBuilder.sized (16);
			var i = 0;

			foreach (var c in data) {
				if (i % 16 == 0)
					printerr ("%08x | ", i);

				printerr ("%02x ", c);

				if (((char) c).isprint ())
					builder.append_c ((char) c);
				else
					builder.append (".");

				i++;
				if (i % 16 == 0) {
					printerr ("| %s\n", builder.str);
					builder.erase ();
				}
			}

			if (i % 16 != 0)
				printerr ("%s| %s\n", string.nfill ((16 - (i % 16)) * 3, ' '), builder.str);
		}
}
#else
	private class EndpointEnumerator : Object {
	}
#endif
}
