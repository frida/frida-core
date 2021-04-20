namespace Frida {
	public class WebGatewayService : Object {
		public EndpointParameters gateway_params {
			get;
			construct;
		}

		public EndpointParameters target_params {
			get;
			construct;
		}

		public File? root {
			get;
			construct;
		}

		public string? origin {
			get;
			construct;
		}

		private Soup.Server server;
		private SocketAddress? target_address;

		private Gee.Map<Soup.WebsocketConnection, Peer> peers = new Gee.HashMap<Soup.WebsocketConnection, Peer> ();

		private Cancellable io_cancellable;

		public WebGatewayService (EndpointParameters gateway_params, EndpointParameters target_params, File? root = null,
				string? origin = null) {
			Object (
				gateway_params: gateway_params,
				target_params: target_params,
				root: root,
				origin: origin
			);
		}

		construct {
			server = (Soup.Server) Object.new (typeof (Soup.Server),
				"tls-certificate", gateway_params.certificate);

			if (root != null)
				server.add_handler ("/", on_asset_request);

			server.add_websocket_handler ("/ws", origin, null, on_websocket_opened);
		}

		public async void start (Cancellable? cancellable = null) throws Error, IOError {
			io_cancellable = new Cancellable ();

			SocketAddress? address;

			bool tls = gateway_params.certificate != null;
			uint16 default_port = tls ? 443 : 80;
			SocketConnectable gateway_connectable =
				parse_socket_address (gateway_params.address, gateway_params.port, "127.0.0.1", default_port);
			try {
				var enumerator = gateway_connectable.enumerate ();
				while ((address = yield enumerator.next_async (cancellable)) != null) {
					server.listen (address, tls ? Soup.ServerListenOptions.HTTPS : 0);
				}
			} catch (GLib.Error e) {
				throw new Error.ADDRESS_IN_USE ("%s", e.message);
			}

			try {
				var enumerator = parse_control_address (target_params.address, target_params.port).enumerate ();
				address = yield enumerator.next_async (cancellable);
			} catch (GLib.Error e) {
				throw new Error.INVALID_ARGUMENT ("Invalid target endpoint: %s", e.message);
			}
			if (address == null)
				throw new Error.INVALID_ARGUMENT ("Invalid target endpoint");
			target_address = address;
		}

		public void start_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<StartTask> ().execute (cancellable);
		}

		private class StartTask : WebGatewayServiceTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.start (cancellable);
			}
		}

		public async void stop (Cancellable? cancellable = null) throws IOError {
			server.disconnect ();

			io_cancellable.cancel ();

			foreach (var peer in peers.values.to_array ())
				peer.close ();
			peers.clear ();
		}

		public void stop_sync (Cancellable? cancellable = null) throws IOError {
			try {
				create<StopTask> ().execute (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}
		}

		private class StopTask : WebGatewayServiceTask<void> {
			protected override async void perform_operation () throws IOError {
				yield parent.stop (cancellable);
			}
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		private abstract class WebGatewayServiceTask<T> : AsyncTask<T> {
			public weak WebGatewayService parent {
				get;
				construct;
			}
		}

		private void on_asset_request (Soup.Server server, Soup.Message msg, string path, HashTable<string, string>? query,
				Soup.ClientContext client) {
			if (msg.method != "GET") {
				msg.set_status (Soup.Status.METHOD_NOT_ALLOWED);
				return;
			}

			File location = (path != "/")
				? root.resolve_relative_path (path.next_char ())
				: root.resolve_relative_path ("index.html");

			server.pause_message (msg);
			send_file.begin (location, msg);
		}

		private async void send_file (File file, Soup.Message msg) {
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

			var body = msg.response_body;
			body.set_accumulate (false);

			bool finished = false;
			bool waiting = false;
			ulong finished_handler = msg.finished.connect (() => {
				finished = true;
				if (waiting)
					send_file.callback ();
			});
			ulong write_handler = msg.wrote_body_data.connect (chunk => {
				if (waiting)
					send_file.callback ();
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

		private void on_websocket_opened (Soup.Server server, Soup.WebsocketConnection connection, string path,
				Soup.ClientContext client) {
			var peer = new Peer (connection, target_address, target_params.certificate);
			peers[connection] = peer;

			connection.closed.connect (on_websocket_closed);
		}

		private void on_websocket_closed (Soup.WebsocketConnection connection) {
			Peer peer;
			if (peers.unset (connection, out peer))
				peer.close ();
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

		private class Peer : Object {
			public Soup.WebsocketConnection gateway_connection {
				get;
				construct;
			}

			public SocketAddress target_address {
				get;
				construct;
			}

			public TlsCertificate? target_certificate {
				get;
				construct;
			}

			private IOStream? target_stream;
			private Gee.ArrayQueue<Bytes> pending_writes = new Gee.ArrayQueue<Bytes> ();
			private bool write_in_progress = false;

			private Cancellable io_cancellable = new Cancellable ();

			public Peer (Soup.WebsocketConnection gateway_connection, SocketAddress target_address,
					TlsCertificate? target_certificate) {
				Object (
					gateway_connection: gateway_connection,
					target_address: target_address,
					target_certificate: target_certificate
				);
			}

			construct {
				gateway_connection.message.connect (on_gateway_message);

				process_io.begin ();
			}

			public void close () {
				io_cancellable.cancel ();
				gateway_connection.close (1000, "Closing");
			}

			private async void process_io () {
				try {
					var client = new SocketClient ();
					var socket_connection = yield client.connect_async (target_address, io_cancellable);

					Socket socket = socket_connection.socket;
					SocketFamily family = socket.get_family ();

					if (family != UNIX)
						Tcp.enable_nodelay (socket);

					IOStream stream = socket_connection;

					if (target_certificate != null) {
						var tc = TlsClientConnection.new (stream, null);
						tc.set_database (null);
						var accept_handler = tc.accept_certificate.connect ((peer_cert, errors) => {
							return peer_cert.verify (null, target_certificate) == 0;
						});
						try {
							yield tc.handshake_async (Priority.DEFAULT, io_cancellable);
						} finally {
							tc.disconnect (accept_handler);
						}
						stream = tc;
					}

					target_stream = stream;

					maybe_process_pending_writes ();

					InputStream input = target_stream.input_stream;
					var buffer = new uint8[64 * 1024];
					while (true) {
						ssize_t n = yield input.read_async (buffer, Priority.DEFAULT, io_cancellable);
						if (n == 0) {
							gateway_connection.close (1000, "Connection reset by peer");
							break;
						}

						gateway_connection.send_message (Soup.WebsocketDataType.BINARY, new Bytes (buffer[0:n]));
					}
				} catch (GLib.Error e) {
					if (e is IOError.CANCELLED)
						return;
					gateway_connection.close (1013, e.message);
				}
			}

			private void on_gateway_message (int type, Bytes message) {
				pending_writes.offer_tail (message);
				maybe_process_pending_writes ();
			}

			private void maybe_process_pending_writes () {
				if (write_in_progress || pending_writes.is_empty || target_stream == null)
					return;
				write_in_progress = true;
				process_pending_writes.begin ();
			}

			private async void process_pending_writes () {
				OutputStream output = target_stream.output_stream;

				try {
					while (!pending_writes.is_empty) {
						Bytes current = pending_writes.peek_head ();

						size_t bytes_written;
						try {
							yield output.write_all_async (current.get_data (), Priority.DEFAULT, io_cancellable,
								out bytes_written);
						} catch (GLib.Error e) {
							return;
						}

						pending_writes.poll_head ();
					}
				} finally {
					write_in_progress = false;
				}
			}
		}
	}
}
