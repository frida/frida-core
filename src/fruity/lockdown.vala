namespace Frida.Fruity {
	public class LockdownClient : Object, AsyncInitable {
		public signal void closed ();

		public DeviceDetails device_details {
			get;
			construct;
		}

		public IOStream stream {
			get { return service.stream; }
		}

		private PlistServiceClient service;
		private string host_id;
		private string system_buid;
		private TlsCertificate tls_certificate;

		private Promise<bool>? pending_service_query;

		private const uint16 LOCKDOWN_PORT = 62078;

		private LockdownClient (DeviceDetails device_details) {
			Object (device_details: device_details);
		}

		public static async LockdownClient open (DeviceDetails device_details, Cancellable? cancellable = null)
				throws LockdownError, IOError {
			var client = new LockdownClient (device_details);

			try {
				yield client.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_local_error (e);
			}

			return client;
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws LockdownError, IOError {
			var device = device_details;

			try {
				var usbmux = yield UsbmuxClient.open (cancellable);

				var pair_record = yield usbmux.read_pair_record (device.udid, cancellable);
				try {
					host_id = pair_record.get_string ("HostID");
					system_buid = pair_record.get_string ("SystemBUID");

					var cert = pair_record.get_bytes_as_string ("HostCertificate");
					var key = pair_record.get_bytes_as_string ("HostPrivateKey");
					tls_certificate = new TlsCertificate.from_pem (string.join ("\n", cert, key), -1);
				} catch (GLib.Error e) {
					throw new LockdownError.UNSUPPORTED ("Invalid pair record: %s", e.message);
				}

				yield usbmux.connect_to_port (device.id, LOCKDOWN_PORT, cancellable);

				service = new PlistServiceClient (usbmux.connection);
				service.closed.connect (on_service_closed);

				yield query_type (cancellable);

				yield start_session (cancellable);
			} catch (UsbmuxError e) {
				throw new LockdownError.UNSUPPORTED ("%s", e.message);
			}

			return true;
		}

		public async void close (Cancellable? cancellable = null) throws IOError {
			yield service.close (cancellable);
		}

		private void on_service_closed () {
			closed ();
		}

		public async IOStream start_service (string name_with_options, Cancellable? cancellable = null) throws LockdownError, IOError {
			var tokens = name_with_options.split ("?", 2);
			unowned string name = tokens[0];
			bool tls_handshake_only = false;
			if (tokens.length > 1) {
				unowned string options = tokens[1];
				tls_handshake_only = options == "tls=handshake-only";
			}

			Plist request = create_request ("StartService");
			request.set_string ("Service", name);

			Plist? response = null;
			while (pending_service_query != null) {
				var future = pending_service_query.future;
				try {
					yield future.wait_async (cancellable);
				} catch (GLib.Error e) {
				}
				cancellable.set_error_if_cancelled ();
			}
			pending_service_query = new Promise<bool> ();
			try {
				response = yield service.query (request, cancellable);
			} catch (PlistServiceError e) {
				throw error_from_service (e);
			} finally {
				pending_service_query = null;
			}

			try {
				if (response.has ("Error")) {
					var error = response.get_string ("Error");
					if (error == "InvalidService")
						throw new LockdownError.INVALID_SERVICE ("Service '%s' not found", name);
					else
						throw new LockdownError.PROTOCOL ("Unexpected response: %s", error);
				}

				bool enable_encryption = response.has ("EnableServiceSSL") && response.get_boolean ("EnableServiceSSL");

				var client = yield UsbmuxClient.open (cancellable);
				yield client.connect_to_port (device_details.id, (uint16) response.get_integer ("Port"), cancellable);

				SocketConnection raw_connection = client.connection;
				IOStream stream = raw_connection;

				if (enable_encryption) {
					var tls_connection = yield start_tls (raw_connection, cancellable);

					if (tls_handshake_only) {
						/*
						 * In this case we assume that communication should be cleartext after the handshake.
						 *
						 * Also, because TlsConnection closes its base stream once destroyed, and because it holds a strong
						 * ref on the base stream, we cannot return the base stream here and still keep the TlsConnection
						 * instance alive. And attaching it as data to the base stream would create a reference loop.
						 *
						 * So instead we get the underlying Socket and create a new SocketConnection for the Socket, where
						 * we keep the TlsConnection and its base stream alive by attaching it as data.
						 */
						stream = Object.new (typeof (SocketConnection), "socket", raw_connection.socket) as IOStream;
						stream.set_data ("tls-connection", tls_connection);
					} else {
						stream = tls_connection;
					}
				}

				return stream;
			} catch (PlistError e) {
				throw error_from_plist (e);
			} catch (UsbmuxError e) {
				throw new LockdownError.UNSUPPORTED ("%s", e.message);
			}
		}

		private async string query_type (Cancellable? cancellable) throws LockdownError, IOError {
			try {
				var response = yield service.query (create_request ("QueryType"), cancellable);

				return response.get_string ("Type");
			} catch (PlistServiceError e) {
				throw error_from_service (e);
			} catch (PlistError e) {
				throw error_from_plist (e);
			}
		}

		private async void start_session (Cancellable? cancellable) throws LockdownError, IOError {
			try {
				var request = create_request ("StartSession");
				request.set_string ("HostID", host_id);
				request.set_string ("SystemBUID", system_buid);

				var response = yield service.query (request, cancellable);
				if (response.has ("Error"))
					throw new LockdownError.PROTOCOL ("Unexpected response: %s", response.get_string ("Error"));

				if (response.get_boolean ("EnableSessionSSL"))
					service.stream = yield start_tls (service.stream, cancellable);
			} catch (PlistServiceError e) {
				throw error_from_service (e);
			} catch (PlistError e) {
				throw error_from_plist (e);
			}
		}

		private async TlsConnection start_tls (IOStream stream, Cancellable? cancellable) throws LockdownError, IOError {
			try {
				var server_identity = new NetworkAddress ("apple.com", 62078);
				var connection = TlsClientConnection.new (stream, server_identity);
				connection.accept_certificate.connect (on_accept_certificate);

				connection.set_certificate (tls_certificate);

				yield connection.handshake_async (Priority.DEFAULT, cancellable);

				return connection;
			} catch (GLib.Error e) {
				throw new LockdownError.PROTOCOL ("%s", e.message);
			}
		}

		private bool on_accept_certificate (TlsCertificate peer_cert, TlsCertificateFlags errors) {
			return true;
		}

		private static Plist create_request (string request_type) {
			var request = new Plist ();
			request.set_string ("Request", request_type);
			request.set_string ("Label", "Xcode");
			request.set_string ("ProtocolVersion", "2");
			return request;
		}

		private static void throw_local_error (GLib.Error e) throws LockdownError, IOError {
			if (e is LockdownError)
				throw (LockdownError) e;

			if (e is IOError)
				throw (IOError) e;

			assert_not_reached ();
		}

		private static LockdownError error_from_service (PlistServiceError e) {
			return new LockdownError.PROTOCOL ("%s", e.message);
		}

		private static LockdownError error_from_plist (PlistError e) {
			return new LockdownError.PROTOCOL ("Unexpected response: %s", e.message);
		}
	}

	public errordomain LockdownError {
		INVALID_SERVICE,
		UNSUPPORTED,
		PROTOCOL
	}
}
