namespace Frida.Fruity {
	public class LockdownClient : Object, AsyncInitable {
		public DeviceDetails device_details {
			get;
			construct;
		}

		private PlistServiceClient service;

		private const uint16 LOCKDOWN_PORT = 62078;

		private LockdownClient (DeviceDetails device_details) {
			Object (device_details: device_details);
		}

		public static async LockdownClient open (DeviceDetails device_details, Cancellable? cancellable = null) throws LockdownError {
			var client = new LockdownClient (device_details);

			try {
				yield client.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				assert (e is LockdownError);
				throw (LockdownError) e;
			}

			return client;
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws LockdownError {
			var device = device_details;

			try {
				var usbmux = yield UsbmuxClient.open (cancellable);

				var pair_record = yield usbmux.read_pair_record (device.udid);

				yield usbmux.connect_to_port (device.id, LOCKDOWN_PORT);

				service = new PlistServiceClient (usbmux.connection);

				yield query_type ();

				yield start_session (pair_record);
			} catch (UsbmuxError e) {
				throw new LockdownError.FAILED ("%s", e.message);
			}

			return true;
		}

		public async void close () {
			yield service.close ();
		}

		public async IOStream start_service (string name) throws LockdownError {
			try {
				var request = create_request ("StartService");
				request.set_string ("Service", name);

				var response = yield service.query (request);
				if (response.has ("Error")) {
					var error = response.get_string ("Error");
					if (error == "InvalidService")
						throw new LockdownError.INVALID_SERVICE ("Service '%s' not found", name);
					else
						throw new LockdownError.FAILED ("Unexpected response: %s", error);
				}

				var service_transport = yield UsbmuxClient.open ();
				yield service_transport.connect_to_port (device_details.id, (uint16) response.get_integer ("Port"));

				return service_transport.connection;
			} catch (PlistServiceError e) {
				throw error_from_service (e);
			} catch (PlistError e) {
				throw error_from_plist (e);
			} catch (UsbmuxError e) {
				throw new LockdownError.FAILED ("%s", e.message);
			}
		}

		private async string query_type () throws LockdownError {
			try {
				var response = yield service.query (create_request ("QueryType"));

				return response.get_string ("Type");
			} catch (PlistServiceError e) {
				throw error_from_service (e);
			} catch (PlistError e) {
				throw error_from_plist (e);
			}
		}

		private async void start_session (Plist pair_record) throws LockdownError {
			string host_id, system_buid;
			try {
				host_id = pair_record.get_string ("HostID");
				system_buid = pair_record.get_string ("SystemBUID");
			} catch (PlistError e) {
				throw new LockdownError.FAILED ("Invalid pair record: %s", e.message);
			}

			try {
				var request = create_request ("StartSession");
				request.set_string ("HostID", host_id);
				request.set_string ("SystemBUID", system_buid);

				var response = yield service.query (request);
				if (response.has ("Error"))
					throw new LockdownError.FAILED ("Unexpected response: %s", response.get_string ("Error"));

				if (response.get_boolean ("EnableSessionSSL"))
					yield service.enable_encryption (pair_record);
			} catch (PlistServiceError e) {
				throw error_from_service (e);
			} catch (PlistError e) {
				throw error_from_plist (e);
			}
		}

		private Plist create_request (string request_type) {
			var request = new Plist ();
			request.set_string ("Request", request_type);
			request.set_string ("Label", "Xcode");
			request.set_string ("ProtocolVersion", "2");
			return request;
		}

		private LockdownError error_from_service (PlistServiceError e) {
			if (e is PlistServiceError.CONNECTION_CLOSED)
				return new LockdownError.CONNECTION_CLOSED ("%s", e.message);
			return new LockdownError.FAILED ("%s", e.message);
		}

		private LockdownError error_from_plist (PlistError e) {
			return new LockdownError.PROTOCOL ("Unexpected response: %s", e.message);
		}
	}

	public errordomain LockdownError {
		FAILED,
		CONNECTION_CLOSED,
		INVALID_SERVICE,
		PROTOCOL
	}
}
