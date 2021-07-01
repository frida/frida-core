[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
	public class SpringboardServicesClient : Object, AsyncInitable {
		public LockdownClient lockdown {
			get;
			construct;
		}

		private PlistServiceClient service;

		private SpringboardServicesClient (LockdownClient lockdown) {
			Object (lockdown: lockdown);
		}

		public static async SpringboardServicesClient open (LockdownClient lockdown,
				Cancellable? cancellable = null) throws SpringboardServicesError, IOError {
			var client = new SpringboardServicesClient (lockdown);

			try {
				yield client.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_local_error (e);
			}

			return client;
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws SpringboardServicesError, IOError {
			try {
				var stream = yield lockdown.start_service ("com.apple.springboardservices", cancellable);

				service = new PlistServiceClient (stream);
			} catch (LockdownError e) {
				throw new SpringboardServicesError.PROTOCOL ("%s", e.message);
			}

			return true;
		}

		public async void close (Cancellable? cancellable = null) throws IOError {
			yield service.close (cancellable);
		}

		public async Bytes get_icon_png_data (string bundle_id,
				Cancellable? cancellable = null) throws SpringboardServicesError, IOError {
			try {
				var request = make_request ("getIconPNGData");
				request.set_string ("bundleId", bundle_id);

				var response = yield service.query (request, cancellable);
				if (response.has ("Error"))
					throw new SpringboardServicesError.INVALID_ARGUMENT ("%s", response.get_string ("Error"));

				return response.get_bytes ("pngData");
			} catch (PlistServiceError e) {
				throw error_from_service (e);
			} catch (PlistError e) {
				throw error_from_plist (e);
			}
		}

		public async Gee.HashMap<string, Bytes> get_icon_png_data_batch (string[] bundle_ids,
				Cancellable? cancellable = null) throws SpringboardServicesError, IOError {
			try {
				foreach (unowned string bundle_id in bundle_ids) {
					var request = make_request ("getIconPNGData");
					request.set_string ("bundleId", bundle_id);
					service.write_message (request);
				}

				var result = new Gee.HashMap<string, Bytes> ();
				uint offset = 0;
				do {
					foreach (Plist response in yield service.read_messages (0, cancellable)) {
						if (response.has ("Error")) {
							throw new SpringboardServicesError.INVALID_ARGUMENT ("%s",
								response.get_string ("Error"));
						}

						result[bundle_ids[offset]] = response.get_bytes ("pngData");

						offset++;
						if (offset == bundle_ids.length)
							break;
					}
				} while (offset != bundle_ids.length);
				return result;
			} catch (PlistServiceError e) {
				throw error_from_service (e);
			} catch (PlistError e) {
				throw error_from_plist (e);
			}
		}

		private static Plist make_request (string command) {
			var request = new Plist ();
			request.set_string ("command", command);
			return request;
		}

		private static void throw_local_error (GLib.Error e) throws SpringboardServicesError, IOError {
			if (e is SpringboardServicesError)
				throw (SpringboardServicesError) e;

			if (e is IOError)
				throw (IOError) e;

			assert_not_reached ();
		}

		private static SpringboardServicesError error_from_service (PlistServiceError e) {
			return new SpringboardServicesError.PROTOCOL ("%s", e.message);
		}

		private static SpringboardServicesError error_from_plist (PlistError e) {
			return new SpringboardServicesError.PROTOCOL ("Unexpected response: %s", e.message);
		}
	}

	public errordomain SpringboardServicesError {
		INVALID_ARGUMENT,
		PROTOCOL
	}
}
