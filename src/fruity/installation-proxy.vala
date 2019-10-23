namespace Frida.Fruity {
	public class InstallationProxyClient : Object, AsyncInitable {
		public LockdownClient lockdown {
			get;
			construct;
		}

		private PlistServiceClient service;

		private InstallationProxyClient (LockdownClient lockdown) {
			Object (lockdown: lockdown);
		}

		public static async InstallationProxyClient open (LockdownClient lockdown, Cancellable? cancellable = null) throws InstallationProxyError, IOError {
			var client = new InstallationProxyClient (lockdown);

			try {
				yield client.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_local_error (e);
			}

			return client;
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws InstallationProxyError, IOError {
			try {
				var stream = yield lockdown.start_service ("com.apple.mobile.installation_proxy", cancellable);

				service = new PlistServiceClient (stream);
			} catch (LockdownError e) {
				throw new InstallationProxyError.PROTOCOL ("%s", e.message);
			}

			return true;
		}

		public async void close (Cancellable? cancellable = null) throws IOError {
			yield service.close (cancellable);
		}

		public async Gee.ArrayList<ApplicationDetails> browse (Cancellable? cancellable = null)
				throws InstallationProxyError, IOError {
			try {
				var result = new Gee.ArrayList<ApplicationDetails> ();

				var request = make_request ("Browse");

				request.set_dict ("ClientOptions", make_client_options ());

				var reader = yield service.begin_query (request, cancellable);
				string status = "";
				do {
					var response = yield reader.read (cancellable);

					status = response.get_string ("Status");
					if (status == "BrowsingApplications") {
						var entries = response.get_array ("CurrentList");
						var length = entries.length;
						for (int i = 0; i != length; i++)
							result.add (parse_application_details (entries.get_dict (i)));
					}
				} while (status != "Complete");

				return result;
			} catch (PlistServiceError e) {
				throw error_from_service (e);
			} catch (PlistError e) {
				throw error_from_plist (e);
			}
		}

		public async Gee.HashMap<string, ApplicationDetails> lookup (PlistDict query, Cancellable? cancellable = null)
				throws InstallationProxyError, IOError {
			try {
				var result = new Gee.HashMap<string, ApplicationDetails> ();

				var request = make_request ("Lookup");

				var options = make_client_options ();
				request.set_dict ("ClientOptions", options);
				foreach (var key in query.keys) {
					var val = query.get_value (key);
					Value? val_copy = Value (val.type ());
					val.copy (ref val_copy);
					options.set_value (key, (owned) val_copy);
				}

				var reader = yield service.begin_query (request, cancellable);
				string status = "";
				do {
					var response = yield reader.read (cancellable);

					var result_dict = response.get_dict ("LookupResult");
					foreach (var identifier in result_dict.keys)
						result[identifier] = parse_application_details (result_dict.get_dict (identifier));

					status = response.get_string ("Status");
				} while (status != "Complete");

				return result;
			} catch (PlistServiceError e) {
				throw error_from_service (e);
			} catch (PlistError e) {
				throw error_from_plist (e);
			}
		}

		public async string resolve_id_from_path (string path, Cancellable? cancellable = null)
				throws InstallationProxyError, IOError {
			try {
				string? result = null;

				var request = make_request ("Lookup");

				var options = new PlistDict ();
				var attributes = new PlistArray ();
				options.set_array ("ReturnAttributes", attributes);
				attributes.add_string ("Path");

				var reader = yield service.begin_query (request, cancellable);
				string status = "";
				do {
					var response = yield reader.read (cancellable);

					var result_dict = response.get_dict ("LookupResult");
					if (result == null) {
						foreach (var identifier in result_dict.keys) {
							unowned string app_path = result_dict.get_dict (identifier).get_string ("Path");
							if (app_path == path) {
								result = identifier;
								break;
							}
						}
					}

					status = response.get_string ("Status");
				} while (status != "Complete");

				if (result == null)
					throw new InstallationProxyError.INVALID_ARGUMENT ("Specified path does not match any app");

				return result;
			} catch (PlistServiceError e) {
				throw error_from_service (e);
			} catch (PlistError e) {
				throw error_from_plist (e);
			}
		}

		private static Plist make_request (string command) {
			var request = new Plist ();
			request.set_string ("Command", command);
			return request;
		}

		private static PlistDict make_client_options () {
			var options = new PlistDict ();

			var attributes = new PlistArray ();
			options.set_array ("ReturnAttributes", attributes);
			attributes.add_string ("CFBundleIdentifier");
			attributes.add_string ("CFBundleDisplayName");
			attributes.add_string ("Path");
			attributes.add_string ("Container");
			attributes.add_string ("Entitlements");

			return options;
		}

		private static ApplicationDetails parse_application_details (PlistDict details) throws PlistError {
			unowned string identifier = details.get_string ("CFBundleIdentifier");
			unowned string name = details.get_string ("CFBundleDisplayName");

			unowned string path = details.get_string ("Path");
			unowned string? container = details.has ("Container") ? details.get_string ("Container") : null;

			bool debuggable = false;
			if (details.has ("Entitlements")) {
				var entitlements = details.get_dict ("Entitlements");
				debuggable = entitlements.has ("get-task-allow") && entitlements.get_boolean ("get-task-allow");
			}

			return new ApplicationDetails (identifier, name, path, container, debuggable);
		}

		private static void throw_local_error (GLib.Error e) throws InstallationProxyError, IOError {
			if (e is InstallationProxyError)
				throw (InstallationProxyError) e;

			if (e is IOError)
				throw (IOError) e;

			assert_not_reached ();
		}

		private static InstallationProxyError error_from_service (PlistServiceError e) {
			return new InstallationProxyError.PROTOCOL ("%s", e.message);
		}

		private static InstallationProxyError error_from_plist (PlistError e) {
			return new InstallationProxyError.PROTOCOL ("Unexpected response: %s", e.message);
		}
	}

	public errordomain InstallationProxyError {
		INVALID_ARGUMENT,
		PROTOCOL
	}

	public class ApplicationDetails : Object {
		public string identifier {
			get;
			construct;
		}

		public string name {
			get;
			construct;
		}

		public string path {
			get;
			construct;
		}

		public string? container {
			get;
			construct;
		}

		public bool debuggable {
			get;
			construct;
		}

		public ApplicationDetails (string identifier, string name, string path, string? container, bool debuggable) {
			Object (
				identifier: identifier,
				name: name,
				path: path,
				container: container,
				debuggable: debuggable
			);
		}
	}
}
