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

		public static async InstallationProxyClient open (LockdownClient lockdown, Cancellable? cancellable = null) throws InstallationProxyError {
			var client = new InstallationProxyClient (lockdown);

			try {
				yield client.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				assert (e is InstallationProxyError);
				throw (InstallationProxyError) e;
			}

			return client;
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws InstallationProxyError {
			try {
				var stream = yield lockdown.start_service ("com.apple.mobile.installation_proxy");

				service = new PlistServiceClient (stream);
			} catch (LockdownError e) {
				throw new InstallationProxyError.FAILED ("%s", e.message);
			}

			return true;
		}

		public async void close () {
			yield service.close ();
		}

		public async Gee.ArrayList<ApplicationDetails> browse () throws InstallationProxyError {
			try {
				var result = new Gee.ArrayList<ApplicationDetails> ();

				var request = create_request ("Browse");

				request.set_dict ("ClientOptions", create_client_options ());

				var reader = yield service.begin_query (request);
				string status = "";
				do {
					var response = yield reader.read ();

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

		public async Gee.HashMap<string, ApplicationDetails> lookup (string[] identifiers) throws InstallationProxyError {
			try {
				var result = new Gee.HashMap<string, ApplicationDetails> ();

				var request = create_request ("Lookup");

				var options = create_client_options ();
				request.set_dict ("ClientOptions", options);
				var ids = new PlistArray ();
				options.set_array ("BundleIDs", ids);
				foreach (var bundle_id in identifiers)
					ids.add_string (bundle_id);

				var reader = yield service.begin_query (request);
				string status = "";
				do {
					var response = yield reader.read ();

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

		public async ApplicationDetails? lookup_one (string identifier) throws InstallationProxyError {
			var matches = yield lookup ({ identifier });
			return matches[identifier];
		}

		private static Plist create_request (string command) {
			var request = new Plist ();
			request.set_string ("Command", command);
			return request;
		}

		private static PlistDict create_client_options () {
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
			string identifier = details.get_string ("CFBundleIdentifier");
			string name = details.get_string ("CFBundleDisplayName");

			string path = details.get_string ("Path");
			string? container = details.has ("Container") ? details.get_string ("Container") : null;

			bool debuggable = false;
			if (details.has ("Entitlements")) {
				var entitlements = details.get_dict ("Entitlements");
				debuggable = entitlements.has ("get-task-allow") && entitlements.get_boolean ("get-task-allow");
			}

			return new ApplicationDetails (identifier, name, path, container, debuggable);
		}

		private static InstallationProxyError error_from_service (PlistServiceError e) {
			if (e is PlistServiceError.CONNECTION_CLOSED)
				return new InstallationProxyError.CONNECTION_CLOSED ("%s", e.message);
			return new InstallationProxyError.FAILED ("%s", e.message);
		}

		private static InstallationProxyError error_from_plist (PlistError e) {
			return new InstallationProxyError.PROTOCOL ("Unexpected response: %s", e.message);
		}
	}

	public errordomain InstallationProxyError {
		FAILED,
		CONNECTION_CLOSED,
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
