namespace Zed.HostSessionTest {
	public static void add_tests () {
		GLib.Test.add_func ("/HostSession/Service/provider-available", () => {
			var h = new Harness ((h) => Service.provider_available (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Service/provider-unavailable", () => {
			var h = new Harness ((h) => Service.provider_unavailable (h as Harness));
			h.run ();
		});

#if !LINUX
		GLib.Test.add_func ("/HostSession/Fruity/PropertyList/can-construct-from-xml-document", () => {
			Fruity.PropertyList.can_construct_from_xml_document ();
		});

		GLib.Test.add_func ("/HostSession/Fruity/PropertyList/to-xml-yields-complete-document", () => {
			Fruity.PropertyList.to_xml_yields_complete_document ();
		});

		GLib.Test.add_func ("/HostSession/Fruity/backend", () => {
			var h = new Harness ((h) => Fruity.backend (h as Harness));
			h.run ();
		});
#endif

#if HAVE_LOCAL_BACKENDS

#if DARWIN
		GLib.Test.add_func ("/HostSession/Darwin/backend", () => {
			var h = new Harness ((h) => Darwin.backend (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Darwin/spawn", () => {
			var h = new Harness ((h) => Darwin.spawn (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Darwin/Manual/cross-arch", () => {
			var h = new Harness ((h) => Darwin.Manual.cross_arch (h as Harness));
			h.run ();
		});
#endif

#if WINDOWS
		GLib.Test.add_func ("/HostSession/Windows/backend", () => {
			var h = new Harness ((h) => Windows.backend (h as Harness));
			h.run ();
		});
#endif

#endif

	}

	namespace Service {

		private static async void provider_available (Harness h) {
			h.assert_no_providers_available ();
			var backend = new StubBackend ();
			h.service.add_backend (backend);
			yield h.process_events ();
			h.assert_no_providers_available ();

			yield h.service.start ();
			h.assert_no_providers_available ();
			yield h.process_events ();
			h.assert_n_providers_available (1);

			yield h.service.stop ();
			h.service.remove_backend (backend);

			h.done ();
		}

		private static async void provider_unavailable (Harness h) {
			var backend = new StubBackend ();
			h.service.add_backend (backend);
			yield h.service.start ();
			yield h.process_events ();
			h.assert_n_providers_available (1);

			backend.disable_provider ();
			h.assert_n_providers_available (0);

			yield h.service.stop ();
			h.service.remove_backend (backend);

			h.done ();
		}

		private class StubBackend : Object, HostSessionBackend {
			private StubProvider provider = new StubProvider ();

			public async void start () {
				var source = new IdleSource ();
				source.set_callback (() => {
					provider_available (provider);
					return false;
				});
				source.attach (MainContext.get_thread_default ());
			}

			public async void stop () {
			}

			public void disable_provider () {
				provider_unavailable (provider);
			}
		}

		private class StubProvider : Object, HostSessionProvider {
			public string name {
				get { return "Stub"; }
			}

			public ImageData? icon {
				get { return _icon; }
			}
			private ImageData? _icon;

			public HostSessionProviderKind kind {
				get { return HostSessionProviderKind.LOCAL_SYSTEM; }
			}

			public async HostSession create () throws IOError {
				throw new IOError.FAILED ("not implemented");
			}

			public async AgentSession obtain_agent_session (AgentSessionId id) throws IOError {
				throw new IOError.FAILED ("not implemented");
			}
		}

	}

#if HAVE_LOCAL_BACKENDS

#if DARWIN
	namespace Darwin {

		private static async void backend (Harness h) {
			var backend = new DarwinHostSessionBackend ();
			h.service.add_backend (backend);
			yield h.service.start ();
			yield h.process_events ();
			h.assert_n_providers_available (1);
			var prov = h.first_provider ();

			assert (prov.name == "Local System");
			assert (prov.icon == null);

			try {
				var session = yield prov.create ();
				var processes = yield session.enumerate_processes ();
				assert (processes.length > 0);

				if (GLib.Test.verbose ()) {
					foreach (var process in processes)
						stdout.printf ("pid=%u name='%s'\n", process.pid, process.name);
				}
			} catch (IOError e) {
				assert_not_reached ();
			}

			yield h.service.stop ();
			h.service.remove_backend (backend);
			h.done ();
		}

		private static async void spawn (Harness h) {
			var backend = new DarwinHostSessionBackend ();
			h.service.add_backend (backend);
			yield h.service.start ();
			yield h.process_events ();
			h.assert_n_providers_available (1);
			var prov = h.first_provider ();

			try {
				var host_session = yield prov.create ();

				var tests_dir = Path.get_dirname (Zed.Test.Process.current.filename);
				var victim_path = Path.build_filename (tests_dir, "inject-victim");
				string[] argv = { victim_path };
				string[] envp = {};
				var pid = yield host_session.spawn (victim_path, argv, envp);
				var session_id = yield host_session.attach_to (pid);
				var session = yield prov.obtain_agent_session (session_id);
				string received_message = null;
				var message_handler = session.message_from_script.connect ((script_id, message, data) => {
					received_message = message;
					spawn.callback ();
				});
				var script_id = yield session.create_script (
					"Interceptor.attach (Module.findExportByName('libSystem.B.dylib', 'sleep'), {" +
					"  onEnter: function(args) {" +
					"    send({ seconds: args[0].toInt32() });" +
					"  }" +
					"});");
				yield session.load_script (script_id);
				yield host_session.resume (pid);
				yield;
				session.disconnect (message_handler);
				assert (received_message == "{\"type\":\"send\",\"payload\":{\"seconds\":60}}");
				yield host_session.kill (pid);
			} catch (IOError e) {
				stderr.printf ("Unexpected error: %s\n", e.message);
				assert_not_reached ();
			}

			yield h.service.stop ();
			h.service.remove_backend (backend);
			h.done ();
		}

		namespace Manual {

			private static async void cross_arch (Harness h) {
				if (!GLib.Test.slow ()) {
					stdout.printf ("<skipping, run in slow mode with target application running> ");
					h.done ();
					return;
				}

				uint pid;

				try {
					string pgrep_output;
					Process.spawn_sync (null, new string[] { "/usr/bin/pgrep", "Safari" }, null, 0, null, out pgrep_output, null, null);
					pid = (uint) int.parse (pgrep_output);
				} catch (SpawnError spawn_error) {
					stderr.printf ("ERROR: %s\n", spawn_error.message);
					assert_not_reached ();
				}

				var backend = new DarwinHostSessionBackend ();
				h.service.add_backend (backend);
				yield h.service.start ();
				yield h.process_events ();
				var prov = h.first_provider ();

				try {
					var host_session = yield prov.create ();
					var id = yield host_session.attach_to (pid);
					yield prov.obtain_agent_session (id);
				} catch (IOError e) {
					stderr.printf ("ERROR: %s\n", e.message);
					assert_not_reached ();
				}

				yield h.service.stop ();
				h.service.remove_backend (backend);

				h.done ();
			}

		}

	}
#endif

#if WINDOWS
	namespace Windows {

		private static async void backend (Harness h) {
			var backend = new WindowsHostSessionBackend ();
			h.service.add_backend (backend);
			yield h.service.start ();
			yield h.process_events ();
			h.assert_n_providers_available (1);
			var prov = h.first_provider ();

			assert (prov.name == "Local System");

			var icon = prov.icon;
			assert (icon != null);
			assert (icon.width == 16 && icon.height == 16);
			assert (icon.rowstride == icon.width * 4);
			assert (icon.pixels.length > 0);

			try {
				var session = yield prov.create ();
				var processes = yield session.enumerate_processes ();
				assert (processes.length > 0);

				if (GLib.Test.verbose ()) {
					foreach (var process in processes)
						stdout.printf ("pid=%u name='%s'\n", process.pid, process.name);
				}
			} catch (IOError e) {
				assert_not_reached ();
			}

			yield h.service.stop ();
			h.service.remove_backend (backend);

			h.done ();
		}

	}
#endif

#endif

#if !LINUX
	namespace Fruity {

		private static async void backend (Harness h) {
			if (!GLib.Test.slow ()) {
				stdout.printf ("<skipping, run in slow mode with iOS device connected> ");
				h.done ();
				return;
			}

			var backend = new FruityHostSessionBackend ();
			h.service.add_backend (backend);
			yield h.service.start ();
			h.disable_timeout (); /* this is a manual test after all */
			yield h.wait_for_provider ();
			var prov = h.first_provider ();

#if WINDOWS
			assert (prov.name != "Apple Mobile Device"); /* should manage to extract a user-defined name */

			var icon = prov.icon;
			assert (icon != null);
			assert (icon.width == 16 && icon.height == 16);
			assert (icon.rowstride == icon.width * 4);
			assert (icon.pixels.length > 0);
#endif

			try {
				var session = yield prov.create ();
				var processes = yield session.enumerate_processes ();
				assert (processes.length > 0);

				if (GLib.Test.verbose ()) {
					foreach (var process in processes)
						stdout.printf ("pid=%u name='%s'\n", process.pid, process.name);
				}
			} catch (IOError e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}

			yield h.service.stop ();
			h.service.remove_backend (backend);

			h.done ();
		}

		namespace PropertyList {

			private static void can_construct_from_xml_document () {
				var xml =
					"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
					"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n" +
					"<plist version=\"1.0\">\n" +
					"<dict>\n" +
					"	<key>DeviceID</key>\n" +
					"	<integer>2</integer>\n" +
					"	<key>MessageType</key>\n" +
					"	<string>Attached</string>\n" +
					"	<key>Properties</key>\n" +
					"	<dict>\n" +
					"		<key>ConnectionType</key>\n" +
					"		<string>USB</string>\n" +
					"		<key>DeviceID</key>\n" +
					"		<integer>2</integer>\n" +
					"		<key>LocationID</key>\n" +
					"		<integer>0</integer>\n" +
					"		<key>ProductID</key>\n" +
					"		<integer>4759</integer>\n" +
					"		<key>SerialNumber</key>\n" +
					"		<string>220f889780dda462091a65df48b9b6aedb05490f</string>\n" +
					"	</dict>\n" +
					"</dict>\n" +
					"</plist>\n";
				try {
					var plist = new Zed.Fruity.PropertyList.from_xml (xml);
					var plist_keys = plist.get_keys ();
					assert (plist_keys.length == 3);
					assert (plist.get_int ("DeviceID") == 2);
					assert (plist.get_string ("MessageType") == "Attached");

					var proplist = plist.get_plist ("Properties");
					var proplist_keys = proplist.get_keys ();
					assert (proplist_keys.length == 5);
					assert (proplist.get_string ("ConnectionType") == "USB");
					assert (proplist.get_int ("DeviceID") == 2);
					assert (proplist.get_int ("LocationID") == 0);
					assert (proplist.get_int ("ProductID") == 4759);
					assert (proplist.get_string ("SerialNumber") == "220f889780dda462091a65df48b9b6aedb05490f");
				} catch (IOError e) {
					assert_not_reached ();
				}
			}

			private static void to_xml_yields_complete_document () {
				var plist = new Zed.Fruity.PropertyList ();
				plist.set_string ("MessageType", "Detached");
				plist.set_int ("DeviceID", 2);

				var proplist = new Zed.Fruity.PropertyList ();
				proplist.set_string ("ConnectionType", "USB");
				proplist.set_int ("DeviceID", 2);
				plist.set_plist ("Properties", proplist);

				var actual_xml = plist.to_xml ();
				var expected_xml =
					"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
					"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n" +
					"<plist version=\"1.0\">\n" +
					"<dict>\n" +
					"	<key>DeviceID</key>\n" +
					"	<integer>2</integer>\n" +
					"	<key>MessageType</key>\n" +
					"	<string>Detached</string>\n" +
					"	<key>Properties</key>\n" +
					"	<dict>\n" +
					"		<key>ConnectionType</key>\n" +
					"		<string>USB</string>\n" +
					"		<key>DeviceID</key>\n" +
					"		<integer>2</integer>\n" +
					"	</dict>\n" +
					"</dict>\n" +
					"</plist>\n";
				assert (actual_xml == expected_xml);
			}

		}

	}
#endif

	public class Harness : Zed.Test.AsyncHarness {
		public HostSessionService service {
			get;
			private set;
		}

		private Gee.ArrayList<HostSessionProvider> available_providers = new Gee.ArrayList<HostSessionProvider> ();

		public Harness (owned Zed.Test.AsyncHarness.TestSequenceFunc func) {
			base ((owned) func);
		}

		construct {
			service = new HostSessionService ();
			service.provider_available.connect ((provider) => {
				assert (available_providers.add (provider));
			});
			service.provider_unavailable.connect ((provider) => {
				assert (available_providers.remove (provider));
			});
		}

		public async void wait_for_provider () {
			while (available_providers.is_empty) {
				yield process_events ();
			}
		}

		public void assert_no_providers_available () {
			assert (available_providers.is_empty);
		}

		public void assert_n_providers_available (int n) {
			assert (available_providers.size == n);
		}

		public HostSessionProvider first_provider () {
			assert (available_providers.size >= 1);
			return available_providers[0];
		}
	}
}