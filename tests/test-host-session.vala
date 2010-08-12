using Zed.Service;

namespace Zed.HostSessionTest {
	public static void add_tests () {
		GLib.Test.add_func ("/HostSession/Service/provider-available", () => {
			var h = new Harness ((h) => Service.provider_available (h));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Service/provider-unavailable", () => {
			var h = new Harness ((h) => Service.provider_unavailable (h));
			h.run ();
		});

#if WINDOWS

		GLib.Test.add_func ("/HostSession/Windows/backend", () => {
			var h = new Harness ((h) => Windows.backend (h));
			h.run ();
		});

		GLib.Test.add_func ("/HostSession/Fruity/backend", () => {
			var h = new Harness ((h) => Fruity.backend (h));
			h.run ();
		});

#endif
	}

	namespace Service {

		private static async void provider_available (Harness h) {
			h.assert_no_providers_available ();
			var backend = new StubBackend ();
			h.service.add_backend (backend);
			yield h.process_events ();
			h.assert_no_providers_available ();

			h.service.start ();
			h.assert_no_providers_available ();
			yield h.process_events ();
			h.assert_n_providers_available (1);

			h.done ();
		}

		private static async void provider_unavailable (Harness h) {
			var backend = new StubBackend ();
			h.service.add_backend (backend);
			h.service.start ();
			yield h.process_events ();
			h.assert_n_providers_available (1);

			backend.disable_provider ();
			h.assert_n_providers_available (0);

			h.done ();
		}

		private class StubBackend : Object, HostSessionBackend {
			private StubProvider provider = new StubProvider ();

			public void start () {
				var source = new IdleSource ();
				source.set_callback (() => {
					provider_available (provider);
					return false;
				});
				source.attach (MainContext.get_thread_default ());
			}

			public void disable_provider () {
				provider_unavailable (provider);
			}
		}

		private class StubProvider : Object, HostSessionProvider {
			public string name {
				get { return "Stub"; }
			}

			public HostSessionProviderKind kind {
				get { return HostSessionProviderKind.LOCAL_SYSTEM; }
			}

			public async HostSession create () throws IOError {
				throw new IOError.FAILED ("Not implemented");
			}
		}

	}

#if WINDOWS

	namespace Windows {

		private static async void backend (Harness h) {
			h.service.add_backend (new WindowsHostSessionBackend ());
			h.service.start ();
			yield h.process_events ();
			h.assert_n_providers_available (1);
			var prov = h.first_provider ();

			try {
				var session = yield prov.create ();
				var processes = yield session.enumerate_processes ();
				assert (processes.length > 0);
				foreach (var process in processes)
					stdout.printf ("pid=%u name='%s'\n", process.pid, process.name);
			} catch (IOError e) {
				assert_not_reached ();
			}

			h.done ();
		}

	}

	namespace Fruity {

		private static async void backend (Harness h) {
			h.service.add_backend (new FruityHostSessionBackend ());
			h.service.start ();
			h.disable_timeout (); /* this is a manual test after all */
			yield h.wait_for_provider ();
			var prov = h.first_provider ();

			try {
				var session = yield prov.create ();
				var processes = yield session.enumerate_processes ();
				assert (processes.length > 0);
				foreach (var process in processes)
					stdout.printf ("pid=%u name='%s'\n", process.pid, process.name);
			} catch (IOError e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}

			h.done ();
		}

	}

#endif

	private class Harness : Object {
		public delegate void TestSequenceFunc (Harness h);
		private TestSequenceFunc test_sequence;

		public HostSessionService service {
			get;
			private set;
		}

		private Gee.ArrayList<HostSessionProvider> available_providers = new Gee.ArrayList<HostSessionProvider> ();

		private MainContext main_context;
		private MainLoop main_loop;
		private TimeoutSource timeout_source;

		public Harness (TestSequenceFunc func) {
			test_sequence = func;
		}

		construct {
			service = new HostSessionService ();
			service.provider_available.connect ((provider) => {
				assert (available_providers.add (provider));
			});
			service.provider_unavailable.connect ((provider) => {
				assert (available_providers.remove (provider));
			});
			main_context = new MainContext ();
			main_loop = new MainLoop (main_context);
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

		public void disable_timeout () {
			timeout_source.destroy ();
			timeout_source = null;
		}

		public void run () {
			var timed_out = false;

			timeout_source = new TimeoutSource.seconds (5);
			timeout_source.set_callback (() => {
				timed_out = true;
				main_loop.quit ();
				return false;
			});
			timeout_source.attach (main_context);

			var idle = new IdleSource ();
			var func = test_sequence; /* FIXME: workaround for bug in valac */
			idle.set_callback (() => {
				func (this);
				return false;
			});
			idle.attach (main_context);

			main_context.push_thread_default ();
			main_loop.run ();
			main_context.pop_thread_default ();

			assert (!timed_out);
		}

		public async void process_events () {
			var timeout = new TimeoutSource (10);
			timeout.set_callback (() => {
				process_events.callback ();
				return false;
			});
			timeout.attach (main_context);
			yield;

			return;
		}

		public void done () {
			main_loop.quit ();
		}
	}
}
