using Zed.Service;

namespace Zed.Test.HostSession {
	public static void add_tests () {
		GLib.Test.add_func ("/HostSession/Factory/new-provider", () => {
			var h = new Harness ((h) => Factory.new_provider (h));
			h.run ();
		});
	}

	namespace Factory {

		private static async void new_provider (Harness h) {

			h.done ();
		}

	}

	private class Harness : Object {
		public delegate void TestSequenceFunc (Harness h);
		private TestSequenceFunc test_sequence;

		public HostSessionFactory factory {
			get;
			private set;
		}

		private MainContext main_context;
		private MainLoop main_loop;

		public Harness (TestSequenceFunc func) {
			test_sequence = func;
		}

		construct {
			factory = new HostSessionFactory ();
			main_context = new MainContext ();
			main_loop = new MainLoop (main_context);
		}

		public void run () {
			var timed_out = false;

			var timeout = new TimeoutSource.seconds (1);
			timeout.set_callback (() => {
				timed_out = true;
				main_loop.quit ();
				return false;
			});
			timeout.attach (main_context);

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
