namespace Zed.Test {
	private class AsyncHarness : Object {
		public delegate void TestSequenceFunc (void * h);
		private TestSequenceFunc test_sequence;

		private MainContext main_context;
		private MainLoop main_loop;
		private TimeoutSource timeout_source;

		public AsyncHarness (TestSequenceFunc func) {
			test_sequence = func;
		}

		construct {
			main_context = new MainContext ();
			main_loop = new MainLoop (main_context);
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
			idle.set_callback (() => {
				test_sequence (this);
				return false;
			});
			idle.attach (main_context);

			main_context.push_thread_default ();
			main_loop.run ();
			main_context.pop_thread_default ();

			assert (!timed_out);
			if (timeout_source != null) {
				timeout_source.destroy ();
				timeout_source = null;
			}
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

		public void disable_timeout () {
			timeout_source.destroy ();
			timeout_source = null;
		}

		public virtual void done () {
			/* Queue an idle handler, allowing MainContext to perform any outstanding completions, in turn cleaning up resources */
			var idle = new IdleSource ();
			idle.set_callback (() => {
				main_loop.quit ();
				return false;
			});
			idle.attach (main_context);
		}
	}
}
