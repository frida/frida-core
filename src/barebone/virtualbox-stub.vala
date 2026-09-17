[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	public sealed class VirtualBoxStubClient : GDB.Client {
		private const int64 QUIET_PERIOD_USEC = 250000;
		private const uint QUIET_POLL_MSEC = 25;
		private const size_t MAX_PACKET_SIZE = 0x40000;

		private bool connected = false;

		private VirtualBoxStubClient (IOStream stream) {
			Object (stream: stream);
		}

		public static new async VirtualBoxStubClient open (IOStream stream, Cancellable? cancellable = null)
				throws Error, IOError {
			var client = new VirtualBoxStubClient (stream);

			try {
				yield client.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return client;
		}

		protected override bool pipelining_supported {
			get {
				return false;
			}
		}

		protected override bool stop_notifications_accepted {
			get {
				return connected;
			}
		}

		protected override async void prepare_connection (Cancellable? cancellable) throws Error, IOError {
			yield wait_until_quiet (cancellable);
			set_max_packet_size (MAX_PACKET_SIZE);
		}

		private async void wait_until_quiet (Cancellable? cancellable) throws Error, IOError {
			while (get_monotonic_time () - last_packet_arrival_time < QUIET_PERIOD_USEC) {
				var source = new TimeoutSource (QUIET_POLL_MSEC);
				source.set_callback (wait_until_quiet.callback);
				source.attach (MainContext.get_thread_default ());
				yield;

				cancellable.set_error_if_cancelled ();
			}
		}

		protected override async void enable_extensions (Cancellable? cancellable) throws Error, IOError {
			connected = true;
		}
	}
}
