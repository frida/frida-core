namespace Frida {
	public class FruityHostSessionBackend : Object, HostSessionBackend {
		private Fruity.UsbmuxClient control_client;

		private Gee.HashSet<uint> devices = new Gee.HashSet<uint> ();
		private Gee.HashMap<uint, FruityRemoteProvider> remote_providers = new Gee.HashMap<uint, FruityRemoteProvider> ();
		private Gee.HashMap<uint, FruityLockdownProvider> lockdown_providers = new Gee.HashMap<uint, FruityLockdownProvider> ();

		private Promise<bool> start_request;
		private Cancellable start_cancellable;
		private SourceFunc on_start_completed;

		private Cancellable io_cancellable = new Cancellable ();

		static construct {
#if HAVE_GLIB_SCHANNEL_STATIC
			GLibSChannelStatic.register ();
#endif
#if HAVE_GLIB_OPENSSL_STATIC
			GLibOpenSSLStatic.register ();
#endif
		}

		public async void start (Cancellable? cancellable) throws IOError {
			start_request = new Promise<bool> ();
			start_cancellable = new Cancellable ();
			on_start_completed = start.callback;

			var main_context = MainContext.get_thread_default ();

			var timeout_source = new TimeoutSource (500);
			timeout_source.set_callback (start.callback);
			timeout_source.attach (main_context);

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (start.callback);
			cancel_source.attach (main_context);

			do_start.begin ();

			yield;

			cancel_source.destroy ();
			timeout_source.destroy ();
			on_start_completed = null;
		}

		private async void do_start () {
			bool success = true;

			try {
				control_client = yield Fruity.UsbmuxClient.open (start_cancellable);

				control_client.device_attached.connect ((details) => {
					add_device.begin (details);
				});
				control_client.device_detached.connect ((id) => {
					remove_device (id);
				});

				yield control_client.enable_listen_mode (start_cancellable);
			} catch (GLib.Error e) {
				success = false;
			}

			if (success) {
				/* perform a dummy-request to flush out any pending device attach notifications */
				try {
					yield control_client.connect_to_port (Fruity.DeviceId (uint.MAX), 0, start_cancellable);
					assert_not_reached ();
				} catch (GLib.Error expected_error) {
				}
			} else if (control_client != null) {
				control_client.close.begin (null);
				control_client = null;
			}

			start_request.resolve (success);

			if (on_start_completed != null)
				on_start_completed ();
		}

		public async void stop (Cancellable? cancellable) throws IOError {
			start_cancellable.cancel ();

			try {
				yield start_request.future.wait_async (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}

			if (control_client != null) {
				yield control_client.close (cancellable);
				control_client = null;
			}

			io_cancellable.cancel ();

			devices.clear ();

			foreach (var provider in lockdown_providers.values) {
				provider_unavailable (provider);
				yield provider.close (cancellable);
			}
			lockdown_providers.clear ();

			foreach (var provider in remote_providers.values) {
				provider_unavailable (provider);
				yield provider.close (cancellable);
			}
			remote_providers.clear ();
		}

		private async void add_device (Fruity.DeviceDetails details) {
			var id = details.id;
			var raw_id = id.raw_value;
			if (devices.contains (raw_id))
				return;
			devices.add (raw_id);

			string? name = null;
			ImageData? icon_data = null;

			bool got_details = false;
			for (int i = 1; !got_details && devices.contains (raw_id); i++) {
				try {
					_extract_details_for_device (details.product_id.raw_value, details.udid.raw_value,
						out name, out icon_data);
					got_details = true;
				} catch (Error e) {
					if (i != 20) {
						var main_context = MainContext.get_thread_default ();

						var delay_source = new TimeoutSource.seconds (1);
						delay_source.set_callback (add_device.callback);
						delay_source.attach (main_context);

						var cancel_source = new CancellableSource (io_cancellable);
						cancel_source.set_callback (add_device.callback);
						cancel_source.attach (main_context);

						yield;

						cancel_source.destroy ();
						delay_source.destroy ();

						if (io_cancellable.is_cancelled ())
							return;
					} else {
						break;
					}
				}
			}
			if (!devices.contains (raw_id))
				return;
			if (!got_details) {
				remove_device (id);
				return;
			}

			var icon = Image.from_data (icon_data);

			var remote_provider = new FruityRemoteProvider (name, icon, details);
			remote_providers[raw_id] = remote_provider;

			var lockdown_provider = new FruityLockdownProvider (name, icon, details);
			lockdown_providers[raw_id] = lockdown_provider;

			provider_available (remote_provider);
			provider_available (lockdown_provider);
		}

		private void remove_device (Fruity.DeviceId id) {
			var raw_id = id.raw_value;
			if (!devices.contains (raw_id))
				return;
			devices.remove (raw_id);

			FruityLockdownProvider lockdown_provider;
			if (lockdown_providers.unset (raw_id, out lockdown_provider))
				lockdown_provider.close.begin (io_cancellable);

			FruityRemoteProvider remote_provider;
			if (remote_providers.unset (raw_id, out remote_provider))
				remote_provider.close.begin (io_cancellable);
		}

		public extern static void _extract_details_for_device (int product_id, string udid, out string name, out ImageData? icon)
			throws Error;
	}
}
