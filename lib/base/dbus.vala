namespace Frida {
	// We need to tease out GDBus' private MainContext as libnice needs to know the MainContext up front :(
	public Promise<MainContext> detect_dbus_context (DBusConnection connection, Cancellable? cancellable = null) {
		var promise = new Promise<MainContext> ();

		var caller_context = MainContext.ref_thread_default ();
		uint filter_id = 0;
		int filter_calls = 0;
		CancellableSource cancel_source = null;

		filter_id = connection.add_filter ((connection, message, incoming) => {
			MainContext dbus_context = MainContext.ref_thread_default ();

			if (AtomicInt.add (ref filter_calls, 1) == 0) {
				var idle_source = new IdleSource ();
				idle_source.set_callback (() => {
					if (!promise.future.ready) {
						connection.remove_filter (filter_id);
						cancel_source.destroy ();
						promise.resolve (dbus_context);
					}
					return false;
				});
				idle_source.attach (caller_context);
			}

			return message;
		});

		cancel_source = new CancellableSource (cancellable);
		cancel_source.set_callback (() => {
			if (!promise.future.ready) {
				connection.remove_filter (filter_id);
				promise.reject (new IOError.CANCELLED ("Cancelled"));
			}
			return false;
		});
		cancel_source.attach (caller_context);

		return promise;
	}
}
