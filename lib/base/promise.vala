namespace Frida {
	public sealed class Promise<T> {
		private Impl<T> impl;

		public Future<T> future {
			get {
				return impl;
			}
		}

		public Promise () {
			impl = new Impl<T> ();
		}

		~Promise () {
			impl.abandon ();
		}

		public void resolve (T result) {
			impl.resolve (result);
		}

		public void reject (GLib.Error error) {
			impl.reject (error);
		}

		private class Impl<T> : Object, Future<T> {
			public bool ready {
				get {
					return _ready;
				}
			}
			private bool _ready = false;

			public T? value {
				get {
					return _value;
				}
			}
			private T? _value;

			public GLib.Error? error {
				get {
					return _error;
				}
			}
			private GLib.Error? _error;

			private Gee.ArrayQueue<CompletionFuncEntry> on_complete;

			public async T wait_async (Cancellable? cancellable) throws Frida.Error, IOError {
				if (_ready)
					return get_result ();

				var entry = new CompletionFuncEntry (wait_async.callback);
				if (on_complete == null)
					on_complete = new Gee.ArrayQueue<CompletionFuncEntry> ();
				on_complete.offer (entry);

				var cancel_source = new CancellableSource (cancellable);
				cancel_source.set_callback (() => {
					on_complete.remove (entry);
					wait_async.callback ();
					return false;
				});
				cancel_source.attach (MainContext.get_thread_default ());

				yield;

				cancel_source.destroy ();

				cancellable.set_error_if_cancelled ();

				return get_result ();
			}

			private T get_result () throws Frida.Error, IOError {
				if (error != null) {
					if (error is Frida.Error)
						throw (Frida.Error) error;

					if (error is IOError.CANCELLED)
						throw (IOError) error;

					throw new Frida.Error.TRANSPORT ("%s", error.message);
				}

				return _value;
			}

			internal void resolve (T value) {
				assert (!_ready);

				_value = value;
				transition_to_ready ();
			}

			internal void reject (GLib.Error error) {
				assert (!_ready);

				_error = error;
				transition_to_ready ();
			}

			internal void abandon () {
				if (!_ready) {
					reject (new Frida.Error.INVALID_OPERATION ("Promise abandoned"));
				}
			}

			internal void transition_to_ready () {
				_ready = true;

				if (on_complete != null && !on_complete.is_empty) {
					var source = new IdleSource ();
					source.set_priority (Priority.HIGH);
					source.set_callback (() => {
						CompletionFuncEntry? entry;
						while ((entry = on_complete.poll ()) != null)
							entry.func ();
						on_complete = null;
						return false;
					});
					source.attach (MainContext.get_thread_default ());
				}
			}
		}

		private class CompletionFuncEntry {
			public SourceFunc func;

			public CompletionFuncEntry (owned SourceFunc func) {
				this.func = (owned) func;
			}
		}
	}

	public interface Future<T> : Object {
		public abstract bool ready { get; }
		public abstract T? value { get; }
		public abstract GLib.Error? error { get; }
		public abstract async T wait_async (Cancellable? cancellable) throws Frida.Error, IOError;
	}
}
