namespace Frida {
	public sealed class Promise<T> {
		private Efni.Promise<T> impl;
		private Future<T>? _future;

		public Future<T> future {
			get {
				if (_future == null)
					_future = new FutureImpl<T> (impl.future);
				return _future;
			}
		}

		public Promise () {
			impl = new Efni.Promise<T> ();
		}

		public void resolve (T result) {
			impl.resolve (result);
		}

		public void reject (GLib.Error error) {
			impl.reject (error);
		}

		private class FutureImpl<T> : Object, Future<T> {
			private Efni.Future<T> inner;

			public bool ready {
				get {
					return inner.ready;
				}
			}

			public T? value {
				get {
					return inner.value;
				}
			}

			public GLib.Error? error {
				get {
					return inner.error;
				}
			}

			public FutureImpl (Efni.Future<T> inner) {
				this.inner = inner;
			}

			public async T wait_async (Cancellable? cancellable) throws Error, IOError {
				if (!inner.ready) {
					bool resumed = false;

					var cancel_source = new CancellableSource (cancellable);
					cancel_source.set_callback (() => {
						if (!resumed) {
							resumed = true;
							wait_async.callback ();
						}
						return Source.REMOVE;
					});
					cancel_source.attach (MainContext.get_thread_default ());

					inner.then (f => {
						if (!resumed) {
							resumed = true;
							wait_async.callback ();
						}
					});

					yield;

					cancel_source.destroy ();

					cancellable.set_error_if_cancelled ();
				}

				return get_result ();
			}

			public void then (owned FutureCompletionHandler<T> handler) {
				inner.then (f => {
					handler (this);
				});
			}

			public T get_result () throws Error, IOError {
				GLib.Error? e = inner.error;
				if (e != null) {
					if (e is Error)
						throw (Error) e;

					if (e is Efni.Error)
						throw error_from_efni ((Efni.Error) e);

					if (e is IOError.CANCELLED)
						throw (IOError) e;

					throw new Error.TRANSPORT ("%s", e.message);
				}

				return inner.value;
			}
		}
	}

	public interface Future<T> : Object {
		public abstract bool ready { get; }
		public abstract T? value { get; }
		public abstract GLib.Error? error { get; }
		public abstract async T wait_async (Cancellable? cancellable) throws Error, IOError;
		public abstract void then (owned FutureCompletionHandler<T> handler);
		public abstract T get_result () throws Error, IOError;
	}

	public delegate void FutureCompletionHandler<T> (Future<T> future);
}
