using Efni;

[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	public sealed class AndroidEmulatorStubClient : GDB.Client {
		private AndroidEmulatorStubClient (IOStream stream) {
			Object (stream: stream);
		}

		public static new async AndroidEmulatorStubClient open (IOStream stream, Cancellable? cancellable = null)
				throws Efni.Error, IOError {
			var client = new AndroidEmulatorStubClient (stream);

			try {
				yield client.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				Efni.throw_api_error (e);
			}

			return client;
		}

		protected override async void detect_corellium (Cancellable? cancellable) throws Efni.Error, IOError {
		}
	}
}
