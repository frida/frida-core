#if DARWIN
using Frida;

namespace Fruitjector {
	public int main (string[] args) {
		var service = new Service ();
		service.run ();
		return 0;
	}

	public class Service : Object, FruitjectorHelper {
		private MainLoop loop;

		private DBusConnection connection;
		private uint registration_id;

		public void run () {
			loop = new MainLoop ();
			loop.run ();
		}

		private void shutdown () {
			Idle.add (() => {
				loop.quit ();
				return false;
			});
		}

		private async void start () {
			try {
				connection = yield DBusConnection.new_for_stream (new Pipe ("pipe:role=client,name=" + derive_svcname_for_self ()), null, DBusConnectionFlags.DELAY_MESSAGE_PROCESSING);
				FruitjectorHelper helper = this;
				registration_id = connection.register_object (FruitjectorObjectPath.HELPER, helper);
				connection.start_message_processing ();
			} catch (Error e) {
				stderr.printf ("start failed: %s\n", e.message);
				shutdown ();
			}
		}

		public async void stop () throws IOError {
			Timeout.add (20, () => {
				shutdown ();
				return false;
			});
		}

		public async void inject (uint pid, string filename, string data_string) throws IOError {
		}
	}
}
#endif
