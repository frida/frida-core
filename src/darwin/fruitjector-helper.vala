#if DARWIN
using Frida;

namespace Fruitjector {
	public int main (string[] args) {
		var parent_address = args[1];
		var service = new Service (parent_address);
		return service.run ();
	}

	public class Service : Object, FruitjectorHelper {
		public string parent_address {
			get;
			construct;
		}

		private MainLoop loop = new MainLoop ();
		private int run_result = 0;

		private DBusConnection connection;
		private uint registration_id;

		public Service (string parent_address) {
			Object (parent_address: parent_address);
		}

		public int run () {
			Idle.add (() => {
				start ();
				return false;
			});

			loop.run ();

			return run_result;
		}

		private void shutdown () {
			Idle.add (() => {
				loop.quit ();
				return false;
			});
		}

		private async void start () {
			try {
				connection = yield DBusConnection.new_for_address (parent_address, DBusConnectionFlags.AUTHENTICATION_CLIENT | DBusConnectionFlags.DELAY_MESSAGE_PROCESSING);
				FruitjectorHelper helper = this;
				registration_id = connection.register_object (FruitjectorObjectPath.HELPER, helper);
				connection.start_message_processing ();
			} catch (Error e) {
				stderr.printf ("start failed: %s\n", e.message);
				run_result = 1;
				shutdown ();
			}
		}

		public async void stop () throws IOError {
			Timeout.add (20, () => {
				shutdown ();
				return false;
			});
		}

		public async uint inject (uint pid, string filename, string data_string) throws IOError {
			return 1337;
		}
	}
}
#endif
