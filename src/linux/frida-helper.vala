#if LINUX
namespace Frida {
	public int main (string[] args) {
		var parent_address = args[1];
		var service = new HelperService (parent_address);
		return service.run ();
	}

	public class HelperService : Object, Helper {
		public string parent_address {
			get;
			construct;
		}

		private MainLoop loop = new MainLoop ();
		private int run_result = 0;

		private DBusConnection connection;
		private uint registration_id = 0;

		/* these should be private, but must be accessible to glue code */
		public void * context;
		public Gee.HashMap<uint, void *> spawn_instance_by_pid = new Gee.HashMap<uint, void *> ();
		public Gee.HashMap<uint, void *> inject_instance_by_id = new Gee.HashMap<uint, void *> ();
		public uint last_id = 1;

		public HelperService (string parent_address) {
			Object (parent_address: parent_address);
			_create_context ();
		}

		~HelperService () {
			foreach (var instance in spawn_instance_by_pid.values)
				_free_spawn_instance (instance);
			foreach (var instance in inject_instance_by_id.values)
				_free_inject_instance (instance);
			_destroy_context ();
		}

		public int run () {
			Idle.add (() => {
				start.begin ();
				return false;
			});

			loop.run ();

			return run_result;
		}

		private async void shutdown () {
			if (connection != null) {
				if (registration_id != 0)
					connection.unregister_object (registration_id);
				connection.closed.disconnect (on_connection_closed);
				try {
					yield connection.close ();
				} catch (Error connection_error) {
				}
				connection = null;
			}

			loop.quit ();
		}

		private async void start () {
			try {
				connection = yield DBusConnection.new_for_address (parent_address, DBusConnectionFlags.AUTHENTICATION_CLIENT | DBusConnectionFlags.DELAY_MESSAGE_PROCESSING);
				connection.closed.connect (on_connection_closed);
				Helper helper = this;
				registration_id = connection.register_object (Frida.ObjectPath.HELPER, helper);
				connection.start_message_processing ();
			} catch (Error e) {
				stderr.printf ("start failed: %s\n", e.message);
				run_result = 1;
				shutdown.begin ();
			}
		}

		public async void stop () throws IOError {
			Timeout.add (20, () => {
				shutdown.begin ();
				return false;
			});
		}

		public async uint spawn (string path, string[] argv, string[] envp) throws IOError {
		}

		public async void resume (uint pid) throws IOError {
		}

		public async uint inject (uint pid, string filename, string data_string) throws IOError {
		}

		private void on_connection_closed (bool remote_peer_vanished, GLib.Error? error) {
			shutdown.begin ();
		}

		public extern void _create_context ();
		public extern void _destroy_context ();

		public extern uint _do_spawn (string path, string[] argv, string[] envp) throws IOError;
		public extern void _resume_spawn_instance (void * instance);
		public extern void _free_spawn_instance (void * instance);

		public extern uint _do_inject (uint pid, string dylib_path, string data_string) throws IOError;
		public extern void _free_inject_instance (void * instance);
	}
}
#endif
