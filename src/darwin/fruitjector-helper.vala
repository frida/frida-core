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
		private uint registration_id = 0;

		/* these should be private, but must be accessible to glue code */
		public void * context;
		public Gee.HashMap<uint, void *> instance_by_id = new Gee.HashMap<uint, void *> ();
		public uint last_id = 1;

		public Service (string parent_address) {
			Object (parent_address: parent_address);
			_create_context ();
		}

		~Service () {
			foreach (var instance in instance_by_id.values)
				_free_instance (instance);
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
				FruitjectorHelper helper = this;
				registration_id = connection.register_object (FruitjectorObjectPath.HELPER, helper);
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

		public async uint inject (uint pid, string filename, string data_string) throws IOError {
			return _do_inject (pid, filename, data_string);
		}

		public async FruitjectorPipeEndpoints make_pipe_endpoints (uint local_pid, uint remote_pid) throws IOError {
			return _do_make_pipe_endpoints (local_pid, remote_pid);
		}

		private void on_connection_closed (bool remote_peer_vanished, GLib.Error? error) {
			shutdown.begin ();
		}

		public void _on_instance_dead (uint id) {
			Idle.add (() => {
				void * instance;
				bool instance_id_found = instance_by_id.unset (id, out instance);
				assert (instance_id_found);
				_free_instance (instance);
				uninjected (id);
				return false;
			});
		}

		public extern void _create_context ();
		public extern void _destroy_context ();
		public extern void _free_instance (void * instance);
		public extern uint _do_inject (uint pid, string dylib_path, string data_string) throws IOError;
		public static extern FruitjectorPipeEndpoints _do_make_pipe_endpoints (uint local_pid, uint remote_pid) throws IOError;
	}
}
#endif
