#if LINUX
namespace Frida {
	public int main (string[] args) {
		Posix.setsid ();

		Gum.init ();

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
		private Gee.HashMap<uint, OutputStream> stdin_streams = new Gee.HashMap<uint, OutputStream> ();

		/* these should be private, but must be accessible to glue code */
		public Gee.HashMap<uint, void *> spawn_instance_by_pid = new Gee.HashMap<uint, void *> ();
		public Gee.HashMap<uint, void *> inject_instance_by_id = new Gee.HashMap<uint, void *> ();
		public uint last_id = 0;

		public HelperService (string parent_address) {
			Object (parent_address: parent_address);
		}

		~HelperService () {
			foreach (var instance in spawn_instance_by_pid.values)
				_free_spawn_instance (instance);
			foreach (var instance in inject_instance_by_id.values)
				_free_inject_instance (instance);
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
				} catch (GLib.Error connection_error) {
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
			} catch (GLib.Error e) {
				printerr ("Unable to start: %s\n", e.message);
				run_result = 1;
				shutdown.begin ();
			}
		}

		public async void stop () throws Error {
			Timeout.add (20, () => {
				shutdown.begin ();
				return false;
			});
		}

		public async uint spawn (string path, string[] argv, string[] envp) throws Error {
			StdioPipes pipes;
			var child_pid = _do_spawn (path, argv, envp, out pipes);

			ChildWatch.add ((Pid) child_pid, on_child_dead);

			stdin_streams[child_pid] = new UnixOutputStream (pipes.input, false);
			process_next_output_from.begin (new UnixInputStream (pipes.output, false), child_pid, 1, pipes);
			process_next_output_from.begin (new UnixInputStream (pipes.error, false), child_pid, 2, pipes);

			return child_pid;
		}

		private void on_child_dead (Pid pid, int status) {
			stdin_streams.unset ((uint) pid);

			void * instance;
			if (spawn_instance_by_pid.unset (pid, out instance))
				_free_spawn_instance (instance);
		}

		private async void process_next_output_from (InputStream stream, uint pid, int fd, Object resource) {
			try {
				var buf = new uint8[4096];
				var n = yield stream.read_async (buf);

				var data = buf[0:n];
				output (pid, fd, data);

				if (n > 0)
					process_next_output_from.begin (stream, pid, fd, resource);
			} catch (GLib.Error e) {
				output (pid, fd, new uint8[0] {});
			}
		}

		public async void input (uint pid, uint8[] data) throws GLib.Error {
			var stream = stdin_streams[pid];
			if (stream == null)
				throw new Error.INVALID_ARGUMENT ("Invalid pid");
			var data_copy = data; /* FIXME: workaround for Vala compiler bug */
			yield stream.write_all_async (data_copy, Priority.DEFAULT, null, null);
		}

		public async void resume (uint pid) throws Error {
			void * instance;
			bool instance_found = spawn_instance_by_pid.unset (pid, out instance);
			if (!instance_found)
				throw new Error.INVALID_ARGUMENT ("Invalid pid");
			_resume_spawn_instance (instance);
			_free_spawn_instance (instance);
		}

		public async void kill (uint pid) throws Error {
			Posix.kill ((Posix.pid_t) pid, Posix.SIGKILL);
		}

		public async uint inject (uint pid, string filename, string data_string, string temp_path) throws Error {
			var id = _do_inject (pid, filename, data_string, temp_path);

			var fifo = _get_fifo_for_inject_instance (inject_instance_by_id[id]);
			var buf = new uint8[1];
			var cancellable = new Cancellable ();
			var timeout = Timeout.add_seconds (2, () => {
				cancellable.cancel ();
				return false;
			});
			ssize_t size;
			try {
				size = yield fifo.read_async (buf, Priority.DEFAULT, cancellable);
			} catch (IOError e) {
				if (e is IOError.CANCELLED)
					throw new Error.PROCESS_NOT_RESPONDING ("Unexpectedly timed out while waiting for FIFO to establish");
				else
					throw new Error.PROCESS_NOT_RESPONDING (e.message);
			}
			Source.remove (timeout);
			if (size == 0) {
				Idle.add (() => {
					_on_uninject (id);
					return false;
				});
			} else {
				_monitor_inject_instance.begin (id);
			}

			return id;
		}

		private async void _monitor_inject_instance (uint id) {
			var instance = inject_instance_by_id[id];
			if (instance == null)
				return;
			var fifo = _get_fifo_for_inject_instance (instance);
			while (true) {
				var buf = new uint8[1];
				try {
					var size = yield fifo.read_async (buf);
					if (size == 0) {
						/*
						 * Give it some time to execute its final instructions before we free the memory being executed
						 * Should consider to instead signal the remote thread id and poll /proc until it's gone.
						 */
						Timeout.add (50, () => {
							_on_uninject (id);
							return false;
						});
						return;
					}
				} catch (IOError e) {
					_on_uninject (id);
					return;
				}
			}
		}

		private void _on_uninject (uint id) {
			void * instance;
			bool found = inject_instance_by_id.unset (id, out instance);
			assert (found);
			_free_inject_instance (instance);
			uninjected (id);
		}

		private void on_connection_closed (bool remote_peer_vanished, GLib.Error? error) {
			shutdown.begin ();
		}

		public extern uint _do_spawn (string path, string[] argv, string[] envp, out StdioPipes pipes) throws Error;
		public extern void _resume_spawn_instance (void * instance);
		public extern void _free_spawn_instance (void * instance);

		public extern uint _do_inject (uint pid, string dylib_path, string data_string, string temp_path) throws Error;
		public extern InputStream _get_fifo_for_inject_instance (void * instance);
		public extern void _free_inject_instance (void * instance);
	}

	public class StdioPipes : Object {
		public int input {
			get;
			construct;
		}

		public int output {
			get;
			construct;
		}

		public int error {
			get;
			construct;
		}

		public StdioPipes (int input, int output, int error) {
			Object (input: input, output: output, error: error);
		}

		construct {
			try {
				Unix.set_fd_nonblocking (input, true);
				Unix.set_fd_nonblocking (output, true);
				Unix.set_fd_nonblocking (error, true);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
		}

		~StdioPipes () {
			Posix.close (input);
			Posix.close (output);
			Posix.close (error);
		}
	}
}
#endif
