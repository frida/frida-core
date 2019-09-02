namespace Frida {
	public class HandshakePort : Object {
		protected uint mach_port;
		protected bool is_sender;

		public HandshakePort.local (string name) throws Error {
			mach_port = _create_local (name);
			is_sender = false;
		}

		public HandshakePort.remote (string name) throws Error {
			mach_port = _create_remote (name);
			is_sender = true;
		}

		~HandshakePort () {
			_deallocate ();
		}

		public async void exchange (uint peer_pid, out TaskPort task_port, out IOStream stream) throws Error {
			uint raw_task_port = 0;
			int fd = -1;
			Error error = null;

			new Thread<bool> ("frida-handshake-port-exchange", () => {
				try {
					if (is_sender)
						_perform_exchange_as_sender (out raw_task_port, out fd);
					else
						_perform_exchange_as_receiver (peer_pid, out raw_task_port, out fd);
				} catch (Error e) {
					error = e;
				}

				Idle.add (exchange.callback);

				return true;
			});
			yield;

			if (error != null)
				throw error;

			task_port = new TaskPort (raw_task_port);
			try {
				stream = SocketConnection.factory_create_connection (new Socket.from_fd (fd));
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("%s", e.message);
			}
		}

		protected extern uint _create_local (string name) throws Error;
		protected extern uint _create_remote (string name) throws Error;
		protected extern void _deallocate ();

		protected extern void _perform_exchange_as_sender (out uint task_port, out int fd) throws Error;
		protected extern void _perform_exchange_as_receiver (uint peer_pid, out uint task_port, out int fd) throws Error;
	}

	public class TaskPort : Object {
		public uint mach_port {
			get;
			construct;
		}

		public TaskPort (uint port) {
			Object (mach_port: port);
		}

		~TaskPort () {
			_deallocate ();
		}

		protected extern void _deallocate ();
	}
}
