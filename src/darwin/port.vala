#if DARWIN
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

		public async void exchange (uint peer_pid, out TaskPort task_port, out Pipe pipe) throws Error {
			uint raw_task_port = 0;
			string pipe_address = null;
			Error error = null;

			new Thread<bool> ("frida-handshake-port-exchange", () => {
				try {
					if (is_sender)
						_perform_exchange_as_sender (out raw_task_port, out pipe_address);
					else
						_perform_exchange_as_receiver (peer_pid, out raw_task_port, out pipe_address);
				} catch (Error e) {
					error = e;
				}

				Idle.add (() => {
					exchange.callback ();
					return false;
				});

				return true;
			});
			yield;

			if (error != null)
				throw error;

			task_port = new TaskPort (raw_task_port);
			try {
				pipe = new Pipe (pipe_address);
			} catch (IOError e) {
				assert_not_reached ();
			}
		}

		protected extern uint _create_local (string name) throws Error;
		protected extern uint _create_remote (string name) throws Error;
		protected extern void _deallocate ();

		protected extern void _perform_exchange_as_sender (out uint task_port, out string pipe_address) throws Error;
		protected extern void _perform_exchange_as_receiver (uint peer_pid, out uint task_port, out string pipe_address) throws Error;
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
#endif
