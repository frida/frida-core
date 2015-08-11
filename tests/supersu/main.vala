namespace Frida {
	private static MainLoop loop;

	public int main (string[] args) {
		loop = new MainLoop ();
		Idle.add (() => {
			run_test.begin ();
			return false;
		});
		loop.run ();
		return 0;
	}

	private async void run_test () {
		try {
			var working_directory = "/";
			var argv = new string[] { "su", "-c", "/system/bin/uptime", "--help" };

			var process = yield SuperSU.spawn (working_directory, argv);
			stdout.printf ("spawned\n");

			yield process.wait ();

			stdout.printf ("exit_status = %d\n", process.exit_status);
		} catch (Error e) {
			printerr ("ERROR: %s\n", e.message);
		}

		Idle.add (() => {
			loop.quit ();
			return false;
		});
	}

	namespace SuperSU {
		public async Process spawn (string working_directory, string[] argv, string[]? envp = null) throws Error {
			/* FIXME: workaround for Vala compiler bug */
			var argv_copy = argv;
			var envp_copy = envp;
			if (envp_copy == null)
				envp_copy = Environ.get ();

			var connection = new Connection ();

			try {
				yield connection.open ();
			} catch (GLib.Error e) {
				throw new Error.NOT_SUPPORTED ("SuperSU is not installed");
			}

			try {
				yield connection.write_strv (argv_copy);
				yield connection.write_strv (envp_copy);
				yield connection.write_string (working_directory);
				yield connection.write_string ("");
			} catch (GLib.Error e) {
				throw new Error.PROTOCOL ("Unable to spawn: " + e.message);
			}

			return new Process (connection);
		}

		public class Process : Object {
			private Connection connection;

			public int exit_status {
				get {
					return exit_promise.future.value;
				}
			}

			private Gee.Promise<int> exit_promise;

			internal Process (Connection connection) {
				this.connection = connection;

				this.exit_promise = new Gee.Promise<int> ();

				read_until_exit.begin ();
			}

			public async void wait () {
				try {
					yield exit_promise.future.wait_async ();
				} catch (Gee.FutureError e) {
					assert_not_reached ();
				}
			}

			private async void read_until_exit () {
				try {
					bool done = false;
					int status = int.MIN;

					while (!done) {
						var command = yield connection.read_size ();
						switch (command) {
							case 1: {
								var data = yield connection.read_byte_array ();
								stdout.write (data);
								break;
							}

							case 2: {
								var data = yield connection.read_byte_array ();
								stderr.write (data);
								break;
							}

							case 3: {
								done = true;
								var type = yield connection.read_size ();
								if (type == 4)
									status = (int) yield connection.read_ssize ();
								break;
							}

							default:
								done = true;
								break;
						}
					}

					yield connection.close ();
					exit_promise.set_value (status);
				} catch (GLib.Error e) {
					yield connection.close ();
					exit_promise.set_exception (e);
				}
			}
		}

		private class Connection : Object {
			private SocketConnection connection;
			private DataInputStream input;
			private DataOutputStream output;
			private Socket socket;

			public async void open () throws Error {
				var address = "eu.chainfire.supersu";
				while (true) {
					var redirect = yield establish (address);
					if (redirect == null)
						break;
					address = redirect;
				}
			}

			public async void close () {
				if (connection != null) {
					try {
						yield connection.close_async ();
					} catch (IOError e) {
					}
					connection = null;
				}
				input = null;
				output = null;
			}

			private async string? establish (string address) throws Error {
				try {
					var client = new SocketClient ();
					connection = yield client.connect_async (new UnixSocketAddress.with_type (address, -1, UnixSocketAddressType.ABSTRACT));

					input = new DataInputStream (connection.get_input_stream ());
					input.set_byte_order (DataStreamByteOrder.HOST_ENDIAN);

					output = new DataOutputStream (connection.get_output_stream ());
					output.set_byte_order (DataStreamByteOrder.HOST_ENDIAN);

					socket = connection.get_socket ();

					write_size (0);
					yield write_credentials ();

					var redirect = yield read_string ();
					if (redirect.length > 0)
						yield close ();

					return redirect.length > 0 ? redirect : null;
				} catch (GLib.Error e) {
					throw new Error.NOT_SUPPORTED ("SuperSU is not installed (%s)".printf (e.message));
				}
			}

			public async string read_string () throws GLib.Error {
				var size = yield read_size ();
				if (size == 0)
					return "";

				var data_buf = new uint8[size];
				size_t bytes_read;
				yield input.read_all_async (data_buf, Priority.DEFAULT, null, out bytes_read);
				if (bytes_read != size)
					throw new IOError.FAILED ("Unable to read string");

				var result = new uint8[size + 1];
				Memory.copy (result, data_buf, size);
				result[size] = 0;

				char * v = result;
				return (string) v;
			}

			public async void write_string (string str) throws GLib.Error {
				write_size (str.length);

				if (str.length > 0) {
					unowned uint8[] buf = (uint8[]) str;
					yield output.write_all_async (buf[0:str.length], Priority.DEFAULT, null, null);
				}
			}

			public async void write_strv (string[] strv) throws GLib.Error {
				/* FIXME: workaround for Vala compiler bug */
				var strv_copy = strv;

				write_size (strv_copy.length);
				foreach (string s in strv_copy)
					yield write_string (s);
			}

			public async uint8[] read_byte_array () throws GLib.Error {
				var size = yield read_size ();
				if (size == 0)
					return new uint8[0];

				var data_buf = new uint8[size];
				size_t bytes_read;
				yield input.read_all_async (data_buf, Priority.DEFAULT, null, out bytes_read);
				if (bytes_read != size)
					throw new IOError.FAILED ("Unable to read byte array");

				return data_buf;
			}

			public async size_t read_size () throws GLib.Error {
				yield prepare_to_read (sizeof (uint32));

				return input.read_uint32 ();
			}

			public async ssize_t read_ssize () throws GLib.Error {
				yield prepare_to_read (sizeof (int32));

				return input.read_int32 ();
			}

			public void write_size (size_t size) throws GLib.Error {
				output.put_uint32 ((uint32) size);
			}

			private async void prepare_to_read (size_t required) throws GLib.Error {
				var available = input.get_available ();
				if (available < required)
					yield input.fill_async ((ssize_t) (required - available));
			}

			private async void write_credentials () throws GLib.Error {
				yield output.flush_async ();

				var parameters = new MemoryOutputStream.resizable ();
				var p = new DataOutputStream (parameters);
				p.set_byte_order (DataStreamByteOrder.HOST_ENDIAN);
				p.put_uint32 (Posix.getpid ());
				p.put_uint32 ((uint32) Posix.getuid ());
				p.put_uint32 ((uint32) Posix.getgid ());

				var vector = OutputVector ();
				vector.buffer = parameters.data;
				vector.size = parameters.data_size;

				var vectors = new OutputVector[] { vector };
				var messages = new SocketControlMessage[] { new UnixCredentialsMessage () };
				socket.send_message (null, vectors, messages, SocketMsgFlags.NONE);
			}
		}
	}

	[DBus (name = "re.frida.Error")]
	public errordomain Error {
		SERVER_NOT_RUNNING,
		EXECUTABLE_NOT_FOUND,
		EXECUTABLE_NOT_SUPPORTED,
		PROCESS_NOT_FOUND,
		PROCESS_NOT_RESPONDING,
		INVALID_ARGUMENT,
		INVALID_OPERATION,
		PERMISSION_DENIED,
		ADDRESS_IN_USE,
		TIMED_OUT,
		NOT_SUPPORTED,
		PROTOCOL,
		TRANSPORT
	}
}
