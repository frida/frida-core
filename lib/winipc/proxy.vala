namespace WinIpc {
	public class ServerProxy : Proxy {
		public string address {
			get;
			private set;
		}

		construct {
			address = generate_address ();
			pipe = create_named_pipe (address);
		}

		~ServerProxy () {
			destroy_named_pipe (pipe);
		}

		public async void establish () throws EstablishError {
			var operation = new PipeOperation (pipe);
			var result = connect_named_pipe (pipe, operation);
			assert (result != ConnectResult.ERROR);
			if (result == ConnectResult.IO_PENDING) {
				yield wait_for_operation (operation);
			}
		}

		private string generate_address () {
			var builder = new StringBuilder ();

			builder.append ("\\\\.\\pipe\\zed-");
			for (uint i = 0; i != 16; i++) {
				builder.append_printf ("%02x", Random.int_range (0, 255));
			}

			return builder.str;
		}

		private extern static void * create_named_pipe (string name);
		private extern static void destroy_named_pipe (void * pipe);
		private extern static ConnectResult connect_named_pipe (void * pipe, PipeOperation op);
	}

	public class ClientProxy : Proxy {
		public string server_address {
			get;
			construct;
		}

		public ClientProxy (string server_address) {
			Object (server_address: server_address);
		}

		~ClientProxy () {
			if (pipe != null)
				close_pipe (pipe);
		}

		public async void establish () throws EstablishError {
			pipe = open_pipe (server_address);
			if (pipe == null)
				throw new EstablishError.OPEN_FAILED ("Failed to open pipe");
		}

		private extern static void * open_pipe (string name);
		private extern static void close_pipe (void * pipe);
	}

	public abstract class Proxy : Object {
		protected void * pipe;

		protected extern async uint wait_for_operation (PipeOperation op);
	}

	public errordomain EstablishError {
		OPEN_FAILED
	}

	private enum ConnectResult {
		ERROR,
		IO_PENDING,
		PIPE_CONNECTED
	}

	protected class PipeOperation {
		public void * pipe_handle {
			get;
			private set;
		}

		public void * wait_handle {
			get;
			private set;
		}

		public void * overlapped {
			get;
			private set;
		}

		public PipeOperation (void * pipe) {
			pipe_handle = pipe;

			create_resources ();
		}

		~PipeOperation () {
			destroy_resources ();
		}

		private extern void create_resources ();
		private extern void destroy_resources ();
	}
}
