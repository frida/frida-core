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

		public async void establish () throws ProxyError {
			try {
				var operation = new PipeOperation (pipe);
				var result = connect_named_pipe (pipe, operation);
				yield complete_pipe_operation (result, operation);
			} catch (IOError connect_error) {
				throw new ProxyError.IO_ERROR (connect_error.message);
			}

			process_messages ();
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
		private extern static IOResult connect_named_pipe (void * pipe, PipeOperation op) throws IOError;
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

		public async void establish () throws ProxyError {
			try {
				pipe = open_pipe (server_address);
			} catch (IOError open_error) {
				var not_found_error = new IOError.NOT_FOUND ("");
				if (open_error.code == not_found_error.code) {
					throw new ProxyError.SERVER_NOT_FOUND (open_error.message);
				} else {
					throw new ProxyError.IO_ERROR (open_error.message);
				}
			}

			process_messages ();
		}

		private extern static void * open_pipe (string name) throws IOError;
		private extern static void close_pipe (void * pipe);
	}

	public abstract class Proxy : Object {
		protected void * pipe;

		public delegate string Handler (string query);

		public async string query (string id) throws ProxyError {
			try {
				yield write_message (id);
				return yield read_message ();
			} catch (IOError send_error) {
				throw new ProxyError.IO_ERROR (send_error.message);
			}
		}

		public void register_handler (string query_id, Proxy.Handler handler) {
		}

		protected async void process_messages () {
			try {
				while (pipe != null) {
					string message = yield read_message ();
					stdout.printf ("proxy %p read: '%s'\n", this, message);
				}
			} catch (IOError e) {
				stderr.printf ("proxy %p caught IO error: '%s'\n", this, e.message);
			}
		}

		protected async void complete_pipe_operation (IOResult result, PipeOperation operation) throws IOError {
			if (result == IOResult.SUCCESS)
				return;
			yield wait_for_operation (operation);
			operation.consume_result ();
		}

		protected extern async string read_message () throws IOError;
		protected extern async void write_message (string message) throws IOError;
		protected extern async void wait_for_operation (PipeOperation op) throws IOError;
	}

	public errordomain ProxyError {
		SERVER_NOT_FOUND,
		INVALID_QUERY,
		IO_ERROR
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

		public string function_name {
			get;
			set;
		}

		public void * buffer {
			get;
			set;
		}

		public void * user_data {
			get;
			set;
		}

		public PipeOperation (void * pipe) {
			pipe_handle = pipe;

			create_resources ();
		}

		~PipeOperation () {
			destroy_resources ();
		}

		public void * steal_buffer () {
			assert (this.buffer != null);
			void * result = this.buffer;
			this.buffer = null;
			return result;
		}

		public extern static PipeOperation from_overlapped (void * overlapped);

		public extern uint consume_result () throws IOError;

		private extern void create_resources ();
		private extern void destroy_resources ();
	}

	protected enum IOResult {
		INVALID,
		PENDING,
		SUCCESS
	}
}
