namespace Zed {
	public class Pipe : IOStream {
		public string address {
			get;
			construct;
		}

		public void * _backend;
		private PipeInputStream input;
		private PipeOutputStream output;

		public Pipe (string address) {
			Object (address: address);

			_create_backend ();

			input = new PipeInputStream (_backend);
			output = new PipeOutputStream (_backend);
		}

		~Pipe () {
			_destroy_backend ();
		}

		public override unowned InputStream get_input_stream () {
			return input;
		}

		public override unowned OutputStream get_output_stream () {
			return output;
		}

		public extern void _create_backend ();
		public extern void _destroy_backend ();
	}

	public class PipeInputStream : InputStream {
		public void * _backend;

		public PipeInputStream (void * backend) {
			this._backend = backend;
		}

		public override ssize_t read (uint8[] buffer, Cancellable? cancellable = null) throws IOError {
			return _read (buffer, cancellable);
		}

		public extern ssize_t _read (uint8[] buffer, Cancellable? cancellable) throws IOError;
	}

	public class PipeOutputStream : OutputStream {
		public void * _backend;

		public PipeOutputStream (void * backend) {
			this._backend = backend;
		}

		public override ssize_t write (uint8[] buffer, Cancellable? cancellable = null) throws IOError {
			return _write (buffer, cancellable);
		}

		public extern ssize_t _write (uint8[] buffer, Cancellable? cancellable) throws IOError;
	}
}
