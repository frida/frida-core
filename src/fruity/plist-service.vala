[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
	public class PlistServiceClient : Object {
		public signal void closed ();

		public IOStream stream {
			get {
				return _stream;
			}
			set {
				_stream = value;
				input = stream.get_input_stream ();
				output = stream.get_output_stream ();
			}
		}

		private IOStream _stream;
		private InputStream input;
		private OutputStream output;
		private Cancellable io_cancellable = new Cancellable ();

		private State state = OPEN;

		private ByteArray pending_output = new ByteArray ();
		private bool writing = false;

		private enum State {
			OPEN,
			CLOSED
		}

		private const uint32 MAX_MESSAGE_SIZE = 100 * 1024 * 1024;

		public PlistServiceClient (IOStream stream) {
			Object (stream: stream);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			io_cancellable.cancel ();

			var source = new IdleSource ();
			source.set_callback (close.callback);
			source.attach (MainContext.get_thread_default ());
			yield;

			try {
				yield stream.close_async (Priority.DEFAULT, cancellable);
			} catch (IOError e) {
			}
		}

		public async Plist query (Plist request, Cancellable? cancellable) throws PlistServiceError, IOError {
			write_message (request);
			return yield read_message (cancellable);
		}

		public void write_message (Plist message) {
			var xml = message.to_xml ();
			unowned uint8[] body = ((uint8[]) xml)[0:xml.length];

			uint offset = pending_output.len;
			pending_output.set_size ((uint) (offset + sizeof (uint32) + body.length));

			uint8 * blob = (uint8 *) pending_output.data + offset;

			uint32 * size = blob;
			*size = body.length.to_big_endian ();

			Memory.copy (blob + 4, body, body.length);

			if (!writing) {
				writing = true;

				var source = new IdleSource ();
				source.set_callback (() => {
					process_pending_output.begin ();
					return false;
				});
				source.attach (MainContext.get_thread_default ());
			}
		}

		public async Plist read_message (Cancellable? cancellable) throws PlistServiceError, IOError {
			uint32 size = 0;
			unowned uint8[] size_buf = ((uint8[]) &size)[0:4];
			yield read (size_buf, cancellable);
			size = uint32.from_big_endian (size);
			if (size < 1 || size > MAX_MESSAGE_SIZE)
				throw new PlistServiceError.PROTOCOL ("Invalid message size");

			var body_buf = new uint8[size + 1];
			body_buf[size] = 0;
			unowned uint8[] body = body_buf[0:size];
			yield read (body, cancellable);

			try {
				unowned string body_str = (string) body_buf;
				if (body_str.has_prefix ("bplist"))
					return new Plist.from_binary (body);
				else
					return new Plist.from_xml (body_str);
			} catch (PlistError e) {
				throw new PlistServiceError.PROTOCOL ("Malformed message: %s", e.message);
			}
		}

		private async void process_pending_output () {
			while (pending_output.len > 0) {
				uint8[] batch = pending_output.steal ();

				size_t bytes_written;
				try {
					yield output.write_all_async (batch, Priority.DEFAULT, io_cancellable, out bytes_written);
				} catch (GLib.Error e) {
					ensure_closed ();
					break;
				}
			}

			writing = false;
		}

		private async void read (uint8[] buffer, Cancellable? cancellable) throws PlistServiceError, IOError {
			size_t bytes_read;
			try {
				yield input.read_all_async (buffer, Priority.DEFAULT, cancellable, out bytes_read);
			} catch (GLib.Error e) {
				ensure_closed ();
				throw new PlistServiceError.CONNECTION_CLOSED ("%s", e.message);
			}
			if (bytes_read == 0) {
				ensure_closed ();
				throw new PlistServiceError.CONNECTION_CLOSED ("Connection closed");
			}
		}

		private void ensure_closed () {
			if (state == CLOSED)
				return;
			state = CLOSED;
			closed ();
		}
	}

	public errordomain PlistServiceError {
		CONNECTION_CLOSED,
		PROTOCOL
	}
}
