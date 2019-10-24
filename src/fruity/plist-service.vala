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

		private State state = OPEN;

		private weak PendingQuery pending_query;

		private enum State {
			OPEN,
			CLOSED
		}

		private const uint32 MAX_MESSAGE_SIZE = 1024 * 1024;

		public PlistServiceClient (IOStream stream) {
			Object (stream: stream);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			try {
				yield stream.close_async (Priority.DEFAULT, cancellable);
			} catch (IOError e) {
			}
		}

		public async Plist query (Plist request, Cancellable? cancellable) throws PlistServiceError, IOError {
			var reader = yield begin_query (request, cancellable);
			var response = yield reader.read (cancellable);
			reader.end ();
			return response;
		}

		public async PlistResponseReader begin_query (Plist request, Cancellable? cancellable) throws PlistServiceError, IOError {
			assert (pending_query == null);

			var query = new PendingQuery (this);
			pending_query = query;
			query.ended.connect (on_query_ended);

			yield write_message (request, cancellable);

			return query;
		}

		private void on_query_ended (PendingQuery query) {
			assert (query == pending_query);

			query.ended.disconnect (on_query_ended);
			pending_query = null;
		}

		private async Plist read_message (Cancellable? cancellable) throws PlistServiceError, IOError {
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

		private async void write_message (Plist message, Cancellable? cancellable) throws PlistServiceError, IOError {
			var xml = message.to_xml ();
			unowned uint8[] body = ((uint8[]) xml)[0:xml.length];

			uint8[] blob = new uint8[4 + body.length];

			uint32 * size = (void *) blob;
			*size = body.length.to_big_endian ();

			uint8 * blob_start = (void *) blob;
			Memory.copy (blob_start + 4, body, body.length);

			size_t bytes_written;
			try {
				yield output.write_all_async (blob, Priority.DEFAULT, cancellable, out bytes_written);
			} catch (GLib.Error e) {
				ensure_closed ();
				throw new PlistServiceError.CONNECTION_CLOSED ("%s", e.message);
			}
		}

		private void ensure_closed () {
			if (state == CLOSED)
				return;
			state = CLOSED;
			closed ();
		}

		private class PendingQuery : Object, PlistResponseReader {
			public signal void ended ();

			public PlistServiceClient client {
				get;
				construct;
			}

			private bool in_progress = true;

			public PendingQuery (PlistServiceClient client) {
				Object (client: client);
			}

			public override void dispose () {
				end ();

				base.dispose ();
			}

			private async Plist read (Cancellable? cancellable) throws PlistServiceError, IOError {
				Plist? response = null;
				try {
					response = yield client.read_message (cancellable);
					return response;
				} finally {
					if (response == null)
						end ();
				}
			}

			private void end () {
				if (in_progress) {
					in_progress = false;

					ended ();
				}
			}
		}
	}

	public interface PlistResponseReader : Object {
		public abstract async Plist read (Cancellable? cancellable) throws PlistServiceError, IOError;
		public abstract void end ();
	}

	public errordomain PlistServiceError {
		CONNECTION_CLOSED,
		PROTOCOL
	}
}
