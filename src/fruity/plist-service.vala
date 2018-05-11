namespace Frida.Fruity {
	public class PlistServiceClient : Object {
		public IOStream stream {
			get;
			construct;
		}
		private TlsClientConnection? tls_connection;
		private InputStream input;
		private OutputStream output;
		private Cancellable cancellable = new Cancellable ();

		private Gee.ArrayQueue<PendingQuery> pending_queries = new Gee.ArrayQueue<PendingQuery> ();

		private const uint32 MAX_MESSAGE_SIZE = 128 * 1024;

		public PlistServiceClient (IOStream stream) {
			Object (stream: stream);
		}

		construct {
			input = stream.get_input_stream ();
			output = stream.get_output_stream ();
		}

		public async void close () {
			cancellable.cancel ();

			var source = new IdleSource ();
			source.set_callback (() => {
				close.callback ();
				return false;
			});
			source.attach (MainContext.get_thread_default ());
			yield;

			if (tls_connection != null) {
				try {
					yield tls_connection.close_async ();
				} catch (IOError e) {
				}
				tls_connection = null;
			}

			try {
				yield stream.close_async ();
			} catch (IOError e) {
			}
		}

		public async Plist query (Plist request) throws PlistServiceError {
			var reader = yield begin_query (request);
			var response = yield reader.read ();
			reader.end ();
			return response;
		}

		public async PlistResponseReader begin_query (Plist request) throws PlistServiceError {
			bool written = false;
			bool waiting = false;

			var query = new PendingQuery (this, request);
			var written_handler = query.written.connect (() => {
				written = true;
				if (waiting)
					begin_query.callback ();
			});
			query.ended.connect (on_query_ended);

			on_query_created (query);

			if (!written) {
				waiting = true;
				yield;
				waiting = false;
			}

			query.disconnect (written_handler);

			return query;
		}

		private void on_query_created (PendingQuery query) {
			if (pending_queries.is_empty)
				query.write.begin ();

			pending_queries.offer_tail (query);
		}

		private void on_query_ended (PendingQuery query) {
			pending_queries.poll_head ();

			query.ended.disconnect (on_query_ended);

			var next_query = pending_queries.peek_head ();
			if (next_query != null)
				next_query.write.begin ();
		}

		public async void enable_encryption (Plist pair_record) throws PlistServiceError {
			assert (pending_queries.is_empty);

			try {
				var connection = TlsClientConnection.new (stream, null);
				connection.accept_certificate.connect (on_accept_certificate);

				var host_cert = pair_record.get_bytes_as_string ("HostCertificate");
				var host_key = pair_record.get_bytes_as_string ("HostPrivateKey");
				var host_certificate = new TlsCertificate.from_pem (string.join ("\n", host_cert, host_key), -1);
				connection.set_certificate (host_certificate);

				yield connection.handshake_async (Priority.DEFAULT, cancellable);

				this.tls_connection = connection;
				this.input = connection.get_input_stream ();
				this.output = connection.get_output_stream ();
			} catch (GLib.Error e) {
				throw new PlistServiceError.FAILED ("%s", e.message);
			}
		}

		private bool on_accept_certificate (TlsCertificate peer_cert, TlsCertificateFlags errors) {
			return true;
		}

		private async Plist read_message () throws PlistServiceError {
			uint32 size = 0;
			unowned uint8[] size_buf = ((uint8[]) &size)[0:4];
			yield read (size_buf);
			size = uint32.from_big_endian (size);
			if (size < 1 || size > MAX_MESSAGE_SIZE)
				throw new PlistServiceError.PROTOCOL ("Invalid message size");

			var body_buf = new uint8[size + 1];
			body_buf[size] = 0;
			unowned uint8[] body = body_buf[0:size];
			yield read (body);

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

		private async void read (uint8[] buffer) throws PlistServiceError {
			size_t bytes_read;
			try {
				yield input.read_all_async (buffer, Priority.DEFAULT, cancellable, out bytes_read);
			} catch (GLib.Error e) {
				throw new PlistServiceError.CONNECTION_CLOSED ("%s", e.message);
			}
			if (bytes_read == 0)
				throw new PlistServiceError.CONNECTION_CLOSED ("Connection closed");
		}

		private async void write_message (Plist message) throws PlistServiceError {
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
				throw new PlistServiceError.CONNECTION_CLOSED ("%s", e.message);
			}
		}

		private class PendingQuery : Object, PlistResponseReader {
			public signal void written ();
			public signal void ended ();

			public weak PlistServiceClient client {
				get;
				construct;
			}

			public Plist request {
				get;
				construct;
			}

			public PendingQuery (PlistServiceClient client, Plist request) {
				Object (
					client: client,
					request: request
				);
			}

			public async void write () {
				try {
					yield client.write_message (request);
				} catch (PlistServiceError e) {
					// Safe to assume that read() is going to fail
				} finally {
					written ();
				}
			}

			private async Plist read () throws PlistServiceError {
				try {
					return yield client.read_message ();
				} catch (PlistServiceError e) {
					end ();
					throw e;
				}
			}

			private void end () {
				ended ();
			}
		}
	}

	public interface PlistResponseReader : Object {
		public abstract async Plist read () throws PlistServiceError;
		public abstract void end ();
	}

	public errordomain PlistServiceError {
		FAILED,
		CONNECTION_CLOSED,
		PROTOCOL
	}
}
