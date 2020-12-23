namespace Frida.JDWP {
	public class Session : Object, AsyncInitable {
		public IOStream stream {
			get;
			construct;
		}
		private InputStream input;
		private OutputStream output;
		private uint32 next_id = 1;

		private const string HANDSHAKE = "JDWP-Handshake";

		public static async Session open (IOStream stream, Cancellable? cancellable = null) throws Error, IOError {
			var session = new Session (stream);

			try {
				yield session.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return session;
		}

		private Session (IOStream stream) {
			Object (stream: stream);
		}

		construct {
			input = stream.get_input_stream ();
			output = stream.get_output_stream ();
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			yield handshake (cancellable);

			return true;
		}

		public async void close (Cancellable? cancellable) throws IOError {
			try {
				yield stream.close_async (Priority.DEFAULT, cancellable);
			} catch (IOError e) {
				if (e is IOError.CANCELLED)
					throw (IOError) e;
			}
		}

		private async void handshake (Cancellable? cancellable) throws Error, IOError {
			try {
				size_t n;

				unowned uint8[] raw_handshake = HANDSHAKE.data;
				yield output.write_all_async (raw_handshake, Priority.DEFAULT, cancellable, out n);

				var raw_reply = new uint8[HANDSHAKE.length];
				yield input.read_all_async (raw_reply, Priority.DEFAULT, cancellable, out n);

				if (Memory.cmp (raw_reply, raw_handshake, raw_reply.length) != 0)
					throw new Error.PROTOCOL ("Unexpected handshake reply");
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("%s".printf (e.message));
			}
		}

		public async void get_classes_by_signature (string signature, Cancellable? cancellable = null) throws Error, IOError {
			var command = new CommandBuilder (next_id++, VM, VMCommand.ClassesBySignature);
			command
				.append_string (signature);
			var reply = yield perform_command (command, cancellable);

			uint32 n = reply.read_uint32 ();
			printerr ("Got %u matching classes\n", n);
			for (uint32 i = 0; i != n; i++) {
				uint8 kind = reply.read_uint8 ();
				uint32 type_id = reply.read_uint32 ();
				uint32 status = reply.read_uint32 ();
				printerr ("\tkind=%u type_id=%u status=%u\n", kind, type_id, status);
			}
		}

		public async void get_all_classes (Cancellable? cancellable = null) throws Error, IOError {
			var command = new CommandBuilder (next_id++, VM, VMCommand.AllClasses);
			var reply = yield perform_command (command, cancellable);
		}

		private async ReplyReader perform_command (CommandBuilder builder, Cancellable? cancellable) throws Error, IOError {
			yield write_command (builder, cancellable);

			uint32 id = builder.id;
			while (true) {
				var reply = yield read_reply (cancellable);

				reply.skip (sizeof (uint32));
				var reply_id = reply.read_uint32 ();
				reply.skip (sizeof (uint8));
				var error_code = reply.read_uint16 ();

				if (reply_id == id) {
					if (error_code != 0)
						throw new Error.NOT_SUPPORTED ("Command failed: %u", error_code);

					return reply;
				}
			}
		}

		private async void write_command (CommandBuilder builder, Cancellable? cancellable) throws Error, IOError {
			try {
				Bytes raw_command = builder.build ();

				size_t n;
				yield output.write_all_async (raw_command.get_data (), Priority.DEFAULT, cancellable, out n);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("%s".printf (e.message));
			}
		}

		private async ReplyReader read_reply (Cancellable? cancellable) throws Error, IOError {
			try {
				size_t n;

				var raw_reply = new uint8[11];
				yield input.read_all_async (raw_reply, Priority.DEFAULT, cancellable, out n);

				uint32 reply_size = uint32.from_big_endian (*((uint32 *) raw_reply));
				// TODO: validate reply_size
				raw_reply.resize ((int) reply_size);

				yield input.read_all_async (raw_reply[11:], Priority.DEFAULT, cancellable, out n);

				return new ReplyReader ((owned) raw_reply);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("%s".printf (e.message));
			}
		}
	}

	private enum CommandSet {
		VM = 1,
	}

	private enum VMCommand {
		ClassesBySignature = 2,
		AllClasses = 3,
	}

	private class CommandBuilder {
		public uint32 id {
			get;
			private set;
		}

		public size_t offset {
			get {
				return cursor;
			}
		}

		private ByteArray buffer = new ByteArray.sized (64);
		private size_t cursor = 0;

		public CommandBuilder (uint32 id, CommandSet command_set, uint8 command) {
			this.id = id;

			uint32 length_placeholder = 0;
			append_uint32 (length_placeholder);

			append_uint32 (id);

			uint8 flags = 0;
			append_uint8 (flags);

			append_uint8 (command_set);
			append_uint8 (command);
		}

		public unowned CommandBuilder append_uint8 (uint8 val) {
			*(get_pointer (cursor, sizeof (uint8))) = val;
			cursor += (uint) sizeof (uint8);
			return this;
		}

		public unowned CommandBuilder append_uint32 (uint32 val) {
			*((uint32 *) get_pointer (cursor, sizeof (uint32))) = val.to_big_endian ();
			cursor += (uint) sizeof (uint32);
			return this;
		}

		public unowned CommandBuilder append_string (string str) {
			append_uint32 (str.length);

			uint size = str.length;
			Memory.copy (get_pointer (cursor, size), str, size);
			cursor += size;

			return this;
		}

		private uint8 * get_pointer (size_t offset, size_t n) {
			size_t minimum_size = offset + n;
			if (buffer.len < minimum_size)
				buffer.set_size ((uint) minimum_size);

			return (uint8 *) buffer.data + offset;
		}

		public Bytes build () {
			*((uint32 *) get_pointer (0, sizeof (uint32))) = buffer.len.to_big_endian ();
			return ByteArray.free_to_bytes ((owned) buffer);
		}
	}

	private class ReplyReader {
		public size_t available_bytes {
			get {
				return end - cursor;
			}
		}

		private uint8[] data;
		private uint8 * cursor;
		private uint8 * end;

		public ReplyReader (owned uint8[] data) {
			this.data = (owned) data;
			this.cursor = (uint8 *) this.data;
			this.end = cursor + this.data.length;
		}

		public void skip (size_t n) throws Error {
			check_available (n);
			cursor += n;
		}

		public uint8 read_uint8 () throws Error {
			const size_t n = sizeof (uint8);
			check_available (n);

			uint8 val = *cursor;
			cursor += n;

			return val;
		}

		public uint16 read_uint16 () throws Error {
			const size_t n = sizeof (uint16);
			check_available (n);

			uint16 val = uint16.from_big_endian (*((uint16 *) cursor));
			cursor += n;

			return val;
		}

		public uint32 read_uint32 () throws Error {
			const size_t n = sizeof (uint32);
			check_available (n);

			uint32 val = uint32.from_big_endian (*((uint32 *) cursor));
			cursor += n;

			return val;
		}

		public unowned uint8[] read_byte_array (size_t n) throws Error {
			check_available (n);

			unowned uint8[] arr = ((uint8[]) cursor)[0:n];
			cursor += n;

			return arr;
		}

		public string read_utf16_string () throws Error {
			size_t length = read_uint32 ();
			size_t size = length * sizeof (uint16);

			unowned uint8[] str_bytes = read_byte_array (size);
			var str_words = new uint16[length];
			for (uint i = 0; i != length; i++) {
				str_words[i] = uint16.from_big_endian (*((uint16 *) ((uint8 *) str_bytes + (i * sizeof (uint16)))));
			}

			unowned string16 str_utf16 = (string16) str_words;

			try {
				return str_utf16.to_utf8 ((long) length);
			} catch (ConvertError e) {
				throw new Error.PROTOCOL ("%s", e.message);
			}
		}

		private void check_available (size_t n) throws Error {
			if (cursor + n > end)
				throw new Error.PROTOCOL ("Invalid reply");
		}
	}
}
