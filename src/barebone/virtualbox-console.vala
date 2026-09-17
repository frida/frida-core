[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	public sealed class VirtualBoxConsole : Object {
		private SocketConnection connection;
		private InputStream input;
		private OutputStream output;
		private string pending = "";
		private uint sequence;

		private VirtualBoxConsole (SocketConnection connection) {
			this.connection = connection;
			this.input = connection.get_input_stream ();
			this.output = connection.get_output_stream ();
		}

		public static async VirtualBoxConsole open (string host, uint16 port, Cancellable? cancellable)
				throws Error, IOError {
			SocketConnection connection;
			try {
				var client = new SocketClient ();
				connection = yield client.connect_async (NetworkAddress.parse (host, port), cancellable);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("Unable to reach the VirtualBox debugger console: %s", e.message);
			}

			Tcp.enable_nodelay (connection.socket);

			var console = new VirtualBoxConsole (connection);
			yield console.read_until (PROMPT, cancellable);

			return console;
		}

		public async string run (string command, Cancellable? cancellable) throws Error, IOError {
			yield send (command, cancellable);
			string reply = yield read_until (PROMPT, cancellable);

			string marker = "frida-console-%u".printf (++sequence);
			yield send (marker, cancellable);
			string trailer = yield read_until (marker, cancellable);
			yield read_until (PROMPT, cancellable);

			string answer = reply + drop_last_line (trailer);

			int error_start = answer.contains (EVENT_MARKER) ? -1 : answer.index_of (ERROR_MARKER);
			if (error_start != -1) {
				int message_start = error_start + ERROR_MARKER.length;
				int message_end = answer.index_of_char ('\n', message_start);
				string message = (message_end != -1)
					? answer[message_start:message_end]
					: answer[message_start:];
				throw new Error.NOT_SUPPORTED ("%s", message.strip ());
			}

			return answer;
		}

		private async void send (string line, Cancellable? cancellable) throws Error, IOError {
			try {
				yield output.write_all_async ((line + "\n").data, Priority.DEFAULT, cancellable, null);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("Unable to drive the VirtualBox debugger console: %s", e.message);
			}
		}

		private async string read_until (string needle, Cancellable? cancellable) throws Error, IOError {
			var text = new StringBuilder (pending);
			pending = "";

			var buffer = new uint8[READ_CHUNK_SIZE];
			while (!text.str.contains (needle)) {
				ssize_t n;
				try {
					n = yield input.read_async (buffer, Priority.DEFAULT, cancellable);
				} catch (GLib.Error e) {
					throw new Error.TRANSPORT ("The VirtualBox debugger console went away: %s", e.message);
				}
				if (n <= 0)
					throw new Error.TRANSPORT ("The VirtualBox debugger console closed the connection");

				for (ssize_t i = 0; i != n; i++) {
					uint8 b = buffer[i];
					bool printable = (b >= 0x20 && b < 0x7f) || b == '\n';
					text.append_c (printable ? (char) b : ' ');
				}
			}

			string all = text.str;
			int at = all.index_of (needle);
			pending = all[at + needle.length:];

			return all[0:at];
		}

		private static string drop_last_line (string text) {
			int last = text.last_index_of_char ('\n');
			return (last != -1) ? text[0:last] : "";
		}

		public async Bytes read_memory (uint64 address, size_t size, Cancellable? cancellable)
				throws Error, IOError {
			uint64 start = address & ~((uint64) WORD_SIZE - 1);
			size_t span = (size_t) (address - start) + size;
			size_t words = (span + WORD_SIZE - 1) / WORD_SIZE;

			var raw = new ByteArray ();
			size_t done = 0;
			while (done != words) {
				size_t batch = size_t.min (words - done, MAX_WORDS_PER_READ);
				string answer = yield run ("dq %s L%x".printf (
					format_address (start + done * WORD_SIZE), (uint) batch), cancellable);
				append_words (raw, answer, batch);
				done += batch;
			}

			if (raw.len < span)
				throw new Error.INVALID_ARGUMENT ("Short read at %s", format_address (address));

			size_t offset = (size_t) (address - start);
			return new Bytes (raw.data[offset:offset + size]);
		}

		public async void write_memory (uint64 address, Bytes bytes, Cancellable? cancellable)
				throws Error, IOError {
			unowned uint8[] data = bytes.get_data ();
			for (size_t i = 0; i != data.length; i++)
				yield run ("eb %s %02x".printf (format_address (address + i), data[i]), cancellable);
		}

		public async void load_file (string path, uint64 address, Cancellable? cancellable)
				throws Error, IOError {
			yield run ("writegstmem %s %s".printf (path, format_address (address)), cancellable);
		}

		public async Gee.Map<string, uint64?> read_registers (uint cpu, Cancellable? cancellable)
				throws Error, IOError {
			string answer = yield run ("r all", cancellable);

			var registers = new Gee.HashMap<string, uint64?> ();
			string prefix = "cpu%u.".printf (cpu);
			foreach (string token in tokenize (answer)) {
				if (!token.has_prefix (prefix))
					continue;

				int assign = token.index_of_char ('=');
				if (assign == -1)
					continue;

				string name = token[prefix.length:assign];
				string val = token[assign + 1:];
				if (!val.has_prefix ("0x"))
					continue;

				uint64 parsed;
				if (uint64.try_parse (val[2:], out parsed, null, 16))
					registers[name] = parsed;
			}

			return registers;
		}

		public async void write_register (uint cpu, string name, uint64 val, Cancellable? cancellable)
				throws Error, IOError {
			yield run ("r cpu%u.%s = %s".printf (cpu, name, format_address (val)), cancellable);
		}

		public async uint query_cpu_count (Cancellable? cancellable) throws Error, IOError {
			string answer = yield run ("r all", cancellable);

			uint count = 0;
			while (answer.contains ("cpu%u.rip=".printf (count)))
				count++;

			return uint.max (count, 1);
		}

		public async void resume (Cancellable? cancellable) throws Error, IOError {
			yield run ("g", cancellable);
		}

		public async void halt (Cancellable? cancellable) throws Error, IOError {
			yield run ("stop", cancellable);
		}

		public async Gee.List<LoadedImage> read_loaded_images (Cancellable? cancellable) throws Error, IOError {
			yield run ("detect", cancellable);
			string answer = yield run ("lm", cancellable);

			var images = new Gee.ArrayList<LoadedImage> ();
			foreach (string line in answer.split ("\n")) {
				var words = tokenize (line);
				if (words.size < 3)
					continue;

				uint64 base_address;
				if (!uint64.try_parse (words[0], out base_address, null, 16))
					continue;

				images.add (new LoadedImage () {
					name = words[2],
					base_address = base_address,
				});
			}

			return images;
		}

		public class LoadedImage {
			public string name;
			public uint64 base_address;
		}

		private static Gee.List<string> tokenize (string text) {
			var words = new Gee.ArrayList<string> ();
			foreach (string token in text.replace ("\n", " ").split (" ")) {
				string word = token.strip ();
				if (word.length != 0)
					words.add (word);
			}
			return words;
		}

		private static void append_words (ByteArray raw, string answer, size_t expected) {
			size_t taken = 0;
			foreach (string line in answer.split ("\n")) {
				string item = line.strip ();
				int colon = item.index_of_char (':');
				if (!item.has_prefix ("%") || colon == -1)
					continue;

				foreach (string word in tokenize (item[colon + 1:])) {
					if (word.length != WORD_SIZE * 2)
						continue;
					if (taken == expected)
						return;

					uint64 parsed;
					if (!uint64.try_parse (word, out parsed, null, 16))
						continue;

					for (uint i = 0; i != WORD_SIZE; i++)
						raw.append ({ (uint8) (parsed >> (i * 8)) });
					taken++;
				}
			}
		}

		private static string format_address (uint64 address) {
			return "0x%016llx".printf (address);
		}

		private const string PROMPT = "VBoxDbg>";
		private const string ERROR_MARKER = "error: ";
		private const string EVENT_MARKER = "dbgf event/";
		private const size_t READ_CHUNK_SIZE = 8192;
		private const size_t WORD_SIZE = 8;
		private const size_t MAX_WORDS_PER_READ = 256;
	}
}
