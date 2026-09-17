[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	public sealed class VirtualBoxConsole : Object {
		private SocketConnection connection;
		private InputStream input;
		private OutputStream output;
		private string pending = "";
		private uint sequence;
		private uint cpu_count;

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
				size_t chunk = size_t.min (words - done, MAX_WORDS_PER_READ * MAX_READS_PER_BATCH);

				var batch = new StringBuilder ();
				for (size_t at = 0; at < chunk; at += MAX_WORDS_PER_READ) {
					size_t count = size_t.min (chunk - at, MAX_WORDS_PER_READ);
					batch.append_printf ("dq %s L%x
",
						format_address (start + (done + at) * WORD_SIZE), (uint) count);
				}

				append_words (raw, yield run_many (batch.str, cancellable), chunk);
				done += chunk;
			}

			if (raw.len < span)
				throw new Error.INVALID_ARGUMENT ("Short read at %s", format_address (address));

			size_t offset = (size_t) (address - start);
			return new Bytes (raw.data[offset:offset + size]);
		}

		public async void write_memory (uint64 address, Bytes bytes, Cancellable? cancellable)
				throws Error, IOError {
			if (bytes.get_size () >= MIN_BYTES_PER_STAGED_WRITE)
				yield write_memory_from_file (address, bytes, cancellable);
			else
				yield write_memory_word_by_word (address, bytes, cancellable);
		}

		private async void write_memory_from_file (uint64 address, Bytes bytes, Cancellable? cancellable)
				throws Error, IOError {
			unowned uint8[] data = bytes.get_data ();
			size_t whole = data.length - (data.length % STAGED_WRITE_CHUNK_SIZE);

			if (whole != 0)
				yield write_memory_from_staging_file (address, data[0:whole], cancellable);

			if (whole != data.length) {
				yield write_memory_from_staging_file (address + whole, data[whole:data.length],
					cancellable);
			}
		}

		private async void write_memory_from_staging_file (uint64 address, uint8[] data,
				Cancellable? cancellable) throws Error, IOError {
			string path;
			try {
				FileUtils.close (FileUtils.open_tmp ("frida-barebone-XXXXXX", out path));
				FileUtils.set_data (path, data);
			} catch (FileError e) {
				throw new Error.NOT_SUPPORTED ("Unable to stage a guest memory write: %s", e.message);
			}

			try {
				yield run ("writegstmem '%s' %s".printf (path, format_address (address)), cancellable);
			} finally {
				FileUtils.unlink (path);
			}
		}

		private async void write_memory_word_by_word (uint64 address, Bytes bytes, Cancellable? cancellable)
				throws Error, IOError {
			unowned uint8[] data = bytes.get_data ();

			var batch = new StringBuilder ();
			uint queued = 0;
			size_t i = 0;
			while (i != data.length) {
				uint64 at = address + i;
				if ((at % WORD_SIZE) == 0 && data.length - i >= WORD_SIZE) {
					uint64 word = 0;
					for (uint b = 0; b != WORD_SIZE; b++)
						word |= ((uint64) data[i + b]) << (b * 8);
					batch.append_printf ("eq %s %s
", format_address (at), format_address (word));
					i += WORD_SIZE;
				} else {
					batch.append_printf ("eb %s %02x
", format_address (at), data[i]);
					i++;
				}

				if (++queued == MAX_COMMANDS_PER_BATCH) {
					yield run_many (batch.str, cancellable);
					batch.truncate ();
					queued = 0;
				}
			}

			if (queued != 0)
				yield run_many (batch.str, cancellable);
		}

		private async string run_many (string commands, Cancellable? cancellable) throws Error, IOError {
			string marker = "frida-console-%u".printf (++sequence);
			yield send (commands + marker, cancellable);
			string answer = yield read_until (marker, cancellable);
			yield read_until (PROMPT, cancellable);

			return answer.replace (PROMPT, "");
		}

		public async Gee.List<Gee.Map<string, uint64?>> read_registers (Cancellable? cancellable)
				throws Error, IOError {
			var cpus = parse_registers (yield run ("r all", cancellable));
			cpu_count = cpus.size;

			return cpus;
		}

		public async Gee.List<Gee.Map<string, uint64?>> read_core_registers (Cancellable? cancellable)
				throws Error, IOError {
			if (cpu_count == 0)
				return yield read_registers (cancellable);

			var batch = new StringBuilder ();
			for (uint i = 0; i != cpu_count; i++) {
				foreach (string name in CORE_REGISTERS)
					batch.append_printf ("r cpu%u.%s
", i, name);
			}

			return parse_registers (yield run_many (batch.str, cancellable));
		}

		private static Gee.List<Gee.Map<string, uint64?>> parse_registers (string answer) {
			var cpus = new Gee.ArrayList<Gee.Map<string, uint64?>> ();
			foreach (string token in tokenize (answer)) {
				if (!token.has_prefix ("cpu"))
					continue;

				int dot = token.index_of_char ('.');
				int assign = token.index_of_char ('=');
				if (dot == -1 || assign == -1 || assign < dot)
					continue;

				uint64 cpu;
				if (!uint64.try_parse (token[3:dot], out cpu, null, 10))
					continue;

				string val = token[assign + 1:];
				if (!val.has_prefix ("0x"))
					continue;

				uint64 parsed;
				if (!uint64.try_parse (val[2:], out parsed, null, 16))
					continue;

				string name = token[dot + 1:assign];
				if (!(name in THREAD_REGISTERS))
					continue;

				while (cpus.size <= (int) cpu)
					cpus.add (new Gee.HashMap<string, uint64?> ());
				cpus[(int) cpu][name] = parsed;
			}

			return cpus;
		}

		public async uint64? read_one_register (uint cpu, string name, Cancellable? cancellable)
				throws Error, IOError {
			string answer = yield run ("r cpu%u.%s".printf (cpu, name), cancellable);

			string prefix = "cpu%u.%s=0x".printf (cpu, name);
			foreach (string token in tokenize (answer)) {
				if (!token.has_prefix (prefix))
					continue;

				uint64 val;
				if (uint64.try_parse (token[prefix.length:], out val, null, 16))
					return val;
			}

			return null;
		}

		public async void write_register (uint cpu, string name, uint64 val, Cancellable? cancellable)
				throws Error, IOError {
			yield run ("r cpu%u.%s = %s".printf (cpu, name, format_address (val)), cancellable);
		}

		public async void resume (Cancellable? cancellable) throws Error, IOError {
			yield run ("g", cancellable);
		}

		public async void halt (Cancellable? cancellable) throws Error, IOError {
			yield run ("stop", cancellable);
			yield settle (cancellable);
		}

		private async void settle (Cancellable? cancellable) throws Error, IOError {
			var buffer = new uint8[READ_CHUNK_SIZE];

			while (true) {
				var quiet = new Cancellable ();
				ulong link = 0;
				if (cancellable != null)
					link = cancellable.connect (() => quiet.cancel ());

				var source = new TimeoutSource (QUIET_PERIOD_MSEC);
				source.set_callback (() => {
					quiet.cancel ();
					return Source.REMOVE;
				});
				source.attach (MainContext.get_thread_default ());

				ssize_t n;
				try {
					n = yield input.read_async (buffer, Priority.DEFAULT, quiet);
				} catch (GLib.Error e) {
					n = 0;
				}

				source.destroy ();
				if (link != 0)
					cancellable.disconnect (link);
				if (cancellable != null)
					cancellable.set_error_if_cancelled ();

				if (n <= 0)
					break;
			}

			pending = "";
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
		private const uint QUIET_PERIOD_MSEC = 50;
		private const size_t WORD_SIZE = 8;
		private const string[] THREAD_REGISTERS = {
			"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
			"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
			"rip", "rflags",
			"cs", "ss", "ds", "es", "fs", "gs",
			"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "eflags",
		};
		private const uint MAX_COMMANDS_PER_BATCH = 512;
		private const size_t MIN_BYTES_PER_STAGED_WRITE = 512;
		private const size_t STAGED_WRITE_CHUNK_SIZE = 0x4000;
		internal const string[] CORE_REGISTERS = { "rip", "cs", "rsp" };
		private const size_t MAX_WORDS_PER_READ = 256;
		private const size_t MAX_READS_PER_BATCH = 16;
	}
}
