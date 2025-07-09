[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	public sealed class AgentConnection : Object, AsyncInitable {
		private Cancellable io_cancellable = new Cancellable ();

		private AgentConfig config;
		private Machine machine;
		private Allocator allocator;

		private Allocation allocation;
		private SharedBuffer shared_buffer;

		public static async AgentConnection open (AgentConfig config, Machine machine, Allocator allocator,
				Cancellable? cancellable) throws Error, IOError {
			var connection = new AgentConnection () {
				config = config,
				machine = machine,
				allocator = allocator,
			};

			try {
				yield connection.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return connection;
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			Gum.ElfModule elf;
			try {
				elf = new Gum.ElfModule.from_file (config.path);
			} catch (Gum.Error e) {
				throw new Error.INVALID_ARGUMENT ("%s", e.message);
			}

			Bytes ram = null;
			AgentTransportConfig tc = config.transport;
#if !WINDOWS
			var fd = Posix.open (tc.path, Posix.O_RDWR);
			if (fd == -1)
				throw new Error.INVALID_ARGUMENT ("Unable to open %s: %s", tc.path, strerror (errno));

			try {
# if DARWIN
				// See https://bugs.python.org/issue11277 for details.
				// TODO: Move this quirk to GLib.
				int res = Posix.fcntl (fd, Darwin.XNU.F_FULLFSYNC);
				printerr ("fcntl(F_FULLFSYNC) => %d\n\n", res);
# endif

				var sb = Posix.Stat ();
				if (Posix.fstat (fd, out sb) == -1)
					throw new Error.INVALID_ARGUMENT ("Unable to stat %s: %s", tc.path, strerror (errno));

				size_t size = sb.st_size;
				if (size == 0)
					throw new Error.INVALID_ARGUMENT ("Memory file at %s is empty", tc.path);

				void * mem = Posix.mmap (null, size, Posix.PROT_READ | Posix.PROT_WRITE, Posix.MAP_SHARED, fd, 0);
				if (mem == Posix.MAP_FAILED)
					throw new Error.INVALID_ARGUMENT ("Unable to map %s: %s", tc.path, strerror (errno));

				ram = make_bytes_with_owner (mem, size, new MappedMemoryRegion (mem, size));
			} finally {
				Posix.close (fd);
			}
#else
			try {
				var file = new MappedFile (tc.path, true);
				ram = file.get_bytes ();
			} catch (FileError e) {
				throw new Error.INVALID_ARGUMENT ("%s", e.message);
			}
#endif

			yield machine.enter_exception_level (1, 1000, cancellable);

			allocation = yield inject_elf (elf, machine, allocator, cancellable);

			uint64 start_address = 0;
			uint64 base_va = allocation.virtual_address;
			elf.enumerate_symbols (e => {
				if (e.name == "_start") {
					start_address = base_va + e.address;
					return false;
				}
				return true;
			});
			if (start_address == 0)
				throw new Error.INVALID_ARGUMENT ("Invalid agent: no _start symbol found");

			uint64 buffer_start_pa = yield machine.invoke (start_address, {}, cancellable);
			uint64 buffer_end_pa = buffer_start_pa + SharedBuffer.SIZE;
			printerr ("Got buffer_start_pa=0x%" + uint64.FORMAT_MODIFIER + "x\n", buffer_start_pa);

			var gdb = machine.gdb;
			yield gdb.continue (cancellable);

			uint64 base_pa = tc.base_address;
			size_t ram_size = ram.get_size ();
			if (buffer_start_pa < base_pa || (buffer_end_pa - base_pa) > ram_size)
				throw new Error.INVALID_ARGUMENT ("Invalid transport config: base_address is incorrect");
			var buffer_offset = (size_t) (buffer_start_pa - base_pa);
			printerr ("Using buffer_offset=0x%zx\n\n", buffer_offset);

			Bytes shared_bytes = ram.slice (buffer_offset, buffer_offset + SharedBuffer.SIZE);
			shared_buffer = new SharedBuffer (new Buffer (shared_bytes, gdb.byte_order, gdb.pointer_size));
			shared_buffer.check ();

			var id = yield create_script ("""
					recv('ping', onPing);
					function onPing() {
						send({ type: 'pong', platform: Process.platform });
						recv('ping', onPing);
					}
				""", cancellable);
			printerr ("Created script with ID: %u\n\n", id.handle);

			yield load_script (id, cancellable);
			printerr ("Script loaded\n\n");

			yield post_script_message (id, "{\"type\":\"ping\"}", cancellable);
			printerr ("Message posted\n\n");

			AgentMessage? message = yield fetch_script_message (cancellable);
			if (message != null)
				printerr ("Fetched script message with script_id=%u text=%s\n\n", message.script_id.handle, message.text);
			else
				printerr ("No pending script messages yet\n\n");

			yield destroy_script (id, cancellable);
			printerr ("Script destroyed\n\n");

			throw new Error.NOT_SUPPORTED ("Ready to rock");
		}

		public async void close (Cancellable? cancellable) throws IOError {
			io_cancellable.cancel ();
		}

		public async AgentScriptId create_script (string source, Cancellable? cancellable) throws Error, IOError {
			var payload = new Bytes.static (source.data[:source.data.length + 1]);
			var response = yield execute_command (CREATE_SCRIPT, payload, cancellable);
			return AgentScriptId (response.read_uint32 ());
		}

		public async void load_script (AgentScriptId id, Cancellable? cancellable) throws Error, IOError {
			var payload = make_payload_builder ()
				.append_uint32 (id.handle)
				.build ();
			var response = yield execute_command (LOAD_SCRIPT, payload, cancellable);
			printerr ("Got response: %s\n\n", response.read_string ());
		}

		public async void destroy_script (AgentScriptId id, Cancellable? cancellable) throws Error, IOError {
			var payload = make_payload_builder ()
				.append_uint32 (id.handle)
				.build ();
			var response = yield execute_command (DESTROY_SCRIPT, payload, cancellable);
			printerr ("Got response: %s\n\n", response.read_string ());
		}

		public async void post_script_message (AgentScriptId id, string message, Cancellable? cancellable) throws Error, IOError {
			var payload = make_payload_builder ()
				.append_uint32 (id.handle)
				.append_string (message)
				.build ();
			var response = yield execute_command (POST_SCRIPT_MESSAGE, payload, cancellable);
			printerr ("Got response: %s\n\n", response.read_string ());
		}

		public async AgentMessage? fetch_script_message (Cancellable? cancellable) throws Error, IOError {
			var response = yield execute_command (FETCH_SCRIPT_MESSAGE, new Bytes ({}), cancellable);
			if (response.available == 0)
				return null;
			var script_id = AgentScriptId (response.read_uint32 ());
			var text = response.read_string ();
			return AgentMessage (SCRIPT, script_id, text, false, {});
		}

		private BufferBuilder make_payload_builder () {
			var b = shared_buffer.buf;
			return new BufferBuilder (b.byte_order, b.pointer_size);
		}

		private async BufferReader execute_command (Command command, Bytes payload, Cancellable? cancellable) throws Error, IOError {
			shared_buffer
				.put_data (payload)
				.put_command (command);

			var main_context = MainContext.get_thread_default ();
			while (shared_buffer.fetch_command () != IDLE) {
				var source = new TimeoutSource (10);
				source.set_callback (execute_command.callback);
				source.attach (main_context);
				yield;

				cancellable.set_error_if_cancelled ();
			}

			switch (shared_buffer.fetch_status ()) {
				case DATA_READY: {
					uint8 code = shared_buffer.fetch_result_code ();
					if (code != 0)
						throw new Error.INVALID_ARGUMENT ("%s", shared_buffer.fetch_result_string ());
					return new BufferReader (shared_buffer.fetch_result_buffer ());
				}
				case ERROR:
					throw new Error.INVALID_ARGUMENT ("%s", shared_buffer.fetch_result_string ());
				default:
					throw new Error.PROTOCOL ("Unexpected status");
			}
		}

		private class SharedBuffer {
			public const size_t SIZE = 8192;
			private const uint32 MAGIC = 0x44495246;
			private const uint32 DATA_CAPACITY = 4096;

			public Buffer buf;

			public SharedBuffer (Buffer b) {
				buf = b;
			}

			public void check () throws Error {
				uint32 magic = buf.read_uint32 (0);
				if (magic != MAGIC)
					throw new Error.INVALID_ARGUMENT ("Invalid transport config, incorrect magic: 0x%08x", magic);
			}

			public Status fetch_status () {
				return buf.read_uint8 (5);
			}

			public Command fetch_command () {
				return buf.read_uint8 (4);
			}

			public unowned SharedBuffer put_command (Command command) {
				buf.write_uint8 (4, command);
				flush ();
				return this;
			}

			public unowned SharedBuffer put_data (Bytes data) {
				buf.write_uint32 (8, (uint32) data.get_size ());
				buf.write_bytes (20, data);
				flush ();
				return this;
			}

			public uint8 fetch_result_code () {
				return buf.read_uint8 (12);
			}

			public Buffer fetch_result_buffer () throws Error {
				return new Buffer (fetch_result_bytes (), buf.byte_order, buf.pointer_size);
			}

			public Bytes fetch_result_bytes () throws Error {
				uint32 size = buf.read_uint32 (16);
				if (size > DATA_CAPACITY)
					throw new Error.PROTOCOL ("Invalid result size: %u", size);
				return buf.read_bytes (20, size);
			}

			public string fetch_result_string () throws Error {
				Bytes r = fetch_result_bytes ();
				string s = (string) r.get_data ();
				if (!s.validate ())
					throw new Error.PROTOCOL ("Result is not valid UTF-8");
				return s;
			}

			private void flush () {
#if !WINDOWS
				size_t page_size = Posix.getpagesize ();

				size_t align_mask = ~(page_size - 1);

				Bytes b = buf.bytes;
				size_t size = b.get_size ();

				size_t first_address = (size_t) b.get_data ();
				size_t last_address = first_address + size - 1;

				size_t start_page = first_address & align_mask;
				size_t end_page = (last_address & align_mask) + page_size;

				Posix.msync ((void *) start_page, end_page - start_page, Posix.MS_SYNC);
#endif
			}
		}

		private enum Command {
			IDLE,
			CREATE_SCRIPT,
			LOAD_SCRIPT,
			DESTROY_SCRIPT,
			POST_SCRIPT_MESSAGE,
			FETCH_SCRIPT_MESSAGE,
		}

		private enum Status {
			IDLE,
			BUSY,
			DATA_READY,
			ERROR
		}
	}

#if !WINDOWS
	private class MappedMemoryRegion {
		private void * mem;
		private size_t size;

		public MappedMemoryRegion (void * mem, size_t size) {
			this.mem = mem;
			this.size = size;
		}

		~MappedMemoryRegion () {
			Posix.munmap (mem, size);
		}
	}
#endif
}
