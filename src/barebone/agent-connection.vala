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
				if (res != 0)
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
			printerr ("buffer_start_pa=0x%llx\n\n", buffer_start_pa);
			uint64 buffer_end_pa = buffer_start_pa + SharedBuffer.SIZE;
			printerr ("buffer_end_pa=0x%llx\n\n", buffer_end_pa);

			var gdb = machine.gdb;
			yield gdb.continue (cancellable);

			uint64 base_pa = tc.base_address;
			size_t ram_size = ram.get_size ();
			printerr ("ram_size=%zu\n\n", ram_size);
			if (buffer_start_pa < base_pa || (buffer_end_pa - base_pa) > ram_size)
				throw new Error.INVALID_ARGUMENT ("Invalid transport config: base_address is incorrect");
			var buffer_offset = (size_t) (buffer_start_pa - base_pa);
			printerr ("Using buffer_offset=0x%zx\n\n", buffer_offset);

			Bytes shared_bytes = ram.slice (buffer_offset, buffer_offset + SharedBuffer.SIZE);
			shared_buffer = new SharedBuffer (new Buffer (shared_bytes, gdb.byte_order, gdb.pointer_size));
			shared_buffer.check ();

			var id = yield create_script ("send('Hello hsorbo');", cancellable);
			printerr ("Created script with ID: %u\n\n", id.handle);

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

		private async BufferReader execute_command (Command command, Bytes payload, Cancellable? cancellable) throws Error, IOError {
			shared_buffer
				.put_data (payload)
				.put_command (command);

			var main_context = MainContext.get_thread_default ();
			while (shared_buffer.fetch_command () != IDLE) {
				printerr ("Still waiting...\n");
				var source = new TimeoutSource (1000);
				source.set_callback (execute_command.callback);
				source.attach (main_context);
				yield;

				cancellable.set_error_if_cancelled ();
			}

			var status = shared_buffer.fetch_status ();
			printerr ("status=%s\n", status.to_string ());
			switch (status) {
				case DATA_READY: {
					ResultCode code = shared_buffer.fetch_result_code ();
					if (code != SUCCESS)
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

			private Buffer buf;

			public SharedBuffer (Buffer b) {
				buf = b;
			}

			public void check () throws Error {
				uint32 magic = buf.read_uint32 (0);
				if (magic != MAGIC)
					throw new Error.INVALID_ARGUMENT ("Invalid transport config, incorrect magic: 0x%08x", magic);
			}

			public Status fetch_status () {
				return buf.read_uint8 (4);
			}

			public Command fetch_command () {
				return buf.read_uint8 (5);
			}

			public unowned SharedBuffer put_command (Command command) {
				buf.write_uint8 (5, command);
				flush ();
				return this;
			}

			public unowned SharedBuffer put_data (Bytes data) {
				buf.write_uint32 (8, (uint32) data.get_size ());
				buf.write_bytes (20, data);
				flush ();
				return this;
			}

			public ResultCode fetch_result_code () {
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

				int res = Posix.msync ((void *) start_page, end_page - start_page, Posix.MS_SYNC);
				printerr ("msync(0x%zx->0x%zx) => %d\n\n", start_page, end_page, res);
#endif
			}
		}

		private enum Status {
			IDLE,
			BUSY,
			DATA_READY,
			ERROR
		}

		private enum Command {
			IDLE,
			CREATE_SCRIPT,
			EXEC_JS,
			SHUTDOWN,
		}

		private enum ResultCode {
			SUCCESS,
			INVALID_ARGUMENT,
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
			int res = Posix.munmap (mem, size);
			printerr ("Posix.munmap() => %d\n\n", res);
		}
	}
#endif
}
