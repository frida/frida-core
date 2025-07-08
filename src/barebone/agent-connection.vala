[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	public sealed class AgentConnection : Object, AsyncInitable {
		private Cancellable io_cancellable = new Cancellable ();

		private AgentConfig config;
		private Machine machine;
		private Allocator allocator;

		private Allocation allocation;

		private const size_t BUFFER_SIZE = 8192;

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

			AgentTransportConfig tc = config.transport;
			MappedFile ram;
			try {
				ram = new MappedFile (tc.path, true);
			} catch (FileError e) {
				throw new Error.INVALID_ARGUMENT ("%s", e.message);
			}

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
			uint64 buffer_end_pa = buffer_start_pa + BUFFER_SIZE;
			printerr ("Using buffer_start_pa=0x%llx\n\n", buffer_start_pa);

			uint64 base_pa = tc.base_address;
			size_t ram_size = ram.get_length ();
			if (buffer_start_pa < base_pa || (buffer_end_pa - base_pa) > ram_size)
				throw new Error.INVALID_ARGUMENT ("Invalid transport config: base_address is incorrect");

			var gdb = machine.gdb;
			var buf = new Buffer (ram.get_bytes (), gdb.byte_order, gdb.pointer_size);

			uint32 magic = buf.read_uint32 ((size_t) (buffer_start_pa - base_pa));
			printerr ("Got magic=0x%08x\n\n", magic);

			throw new Error.NOT_SUPPORTED ("TODO");
		}

		public async void close (Cancellable? cancellable) throws IOError {
			io_cancellable.cancel ();
		}
	}
}
