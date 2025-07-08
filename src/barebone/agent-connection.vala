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

			AgentTransportConfig tc = config.transport;
			MappedFile ram_file;
			try {
				ram_file = new MappedFile (tc.path, true);
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
			uint64 buffer_end_pa = buffer_start_pa + SharedBuffer.SIZE;

			uint64 base_pa = tc.base_address;
			size_t ram_size = ram_file.get_length ();
			if (buffer_start_pa < base_pa || (buffer_end_pa - base_pa) > ram_size)
				throw new Error.INVALID_ARGUMENT ("Invalid transport config: base_address is incorrect");
			var buffer_offset = (size_t) (buffer_start_pa - base_pa);

			var gdb = machine.gdb;
			shared_buffer = new SharedBuffer (
				new Buffer (ram_file.get_bytes ().slice (buffer_offset, buffer_offset + SharedBuffer.SIZE),
					gdb.byte_order, gdb.pointer_size));
			shared_buffer.check ();

			throw new Error.NOT_SUPPORTED ("Ready to rock");
		}

		public async void close (Cancellable? cancellable) throws IOError {
			io_cancellable.cancel ();
		}

		private async Bytes execute_command (Command command, Bytes payload, Cancellable? cancellable) throws Error, IOError {
			shared_buffer
				.put_data (payload)
				.put_command (command);

			var main_context = MainContext.get_thread_default ();
			while (true) {
				switch (shared_buffer.fetch_status ()) {
					case DATA_READY: {
						ResultCode code = shared_buffer.fetch_result_code ();
						if (code != SUCCESS)
							throw new Error.INVALID_ARGUMENT ("%s", shared_buffer.fetch_result_string ());
						return shared_buffer.fetch_result_bytes ();
					}
					case ERROR:
						throw new Error.INVALID_ARGUMENT ("%s", shared_buffer.fetch_result_string ());
					default: {
						cancellable.set_error_if_cancelled ();

						var source = new TimeoutSource (10);
						source.set_callback (execute_command.callback);
						source.attach (main_context);
						yield;

						break;
					}
				}
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

			public unowned SharedBuffer put_command (Command command) {
				buf.write_uint8 (5, command);
				return this;
			}

			public unowned SharedBuffer put_data (Bytes data) {
				buf.write_uint32 (8, (uint32) data.get_size ());
				buf.write_bytes (20, data);
				return this;
			}

			public Status fetch_status () {
				return buf.read_uint8 (4);
			}

			public ResultCode fetch_result_code () {
				return buf.read_uint8 (12);
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
		}

		private enum Status {
			IDLE,
			BUSY,
			DATA_READY,
			ERROR
		}

		private enum Command {
			IDLE,
			PING,
			EXEC_JS,
			SHUTDOWN,
		}

		private enum ResultCode {
			SUCCESS,
			INVALID_ARGUMENT,
		}
	}
}
