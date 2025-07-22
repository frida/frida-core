[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	public sealed class AgentConnection : Object, AsyncInitable {
		public signal void script_message (AgentScriptId id, string json, Bytes? data);

		private Cancellable io_cancellable = new Cancellable ();

		private AgentConfig config;
		private Machine machine;
		private Allocator allocator;

		private Allocation elf_allocation;
		private Allocation config_allocation;
		private SharedBuffer shared_buffer;
		private AsyncLock request_lock = new AsyncLock ();
		private Callback mprotect_callback;
		private Callback get_writable_mappings_callback;

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
			var gdb = machine.gdb;
			ByteOrder byte_order = gdb.byte_order;
			uint pointer_size = gdb.pointer_size;

			var config_builder = new VariantBuilder (new VariantType ("(tay)"));

			uint64 kernel_base = 0xfffffff007004000ULL; // TODO: Read from config.
			config_builder.add ("t", kernel_base);

			var timer = new Timer ();
			var hash_builder = new SymbolHashBuilder ();
			string? symbol_source = config.symbol_source;
			if (symbol_source != null) {
				var payload = yield Img4.parse_file (File.new_for_path (symbol_source), cancellable);

				Bytes kerncache = payload.data;
				size_t kerncache_size = kerncache.get_size ();

				Gum.DarwinModule mod;
				try {
					mod = new Gum.DarwinModule.from_blob (kerncache, ARM64, Gum.PtrauthSupport.SUPPORTED);
				} catch (Gum.Error e) {
					throw new Error.NOT_SUPPORTED ("%s", e.message);
				}

				bool info_found = false;
				uint info_start = 0;
				uint info_end = 0;
				mod.enumerate_sections (s => {
					printerr ("> Found %s %s\n", s.segment_name, s.section_name);

					if (s.segment_name == "__PRELINK_DATA" && s.section_name == "__data") {
						printerr ("__PRELINK_DATA.__data vm_address=0x%lx file_offset=0x%x\n\n", (ulong) s.vm_address, s.file_offset);
					}

					if (s.segment_name == "__PRELINK_INFO" && s.section_name == "__kmod_info") {
						printerr ("TODO, parse: vm_address=0x%lx file_offset=0x%x\n\n", (ulong) s.vm_address, s.file_offset);
						info_found = true;
						info_start = s.file_offset;
						info_end = (uint) (info_start + s.size);
					}

					if (s.segment_name == "__PLK_LINKEDIT" && s.section_name == "__data") {
						printerr ("__PLK_LINKEDIT.__data vm_address=0x%lx file_offset=0x%x\n\n", (ulong) s.vm_address, s.file_offset);
					}

					return true;
				});
				if (!info_found)
					throw new Error.NOT_SUPPORTED ("Unable to find prelink info");
				if (info_start >= kerncache_size || info_end > kerncache_size)
					throw new Error.PROTOCOL ("Kernel cache __kmod_info section out of bounds");

				var info_pointers = new BufferReader (new Buffer (kerncache[info_start:info_end], byte_order, pointer_size));
				uint i = 0;
				uint64 chained_ptr_target_mask = (1 << 30) - 1;
				uint64 naked_kernel_base = kernel_base & chained_ptr_target_mask;
				while (info_pointers.available != 0) {
					uint64 chained_info_ptr = info_pointers.read_pointer ();
					// dyld_chained_ptr_64_kernel_cache_rebase, assuming isAuth == 0 and cacheLevel == 0
					uint kmodinfo_start = (uint) ((chained_info_ptr & chained_ptr_target_mask) - naked_kernel_base);
					uint kmodinfo_end = kmodinfo_start + 196;
					if (kmodinfo_start >= kerncache_size || kmodinfo_end > kerncache_size)
						throw new Error.PROTOCOL ("Kernel cache __kmod_info entry out of bounds");

					var kmodinfo = new BufferReader (new Buffer (kerncache[kmodinfo_start:kmodinfo_end], byte_order, pointer_size));

					kmodinfo.skip (pointer_size + 4 + 4);

					string name = kmodinfo.read_fixed_string (64);
					string version = kmodinfo.read_fixed_string (64);

					kmodinfo.skip (4 + pointer_size);

					uint64 address = kmodinfo.read_pointer ();
					uint64 size = kmodinfo.read_uint64 ();
					uint64 hdr_size = kmodinfo.read_uint64 ();

					uint64 start = kernel_base + (kmodinfo.read_pointer () & chained_ptr_target_mask);
					uint64 stop = kernel_base + (kmodinfo.read_pointer () & chained_ptr_target_mask);

					printerr ("kmod_info[%u]: name=\"%s\" version=\"%s\" address=0x%lx size=0x%lx hdr_size=0x%lx start=0x%lx stop=0x%lx\n",
						i, name, version, (ulong) address, (ulong) size, (ulong) hdr_size, (ulong) start, (ulong) stop);

					i++;
				}
				printerr ("\n");

				mod.enumerate_symbols (s => {
					hash_builder.add_symbol (new SymbolInfo () {
						name = (s.name[0] == '_') ? s.name[1:] : s.name,
						offset = (uint32) s.address,
						symbol_type = s.type,
						section = s.section,
						description = s.description
					});
					return true;
				});
			}
			Bytes symbol_data = hash_builder.build (byte_order);
			printerr ("Built symbol hash table (%zu bytes) in %u ms\n\n", symbol_data.get_size (), (uint) (timer.elapsed () * 1000.0));
			config_builder.add_value (Variant.new_from_data (new VariantType ("ay"), symbol_data.get_data (), true, symbol_data));

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

			var bp = yield gdb.add_breakpoint (SOFT, 0xfffffff007a55728, 4, cancellable);
			GDB.Breakpoint? hit_breakpoint = null;
			do {
				var exception = yield gdb.continue_until_exception (cancellable);
				hit_breakpoint = exception.breakpoint;
			} while (hit_breakpoint != bp);
			yield bp.remove (cancellable);

			elf_allocation = yield inject_elf (elf, machine, allocator, cancellable);

			uint64 start_address = 0;
			uint64 mprotect_address = 0;
			uint64 get_writable_mappings_address = 0;
			uint64 base_va = elf_allocation.virtual_address;
			printerr ("ELF injected at base address 0x%lx\n\n", (ulong) base_va);
			elf.enumerate_symbols (e => {
				if (e.name == "_start")
					start_address = base_va + e.address;
				else if (e.name == "gum_try_mprotect")
					mprotect_address = base_va + e.address;
				else if (e.name == "gum_barebone_get_writable_mappings")
					get_writable_mappings_address = base_va + e.address;
				else
					return true;
				return start_address == 0 || mprotect_address == 0 || get_writable_mappings_address == 0;
			});
			if (start_address == 0)
				throw new Error.INVALID_ARGUMENT ("Invalid agent: no _start symbol found");
			if (mprotect_address == 0)
				throw new Error.INVALID_ARGUMENT ("Invalid agent: no gum_try_mprotect symbol found");
			if (get_writable_mappings_address == 0)
				throw new Error.INVALID_ARGUMENT ("Invalid agent: no gum_barebone_get_writable_mappings symbol found");

			mprotect_callback = yield new Callback (mprotect_address, new MemoryProtectHandler (machine), machine, cancellable);
			get_writable_mappings_callback = yield new Callback (get_writable_mappings_address,
				new GetWritableMappingsHandler (machine), machine, cancellable);

			var config_blob = config_builder.end ().get_data_as_bytes ();
			config_allocation = yield allocator.allocate (config_blob.get_size (), 8, cancellable);

			timer.reset ();
			yield gdb.write_byte_array (config_allocation.virtual_address, config_blob, cancellable);
			printerr ("Uploaded %zu bytes of config in %u ms\n\n",
				config_blob.get_size (),
				(uint) (timer.elapsed () * 1000.0));

			uint64 buffer_start_pa = yield machine.invoke (start_address, {
					config_allocation.virtual_address,
					config_allocation.size
				},
				cancellable);
			uint64 buffer_end_pa = buffer_start_pa + SharedBuffer.SIZE;

			yield gdb.continue (cancellable);

			uint64 base_pa = tc.base_address;
			size_t ram_size = ram.get_size ();
			if (buffer_start_pa < base_pa || (buffer_end_pa - base_pa) > ram_size)
				throw new Error.INVALID_ARGUMENT ("Invalid transport config: base_address is incorrect");
			var buffer_offset = (size_t) (buffer_start_pa - base_pa);

			Bytes shared_bytes = ram.slice (buffer_offset, buffer_offset + SharedBuffer.SIZE);
			shared_buffer = new SharedBuffer (new Buffer (shared_bytes, byte_order, pointer_size));
			shared_buffer.check ();

			process_incoming_messages.begin ();

			return true;
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
			yield execute_command (LOAD_SCRIPT, payload, cancellable);
		}

		public async void destroy_script (AgentScriptId id, Cancellable? cancellable) throws Error, IOError {
			var payload = make_payload_builder ()
				.append_uint32 (id.handle)
				.build ();
			yield execute_command (DESTROY_SCRIPT, payload, cancellable);
		}

		public async void post_script_message (AgentScriptId id, string message, Bytes? data, Cancellable? cancellable)
				throws Error, IOError {
			// TODO: Include data.
			var payload = make_payload_builder ()
				.append_uint32 (id.handle)
				.append_string (message)
				.build ();
			yield execute_command (POST_SCRIPT_MESSAGE, payload, cancellable);
		}

		private async void process_incoming_messages () {
			var main_context = MainContext.get_thread_default ();
			try {
				while (true) {
					var source = new TimeoutSource (10);
					source.set_callback (process_incoming_messages.callback);
					source.attach (main_context);
					yield;

					AgentMessage? msg = yield fetch_script_message (io_cancellable);
					if (msg != null)
						script_message (msg.script_id, msg.text, msg.has_data ? new Bytes (msg.data) : null);
				}
			} catch (GLib.Error e) {
			}
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

		private async BufferReader execute_command (Command command, Bytes payload, Cancellable? cancellable)
				throws Error, IOError {
			yield request_lock.acquire (cancellable);
			try {
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
			} finally {
				request_lock.release ();
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
				if (size == 0)
					return new Bytes ({});
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

		private class MemoryProtectHandler : Object, CallbackHandler {
			public signal void output (string message);

			public uint arity {
				get { return 3; }
			}

			private Machine machine;

			public MemoryProtectHandler (Machine machine) {
				this.machine = machine;
			}

			public async uint64 handle_invocation (uint64[] args, CallFrame frame, Cancellable? cancellable)
					throws Error, IOError {
				var address = args[0];
				var size = (size_t) args[1];
				var prot = (Gum.PageProtection) args[2];
				try {
					yield machine.protect_pages (address, size, prot, cancellable);
					return 1;
				} catch (GLib.Error e) {
					return 0;
				}
			}
		}

		private class GetWritableMappingsHandler : Object, CallbackHandler {
			public signal void output (string message);

			public uint arity {
				get { return 2; }
			}

			private Machine machine;

			private Gee.Map<uint64?, Allocation> mappings =
				new Gee.HashMap<uint64?, Allocation> (Numeric.uint64_hash, Numeric.uint64_equal);

			public GetWritableMappingsHandler (Machine machine) {
				this.machine = machine;
			}

			public async uint64 handle_invocation (uint64[] args, CallFrame frame, Cancellable? cancellable)
					throws Error, IOError {
				var pages = args[0];
				var num_pages = (uint) args[1];

				var gdb = machine.gdb;
				var reader = new BufferReader (yield gdb.read_buffer (pages, num_pages * gdb.pointer_size, cancellable));
				var result = gdb.make_buffer_builder ();
				for (uint i = 0; i != num_pages; i++) {
					uint64 physical_address = reader.read_pointer ();
					Allocation? allocation = mappings[physical_address];
					if (allocation == null) {
						allocation = yield machine.allocate_pages (physical_address, 1, cancellable);
						mappings[physical_address] = allocation;
					}
					result.append_pointer (allocation.virtual_address);
					printerr ("pages[%u]: 0x%lx -> 0x%lx\n",
						i,
						(ulong) allocation.virtual_address,
						(ulong) physical_address);
				}

				yield gdb.write_byte_array (pages, result.build (), cancellable);
				printerr ("Wrote num_pages=%u\n\n", num_pages);

				return 0;
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

	private class AsyncLock {
		private bool held = false;
		private Gee.Queue<Waiter> waiters = new Gee.LinkedList<Waiter> ();

		public async void acquire (Cancellable? cancellable) throws IOError {
			if (!held) {
				held = true;
				return;
			}

			var completion_source = new IdleSource ();
			completion_source.set_callback (acquire.callback);

			var cancellable_source = new CancellableSource (cancellable);
			cancellable_source.set_callback (acquire.callback);
			cancellable_source.attach (MainContext.get_thread_default ());

			var w = new Waiter () {
				completion_source = completion_source,
				cancellable_source = cancellable_source
			};
			waiters.offer (w);

			yield;

			if (!w.holds_lock) {
				waiters.remove (w);
				cancellable.set_error_if_cancelled ();
			}
		}

		public void release () {
			Waiter? next = waiters.poll ();
			if (next != null) {
				next.holds_lock = true;
				next.cancellable_source.destroy ();
				next.completion_source.attach (MainContext.get_thread_default ());
			} else {
				held = false;
			}
		}

		private class Waiter {
			public IdleSource completion_source;
			public CancellableSource cancellable_source;

			public bool holds_lock = false;
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

	private class SymbolHashBuilder : Object {
		private Gee.Map<string, Gee.List<SymbolInfo>> symbol_table = new Gee.TreeMap<string, Gee.List<SymbolInfo>> ();

		public void add_symbol (SymbolInfo symbol) {
			var symbol_list = symbol_table[symbol.name];
			if (symbol_list == null) {
				symbol_list = new Gee.ArrayList<SymbolInfo> ();
				symbol_table[symbol.name] = symbol_list;
			}
			symbol_list.add (symbol);
		}

		public Bytes build (ByteOrder byte_order) {
			var builder = new BufferBuilder (byte_order);

			var all_symbols = new Gee.ArrayList<SymbolInfo> ();
			foreach (var entry in symbol_table.entries) {
				foreach (var symbol in entry.value) {
					all_symbols.add (symbol);
				}
			}

			uint total_symbols = all_symbols.size;
			builder.append_uint32 (total_symbols);

			var name_index_offset = builder.offset;
			builder.skip (total_symbols * 4);

			var addr_index_offset = builder.offset;
			builder.skip (total_symbols * 4);

			var symbol_offsets = new uint32[total_symbols];
			for (uint i = 0; i != total_symbols; i++) {
				var symbol = all_symbols[(int) i];

				builder.align (4);
				symbol_offsets[i] = (uint32) builder.offset;

				builder.append_uint32 (symbol.offset);
				builder.append_uint8 (symbol.symbol_type);
				builder.append_uint8 (symbol.section);
				builder.append_uint16 (symbol.description);
				builder.append_string (symbol.name, StringTerminator.NUL);
			}

			for (uint i = 0; i != total_symbols; i++)
				builder.write_uint32 (name_index_offset + (i * 4), symbol_offsets[i]);

			var addr_sorted_symbols = new Gee.ArrayList<int> ();
			for (uint i = 0; i != total_symbols; i++)
				addr_sorted_symbols.add ((int) i);
			addr_sorted_symbols.sort ((a, b) => {
				var symbol_a = all_symbols[a];
				var symbol_b = all_symbols[b];
				if (symbol_a.offset < symbol_b.offset)
					return -1;
				if (symbol_a.offset > symbol_b.offset)
					return 1;
				return 0;
			});

			for (uint i = 0; i != total_symbols; i++) {
				int original_index = addr_sorted_symbols[(int) i];
				uint symbol_data_offset = symbol_offsets[original_index];
				builder.write_uint32 (addr_index_offset + (i * 4), symbol_data_offset);
			}

			return builder.build ();
		}
	}

	private class SymbolInfo {
		public string name;
		public uint32 offset;
		public uint8 symbol_type;
		public uint8 section;
		public uint16 description;
	}
}
