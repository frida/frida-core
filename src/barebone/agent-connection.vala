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
		private Bytes shared_bytes;
		private TransportView transport;
		private Callback mprotect_callback;
		private Callback get_writable_mappings_callback;

		private Gee.Map<uint16, Promise<Variant>> pending_requests = new Gee.HashMap<uint16, Promise<Variant>> ();
		private uint16 next_request_id = 1;

		private const int COMMAND_TIMEOUT_MS = 25000;

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
			var qmp = yield QmpClient.open ("unix:/home/oleavr/src/ios/qmp.sock", 0, cancellable);
			var sock = yield qmp.open_hostlink (cancellable);

			var gdb = machine.gdb;
			ByteOrder byte_order = gdb.byte_order;
			uint pointer_size = gdb.pointer_size;

			var config_builder = new VariantBuilder (new VariantType ("(ta(ssuuuu)ay)"));

			uint64 kernel_base = 0xfffffff007004000ULL; // TODO: Read from config.
			config_builder.add ("t", kernel_base);

			Layout layout;
			string? symbol_source = config.symbol_source;
			if (symbol_source != null) {
				layout = yield Layout.load_from_symbol_source (File.new_for_path (symbol_source), kernel_base, byte_order,
					pointer_size, cancellable);
			} else {
				layout = new Layout.empty ();
			}

			config_builder.open (new VariantType ("a(ssuuuu)"));
			foreach (var m in layout.modules) {
				config_builder.add ("(ssuuuu)",
					m.name,
					m.version,
					m.offset,
					m.size,
					m.start_func_offset,
					m.stop_func_offset
				);
			}
			config_builder.close ();

			var hash_builder = new SymbolHashBuilder ();
			foreach (var s in layout.symbols)
				hash_builder.add_symbol (s);
			Bytes symbol_data = hash_builder.build (byte_order);
			config_builder.add_value (Variant.new_from_data (new VariantType ("ay"), symbol_data.get_data (), true, symbol_data));

			Gum.ElfModule elf;
			try {
				elf = new Gum.ElfModule.from_file (config.path);
			} catch (Gum.Error e) {
				throw new Error.INVALID_ARGUMENT ("%s", e.message);
			}

			yield machine.enter_exception_level (1, 1000, cancellable);

			var bp = yield gdb.add_breakpoint (SOFT, 0xfffffff007a55728, 4, cancellable);
			GDB.Breakpoint? hit_breakpoint = null;
			do {
				var exception = yield gdb.continue_until_exception (cancellable);
				hit_breakpoint = exception.breakpoint;
			} while (hit_breakpoint != bp);
			yield bp.remove (cancellable);

			size_t page_size = yield machine.query_page_size (cancellable);

			elf_allocation = yield inject_elf (elf, page_size, machine, allocator, cancellable);

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

			yield gdb.write_byte_array (config_allocation.virtual_address, config_blob, cancellable);

			yield machine.invoke (start_address, {
					config_allocation.virtual_address,
					config_allocation.size
				},
				cancellable);

			yield gdb.continue (cancellable);

			//process_incoming_messages.begin ();

			return true;
		}

		public async void close (Cancellable? cancellable) throws IOError {
			io_cancellable.cancel ();
		}

		public async AgentScriptId create_script (string source, Cancellable? cancellable) throws Error, IOError {
			var payload = new Variant ("s", source);
			var response = yield execute_command (Command.CREATE_SCRIPT, payload, cancellable);
			if (!response.check_format_string ("u", false))
				throw new Error.PROTOCOL ("Invalid create_script response format");
			uint32 script_handle;
			response.get ("u", out script_handle);
			return AgentScriptId (script_handle);
		}

		public async void load_script (AgentScriptId script_id, Cancellable? cancellable) throws Error, IOError {
			var payload = new Variant ("u", script_id.handle);
			yield execute_command (Command.LOAD_SCRIPT, payload, cancellable);
		}

		public async void destroy_script (AgentScriptId script_id, Cancellable? cancellable) throws Error, IOError {
			var payload = new Variant ("u", script_id.handle);
			yield execute_command (Command.DESTROY_SCRIPT, payload, cancellable);
		}

		public async void post_script_message (AgentScriptId script_id, string message, Bytes? data, Cancellable? cancellable)
				throws Error, IOError {
			var payload = new Variant ("(us)", script_id.handle, message);
			// TODO: Include data.
			yield execute_command (Command.POST_SCRIPT_MESSAGE, payload, cancellable);
		}

		private async Variant execute_command (Command command, Variant payload, Cancellable? cancellable) throws Error, IOError {
			uint16 request_id = next_request_id++;
			var command_message = new Variant ("(yqv)", (uint8) command, request_id, payload);

			if (machine.gdb.byte_order != ByteOrder.HOST)
				command_message = command_message.byteswap ();

			var command_bytes = command_message.get_data_as_bytes ();

			var promise = new Promise<Variant> ();
			pending_requests[request_id] = promise;

			transport.write_message (command_bytes);

			var timeout_source = new TimeoutSource (COMMAND_TIMEOUT_MS);
			timeout_source.set_callback (() => {
				Promise<Variant>? p;
				if (pending_requests.unset (request_id, out p))
					p.reject (new Error.TIMED_OUT ("Command timed out"));
				return Source.REMOVE;
			});
			timeout_source.attach (MainContext.get_thread_default ());

			try {
				return yield promise.future.wait_async (cancellable);
			} finally {
				timeout_source.destroy ();
			}
		}

		/*
		private async void process_incoming_messages () {
			var main_context = MainContext.get_thread_default ();
			var byte_order = machine.gdb.byte_order;
			try {
				while (true) {
					io_cancellable.set_error_if_cancelled ();

					var source = new TimeoutSource (10);
					source.set_callback (process_incoming_messages.callback);
					source.attach (main_context);
					yield;

					transport.flush_pending ();

					Bytes? message_bytes = transport.try_read_message ();
					if (message_bytes == null)
						continue;

					var message = Variant.new_from_data (new VariantType ("(yqv)"), message_bytes.get_data (), false,
						message_bytes);
					if (byte_order != ByteOrder.HOST)
						message = message.byteswap ();
					if (!message.check_format_string ("(yqv)", false))
						throw new Error.PROTOCOL ("Invalid message format");

					uint8 command_code;
					uint16 request_id;
					Variant payload;
					message.get ("(yqv)", out command_code, out request_id, out payload);

					if (command_code == Command.SCRIPT_MESSAGE) {
						if (!payload.check_format_string ("(us)", false))
							throw new Error.PROTOCOL ("Invalid script message payload format");

						uint32 script_handle;
						unowned string json;
						payload.get ("(u&s)", out script_handle, out json);

						script_message (AgentScriptId (script_handle), json, null);
					} else if (command_code == Command.REPLY) {
						Promise<Variant>? promise;
						if (pending_requests.unset (request_id, out promise))
							promise.resolve (payload);
					}
				}
			} catch (GLib.Error e) {
			}
		}
		*/

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
			CREATE_SCRIPT = 1,
			LOAD_SCRIPT = 2,
			DESTROY_SCRIPT = 3,
			POST_SCRIPT_MESSAGE = 4,
			REPLY = 128,
			SCRIPT_MESSAGE = 129
		}

		private enum Status {
			IDLE,
			BUSY,
			DATA_READY,
			ERROR
		}
	}

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
				foreach (var symbol in entry.value)
					all_symbols.add (symbol);
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
				// TODO: Only include details we need.
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
}
