namespace Frida.LLDB {
	public class Client : Object, AsyncInitable {
		public signal void closed ();
		public signal void console_output (Bytes bytes);

		public IOStream stream {
			get;
			construct;
		}

		public Process? process {
			get {
				return _process;
			}
		}

		public State state {
			get {
				return _state;
			}
		}

		public Exception? exception {
			get {
				return _exception;
			}
		}

		private DataInputStream input;
		private OutputStream output;
		private Cancellable io_cancellable = new Cancellable ();

		private State _state = STOPPED;
		private Exception? _exception;
		private Exception? breakpoint_exception;
		private Gee.ArrayList<StopObserverEntry> on_stop = new Gee.ArrayList<StopObserverEntry> ();
		private AckMode ack_mode = SEND_ACKS;
		private Gee.ArrayQueue<Bytes> pending_writes = new Gee.ArrayQueue<Bytes> ();
		private Gee.ArrayQueue<PendingResponse> pending_responses = new Gee.ArrayQueue<PendingResponse> ();

		private Process? _process;
		private uint64 ptrauth_removal_mask;
		private Gee.HashMap<string, Register>? register_by_name;
		private Gee.HashMap<uint, Register>? register_by_id;
		private Gee.HashMap<uint64?, Breakpoint> breakpoints = new Gee.HashMap<uint64?, Breakpoint> (
			(n) => { return int64_hash ((int64?) n); },
			(a, b) => { return int64_equal ((int64?) a, (int64?) b); }
		);
		private AppleDyldFields? cached_dyld_fields;

		public enum State {
			STOPPED,
			RUNNING,
			STOPPING,
			CLOSED
		}

		private enum AckMode {
			SEND_ACKS,
			SKIP_ACKS
		}

		public enum ChecksumType {
			PROPER,
			ZEROED
		}

		private const char NOTIFICATION_TYPE_EXIT_STATUS = 'W';
		private const char NOTIFICATION_TYPE_EXIT_SIGNAL = 'X';
		private const char NOTIFICATION_TYPE_THREADS = 'T';
		private const char NOTIFICATION_TYPE_OUTPUT = 'O';

		private const char STOP_CHARACTER = 0x03;
		private const string ACK_NOTIFICATION = "+";
		private const string NACK_NOTIFICATION = "-";
		private const string PACKET_MARKER = "$";
		private const char PACKET_CHARACTER = '$';
		private const string CHECKSUM_MARKER = "#";
		private const char CHECKSUM_CHARACTER = '#';
		private const char ESCAPE_CHARACTER = '}';
		private const uint8 ESCAPE_KEY = 0x20;
		private const char REPEAT_CHARACTER = '*';
		private const uint8 REPEAT_BASE = 0x20;
		private const uint8 REPEAT_BIAS = 3;

		private Client (IOStream stream) {
			Object (stream: stream);
		}

		public static async Client open (IOStream stream, Cancellable? cancellable = null) throws Error, IOError {
			var client = new Client (stream);

			try {
				yield client.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_local_error (e);
			}

			return client;
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			try {
				input = new DataInputStream (stream.get_input_stream ());
				output = stream.get_output_stream ();

				process_incoming_packets.begin ();
				write_string (ACK_NOTIFICATION);

				yield _execute_simple ("QStartNoAckMode", cancellable);
				ack_mode = SKIP_ACKS;

				yield _execute_simple ("QThreadSuffixSupported", cancellable);
				yield _execute_simple ("QListThreadsInStopReply", cancellable);
				yield _execute_simple ("QSetDetachOnError:0", cancellable);
			} catch (GLib.Error e) {
				io_cancellable.cancel ();

				throw new Error.PROTOCOL ("%s", e.message);
			}

			return true;
		}

		private void change_state (State new_state, Exception? new_exception = null) {
			bool state_differs = new_state != _state;
			if (state_differs)
				_state = new_state;

			bool exception_differs = new_exception != _exception;
			if (exception_differs)
				_exception = new_exception;

			if (state_differs)
				notify_property ("state");

			if (exception_differs)
				notify_property ("exception");
		}

		private void clear_current_exception () {
			if (_exception == null)
				return;

			_exception = null;
			notify_property ("exception");
		}

		public async void close (Cancellable? cancellable = null) throws IOError {
			if (state == CLOSED)
				return;

			io_cancellable.cancel ();

			var source = new IdleSource ();
			source.set_callback (close.callback);
			source.attach (MainContext.get_thread_default ());
			yield;

			try {
				yield stream.close_async (Priority.DEFAULT, cancellable);
			} catch (IOError e) {
			}
		}

		public async Process launch (string[] argv, LaunchOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			if (options != null) {
				foreach (var env in options.env)
					yield _execute_simple ("QEnvironment:" + env, cancellable);

				var arch = options.arch;
				if (arch != null)
					yield _execute_simple ("QLaunchArch:" + arch, cancellable);

				if (options.aslr == DISABLE)
					yield _execute_simple ("QSetDisableASLR:1", cancellable);
			}

			var set_args_command = _make_packet_builder_sized (256)
				.append_c ('A');
			uint arg_index = 0;
			foreach (var arg in argv) {
				if (arg_index > 0)
					set_args_command.append_c (',');

				uint length = arg.length;
				uint hex_length = length * 2;
				set_args_command
					.append_uint (hex_length)
					.append_c (',')
					.append_uint (arg_index)
					.append_c (',');

				for (int byte_index = 0; byte_index != length; byte_index++)
					set_args_command.append_hexbyte (arg[byte_index]);

				arg_index++;
			}
			yield _execute (set_args_command.build (), cancellable);

			try {
				yield _execute_simple ("qLaunchSuccess", cancellable);
			} catch (Error e) {
				if (e is Error.REQUEST_REJECTED && e.message == "Locked")
					throw new Error.DEVICE_LOCKED ("Device is locked");
				else
					throw e;
			}

			var process = yield probe_target (cancellable);

			var dyld_fields = yield get_apple_dyld_fields (cancellable);
			bool libsystem_initialized = yield read_bool (dyld_fields.libsystem_initialized, cancellable);

			process.observed_state = libsystem_initialized
				? Process.ObservedState.ALREADY_RUNNING
				: Process.ObservedState.FRESHLY_CREATED;

			return process;
		}

		public async Process attach_by_name (string name, Cancellable? cancellable = null) throws Error, IOError {
			var request = _make_packet_builder_sized (64)
				.append ("vAttachName;");

			int length = name.length;
			for (int i = 0; i != length; i++)
				request.append_hexbyte (name[i]);

			return yield perform_attach (request, cancellable);
		}

		public async Process attach_by_pid (uint pid, Cancellable? cancellable = null) throws Error, IOError {
			var request = _make_packet_builder_sized (32)
				.append ("vAttach;")
				.append_process_id (pid);

			return yield perform_attach (request, cancellable);
		}

		private async Process perform_attach (PacketBuilder request, Cancellable? cancellable) throws Error, IOError {
			var response = yield _query (request.build (), cancellable);

			if (response.payload[0] == 'E')
				throw new Error.REQUEST_REJECTED ("Unable to attach to the specified process");

			var process = yield probe_target (cancellable);

			handle_notification (response);

			return process;
		}

		private async Process probe_target (Cancellable? cancellable) throws Error, IOError {
			_process = yield get_process_info (cancellable);

			ptrauth_removal_mask = (_process.cpu_type == ARM64) ? 0x0000007fffffffffULL : 0xffffffffffffffffULL;

			register_by_name = yield get_register_mappings (cancellable);

			register_by_id = new Gee.HashMap<uint, Register> ();
			foreach (var reg in register_by_name.values)
				register_by_id[reg.id] = reg;

			return _process;
		}

		public async void continue (Cancellable? cancellable = null) throws Error, IOError {
			check_stopped ();

			var exception = breakpoint_exception;
			if (exception != null) {
				breakpoint_exception = null;

				var breakpoint = exception.breakpoint;
				yield breakpoint.disable (cancellable);
				yield exception.thread.step (cancellable);
				yield breakpoint.enable (cancellable);

				check_stopped ();
			}

			change_state (RUNNING);

			var command = _make_packet_builder_sized (1)
				.append_c ('c')
				.build ();
			write_bytes (command);
		}

		public async void continue_specific_threads (Gee.Iterable<Thread> threads, Cancellable? cancellable = null)
				throws Error, IOError {
			check_stopped ();

			change_state (RUNNING);

			var command = _make_packet_builder_sized (1)
				.append ("vCont");
			foreach (var thread in threads) {
				command
					.append (";c:")
					.append_thread_id (thread.id);
			}
			write_bytes (command.build ());
		}

		public async Exception continue_until_exception (Cancellable? cancellable = null) throws Error, IOError {
			check_stopped ();

			clear_current_exception ();

			if (breakpoint_exception != null)
				yield continue (cancellable);

			if (_exception != null)
				return _exception;

			bool waiting = false;

			var stop_observer = new StopObserverEntry (() => {
				if (waiting)
					continue_until_exception.callback ();
				return false;
			});
			on_stop.add (stop_observer);

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (() => {
				if (waiting)
					continue_until_exception.callback ();
				return false;
			});
			cancel_source.attach (MainContext.get_thread_default ());

			try {
				if (state == STOPPED)
					yield continue (cancellable);

				if (state != STOPPED) {
					waiting = true;
					yield;
					waiting = false;
				}
			} finally {
				cancel_source.destroy ();

				on_stop.remove (stop_observer);
			}

			if (_exception == null)
				throw new Error.CONNECTION_CLOSED ("Connection closed while waiting for exception");

			return _exception;
		}

		public async void stop (Cancellable? cancellable = null) throws Error, IOError {
			if (state == STOPPED)
				return;

			if (state == CLOSED)
				throw new Error.INVALID_OPERATION ("Unable to stop; connection is closed");

			if (state == RUNNING) {
				change_state (STOPPING);

				write_bytes (new Bytes ({ STOP_CHARACTER }));
			}

			yield wait_until_stopped (cancellable);
		}

		private async void wait_until_stopped (Cancellable? cancellable) throws Error, IOError {
			var stop_observer = new StopObserverEntry (() => {
				wait_until_stopped.callback ();
				return false;
			});
			on_stop.add (stop_observer);

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (() => {
				wait_until_stopped.callback ();
				return false;
			});
			cancel_source.attach (MainContext.get_thread_default ());

			yield;

			cancel_source.destroy ();

			on_stop.remove (stop_observer);

			if (state == CLOSED)
				throw new Error.CONNECTION_CLOSED ("Connection closed while waiting for target to stop");
		}

		public async void detach (Cancellable? cancellable = null) throws Error, IOError {
			yield stop (cancellable);

			yield _execute_simple ("D", cancellable);
		}

		public async void kill (Cancellable? cancellable = null) throws Error, IOError {
			yield stop (cancellable);

			var kill_response = yield _query_simple ("k", cancellable);
			if (kill_response.payload != "X09")
				throw new Error.REQUEST_REJECTED ("Unable to kill existing process");

			change_state (STOPPING);
		}

		public async void _step (Thread thread, Cancellable? cancellable) throws Error, IOError {
			check_stopped ();

			change_state (RUNNING);

			var command = _make_packet_builder_sized (16)
				.append ("vCont;s:")
				.append_thread_id (thread.id)
				.build ();
			write_bytes (command);

			yield wait_until_stopped (cancellable);
		}

		public async void enumerate_threads (FoundThreadFunc func, Cancellable? cancellable = null) throws Error, IOError {
			var response = yield _query_simple ("jThreadsInfo", cancellable);

			Json.Reader reader;
			try {
				reader = new Json.Reader (Json.from_string (response.payload));
			} catch (GLib.Error e) {
				throw new Error.PROTOCOL ("Invalid response");
			}

			int thread_count = reader.count_elements ();
			if (thread_count == -1)
				throw new Error.PROTOCOL ("Invalid response");

			int thread_index;
			for (thread_index = 0; thread_index != thread_count; thread_index++) {
				reader.read_element (thread_index);

				reader.read_member ("tid");
				int64 tid = reader.get_int_value ();
				if (tid == 0)
					break;
				reader.end_member ();

				string? name = null;
				if (reader.read_member ("name"))
					name = reader.get_string_value ();
				reader.end_member ();

				var thread = new Thread ((uint) tid, name, this);
				bool carry_on = func (thread);
				if (!carry_on)
					return;

				reader.end_element ();
			}
			if (thread_index != thread_count)
				throw new Error.PROTOCOL ("Invalid response");
		}

		public delegate bool FoundThreadFunc (Thread thread);

		public async void enumerate_modules (FoundModuleFunc func, Cancellable? cancellable = null) throws Error, IOError {
			var response = yield _query_simple ("jGetLoadedDynamicLibrariesInfos:{\"fetch_all_solibs\":true}", cancellable);

			Json.Reader reader;
			try {
				reader = new Json.Reader (Json.from_string (response.payload));
			} catch (GLib.Error e) {
				throw new Error.PROTOCOL ("Invalid response");
			}

			reader.read_member ("images");

			int module_count = reader.count_elements ();
			if (module_count == -1)
				throw new Error.PROTOCOL ("Invalid response");

			int module_index;
			for (module_index = 0; module_index != module_count; module_index++) {
				reader.read_element (module_index);

				reader.read_member ("load_address");
				uint64 load_address = (uint64) reader.get_int_value ();
				if (load_address == 0)
					break;
				reader.end_member ();

				reader.read_member ("pathname");
				string pathname = reader.get_string_value ();
				if (pathname == null)
					break;
				reader.end_member ();

				reader.read_member ("segments");
				int segment_count = reader.count_elements ();
				if (segment_count == -1)
					break;
				var segments = new Gee.ArrayList<Module.Segment> ();
				int segment_index;
				for (segment_index = 0; segment_index != segment_count; segment_index++) {
					reader.read_element (segment_index);

					var segment = new Module.Segment ();

					reader.read_member ("name");
					segment.name = reader.get_string_value ();
					reader.end_member ();

					reader.read_member ("vmaddr");
					segment.vmaddr = (uint64) reader.get_int_value ();
					reader.end_member ();

					reader.read_member ("vmsize");
					segment.vmsize = (uint64) reader.get_int_value ();
					reader.end_member ();

					reader.read_member ("fileoff");
					segment.fileoff = (uint64) reader.get_int_value ();
					reader.end_member ();

					reader.read_member ("filesize");
					segment.filesize = (uint64) reader.get_int_value ();
					reader.end_member ();

					segments.add (segment);

					reader.end_element ();
				}
				if (segment_index != segment_count)
					break;
				reader.end_member ();

				var module = new Module (load_address, pathname, segments);
				bool carry_on = func (module);
				if (!carry_on)
					return;

				reader.end_element ();
			}
			if (module_index != module_count)
				throw new Error.PROTOCOL ("Invalid response");

			reader.end_member ();
		}

		public delegate bool FoundModuleFunc (Module module);

		public async uint64 allocate (size_t size, string protection, Cancellable? cancellable = null) throws Error, IOError {
			var request = _make_packet_builder_sized (16)
				.append ("_M")
				.append_size (size)
				.append_c (',')
				.append (protection)
				.build ();
			var response = yield _query (request, cancellable);

			return Protocol.parse_address (response.payload);
		}

		public async void deallocate (uint64 address, Cancellable? cancellable = null) throws Error, IOError {
			var command = _make_packet_builder_sized (16)
				.append ("_m")
				.append_address (address)
				.build ();
			yield _execute (command, cancellable);
		}

		public async Bytes read_byte_array (uint64 address, size_t size, Cancellable? cancellable = null)
				throws Error, IOError {
			var request = _make_packet_builder_sized (16)
				.append_c ('x')
				.append_address (address)
				.append_c (',')
				.append_size (size)
				.build ();
			var response = yield _query (request, cancellable);

			var result = response.payload_bytes;
			if (result.get_size () != size) {
				throw new Error.INVALID_ADDRESS (
					"Unable to read from 0x%" + uint64.FORMAT_MODIFIER + "x: invalid address", address);
			}

			return result;
		}

		public async void write_byte_array (uint64 address, Bytes bytes, Cancellable? cancellable = null)
				throws Error, IOError {
			const uint max_transfer_size = 65536;

			var data = bytes.get_data ();
			size_t offset = 0;
			size_t remaining = bytes.length;

			var builder = _make_packet_builder_sized (32 + (remaining * 2));

			while (remaining != 0) {
				uint64 slice_address = address + offset;
				size_t slice_size = size_t.min (remaining, max_transfer_size);

				builder
					.append_c ('M')
					.append_address (slice_address)
					.append_c (',')
					.append_size (slice_size)
					.append_c (':');

				for (size_t i = 0; i != slice_size; i++) {
					uint8 byte = data[offset + i];
					builder.append_hexbyte (byte);
				}

				yield _execute (builder.build (), cancellable);

				builder.reset ();

				offset += slice_size;
				remaining -= slice_size;
			}
		}

		public async uint64 read_pointer (uint64 address, Cancellable? cancellable = null) throws Error, IOError {
			var buffer = yield read_buffer (address, _process.pointer_size, cancellable);
			return buffer.read_pointer (0);
		}

		public async void write_pointer (uint64 address, uint64 val, Cancellable? cancellable = null) throws Error, IOError {
			var buffer = make_buffer_builder ()
				.append_pointer (val)
				.build ();
			yield write_byte_array (address, buffer, cancellable);
		}

		public async bool read_bool (uint64 address, Cancellable? cancellable = null) throws Error, IOError {
			var data = yield read_byte_array (address, 1);
			return data.get (0) != 0 ? true : false;
		}

		public async void write_bool (uint64 address, bool val, Cancellable? cancellable = null) throws Error, IOError {
			yield write_byte_array (address, new Bytes ({ val ? 1 : 0 }), cancellable);
		}

		public BufferBuilder make_buffer_builder () {
			return new BufferBuilder (_process.pointer_size, _process.byte_order);
		}

		public Buffer make_buffer (Bytes bytes) {
			return new Buffer (bytes, _process.pointer_size, _process.byte_order);
		}

		public async Buffer read_buffer (uint64 address, size_t size, Cancellable? cancellable = null) throws Error, IOError {
			var bytes = yield read_byte_array (address, size, cancellable);
			return make_buffer (bytes);
		}

		public async Breakpoint add_breakpoint (uint64 address, Cancellable? cancellable = null) throws Error, IOError {
			check_stopped ();

			uint size = _process.pointer_size == 4 ? 2 : 4;

			var breakpoint = new Breakpoint (address, size, this);
			yield breakpoint.enable (cancellable);
			breakpoints[address] = breakpoint;

			breakpoint.removed.connect (on_breakpoint_removed);

			return breakpoint;
		}

		private void on_breakpoint_removed (Breakpoint breakpoint) {
			breakpoints.unset (breakpoint.address);

			var exception = breakpoint_exception;
			if (exception != null && exception.breakpoint == breakpoint)
				breakpoint_exception = null;
		}

		public async AppleDyldFields get_apple_dyld_fields (Cancellable? cancellable = null) throws Error, IOError {
			if (cached_dyld_fields != null)
				return cached_dyld_fields;

			var response = yield _query_simple ("qShlibInfoAddr", cancellable);

			var info_address = Protocol.parse_address (response.payload);
			var pointer_size = _process.pointer_size;

			uint64 notification_callback = info_address + 4 + 4 + pointer_size;
			uint64 libsystem_initialized = notification_callback + pointer_size + 1;
			uint64 dyld_load_address = notification_callback + (2 * pointer_size);

			cached_dyld_fields = new AppleDyldFields (info_address, notification_callback, libsystem_initialized, dyld_load_address);

			return cached_dyld_fields;
		}

		public uint64 strip_code_address (uint64 address) {
			return address & ptrauth_removal_mask;
		}

		private async Process get_process_info (Cancellable? cancellable = null) throws Error, IOError {
			var response = yield _query_simple ("qProcessInfo", cancellable);

			var raw_info = PropertyDictionary.parse (response.payload);

			var info = new Process ();
			info.pid = raw_info.get_uint ("pid");
			info.parent_pid = raw_info.get_uint ("parent-pid");
			info.real_uid = raw_info.get_uint ("real-uid");
			info.real_gid = raw_info.get_uint ("real-gid");
			info.effective_uid = raw_info.get_uint ("effective-uid");
			info.effective_gid = raw_info.get_uint ("effective-gid");
			info.cpu_type = (DarwinCpuType) raw_info.get_uint ("cputype");
			info.cpu_subtype = (DarwinCpuSubtype) raw_info.get_uint ("cpusubtype");
			info.pointer_size = raw_info.get_uint ("ptrsize");
			info.os_type = raw_info.get_string ("ostype");
			info.vendor = raw_info.get_string ("vendor");
			info.byte_order = (raw_info.get_string ("endian") == "little")
				? ByteOrder.LITTLE_ENDIAN
				: ByteOrder.BIG_ENDIAN;

			return info;
		}

		private async Gee.HashMap<string, Register> get_register_mappings (Cancellable? cancellable) throws Error, IOError {
			var response = yield _query_simple ("qXfer:features:read:target.xml:0,1ffff", cancellable);

			string * target_xml = (string *) response.payload + 1;

			var parser = new TargetXmlParser ();
			parser.parse (target_xml);

			return parser.registers;
		}

		internal Register get_register_by_name (string name) throws Error {
			Register? reg = register_by_name[name];
			if (reg == null)
				throw new Error.INVALID_REGISTER ("Invalid register: %s", name);
			return reg;
		}

		private void check_stopped () throws Error {
			if (state != STOPPED) {
				throw new Error.INVALID_OPERATION ("Invalid operation when not STOPPED, current state is %s",
					state.to_string ());
			}
		}

		public async void _execute_simple (string command, Cancellable? cancellable) throws Error, IOError {
			var raw_command = _make_packet_builder_sized (command.length + 15 & (size_t) ~15)
				.append (command)
				.build ();
			yield _execute (raw_command, cancellable);
		}

		public async void _execute (Bytes command, Cancellable? cancellable) throws Error, IOError {
			var response_packet = yield _query (command, cancellable);

			var response = response_packet.payload;
			if (response[0] == 'E')
				throw new Error.REQUEST_REJECTED ("%s", response[1:response.length]);

			if (response != "OK")
				throw new Error.PROTOCOL ("Unexpected response: %s", response);
		}

		public async Packet _query_simple (string request, Cancellable? cancellable) throws Error, IOError {
			var raw_request = _make_packet_builder_sized (request.length + 15 & (size_t) ~15)
				.append (request)
				.build ();
			return yield _query (raw_request, cancellable);
		}

		public async Packet _query (Bytes request, Cancellable? cancellable) throws Error, IOError {
			if (state == CLOSED)
				throw new Error.INVALID_OPERATION ("Unable to perform query; connection is closed");

			var pending = new PendingResponse (_query.callback);
			pending_responses.offer_tail (pending);

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (() => {
				pending.complete_with_error (new IOError.CANCELLED ("Operation was cancelled"));
				return false;
			});
			cancel_source.attach (MainContext.get_thread_default ());

			write_bytes (request);

			yield;

			cancel_source.destroy ();

			cancellable.set_error_if_cancelled ();

			var response = pending.response;
			if (response == null)
				throw_local_error (pending.error);

			return response;
		}

		private async void process_incoming_packets () {
			while (true) {
				try {
					var packet = yield read_packet ();

					dispatch_packet (packet);
				} catch (GLib.Error error) {
					change_state (CLOSED);

					foreach (var pending_response in pending_responses)
						pending_response.complete_with_error (error);
					pending_responses.clear ();

					foreach (var observer in on_stop.to_array ())
						observer.func ();

					closed ();

					return;
				}
			}
		}

		private async void process_pending_writes () {
			while (!pending_writes.is_empty) {
				Bytes current = pending_writes.peek_head ();

				size_t bytes_written;
				try {
					yield output.write_all_async (current.get_data (), Priority.DEFAULT, io_cancellable,
						out bytes_written);
				} catch (GLib.Error e) {
					return;
				}

				pending_writes.poll_head ();
			}
		}

		private void dispatch_packet (Packet packet) throws Error {
			switch (state) {
				case STOPPED:
					handle_response (packet);
					break;
				case RUNNING:
				case STOPPING:
					handle_notification (packet);
					break;
				default:
					assert_not_reached ();
			}
		}

		private void handle_response (Packet response) throws Error {
			var pending = pending_responses.poll_head ();
			if (pending == null)
				throw new Error.PROTOCOL ("Unexpected response");

			pending.complete_with_response (response);
		}

		private void handle_notification (Packet packet) throws Error {
			if (state == CLOSED)
				throw new Error.INVALID_OPERATION ("Unable to handle notification; connection is closed");

			unowned string payload = packet.payload;
			unowned string data = (string) ((char *) payload + 1);
			switch (payload[0]) {
				case NOTIFICATION_TYPE_EXIT_STATUS:
				case NOTIFICATION_TYPE_EXIT_SIGNAL:
					handle_exit (data);
					break;
				case NOTIFICATION_TYPE_THREADS:
					handle_stop (data);
					break;
				case NOTIFICATION_TYPE_OUTPUT:
					handle_output (data);
					break;
			}
		}

		private void handle_exit (string data) throws Error {
			change_state (STOPPED);
			foreach (var observer in on_stop.to_array ())
				observer.func ();
		}

		private void handle_stop (string data) throws Error {
			if (data.length < 11)
				throw new Error.PROTOCOL ("Invalid stop packet");

			uint64 raw_signum;
			try {
				uint64.from_string (data[0:2], out raw_signum, 16);
			} catch (NumberParserError e) {
				throw new Error.PROTOCOL ("Invalid stop packet: %s", e.message);
			}
			Signal signum = (Signal) raw_signum;

			unowned string rest = (string) ((char *) data + 2);
			var properties = PropertyDictionary.parse (rest);

			MachExceptionType metype = NONE;
			var medata = new Gee.ArrayList<uint64?> ();
			if (properties.has ("metype")) {
				metype = (MachExceptionType) properties.get_uint ("metype");
				if (properties.has ("medata")) {
					var mecount = properties.get_uint ("mecount");
					if (mecount == 1) {
						medata.add (properties.get_uint64 ("medata"));
					} else {
						medata.add_all (properties.get_uint64_array ("medata"));
					}
				}
			}

			string? thread_name = null;
			if (properties.has ("hexname")) {
				thread_name = Protocol.parse_hex_encoded_utf8_string (properties.get_string ("hexname"));
			}

			var thread = new Thread (properties.get_uint ("thread"), thread_name, this);

			var thread_ids = properties.get_uint_array ("threads");
			var thread_pcs = properties.get_uint64_array ("thread-pcs");

			var active_thread_index = thread_ids.index_of (thread.id);
			if (active_thread_index == -1)
				throw new Error.PROTOCOL ("Invalid stop packet");

			uint64 pc = thread_pcs[active_thread_index];

			Breakpoint? breakpoint = null;
			if (signum == SIGTRAP)
				breakpoint = breakpoints[pc];

			var context = new Gee.HashMap<string, uint64?> ();
			var pointer_size = _process.pointer_size;
			var byte_order = _process.byte_order;
			properties.foreach (entry => {
				string key = entry.key;
				if (key.length != 2)
					return true;

				uint64 register_id;
				try {
					uint64.from_string (key, out register_id, 16);
				} catch (NumberParserError e) {
					return true;
				}

				Register? reg = register_by_id[(uint) register_id];
				if (reg == null)
					return true;

				if (reg.bitsize != pointer_size * 8)
					return true;

				uint64 val;
				try {
					val = Protocol.parse_pointer_value (entry.value, pointer_size, byte_order);
				} catch (Error e) {
					return true;
				}

				context[reg.name] = val;

				return true;
			});

			var exception = new Exception (signum, metype, medata, breakpoint, thread, context);

			breakpoint_exception = (breakpoint != null) ? exception : null;
			change_state (STOPPED, exception);
			foreach (var observer in on_stop.to_array ())
				observer.func ();
		}

		private void handle_output (string hex_bytes) throws Error {
			var bytes = Protocol.parse_hex_bytes (hex_bytes);
			console_output (bytes);
		}

		public PacketBuilder _make_packet_builder_sized (size_t capacity) {
			var checksum_type = (ack_mode == SEND_ACKS) ? ChecksumType.PROPER : ChecksumType.ZEROED;
			return new PacketBuilder (capacity, checksum_type);
		}

		private async Packet read_packet () throws Error, IOError {
			string header = yield read_string (1);
			if (header == ACK_NOTIFICATION || header == NACK_NOTIFICATION)
				return yield read_packet ();

			string body;
			size_t body_size;
			try {
				body = yield input.read_upto_async (CHECKSUM_MARKER, 1, Priority.DEFAULT, io_cancellable, out body_size);
				if (body_size == 0)
					throw new Error.CONNECTION_CLOSED ("Connection closed");
			} catch (IOError e) {
				if (e is IOError.CANCELLED)
					throw e;
				throw new Error.CONNECTION_CLOSED ("%s", e.message);
			}

			string trailer = yield read_string (3);

			var packet = depacketize (header, body, body_size, trailer);

			if (ack_mode == SEND_ACKS)
				write_string (ACK_NOTIFICATION);

			return packet;
		}

		private async string read_string (uint length) throws Error, IOError {
			var buf = new uint8[length + 1];
			buf[length] = 0;

			size_t bytes_read;
			try {
				yield input.read_all_async (buf[0:length], Priority.DEFAULT, io_cancellable, out bytes_read);
			} catch (GLib.Error e) {
				if (e is IOError.CANCELLED)
					throw (IOError) e;
				throw new Error.CONNECTION_CLOSED ("%s", e.message);
			}

			if (bytes_read == 0)
				throw new Error.CONNECTION_CLOSED ("Connection closed");

			return (string) buf;
		}

		private void write_string (string str) {
			unowned uint8[] buf = (uint8[]) str;
			write_bytes (new Bytes (buf[0:str.length]));
		}

		private void write_bytes (Bytes bytes) {
			pending_writes.offer_tail (bytes);
			if (pending_writes.size == 1)
				process_pending_writes.begin ();
		}

		private static Packet depacketize (string header, string data, size_t data_size, string trailer) throws Error {
			var result = new StringBuilder.sized (data_size);

			for (size_t offset = 0; offset != data_size; offset++) {
				char ch = data[(long) offset];
				if (ch == ESCAPE_CHARACTER) {
					if (offset == data_size - 1)
						throw new Error.PROTOCOL ("Invalid packet");
					uint8 escaped_byte = data[(long) (++offset)];
					result.append_c ((char) (escaped_byte ^ ESCAPE_KEY));
				} else if (ch == REPEAT_CHARACTER) {
					if (offset == 0 || offset == data_size - 1)
						throw new Error.PROTOCOL ("Invalid packet");
					char char_to_repeat = data[(long) (offset - 1)];
					uint8 repeat_count = (uint8) data[(long) (++offset)] - REPEAT_BASE + REPEAT_BIAS;
					for (uint8 repeat_index = 0; repeat_index != repeat_count; repeat_index++)
						result.append_c (char_to_repeat);
				} else {
					result.append_c (ch);
				}
			}

			return new Packet.from_bytes (StringBuilder.free_to_bytes ((owned) result));
		}

		private static void throw_local_error (GLib.Error e) throws Error, IOError {
			if (e is Error)
				throw (Error) e;

			if (e is IOError)
				throw (IOError) e;

			assert_not_reached ();
		}

		private static uint8 compute_checksum (string data, long offset, long length) {
			uint8 sum = 0;

			long end_index = offset + length;
			for (long i = offset; i != end_index; i++)
				sum += (uint8) data[i];

			return sum;
		}

		public class Packet {
			public string payload {
				get;
				private set;
			}

			public Bytes payload_bytes {
				get;
				private set;
			}

			public Packet.from_bytes (Bytes payload_bytes) {
				this.payload = (string) payload_bytes.get_data ();
				this.payload_bytes = payload_bytes;
			}
		}

		public class PacketBuilder {
			private StringBuilder buffer;
			private size_t initial_capacity;
			private ChecksumType checksum_type;

			public PacketBuilder (size_t capacity, ChecksumType checksum_type) {
				this.initial_capacity = 1 + capacity + 1 + 2;
				this.checksum_type = checksum_type;

				reset ();
			}

			public void reset () {
				if (buffer == null)
					buffer = new StringBuilder.sized (initial_capacity);
				else
					buffer.truncate ();

				buffer.append_c (PACKET_CHARACTER);
			}

			public unowned PacketBuilder append (string val) {
				long length = val.length;
				for (long i = 0; i != length; i++)
					append_c (val[i]);
				return this;
			}

			public unowned PacketBuilder append_c (char c) {
				switch (c) {
					case PACKET_CHARACTER:
					case CHECKSUM_CHARACTER:
					case ESCAPE_CHARACTER:
					case REPEAT_CHARACTER:
						buffer.append_c (ESCAPE_CHARACTER);
						buffer.append_c ((char) ((uint8) c ^ ESCAPE_KEY));
						break;
					default:
						buffer.append_c (c);
						break;
				}
				return this;
			}

			public unowned PacketBuilder append_escaped (string val) {
				buffer.append (val);
				return this;
			}

			public unowned PacketBuilder append_c_escaped (char c) {
				buffer.append_c (c);
				return this;
			}

			public unowned PacketBuilder append_address (uint64 address) {
				buffer.append_printf ("%" + uint64.FORMAT_MODIFIER + "x", address);
				return this;
			}

			public unowned PacketBuilder append_size (size_t size) {
				buffer.append_printf ("%" + size_t.FORMAT_MODIFIER + "x", size);
				return this;
			}

			public unowned PacketBuilder append_uint (uint val) {
				buffer.append_printf ("%u", val);
				return this;
			}

			public unowned PacketBuilder append_process_id (uint process_id) {
				buffer.append_printf ("%x", process_id);
				return this;
			}

			public unowned PacketBuilder append_thread_id (uint thread_id) {
				buffer.append_printf ("%x", thread_id);
				return this;
			}

			public unowned PacketBuilder append_register_id (uint register_id) {
				buffer.append_printf ("%x", register_id);
				return this;
			}

			public unowned PacketBuilder append_register_value (uint64 val) {
				return append_address (val);
			}

			public unowned PacketBuilder append_hexbyte (uint8 byte) {
				buffer.append_c (Protocol.NIBBLE_TO_HEX_CHAR[byte >> 4]);
				buffer.append_c (Protocol.NIBBLE_TO_HEX_CHAR[byte & 0xf]);
				return this;
			}

			public Bytes build () {
				buffer.append_c (CHECKSUM_CHARACTER);

				if (checksum_type == PROPER) {
					buffer.append_printf ("%02x", compute_checksum (buffer.str, 1, buffer.len - 2));
				} else {
					buffer.append ("00");
				}

				return StringBuilder.free_to_bytes ((owned) buffer);
			}
		}

		private class StopObserverEntry {
			public SourceFunc? func;

			public StopObserverEntry (owned SourceFunc func) {
				this.func = (owned) func;
			}
		}

		private class PendingResponse {
			private SourceFunc? handler;

			public Packet? response {
				get;
				private set;
			}

			public GLib.Error? error {
				get;
				private set;
			}

			public PendingResponse (owned SourceFunc handler) {
				this.handler = (owned) handler;
			}

			public void complete_with_response (Packet? response) {
				if (handler == null)
					return;
				this.response = response;
				handler ();
				handler = null;
			}

			public void complete_with_error (GLib.Error error) {
				if (handler == null)
					return;
				this.error = error;
				handler ();
				handler = null;
			}
		}

		private class PropertyDictionary {
			private Gee.HashMap<string, string> properties = new Gee.HashMap<string, string> ();

			public static PropertyDictionary parse (string raw_properties) throws Error {
				var dictionary = new PropertyDictionary ();

				var properties = dictionary.properties;

				var pairs = raw_properties.split (";");
				foreach (var pair in pairs) {
					if (pair.length == 0)
						continue;

					var tokens = pair.split (":", 2);
					if (tokens.length != 2)
						throw new Error.PROTOCOL ("Invalid property dictionary pair");
					unowned string key = tokens[0];
					unowned string val = tokens[1];

					if (!properties.has_key (key)) {
						properties[key] = val;
					} else {
						properties[key] = properties[key] + "," + val;
					}
				}

				return dictionary;
			}

			public void foreach (Gee.ForallFunc<Gee.Map.Entry<string, string>> f) {
				properties.foreach (f);
			}

			public bool has (string name) {
				return properties.has_key (name);
			}

			public string get_string (string name) throws Error {
				var val = properties[name];
				if (val == null)
					throw new Error.PROTOCOL ("Property '%s' not found", name);
				return val;
			}

			public uint get_uint (string name) throws Error {
				return Protocol.parse_uint (get_string (name), 16);
			}

			public uint64 get_uint64 (string name) throws Error {
				return Protocol.parse_uint64 (get_string (name), 16);
			}

			public Gee.ArrayList<uint> get_uint_array (string name) throws Error {
				var result = new Gee.ArrayList<uint> ();

				foreach (var element in get_string (name).split (","))
					result.add (Protocol.parse_uint (element, 16));

				return result;
			}

			public Gee.ArrayList<uint64?> get_uint64_array (string name) throws Error {
				var result = new Gee.ArrayList<uint64?> ();

				foreach (var element in get_string (name).split (","))
					result.add (Protocol.parse_uint64 (element, 16));

				return result;
			}
		}

		internal class Register {
			public string name {
				get;
				private set;
			}

			public uint id {
				get;
				private set;
			}

			public uint bitsize {
				get;
				private set;
			}

			public Register (string name, uint id, uint bitsize) {
				this.name = name;
				this.id = id;
				this.bitsize = bitsize;
			}
		}

		private class TargetXmlParser : Object {
			public Gee.HashMap<string, Register> registers = new Gee.HashMap<string, Register> ();

			private const MarkupParser CALLBACKS = {
				on_start_element,
				null,
				null,
				null,
				null
			};

			public void parse (string xml) throws Error {
				try {
					var context = new MarkupParseContext (CALLBACKS, 0, this, null);
					context.parse (xml, -1);
				} catch (MarkupError e) {
					throw new Error.PROTOCOL ("%s", e.message);
				}
			}

			private void on_start_element (MarkupParseContext context, string element_name, string[] attribute_names, string[] attribute_values) throws MarkupError {
				if (element_name != "reg")
					return;

				unowned string? name = null;
				unowned string? altname = null;
				unowned string? group = null;
				int regnum = -1;
				int bitsize = -1;
				int i = 0;
				foreach (var attribute_name in attribute_names) {
					unowned string val = attribute_values[i];

					if (attribute_name == "name")
						name = val;
					else if (attribute_name == "altname")
						altname = val;
					else if (attribute_name == "group")
						group = val;
					else if (attribute_name == "regnum")
						regnum = int.parse (val);
					else if (attribute_name == "bitsize")
						bitsize = int.parse (val);

					i++;
				}
				if (name == null || group == null || regnum == -1)
					return;
				if (group != "general")
					return;

				var reg = new Register (name, regnum, bitsize);
				registers[name] = reg;
				if (altname != null)
					registers[altname] = reg;
			}
		}
	}

	public errordomain Error {
		CONNECTION_CLOSED,
		DDI_NOT_MOUNTED,
		DEVICE_LOCKED,
		ALREADY_RUNNING,
		REQUEST_REJECTED,
		INVALID_OPERATION,
		INVALID_ADDRESS,
		INVALID_REGISTER,
		PROTOCOL
	}

	public class LaunchOptions : Object {
		public string[] env {
			get;
			set;
			default = {};
		}

		public string? arch {
			get;
			set;
		}

		public ASLR aslr {
			get;
			set;
			default = AUTO;
		}
	}

	public class Process : Object {
		public uint pid {
			get;
			set;
		}

		public uint parent_pid {
			get;
			set;
		}

		public uint real_uid {
			get;
			set;
		}

		public uint real_gid {
			get;
			set;
		}

		public uint effective_uid {
			get;
			set;
		}

		public uint effective_gid {
			get;
			set;
		}

		public DarwinCpuType cpu_type {
			get;
			set;
		}

		public DarwinCpuSubtype cpu_subtype {
			get;
			set;
		}

		public uint pointer_size {
			get;
			set;
		}

		public string os_type {
			get;
			set;
		}

		public string vendor {
			get;
			set;
		}

		public ByteOrder byte_order {
			get;
			set;
		}

		public ObservedState observed_state {
			get;
			set;
			default = ALREADY_RUNNING;
		}

		public enum ObservedState {
			FRESHLY_CREATED,
			ALREADY_RUNNING
		}
	}

	public enum ASLR {
		AUTO,
		DISABLE
	}

	public enum DarwinCpuArchType {
		ABI64		= 0x01000000,
		ABI64_32	= 0x02000000,
	}

	public enum DarwinCpuType {
		X86		= 7,
		X86_64		= 7 | DarwinCpuArchType.ABI64,
		ARM		= 12,
		ARM64		= 12 | DarwinCpuArchType.ABI64,
		ARM64_32	= 12 | DarwinCpuArchType.ABI64_32,
	}

	public enum DarwinCpuSubtype {
		ARM64E		= 2,
	}

	public class Thread : Object {
		public uint id {
			get;
			construct;
		}

		public string? name {
			get;
			construct;
		}

		public weak Client client {
			get;
			construct;
		}

		private const uint PAGE_SIZE = 16384U;
		private const uint32 THREAD_MAGIC = 0x54485244U;

		public Thread (uint id, string? name, Client client) {
			Object (
				id: id,
				name: name,
				client: client
			);
		}

		public async void step (Cancellable? cancellable = null) throws Error, IOError {
			yield client._step (this, cancellable);
		}

		public async uint64 read_register (string name, Cancellable? cancellable = null) throws Error, IOError {
			var reg = client.get_register_by_name (name);

			var request = client._make_packet_builder_sized (32)
				.append_c ('p')
				.append_register_id (reg.id)
				.append (";thread:")
				.append_thread_id (id)
				.append_c (';')
				.build ();

			var response = yield client._query (request, cancellable);

			var process = client.process;
			return Protocol.parse_pointer_value (response.payload, process.pointer_size, process.byte_order);
		}

		public async void write_register (string name, uint64 val, Cancellable? cancellable = null) throws Error, IOError {
			var reg = client.get_register_by_name (name);
			var process = client.process;

			var command = client._make_packet_builder_sized (48)
				.append_c ('P')
				.append_register_id (reg.id)
				.append_c ('=')
				.append (Protocol.unparse_pointer_value (val, process.pointer_size, process.byte_order))
				.append (";thread:")
				.append_thread_id (id)
				.append_c (';')
				.build ();

			yield client._execute (command, cancellable);
		}

		public async Snapshot save_register_state (Cancellable? cancellable = null) throws Error, IOError {
			var request = client._make_packet_builder_sized (48)
				.append ("QSaveRegisterState;thread:")
				.append_thread_id (id)
				.append_c (';')
				.build ();

			var response = yield client._query (request, cancellable);

			return new Snapshot (Protocol.parse_uint (response.payload, 10));
		}

		public async void restore_register_state (Snapshot snapshot, Cancellable? cancellable = null) throws Error, IOError {
			var command = client._make_packet_builder_sized (48)
				.append ("QRestoreRegisterState:")
				.append_uint (snapshot.handle)
				.append (";thread:")
				.append_thread_id (id)
				.append_c (';')
				.build ();

			yield client._execute (command, cancellable);
		}

		public async Gee.ArrayList<Frame> generate_backtrace (StackBounds? stack = null, Cancellable? cancellable = null) throws Error, IOError {
			var result = new Gee.ArrayList<Frame> ();

			var sp = yield read_register ("sp", cancellable);
			var lr = client.strip_code_address (yield read_register ("lr", cancellable));
			var fp = yield read_register ("fp", cancellable);

			result.add (new Frame (lr, sp));

			uint64 current = fp;

			if (stack == null)
				stack = yield find_stack_bounds (sp, cancellable);

			while (current >= stack.bottom && current < stack.top && frame_pointer_is_aligned (current)) {
				var frame = yield client.read_buffer (current, 16, cancellable);

				uint64 next = frame.read_pointer (0);
				uint64 return_address = client.strip_code_address (frame.read_pointer (8));

				if (next == 0 || return_address == 0)
					break;
				result.add (new Frame (return_address, current));

				if (next <= current)
					break;
				current = next;
			}

			return result;
		}

		private static bool frame_pointer_is_aligned (uint64 fp) {
			return (fp & 1) == 0;
		}

		private async StackBounds find_stack_bounds (uint64 sp, Cancellable? cancellable) {
			uint64 start_page = round_down_to_page_boundary (sp);
			uint64 end_page = start_page + (1024 * PAGE_SIZE);

			uint64 cur_region = (start_page + 4095) & ~4095ULL;
			while (cur_region != end_page) {
				Buffer chunk;
				try {
					chunk = yield client.read_buffer (cur_region, 4, cancellable);
				} catch (GLib.Error e) {
					return StackBounds (sp, round_down_to_page_boundary (cur_region));
				}

				if (chunk.read_uint32 (0) == THREAD_MAGIC)
					return StackBounds (sp, cur_region);

				cur_region += 4096;
			}

			return StackBounds (sp, cur_region);
		}

		private static uint64 round_down_to_page_boundary (uint64 address) {
			return address & ~((uint64) (PAGE_SIZE - 1));
		}

		public class Snapshot {
			public uint handle {
				get;
				private set;
			}

			internal Snapshot (uint handle) {
				this.handle = handle;
			}
		}

		public class Frame {
			public uint64 address {
				get;
				private set;
			}

			public uint64 stack_location {
				get;
				private set;
			}

			public Frame (uint64 address, uint64 stack_location) {
				this.address = address;
				this.stack_location = stack_location;
			}
		}

		public struct StackBounds {
			public uint64 bottom;
			public uint64 top;

			public StackBounds (uint64 bottom, uint64 top) {
				this.bottom = bottom;
				this.top = top;
			}
		}
	}

	public class Module : Object {
		public uint64 load_address {
			get;
			construct;
		}

		public string pathname {
			get;
			construct;
		}

		public Gee.ArrayList<Segment> segments {
			get;
			construct;
		}

		public Module (uint64 load_address, string pathname, owned Gee.ArrayList<Segment> segments) {
			Object (
				load_address: load_address,
				pathname: pathname,
				segments: segments
			);
		}

		public class Segment {
			public string name;

			public uint64 vmaddr;
			public uint64 vmsize;

			public uint64 fileoff;
			public uint64 filesize;
		}
	}

	public class Exception : Object {
		public Signal signum {
			get;
			construct;
		}

		public MachExceptionType metype {
			get;
			construct;
		}

		public Gee.ArrayList<uint64?> medata {
			get;
			construct;
		}

		public Breakpoint? breakpoint {
			get;
			construct;
		}

		public Thread thread {
			get;
			construct;
		}

		public Gee.HashMap<string, uint64?> context {
			get;
			construct;
		}

		public Exception (Signal signum, MachExceptionType metype, Gee.ArrayList<uint64?> medata, Breakpoint? breakpoint,
				Thread thread, Gee.HashMap<string, uint64?> context) {
			Object (
				signum: signum,
				metype: metype,
				medata: medata,
				breakpoint: breakpoint,
				thread: thread,
				context: context
			);
		}

		public string to_string () {
			var result = new StringBuilder.sized (128);

			result
				.append (signum.to_name ())
				.append (", ")
				.append (metype.to_name ())
				.append (", [ ");

			uint i = 0;
			foreach (uint64 val in medata) {
				if (i != 0)
					result.append (", ");

				result.append_printf ("0x%" + uint64.FORMAT_MODIFIER + "x", val);

				i++;
			}

			result.append (" ]\n\nREGISTERS:");

			var sorted_register_names = context.keys.order_by ((a, b) => {
					var sa = score_register (a);
					var sb = score_register (b);
					if (sa != sb)
						return sa - sb;

					return strcmp (a, b);
				});
			uint offset = 0;
			while (sorted_register_names.next ()) {
				string name = sorted_register_names.get ();
				uint64 val = context[name];

				if (offset % 4 == 0)
					result.append ("\n   ");
				else
					result.append ("  ");

				result.append_printf ("%3s: 0x%016" + uint64.FORMAT_MODIFIER + "x", name, val);

				offset++;
			}

			return result.str;
		}

		private static int score_register (string name) {
			if (name[0] == 'x')
				return name.length;

			return 10;
		}
	}

	public enum Signal {
		SIGHUP = 1,
		SIGINT,
		SIGQUIT,
		SIGILL,
		SIGTRAP,
		SIGABRT,
		SIGEMT,
		SIGFPE,
		SIGKILL,
		SIGBUS,
		SIGSEGV,
		SIGSYS,
		SIGPIPE,
		SIGALRM,
		SIGTERM,
		SIGURG,
		SIGSTOP,
		SIGTSTP,
		SIGCONT,
		SIGCHLD,
		SIGTTIN,
		SIGTTOU,
		SIGIO,
		SIGXCPU,
		SIGXFSZ,
		SIGVTALRM,
		SIGPROF,
		SIGWINCH,
		SIGINFO,
		SIGUSR1,
		SIGUSR2,
		TARGET_EXC_BAD_ACCESS = 0x91,
		TARGET_EXC_BAD_INSTRUCTION,
		TARGET_EXC_ARITHMETIC,
		TARGET_EXC_EMULATION,
		TARGET_EXC_SOFTWARE,
		TARGET_EXC_BREAKPOINT;

		public string to_name () {
			return to_nick ().ascii_up ().replace ("-", "_");
		}

		public string to_nick () {
			return Marshal.enum_to_nick<Signal> (this);
		}
	}

	public enum MachExceptionType {
		NONE,
		EXC_BAD_ACCESS,
		EXC_BAD_INSTRUCTION,
		EXC_ARITHMETIC,
		EXC_EMULATION,
		EXC_SOFTWARE,
		EXC_BREAKPOINT,
		EXC_SYSCALL,
		EXC_MACH_SYSCALL,
		EXC_RPC_ALERT,
		EXC_CRASH,
		EXC_RESOURCE,
		EXC_GUARD,
		EXC_CORPSE_NOTIFY;

		public string to_name () {
			return to_nick ().ascii_up ().replace ("-", "_");
		}

		public string to_nick () {
			return Marshal.enum_to_nick<MachExceptionType> (this);
		}
	}

	public class Breakpoint : Object {
		public signal void removed ();

		public uint64 address {
			get;
			construct;
		}

		public uint size {
			get;
			construct;
		}

		public weak Client client {
			get;
			construct;
		}

		private enum State {
			DISABLED,
			ENABLED
		}

		private State state = DISABLED;

		public Breakpoint (uint64 address, uint size, Client client) {
			Object (
				address: address,
				size: size,
				client: client
			);
		}

		public async void enable (Cancellable? cancellable = null) throws Error, IOError {
			if (state != DISABLED)
				throw new Error.INVALID_OPERATION ("Already enabled");

			var command = client._make_packet_builder_sized (16)
				.append ("Z0,")
				.append_address (address)
				.append_c (',')
				.append_size (size)
				.build ();

			yield client._execute (command, cancellable);

			state = ENABLED;
		}

		public async void disable (Cancellable? cancellable = null) throws Error, IOError {
			if (state != ENABLED)
				throw new Error.INVALID_OPERATION ("Already disabled");

			var command = client._make_packet_builder_sized (16)
				.append ("z0,")
				.append_address (address)
				.append_c (',')
				.append_size (size)
				.build ();

			yield client._execute (command, cancellable);

			state = DISABLED;
		}

		public async void remove (Cancellable? cancellable = null) throws Error, IOError {
			if (state == ENABLED)
				yield disable (cancellable);

			removed ();
		}
	}

	public class BufferBuilder : Object {
		public uint pointer_size {
			get;
			construct;
		}

		public ByteOrder byte_order {
			get;
			construct;
		}

		public size_t offset {
			get {
				return cursor;
			}
		}

		private ByteArray buffer = new ByteArray ();
		private size_t cursor = 0;

		public BufferBuilder (uint pointer_size, ByteOrder byte_order) {
			Object (
				pointer_size: pointer_size,
				byte_order: byte_order
			);
		}

		public unowned BufferBuilder seek (size_t offset) {
			if (buffer.len < offset) {
				size_t n = offset - buffer.len;
				Memory.set (get_pointer (offset - n, n), 0, n);
			}
			cursor = offset;
			return this;
		}

		public unowned BufferBuilder skip (size_t n) {
			seek (cursor + n);
			return this;
		}

		public unowned BufferBuilder append_pointer (uint64 val) {
			write_pointer (cursor, val);
			cursor += pointer_size;
			return this;
		}

		public unowned BufferBuilder append_uint8 (uint8 val) {
			write_uint8 (cursor, val);
			cursor += (uint) sizeof (uint8);
			return this;
		}

		public unowned BufferBuilder append_uint16 (uint16 val) {
			write_uint16 (cursor, val);
			cursor += (uint) sizeof (uint16);
			return this;
		}

		public unowned BufferBuilder append_uint32 (uint32 val) {
			write_uint32 (cursor, val);
			cursor += (uint) sizeof (uint32);
			return this;
		}

		public unowned BufferBuilder append_uint64 (uint64 val) {
			write_uint64 (cursor, val);
			cursor += (uint) sizeof (uint64);
			return this;
		}

		public unowned BufferBuilder append_string (string val) {
			uint size = val.length + 1;
			Memory.copy (get_pointer (cursor, size), val, size);
			cursor += size;
			return this;
		}

		public unowned BufferBuilder write_pointer (size_t offset, uint64 val) {
			if (pointer_size == 4)
				write_uint32 (offset, (uint32) val);
			else
				write_uint64 (offset, val);
			return this;
		}

		public unowned BufferBuilder write_uint8 (size_t offset, uint8 val) {
			*((uint8 *) get_pointer (offset, sizeof (uint8))) = val;
			return this;
		}

		public unowned BufferBuilder write_uint16 (size_t offset, uint16 val) {
			uint16 target_val = (byte_order == BIG_ENDIAN)
				? val.to_big_endian ()
				: val.to_little_endian ();
			*((uint16 *) get_pointer (offset, sizeof (uint16))) = target_val;
			return this;
		}

		public unowned BufferBuilder write_uint32 (size_t offset, uint32 val) {
			uint32 target_val = (byte_order == BIG_ENDIAN)
				? val.to_big_endian ()
				: val.to_little_endian ();
			*((uint32 *) get_pointer (offset, sizeof (uint32))) = target_val;
			return this;
		}

		public unowned BufferBuilder write_uint64 (size_t offset, uint64 val) {
			uint64 target_val = (byte_order == BIG_ENDIAN)
				? val.to_big_endian ()
				: val.to_little_endian ();
			*((uint64 *) get_pointer (offset, sizeof (uint64))) = target_val;
			return this;
		}

		public unowned BufferBuilder write_string (size_t offset, string val) {
			uint size = val.length + 1;
			Memory.copy (get_pointer (offset, size), val, size);
			return this;
		}

		private uint8 * get_pointer (size_t offset, size_t n) {
			size_t minimum_size = offset + n;
			if (buffer.len < minimum_size)
				buffer.set_size ((uint) minimum_size);

			return (uint8 *) buffer.data + offset;
		}

		public Bytes build () {
			return ByteArray.free_to_bytes ((owned) buffer);
		}
	}

	public class Buffer : Object {
		public Bytes bytes {
			get;
			construct;
		}

		public uint pointer_size {
			get;
			construct;
		}

		public ByteOrder byte_order {
			get;
			construct;
		}

		private unowned uint8 * data;
		private size_t size;

		public Buffer (Bytes bytes, uint pointer_size, ByteOrder byte_order) {
			Object (
				bytes: bytes,
				pointer_size: pointer_size,
				byte_order: byte_order
			);
		}

		construct {
			data = bytes.get_data ();
			size = bytes.get_size ();
		}

		public uint64 read_pointer (size_t offset) {
			return (pointer_size == 4)
				? read_uint32 (offset)
				: read_uint64 (offset);
		}

		public void write_pointer (size_t offset, uint64 val) {
			if (pointer_size == 4)
				write_uint32 (offset, (uint32) val);
			else
				write_uint64 (offset, val);
		}

		public uint32 read_uint32 (size_t offset) {
			uint32 val = *((uint32 *) get_pointer (offset, sizeof (uint32)));
			return (byte_order == BIG_ENDIAN)
				? uint32.from_big_endian (val)
				: uint32.from_little_endian (val);
		}

		public unowned Buffer write_uint32 (size_t offset, uint32 val) {
			uint32 target_val = (byte_order == BIG_ENDIAN)
				? val.to_big_endian ()
				: val.to_little_endian ();
			*((uint32 *) get_pointer (offset, sizeof (uint32))) = target_val;
			return this;
		}

		public uint64 read_uint64 (size_t offset) {
			uint64 val = *((uint64 *) get_pointer (offset, sizeof (uint64)));
			return (byte_order == BIG_ENDIAN)
				? uint64.from_big_endian (val)
				: uint64.from_little_endian (val);
		}

		public unowned Buffer write_uint64 (size_t offset, uint64 val) {
			uint64 target_val = (byte_order == BIG_ENDIAN)
				? val.to_big_endian ()
				: val.to_little_endian ();
			*((uint64 *) get_pointer (offset, sizeof (uint64))) = target_val;
			return this;
		}

		public string read_string (size_t offset) {
			string * val = (string *) get_pointer (offset, sizeof (char));
			size_t max_length = size - offset;
			return val->substring (0, (long) max_length);
		}

		public unowned Buffer write_string (size_t offset, string val) {
			uint size = val.length + 1;
			Memory.copy (get_pointer (offset, size), val, size);
			return this;
		}

		private uint8 * get_pointer (size_t offset, size_t n) {
			size_t minimum_size = offset + n;
			assert (size >= minimum_size);

			return data + offset;
		}
	}

	public class AppleDyldFields : Object {
		public uint64 all_image_info {
			get;
			construct;
		}

		public uint64 notification_callback {
			get;
			construct;
		}

		public uint64 libsystem_initialized {
			get;
			construct;
		}

		public uint64 dyld_load_address {
			get;
			construct;
		}

		public AppleDyldFields (uint64 all_image_info, uint64 notification_callback, uint64 libsystem_initialized,
				uint64 dyld_load_address) {
			Object (
				all_image_info: all_image_info,
				notification_callback: notification_callback,
				libsystem_initialized: libsystem_initialized,
				dyld_load_address: dyld_load_address
			);
		}
	}

	namespace Protocol {
		internal uint64 parse_address (string raw_val) throws Error {
			return parse_uint64 (raw_val, 16);
		}

		internal uint parse_uint (string raw_val, uint radix) throws Error {
			uint64 val;

			try {
				uint64.from_string (raw_val, out val, radix, uint.MIN, uint.MAX);
			} catch (NumberParserError e) {
				throw new Error.PROTOCOL ("Invalid response: %s", e.message);
			}

			return (uint) val;
		}

		internal uint64 parse_uint64 (string raw_val, uint radix) throws Error {
			uint64 val;

			try {
				uint64.from_string (raw_val, out val, radix);
			} catch (NumberParserError e) {
				throw new Error.PROTOCOL ("Invalid response: %s", e.message);
			}

			return val;
		}

		internal uint64 parse_pointer_value (string raw_val, uint pointer_size, ByteOrder byte_order) throws Error {
			int length = raw_val.length;
			if (length != pointer_size * 2)
				throw new Error.PROTOCOL ("Invalid pointer value: %s", raw_val);

			int start_offset, end_offset, step;
			if (byte_order == BIG_ENDIAN) {
				start_offset = 0;
				end_offset = length;
				step = 2;
			} else {
				start_offset = length - 2;
				end_offset = -2;
				step = -2;
			}

			uint64 val = 0;

			for (int hex_offset = start_offset; hex_offset != end_offset; hex_offset += step) {
				uint8 byte = parse_hex_byte (raw_val[hex_offset + 0], raw_val[hex_offset + 1]);
				val = (val << 8) | byte;
			}

			return val;
		}

		internal string unparse_pointer_value (uint64 val, uint pointer_size, ByteOrder byte_order) {
			char * result = malloc ((pointer_size * 2) + 1);

			int start_byte_offset, end_byte_offset, byte_step;
			if (byte_order == LITTLE_ENDIAN) {
				start_byte_offset = 0;
				end_byte_offset = (int) pointer_size;
				byte_step = 1;
			} else {
				start_byte_offset = (int) pointer_size - 1;
				end_byte_offset = -1;
				byte_step = -1;
			}

			int hex_offset = 0;
			for (int byte_offset = start_byte_offset;
					byte_offset != end_byte_offset;
					byte_offset += byte_step, hex_offset += 2) {
				uint8 byte = (uint8) ((val >> (byte_offset * 8)) & 0xff);
				result[hex_offset + 0] = NIBBLE_TO_HEX_CHAR[byte >> 4];
				result[hex_offset + 1] = NIBBLE_TO_HEX_CHAR[byte & 0xf];
			}
			result[hex_offset] = '\0';

			return (string) (owned) result;
		}

		internal static string parse_hex_encoded_utf8_string (string hex_str) throws Error {
			Bytes bytes = parse_hex_bytes (hex_str);
			unowned string str = (string) bytes.get_data ();
			return str.make_valid ((ssize_t) bytes.get_size ());
		}

		internal static Bytes parse_hex_bytes (string hex_bytes) throws Error {
			int size = hex_bytes.length / 2;
			uint8[] data = new uint8[size];

			for (int byte_offset = 0, hex_offset = 0; byte_offset != size; byte_offset++, hex_offset += 2) {
				data[byte_offset] = parse_hex_byte (hex_bytes[hex_offset + 0], hex_bytes[hex_offset + 1]);
			}

			return new Bytes.take ((owned) data);
		}

		internal uint8 parse_hex_byte (char upper_ch, char lower_ch) throws Error {
			int8 upper = HEX_CHAR_TO_NIBBLE[upper_ch];
			int8 lower = HEX_CHAR_TO_NIBBLE[lower_ch];
			if (upper == -1 || lower == -1)
				throw new Error.PROTOCOL ("Invalid hex byte");
			return (upper << 4) | lower;
		}

		internal const int8[] HEX_CHAR_TO_NIBBLE = {
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, -1, -1, -1,
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
		};

		internal const char[] NIBBLE_TO_HEX_CHAR = {
			'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
		};
	}
}
