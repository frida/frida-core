namespace Frida.JDWP {
	public class Client : Object, AsyncInitable {
		public signal void closed ();
		public signal void events_received (Events events);

		public IOStream stream {
			get;
			construct;
		}

		public State state {
			get {
				return _state;
			}
		}

		private InputStream input;
		private OutputStream output;
		private Cancellable io_cancellable = new Cancellable ();

		private State _state = CREATED;
		private uint32 next_id = 1;
		private IDSizes id_sizes = new IDSizes.unknown ();
		private Gee.ArrayQueue<Bytes> pending_writes = new Gee.ArrayQueue<Bytes> ();
		private Gee.Map<uint32, PendingReply> pending_replies = new Gee.HashMap<uint32, PendingReply> ();

		public enum State {
			CREATED,
			READY,
			CLOSED
		}

		private const uint32 MAX_PACKET_SIZE = 10 * 1024 * 1024;

		public static async Client open (IOStream stream, Cancellable? cancellable = null) throws Error, IOError {
			var session = new Client (stream);

			try {
				yield session.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return session;
		}

		private Client (IOStream stream) {
			Object (stream: stream);
		}

		construct {
			input = stream.get_input_stream ();
			output = stream.get_output_stream ();
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			yield handshake (cancellable);
			process_incoming_packets.begin ();

			id_sizes = yield get_id_sizes (cancellable);

			change_state (READY);

			return true;
		}

		private void change_state (State new_state) {
			bool state_differs = new_state != _state;
			if (state_differs)
				_state = new_state;

			if (state_differs)
				notify_property ("state");
		}

		public async void close (Cancellable? cancellable) throws IOError {
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

		public async void suspend (Cancellable? cancellable = null) throws Error, IOError {
			yield execute (make_command (VM, VMCommand.SUSPEND), cancellable);
		}

		public async void resume (Cancellable? cancellable = null) throws Error, IOError {
			yield execute (make_command (VM, VMCommand.RESUME), cancellable);
		}

		public async ClassInfo get_class_by_signature (string signature, Cancellable? cancellable = null) throws Error, IOError {
			var candidates = yield get_classes_by_signature (signature, cancellable);
			if (candidates.is_empty)
				throw new Error.INVALID_ARGUMENT ("Class %s not found", signature);
			if (candidates.size > 1)
				throw new Error.INVALID_ARGUMENT ("Class %s is ambiguous", signature);
			return candidates.get (0);
		}

		public async Gee.List<ClassInfo> get_classes_by_signature (string signature, Cancellable? cancellable = null)
				throws Error, IOError {
			var command = make_command (VM, VMCommand.CLASSES_BY_SIGNATURE);
			command.append_utf8_string (signature);

			var reply = yield execute (command, cancellable);

			var result = new Gee.ArrayList<ClassInfo> ();
			int32 n = reply.read_int32 ();
			for (int32 i = 0; i != n; i++)
				result.add (ClassInfo.deserialize (reply));
			return result;
		}

		public async Gee.List<MethodInfo> get_methods (ReferenceTypeID type, Cancellable? cancellable = null)
				throws Error, IOError {
			var command = make_command (REFERENCE_TYPE, ReferenceTypeCommand.METHODS);
			command.append_reference_type_id (type);

			var reply = yield execute (command, cancellable);

			var result = new Gee.ArrayList<MethodInfo> ();
			int32 n = reply.read_int32 ();
			for (int32 i = 0; i != n; i++)
				result.add (MethodInfo.deserialize (reply));
			return result;
		}

		public async EventRequestID set_event_request (EventKind kind, SuspendPolicy suspend_policy, EventModifier[] modifiers,
				Cancellable? cancellable = null) throws Error, IOError {
			var command = make_command (EVENT_REQUEST, EventRequestCommand.SET);
			command
				.append_uint8 (kind)
				.append_uint8 (suspend_policy)
				.append_int32 (modifiers.length);
			foreach (var modifier in modifiers)
				modifier.serialize (command);

			var reply = yield execute (command, cancellable);

			return EventRequestID (reply.read_int32 ());
		}

		public async void clear_event_request (EventKind kind, EventRequestID request_id, Cancellable? cancellable = null)
				throws Error, IOError {
			var command = make_command (EVENT_REQUEST, EventRequestCommand.CLEAR);
			command
				.append_uint8 (kind)
				.append_int32 (request_id.handle);

			yield execute (command, cancellable);
		}

		public async void clear_all_breakpoints (Cancellable? cancellable = null) throws Error, IOError {
			var command = make_command (EVENT_REQUEST, EventRequestCommand.CLEAR_ALL_BREAKPOINTS);

			yield execute (command, cancellable);
		}

		private async void handshake (Cancellable? cancellable) throws Error, IOError {
			try {
				size_t n;

				string magic = "JDWP-Handshake";

				unowned uint8[] raw_handshake = magic.data;
				yield output.write_all_async (raw_handshake, Priority.DEFAULT, cancellable, out n);

				var raw_reply = new uint8[magic.length];
				yield input.read_all_async (raw_reply, Priority.DEFAULT, cancellable, out n);

				if (Memory.cmp (raw_reply, raw_handshake, raw_reply.length) != 0)
					throw new Error.PROTOCOL ("Unexpected handshake reply");
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("%s".printf (e.message));
			}
		}

		private async IDSizes get_id_sizes (Cancellable? cancellable) throws Error, IOError {
			var command = make_command (VM, VMCommand.ID_SIZES);

			var reply = yield execute (command, cancellable);

			var field_id_size = reply.read_int32 ();
			var method_id_size = reply.read_int32 ();
			var object_id_size = reply.read_int32 ();
			var reference_type_id_size = reply.read_int32 ();
			var frame_id_size = reply.read_int32 ();
			return new IDSizes (field_id_size, method_id_size, object_id_size, reference_type_id_size, frame_id_size);
		}

		private CommandBuilder make_command (CommandSet command_set, uint8 command) {
			return new CommandBuilder (next_id++, command_set, command, id_sizes);
		}

		private async PacketReader execute (CommandBuilder command, Cancellable? cancellable) throws Error, IOError {
			if (state == CLOSED)
				throw new Error.INVALID_OPERATION ("Unable to perform command; connection is closed");

			var pending = new PendingReply (execute.callback);
			pending_replies[command.id] = pending;

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (() => {
				pending.complete_with_error (new IOError.CANCELLED ("Operation was cancelled"));
				return false;
			});
			cancel_source.attach (MainContext.get_thread_default ());

			write_bytes (command.build ());

			yield;

			cancel_source.destroy ();

			cancellable.set_error_if_cancelled ();

			var reply = pending.reply;
			if (reply == null)
				throw_local_error (pending.error);

			return reply;
		}

		private async void process_incoming_packets () {
			while (true) {
				try {
					var packet = yield read_packet ();

					dispatch_packet (packet);
				} catch (GLib.Error error) {
					printerr ("!!! Oops: %s\n", error.message);

					change_state (CLOSED);

					foreach (var pending in pending_replies.values)
						pending.complete_with_error (error);
					pending_replies.clear ();

					closed ();

					return;
				}
			}
		}

		private async void process_pending_writes () {
			while (!pending_writes.is_empty) {
				Bytes current = pending_writes.peek_head ();

				try {
					size_t n;
					yield output.write_all_async (current.get_data (), Priority.DEFAULT, io_cancellable, out n);
				} catch (GLib.Error e) {
					return;
				}

				pending_writes.poll_head ();
			}
		}

		private void dispatch_packet (PacketReader packet) throws Error {
			packet.skip (sizeof (uint32));
			var id = packet.read_uint32 ();
			var flags = (PacketFlags) packet.read_uint8 ();

			if ((flags & PacketFlags.REPLY) != 0)
				handle_reply (packet, id);
			else
				handle_command (packet, id);
		}

		private void handle_reply (PacketReader packet, uint32 id) throws Error {
			PendingReply? pending;
			if (!pending_replies.unset (id, out pending))
				return;

			var error_code = packet.read_uint16 ();
			if (error_code == 0)
				pending.complete_with_reply (packet);
			else
				pending.complete_with_error (new Error.NOT_SUPPORTED ("Command failed: %u", error_code));
		}

		private void handle_command (PacketReader packet, uint32 id) throws Error {
			var command_set = (CommandSet) packet.read_uint8 ();
			var command = packet.read_uint8 ();
			switch (command_set) {
				case EVENT:
					handle_event ((EventCommand) command, packet);
					break;
				default:
					break;
			}
		}

		private void handle_event (EventCommand command, PacketReader packet) throws Error {
			switch (command) {
				case COMPOSITE:
					handle_event_composite (packet);
					break;
				default:
					break;
			}
		}

		private void handle_event_composite (PacketReader packet) throws Error {
			var suspend_policy = (SuspendPolicy) packet.read_uint8 ();

			var items = new Gee.ArrayList<Event> ();
			int32 n = packet.read_int32 ();
			for (int32 i = 0; i != n; i++) {
				Event? event = null;
				var kind = (EventKind) packet.read_uint8 ();
				switch (kind) {
					case SINGLE_STEP:
						event = parse_single_step (packet);
						break;
					case BREAKPOINT:
						event = BreakpointEvent.deserialize (packet);
						break;
					case FRAME_POP:
						event = parse_frame_pop (packet);
						break;
					case EXCEPTION:
						event = parse_exception (packet);
						break;
					case USER_DEFINED:
						event = parse_user_defined (packet);
						break;
					case THREAD_START:
						event = parse_thread_start (packet);
						break;
					case THREAD_DEATH:
						event = parse_thread_death (packet);
						break;
					case CLASS_PREPARE:
						event = parse_class_prepare (packet);
						break;
					case CLASS_UNLOAD:
						event = parse_class_unload (packet);
						break;
					case CLASS_LOAD:
						event = parse_class_load (packet);
						break;
					case FIELD_ACCESS:
						event = parse_field_access (packet);
						break;
					case FIELD_MODIFICATION:
						event = parse_field_modification (packet);
						break;
					case EXCEPTION_CATCH:
						event = parse_exception_catch (packet);
						break;
					case METHOD_ENTRY:
						event = parse_method_entry (packet);
						break;
					case METHOD_EXIT:
						event = parse_method_exit (packet);
						break;
					case METHOD_EXIT_WITH_RETURN_VALUE:
						event = parse_method_exit_with_return_value (packet);
						break;
					case MONITOR_CONTENDED_ENTER:
						event = parse_monitor_contended_enter (packet);
						break;
					case MONITOR_CONTENDED_ENTERED:
						event = parse_monitor_contended_entered (packet);
						break;
					case MONITOR_WAIT:
						event = parse_monitor_wait (packet);
						break;
					case MONITOR_WAITED:
						event = parse_monitor_waited (packet);
						break;
					case VM_START:
						event = parse_vm_start (packet);
						break;
					case VM_DEATH:
						event = parse_vm_death (packet);
						break;
					case VM_DISCONNECTED:
						event = parse_vm_disconnected (packet);
						break;
				}
				if (event != null)
					items.add (event);
			}

			events_received (new Events (suspend_policy, items));
		}

		private Event parse_single_step (PacketReader packet) throws Error {
			throw new Error.NOT_SUPPORTED ("SINGLE_STEP event not yet handled");
		}

		private Event parse_frame_pop (PacketReader packet) throws Error {
			throw new Error.NOT_SUPPORTED ("FRAME_POP event not yet handled");
		}

		private Event parse_exception (PacketReader packet) throws Error {
			throw new Error.NOT_SUPPORTED ("EXCEPTION event not yet handled");
		}

		private Event parse_user_defined (PacketReader packet) throws Error {
			throw new Error.NOT_SUPPORTED ("USER_DEFINED event not yet handled");
		}

		private Event parse_thread_start (PacketReader packet) throws Error {
			throw new Error.NOT_SUPPORTED ("THREAD_START event not yet handled");
		}

		private Event parse_thread_death (PacketReader packet) throws Error {
			throw new Error.NOT_SUPPORTED ("THREAD_DEATH event not yet handled");
		}

		private Event parse_class_prepare (PacketReader packet) throws Error {
			throw new Error.NOT_SUPPORTED ("CLASS_PREPARE event not yet handled");
		}

		private Event parse_class_unload (PacketReader packet) throws Error {
			throw new Error.NOT_SUPPORTED ("CLASS_UNLOAD event not yet handled");
		}

		private Event parse_class_load (PacketReader packet) throws Error {
			throw new Error.NOT_SUPPORTED ("CLASS_LOAD event not yet handled");
		}

		private Event parse_field_access (PacketReader packet) throws Error {
			throw new Error.NOT_SUPPORTED ("FIELD_ACCESS event not yet handled");
		}

		private Event parse_field_modification (PacketReader packet) throws Error {
			throw new Error.NOT_SUPPORTED ("FIELD_MODIFICATION event not yet handled");
		}

		private Event parse_exception_catch (PacketReader packet) throws Error {
			throw new Error.NOT_SUPPORTED ("EXCEPTION_CATCH event not yet handled");
		}

		private Event parse_method_entry (PacketReader packet) throws Error {
			throw new Error.NOT_SUPPORTED ("METHOD_ENTRY event not yet handled");
		}

		private Event parse_method_exit (PacketReader packet) throws Error {
			throw new Error.NOT_SUPPORTED ("METHOD_EXIT event not yet handled");
		}

		private Event parse_method_exit_with_return_value (PacketReader packet) throws Error {
			throw new Error.NOT_SUPPORTED ("METHOD_EXIT_WITH_RETURN_VALUE event not yet handled");
		}

		private Event parse_monitor_contended_enter (PacketReader packet) throws Error {
			throw new Error.NOT_SUPPORTED ("MONITOR_CONTENDED_ENTER event not yet handled");
		}

		private Event parse_monitor_contended_entered (PacketReader packet) throws Error {
			throw new Error.NOT_SUPPORTED ("MONITOR_CONTENDED_ENTERED event not yet handled");
		}

		private Event parse_monitor_wait (PacketReader packet) throws Error {
			throw new Error.NOT_SUPPORTED ("MONITOR_WAIT event not yet handled");
		}

		private Event parse_monitor_waited (PacketReader packet) throws Error {
			throw new Error.NOT_SUPPORTED ("MONITOR_WAITED event not yet handled");
		}

		private Event parse_vm_start (PacketReader packet) throws Error {
			throw new Error.NOT_SUPPORTED ("VM_START event not yet handled");
		}

		private Event parse_vm_death (PacketReader packet) throws Error {
			throw new Error.NOT_SUPPORTED ("VM_DEATH event not yet handled");
		}

		private Event parse_vm_disconnected (PacketReader packet) throws Error {
			throw new Error.NOT_SUPPORTED ("VM_DISCONNECTED event not yet handled");
		}

		private async PacketReader read_packet () throws Error, IOError {
			try {
				size_t n;

				int header_size = 11;
				var raw_reply = new uint8[header_size];
				yield input.read_all_async (raw_reply, Priority.DEFAULT, io_cancellable, out n);

				uint32 reply_size = uint32.from_big_endian (*((uint32 *) raw_reply));
				if (reply_size != raw_reply.length) {
					if (reply_size < raw_reply.length)
						throw new Error.PROTOCOL ("Invalid packet length (too small)");
					if (reply_size > MAX_PACKET_SIZE)
						throw new Error.PROTOCOL ("Invalid packet length (too large)");

					raw_reply.resize ((int) reply_size);
					yield input.read_all_async (raw_reply[header_size:], Priority.DEFAULT, io_cancellable, out n);
				}

				return new PacketReader ((owned) raw_reply, id_sizes);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("%s".printf (e.message));
			}
		}

		private void write_bytes (Bytes bytes) {
			pending_writes.offer_tail (bytes);
			if (pending_writes.size == 1)
				process_pending_writes.begin ();
		}

		private static void throw_local_error (GLib.Error e) throws Error, IOError {
			if (e is Error)
				throw (Error) e;

			if (e is IOError)
				throw (IOError) e;

			assert_not_reached ();
		}

		private class PendingReply {
			private SourceFunc? handler;

			public PacketReader? reply {
				get;
				private set;
			}

			public GLib.Error? error {
				get;
				private set;
			}

			public PendingReply (owned SourceFunc handler) {
				this.handler = (owned) handler;
			}

			public void complete_with_reply (PacketReader? reply) {
				if (handler == null)
					return;
				this.reply = reply;
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
	}

	public enum TypeTag {
		CLASS     = 1,
		INTERFACE = 2,
		ARRAY     = 3;

		public string to_short_string () {
			return Marshal.enum_to_nick<TypeTag> (this).up ();
		}
	}

	public class ClassInfo : Object {
		public TypeTag tag {
			get;
			construct;
		}

		public ReferenceTypeID id {
			get;
			construct;
		}

		public ClassStatus status {
			get;
			construct;
		}

		public ClassInfo (TypeTag tag, ReferenceTypeID id, ClassStatus status) {
			Object (
				tag: tag,
				id: id,
				status: status
			);
		}

		public string to_string () {
			return "ClassInfo(tag: %s, id: %s, status: %s)".printf (
				tag.to_short_string (),
				id.to_string (),
				status.to_short_string ());
		}

		internal static ClassInfo deserialize (PacketReader packet) throws Error {
			var tag = (TypeTag) packet.read_uint8 ();
			var id = packet.read_reference_type_id ();
			var status = (ClassStatus) packet.read_int32 ();
			return new ClassInfo (tag, id, status);
		}
	}

	[Flags]
	public enum ClassStatus {
		VERIFIED    = (1 << 0),
		PREPARED    = (1 << 1),
		INITIALIZED = (1 << 2),
		ERROR       = (1 << 3);

		public string to_short_string () {
			return this.to_string ().replace ("FRIDA_JDWP_CLASS_STATUS_", "");
		}
	}

	public class MethodInfo : Object {
		public MethodID id {
			get;
			construct;
		}

		public string name {
			get;
			construct;
		}

		public string signature {
			get;
			construct;
		}

		public int32 mod_bits {
			get;
			construct;
		}

		public MethodInfo (MethodID id, string name, string signature, int32 mod_bits) {
			Object (
				id: id,
				name: name,
				signature: signature,
				mod_bits: mod_bits
			);
		}

		public string to_string () {
			return "MethodInfo(id: %s, name: \"%s\", signature: \"%s\", mod_bits: 0x%08x)".printf (
				id.to_string (),
				name,
				signature,
				mod_bits);
		}

		internal static MethodInfo deserialize (PacketReader packet) throws Error {
			var id = packet.read_method_id ();
			var name = packet.read_utf8_string ();
			var signature = packet.read_utf8_string ();
			var mod_bits = packet.read_int32 ();
			return new MethodInfo (id, name, signature, mod_bits);
		}
	}

	public struct ObjectID {
		public int64 handle {
			get;
			private set;
		}

		public ObjectID (int64 handle) {
			this.handle = handle;
		}

		public string to_string () {
			return (handle != 0) ? handle.to_string () : "null";
		}
	}

	public struct ThreadID {
		public int64 handle {
			get;
			private set;
		}

		public ThreadID (int64 handle) {
			this.handle = handle;
		}

		public string to_string () {
			return handle.to_string ();
		}
	}

	public struct ReferenceTypeID {
		public int64 handle {
			get;
			private set;
		}

		public ReferenceTypeID (int64 handle) {
			this.handle = handle;
		}

		public string to_string () {
			return (handle != 0) ? handle.to_string () : "null";
		}
	}

	public struct MethodID {
		public int64 handle {
			get;
			private set;
		}

		public MethodID (int64 handle) {
			this.handle = handle;
		}

		public string to_string () {
			return handle.to_string ();
		}
	}

	public struct FieldID {
		public int64 handle {
			get;
			private set;
		}

		public FieldID (int64 handle) {
			this.handle = handle;
		}

		public string to_string () {
			return handle.to_string ();
		}
	}

	public class Location : Object {
		public TypeTag tag {
			get;
			construct;
		}

		public ReferenceTypeID declaring {
			get;
			construct;
		}

		public MethodID method {
			get;
			construct;
		}

		public uint64 index {
			get;
			construct;
		}

		public Location (TypeTag tag, ReferenceTypeID declaring, MethodID method, uint64 index = 0) {
			Object (
				tag: tag,
				declaring: declaring,
				method: method,
				index: index
			);
		}

		public string to_string () {
			return "Location(tag: %s, declaring: %s, method: %s, index: %s)".printf (
				tag.to_short_string (),
				declaring.to_string (),
				method.to_string (),
				index.to_string ());
		}

		internal void serialize (PacketBuilder builder) {
			builder
				.append_uint8 (tag)
				.append_reference_type_id (declaring)
				.append_method_id (method)
				.append_uint64 (index);
		}

		internal static Location deserialize (PacketReader packet) throws Error {
			var tag = (TypeTag) packet.read_uint8 ();
			var declaring = packet.read_reference_type_id ();
			var method = packet.read_method_id ();
			var index = packet.read_uint64 ();
			return new Location (tag, declaring, method, index);
		}
	}

	public enum EventKind {
		SINGLE_STEP                   = 1,
		BREAKPOINT                    = 2,
		FRAME_POP                     = 3,
		EXCEPTION                     = 4,
		USER_DEFINED                  = 5,
		THREAD_START                  = 6,
		THREAD_DEATH                  = 7,
		CLASS_PREPARE                 = 8,
		CLASS_UNLOAD                  = 9,
		CLASS_LOAD                    = 10,
		FIELD_ACCESS                  = 20,
		FIELD_MODIFICATION            = 21,
		EXCEPTION_CATCH               = 30,
		METHOD_ENTRY                  = 40,
		METHOD_EXIT                   = 41,
		METHOD_EXIT_WITH_RETURN_VALUE = 42,
		MONITOR_CONTENDED_ENTER       = 43,
		MONITOR_CONTENDED_ENTERED     = 44,
		MONITOR_WAIT                  = 45,
		MONITOR_WAITED                = 46,
		VM_START                      = 90,
		VM_DEATH                      = 99,
		VM_DISCONNECTED               = 100,
	}

	public enum SuspendPolicy {
		NONE         = 0,
		EVENT_THREAD = 1,
		ALL          = 2,
	}

	public class Events : Object {
		public SuspendPolicy suspend_policy {
			get;
			construct;
		}

		public Gee.List<Event> items {
			get;
			construct;
		}

		public Events (SuspendPolicy suspend_policy, Gee.List<Event> items) {
			Object (
				suspend_policy: suspend_policy,
				items: items
			);
		}

		public string to_string () {
			var result = new StringBuilder ("Events(\n");

			foreach (var event in items) {
				result
					.append ("\t\t")
					.append (event.to_string ())
					.append_c ('\n');
			}

			result.append ("\t)");

			return result.str;
		}
	}

	public abstract class Event : Object {
		public EventKind kind {
			get;
			construct;
		}

		public abstract string to_string ();
	}

	public class BreakpointEvent : Event {
		public EventRequestID request_id {
			get;
			construct;
		}

		public ThreadID thread {
			get;
			construct;
		}

		public Location location {
			get;
			construct;
		}

		public BreakpointEvent (EventRequestID request_id, ThreadID thread, Location location) {
			Object (
				kind: EventKind.BREAKPOINT,
				request_id: request_id,
				thread: thread,
				location: location
			);
		}

		public override string to_string () {
			return "BreakpointEvent(request_id: %s, thread: %s, location: %s)".printf (
				request_id.to_string (),
				thread.to_string (),
				location.to_string ());
		}

		internal static BreakpointEvent deserialize (PacketReader packet) throws Error {
			var request_id = EventRequestID (packet.read_int32 ());
			var thread_id = packet.read_thread_id ();
			var location = Location.deserialize (packet);
			return new BreakpointEvent (request_id, thread_id, location);
		}
	}

	public abstract class EventModifier : Object {
		internal abstract void serialize (PacketBuilder builder);
	}

	public class CountModifier : EventModifier {
		public int32 count {
			get;
			construct;
		}

		public CountModifier (int32 count) {
			Object (count: count);
		}

		internal override void serialize (PacketBuilder builder) {
			builder
				.append_uint8 (EventModifierKind.COUNT)
				.append_int32 (count);
		}
	}

	public class ThreadOnlyModifier : EventModifier {
		public ThreadID thread {
			get;
			construct;
		}

		public ThreadOnlyModifier (ThreadID thread) {
			Object (thread: thread);
		}

		internal override void serialize (PacketBuilder builder) {
			builder
				.append_uint8 (EventModifierKind.THREAD_ONLY)
				.append_thread_id (thread);
		}
	}

	public class ClassOnlyModifier : EventModifier {
		public ReferenceTypeID clazz {
			get;
			construct;
		}

		public ClassOnlyModifier (ReferenceTypeID clazz) {
			Object (clazz: clazz);
		}

		internal override void serialize (PacketBuilder builder) {
			builder
				.append_uint8 (EventModifierKind.CLASS_ONLY)
				.append_reference_type_id (clazz);
		}
	}

	public class ClassMatchModifier : EventModifier {
		public string class_pattern {
			get;
			construct;
		}

		public ClassMatchModifier (string class_pattern) {
			Object (class_pattern: class_pattern);
		}

		internal override void serialize (PacketBuilder builder) {
			builder
				.append_uint8 (EventModifierKind.CLASS_MATCH)
				.append_utf8_string (class_pattern);
		}
	}

	public class ClassExcludeModifier : EventModifier {
		public string class_pattern {
			get;
			construct;
		}

		public ClassExcludeModifier (string class_pattern) {
			Object (class_pattern: class_pattern);
		}

		internal override void serialize (PacketBuilder builder) {
			builder
				.append_uint8 (EventModifierKind.CLASS_EXCLUDE)
				.append_utf8_string (class_pattern);
		}
	}

	public class LocationOnlyModifier : EventModifier {
		public Location location {
			get;
			construct;
		}

		public LocationOnlyModifier (TypeTag tag, ReferenceTypeID declaring, MethodID method, uint64 index = 0) {
			Object (location: new Location (tag, declaring, method, index));
		}

		internal override void serialize (PacketBuilder builder) {
			builder.append_uint8 (EventModifierKind.LOCATION_ONLY);
			location.serialize (builder);
		}
	}

	public class ExceptionOnlyModifier : EventModifier {
		public ReferenceTypeID exception_or_null {
			get;
			construct;
		}

		public bool caught {
			get;
			construct;
		}

		public bool uncaught {
			get;
			construct;
		}

		public ExceptionOnlyModifier (ReferenceTypeID exception_or_null, bool caught, bool uncaught) {
			Object (
				exception_or_null: exception_or_null,
				caught: caught,
				uncaught: uncaught
			);
		}

		internal override void serialize (PacketBuilder builder) {
			builder
				.append_uint8 (EventModifierKind.EXCEPTION_ONLY)
				.append_reference_type_id (exception_or_null)
				.append_bool (caught)
				.append_bool (uncaught);
		}
	}

	public class FieldOnlyModifier : EventModifier {
		public ReferenceTypeID declaring {
			get;
			construct;
		}

		public FieldID field {
			get;
			construct;
		}

		public FieldOnlyModifier (ReferenceTypeID declaring, FieldID field) {
			Object (
				declaring: declaring,
				field: field
			);
		}

		internal override void serialize (PacketBuilder builder) {
			builder
				.append_uint8 (EventModifierKind.FIELD_ONLY)
				.append_reference_type_id (declaring)
				.append_field_id (field);
		}
	}

	public class StepModifier : EventModifier {
		public ThreadID thread {
			get;
			construct;
		}

		public StepSize step_size {
			get;
			construct;
		}

		public StepDepth step_depth {
			get;
			construct;
		}

		public StepModifier (ThreadID thread, StepSize step_size, StepDepth step_depth) {
			Object (
				thread: thread,
				step_size: step_size,
				step_depth: step_depth
			);
		}

		internal override void serialize (PacketBuilder builder) {
			builder
				.append_uint8 (EventModifierKind.STEP)
				.append_thread_id (thread)
				.append_int32 (step_size)
				.append_int32 (step_depth);
		}
	}

	public enum StepSize {
		MIN  = 0,
		LINE = 1,
	}

	public enum StepDepth {
		INTO = 0,
		OVER = 1,
		OUT  = 2,
	}

	public class InstanceOnlyModifier : EventModifier {
		public ObjectID instance {
			get;
			construct;
		}

		public InstanceOnlyModifier (ObjectID instance) {
			Object (instance: instance);
		}

		internal override void serialize (PacketBuilder builder) {
			builder
				.append_uint8 (EventModifierKind.INSTANCE_ONLY)
				.append_object_id (instance);
		}
	}

	public class SourceNameMatchModifier : EventModifier {
		public string source_name_pattern {
			get;
			construct;
		}

		public SourceNameMatchModifier (string source_name_pattern) {
			Object (source_name_pattern: source_name_pattern);
		}

		internal override void serialize (PacketBuilder builder) {
			builder
				.append_uint8 (EventModifierKind.SOURCE_NAME_MATCH)
				.append_utf8_string (source_name_pattern);
		}
	}

	private enum EventModifierKind {
		COUNT             = 1,
		THREAD_ONLY       = 3,
		CLASS_ONLY        = 4,
		CLASS_MATCH       = 5,
		CLASS_EXCLUDE     = 6,
		LOCATION_ONLY     = 7,
		EXCEPTION_ONLY    = 8,
		FIELD_ONLY        = 9,
		STEP              = 10,
		INSTANCE_ONLY     = 11,
		SOURCE_NAME_MATCH = 12,
	}

	public struct EventRequestID {
		public int32 handle {
			get;
			private set;
		}

		public EventRequestID (int32 handle) {
			this.handle = handle;
		}

		public string to_string () {
			return handle.to_string ();
		}
	}

	private enum CommandSet {
		VM             = 1,
		REFERENCE_TYPE = 2,
		EVENT_REQUEST  = 15,
		EVENT          = 64,
	}

	private enum VMCommand {
		CLASSES_BY_SIGNATURE = 2,
		ID_SIZES             = 7,
		SUSPEND              = 8,
		RESUME               = 9,
	}

	private enum ReferenceTypeCommand {
		METHODS = 5,
	}

	private enum EventRequestCommand {
		SET                   = 1,
		CLEAR                 = 2,
		CLEAR_ALL_BREAKPOINTS = 3,
	}

	private enum EventCommand {
		COMPOSITE = 100,
	}

	[Flags]
	private enum PacketFlags {
		REPLY = (1 << 7),
	}

	private class CommandBuilder : PacketBuilder {
		public CommandBuilder (uint32 id, CommandSet command_set, uint8 command, IDSizes id_sizes) {
			base (id, 0, id_sizes);

			append_uint8 (command_set);
			append_uint8 (command);
		}
	}

	private class PacketBuilder {
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

		private IDSizes id_sizes;

		public PacketBuilder (uint32 id, uint8 flags, IDSizes id_sizes) {
			this.id = id;
			this.id_sizes = id_sizes;

			uint32 length_placeholder = 0;
			append_uint32 (length_placeholder);
			append_uint32 (id);
			append_uint8 (flags);
		}

		public unowned PacketBuilder append_uint8 (uint8 val) {
			*(get_pointer (cursor, sizeof (uint8))) = val;
			cursor += (uint) sizeof (uint8);
			return this;
		}

		public unowned PacketBuilder append_int32 (int32 val) {
			*((int32 *) get_pointer (cursor, sizeof (int32))) = val.to_big_endian ();
			cursor += (uint) sizeof (int32);
			return this;
		}

		public unowned PacketBuilder append_uint32 (uint32 val) {
			*((uint32 *) get_pointer (cursor, sizeof (uint32))) = val.to_big_endian ();
			cursor += (uint) sizeof (uint32);
			return this;
		}

		public unowned PacketBuilder append_int64 (int64 val) {
			*((int64 *) get_pointer (cursor, sizeof (int64))) = val.to_big_endian ();
			cursor += (uint) sizeof (int64);
			return this;
		}

		public unowned PacketBuilder append_uint64 (uint64 val) {
			*((uint64 *) get_pointer (cursor, sizeof (uint64))) = val.to_big_endian ();
			cursor += (uint) sizeof (uint64);
			return this;
		}

		public unowned PacketBuilder append_bool (bool val) {
			return append_uint8 ((uint8) val);
		}

		public unowned PacketBuilder append_utf8_string (string str) {
			append_uint32 (str.length);

			uint size = str.length;
			Memory.copy (get_pointer (cursor, size), str, size);
			cursor += size;

			return this;
		}

		public unowned PacketBuilder append_object_id (ObjectID object) {
			return append_handle (object.handle, id_sizes.get_object_id_size_or_die ());
		}

		public unowned PacketBuilder append_thread_id (ThreadID thread) {
			return append_handle (thread.handle, id_sizes.get_object_id_size_or_die ());
		}

		public unowned PacketBuilder append_reference_type_id (ReferenceTypeID type) {
			return append_handle (type.handle, id_sizes.get_reference_type_id_size_or_die ());
		}

		public unowned PacketBuilder append_method_id (MethodID method) {
			return append_handle (method.handle, id_sizes.get_method_id_size_or_die ());
		}

		public unowned PacketBuilder append_field_id (FieldID field) {
			return append_handle (field.handle, id_sizes.get_field_id_size_or_die ());
		}

		private unowned PacketBuilder append_handle (int64 val, size_t size) {
			switch (size) {
				case 4:
					return append_int32 ((int32) val);
				case 8:
					return append_int64 (val);
				default:
					assert_not_reached ();
			}
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

	private class PacketReader {
		public size_t available_bytes {
			get {
				return end - cursor;
			}
		}

		private uint8[] data;
		private uint8 * cursor;
		private uint8 * end;

		private IDSizes id_sizes;

		public PacketReader (owned uint8[] data, IDSizes id_sizes) {
			this.data = (owned) data;
			this.cursor = (uint8 *) this.data;
			this.end = cursor + this.data.length;

			this.id_sizes = id_sizes;
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

		public int32 read_int32 () throws Error {
			const size_t n = sizeof (int32);
			check_available (n);

			int32 val = int32.from_big_endian (*((int32 *) cursor));
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

		public int64 read_int64 () throws Error {
			const size_t n = sizeof (int64);
			check_available (n);

			int64 val = int64.from_big_endian (*((int64 *) cursor));
			cursor += n;

			return val;
		}

		public uint64 read_uint64 () throws Error {
			const size_t n = sizeof (uint64);
			check_available (n);

			uint64 val = uint64.from_big_endian (*((uint64 *) cursor));
			cursor += n;

			return val;
		}

		public string read_utf8_string () throws Error {
			size_t size = read_uint32 ();
			check_available (size);

			unowned string data = (string) cursor;
			string str = data.substring (0, (long) size);
			cursor += size;

			return str;
		}

		public ThreadID read_thread_id () throws Error {
			return ThreadID (read_handle (id_sizes.get_object_id_size ()));
		}

		public ReferenceTypeID read_reference_type_id () throws Error {
			return ReferenceTypeID (read_handle (id_sizes.get_reference_type_id_size ()));
		}

		public MethodID read_method_id () throws Error {
			return MethodID (read_handle (id_sizes.get_method_id_size ()));
		}

		private int64 read_handle (size_t size) throws Error {
			switch (size) {
				case 4:
					return read_int32 ();
				case 8:
					return read_int64 ();
				default:
					assert_not_reached ();
			}
		}

		private void check_available (size_t n) throws Error {
			if (cursor + n > end)
				throw new Error.PROTOCOL ("Invalid JDWP packet");
		}
	}

	private class IDSizes {
		private bool valid;
		private int field_id_size = -1;
		private int method_id_size = -1;
		private int object_id_size = -1;
		private int reference_type_id_size = -1;
		private int frame_id_size = -1;

		public IDSizes (int field_id_size, int method_id_size, int object_id_size, int reference_type_id_size, int frame_id_size) {
			this.field_id_size = field_id_size;
			this.method_id_size = method_id_size;
			this.object_id_size = object_id_size;
			this.reference_type_id_size = reference_type_id_size;
			this.frame_id_size = frame_id_size;

			valid = true;
		}

		public IDSizes.unknown () {
			valid = false;
		}

		public size_t get_field_id_size () throws Error {
			check ();
			return field_id_size;
		}

		public size_t get_field_id_size_or_die () {
			assert (valid);
			return field_id_size;
		}

		public size_t get_method_id_size () throws Error {
			check ();
			return method_id_size;
		}

		public size_t get_method_id_size_or_die () {
			assert (valid);
			return method_id_size;
		}

		public size_t get_object_id_size () throws Error {
			check ();
			return object_id_size;
		}

		public size_t get_object_id_size_or_die () {
			assert (valid);
			return object_id_size;
		}

		public size_t get_reference_type_id_size () throws Error {
			check ();
			return reference_type_id_size;
		}

		public size_t get_reference_type_id_size_or_die () {
			assert (valid);
			return reference_type_id_size;
		}

		private void check () throws Error {
			if (!valid)
				throw new Error.PROTOCOL ("ID sizes not known");
		}
	}
}
