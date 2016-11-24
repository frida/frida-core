namespace Frida {
	private class Debugger : Object {
		public uint port {
			get;
			construct;
		}

		public AgentSession agent_session {
			get;
			construct;
		}

		private DebugServer server;

		public Debugger (uint16 port, AgentSession agent_session) {
			Object (port: port, agent_session: agent_session);
		}

		public async void enable () throws Error {
			string? sync_message = null;
			var sync_handler = agent_session.message_from_debugger.connect ((message) => {
				sync_message = message;
			});

			try {
				yield agent_session.enable_debugger ();
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}

			agent_session.disconnect (sync_handler);

			try {
				if (sync_message == null)
					server = new V8DebugServer (port, agent_session);
				else
					server = new DuktapeDebugServer (port, agent_session);
				server.start (sync_message);
			} catch (Error e) {
				agent_session.disable_debugger.begin ();
				throw e;
			}
		}

		public void disable () {
			server.stop ();
			server = null;

			agent_session.disable_debugger.begin ();
		}
	}

	private interface DebugServer : Object {
		public abstract void start (string? sync_message) throws Error;
		public abstract void stop ();
	}

	private class V8DebugServer : Object, DebugServer {
		public uint port {
			get;
			construct;
		}

		public AgentSession agent_session {
			get;
			construct;
		}

		private SocketService service = new SocketService ();
		private Gee.HashSet<Session> sessions = new Gee.HashSet<Session> ();

		public V8DebugServer (uint port, AgentSession agent_session) {
			Object (port: port, agent_session: agent_session);
		}

		public void start (string? sync_message) throws Error {
			try {
				service.add_inet_port ((uint16) port, null);
			} catch (GLib.Error e) {
				throw new Error.ADDRESS_IN_USE (e.message);
			}

			service.incoming.connect (on_incoming_connection);

			service.start ();

			agent_session.message_from_debugger.connect (on_message_from_debugger);
		}

		public void stop () {
			foreach (var session in sessions)
				session.close ();

			agent_session.message_from_debugger.disconnect (on_message_from_debugger);

			service.stop ();

			service.incoming.disconnect (on_incoming_connection);
		}

		private bool on_incoming_connection (SocketConnection connection, Object? source_object) {
			var session = new Session (connection);
			session.end.connect (on_session_end);
			session.receive.connect (on_session_receive);
			sessions.add (session);

			session.open ();

			return true;
		}

		private void on_session_end (Session session) {
			sessions.remove (session);
			session.end.disconnect (on_session_end);
			session.receive.disconnect (on_session_receive);
		}

		private void on_session_receive (string message) {
			agent_session.post_message_to_debugger.begin (message);
		}

		private void on_message_from_debugger (string message) {
			var headers = new string[] {};
			foreach (var session in sessions)
				session.send (headers, message);
		}

		private class Session : Object {
			public signal void end ();
			public signal void receive (string message);

			public IOStream stream {
				get;
				construct;
			}

			private const size_t CHUNK_SIZE = 512;
			private const size_t MAX_MESSAGE_SIZE = 2048;

			private InputStream input;
			private char * buffer;
			private size_t length;
			private size_t capacity;

			private OutputStream output;
			private Queue<string> outgoing = new Queue<string> ();

			private Cancellable cancellable = new Cancellable ();

			public Session (IOStream stream) {
				Object (stream: stream);
			}

			construct {
				this.input = stream.get_input_stream ();
				this.output = stream.get_output_stream ();
			}

			~Session () {
				stream.close_async.begin ();

				free (buffer);
			}

			public void open () {
				var headers = new string[] {
					"Type", "connect",
					"V8-Version", "5.4.401", // FIXME
					"Protocol-Version", "1",
					"Embedding-Host", "Frida " + Frida.version_string ()
				};
				var body = "";
				send (headers, body);

				process_incoming_messages.begin ();
			}

			public void close () {
				cancellable.cancel ();
			}

			public void send (string[] headers, string content) {
				assert (headers.length % 2 == 0);

				var message = new StringBuilder ("");
				for (var i = 0; i != headers.length; i += 2) {
					var key = headers[i];
					var val = headers[i + 1];
					message.append_printf ("%s: %s\r\n", key, val);
				}
				message.append_printf ("Content-Length: %ld\r\n\r\n%s", content.length, content);

				bool write_now = outgoing.is_empty ();
				outgoing.push_tail (message.str);
				if (write_now)
					process_outgoing_messages.begin ();
			}

			private async void process_incoming_messages () {
				try {
					while (true) {
						var message = yield read_message ();
						receive (message);
					}
				} catch (GLib.Error e) {
				}

				close ();

				end ();
			}

			private async void process_outgoing_messages () {
				try {
					do {
						var m = outgoing.peek_head ();
						unowned uint8[] buf = (uint8[]) m;
						yield output.write_all_async (buf[0:m.length], Priority.DEFAULT, cancellable, null);
						outgoing.pop_head ();
					} while (!outgoing.is_empty ());
				} catch (GLib.Error e) {
				}
			}

			private async string read_message () throws IOError {
				long message_length = 0;
				long header_length = 0;
				long content_length = 0;

				while (true) {
					if (length > 0) {
						unowned string message = (string) buffer;

						if (message_length == 0) {
							int header_end = message.index_of ("\r\n\r\n");
							if (header_end != -1) {
								header_length = header_end + 4;
								var headers = message[0:header_end];
								parse_headers (headers, out content_length);
								message_length = header_length + content_length;
							}
						}

						if (message_length != 0 && length >= message_length) {
							var content = message[header_length:message_length];
							consume_buffer (message_length);
							return content;
						}
					}

					yield fill_buffer ();
				}
			}

			private async void fill_buffer () throws IOError {
				var available = capacity - length;
				if (available < CHUNK_SIZE) {
					capacity = size_t.min (capacity + (CHUNK_SIZE - available), MAX_MESSAGE_SIZE);
					buffer = realloc (buffer, capacity + 1);

					available = capacity - length;
				}

				if (available == 0)
					throw new IOError.FAILED ("Maximum message size exceeded");

				buffer[length + available] = 0;
				unowned uint8[] buf = (uint8[]) buffer;
				var n = yield input.read_async (buf[length:length + available], Priority.DEFAULT, cancellable);
				if (n == 0)
					throw new IOError.CLOSED ("Connection is closed");
				length += n;
			}

			private void consume_buffer (long n) {
				length -= n;
				if (length > 0) {
					Memory.move (buffer, buffer + n, length);
					buffer[length] = 0;
				}
			}

			private void parse_headers (string headers, out long content_length) throws IOError {
				var lines = headers.split ("\r\n");
				foreach (var line in lines) {
					var tokens = line.split (": ", 2);
					if (tokens.length != 2)
						throw new IOError.FAILED ("Malformed header");
					var key = tokens[0];
					var val = tokens[1];
					if (key == "Content-Length") {
						uint64 l;
						if (uint64.try_parse (val, out l)) {
							content_length = (long) l;
							return;
						}
					}
				}

				throw new IOError.FAILED ("Missing content length");
			}
		}
	}

	private class DuktapeDebugServer : Object, DebugServer {
		public uint port {
			get;
			construct;
		}

		public AgentSession agent_session {
			get;
			construct;
		}

		private Gee.HashMap<uint, Channel> channels = new Gee.HashMap<uint, Channel> ();
		private uint next_port;

		public DuktapeDebugServer (uint port, AgentSession agent_session) {
			Object (port: port, agent_session: agent_session);
		}

		construct {
			next_port = port;
		}

		public void start (string? sync_message) throws Error {
			if (!sync_message.has_prefix ("SYNC\n"))
				throw new Error.PROTOCOL ("invalid sync message");

			foreach (var line in sync_message.substring (5).split ("\n")) {
				var tokens = line.split (" ");
				if (tokens.length != 2)
					throw new Error.PROTOCOL ("invalid sync message");
				var id = (uint) uint64.parse (tokens[0]);
				var name = tokens[1].compress ();
				add_channel (id, name);
			}

			foreach (var channel in channels.values)
				channel.open ();

			agent_session.message_from_debugger.connect (on_message_from_debugger);
		}

		public void stop () {
			while (!channels.is_empty) {
				var iterator = channels.keys.iterator ();
				iterator.next ();
				var id = iterator.get ();
				remove_channel (id);
			}

			agent_session.message_from_debugger.disconnect (on_message_from_debugger);
		}

		private void on_message_from_debugger (string message) {
			var tokens = message.split (" ");

			var num_tokens = tokens.length;
			if (num_tokens < 2)
				return;

			var notification = tokens[0];

			var id = (uint) uint64.parse (tokens[1]);

			if (notification == "EMIT" && num_tokens == 3) {
				var channel = channels[id];
				if (channel == null)
					return;
				var bytes = new Bytes.take (Base64.decode (tokens[2]));
				channel.send (bytes);
			} else if (notification == "ADD" && num_tokens == 3) {
				var name = tokens[2].compress ();
				try {
					var channel = add_channel (id, name);
					channel.open ();
				} catch (Error e) {
				}
			} else if (notification == "REMOVE") {
				remove_channel (id);
			} else if (notification == "DETACH") {
				var channel = channels[id];
				if (channel == null)
					return;
				channel.close_all_sessions ();
			}
		}

		private Channel add_channel (uint id, string name) throws Error {
			var service = new SocketService ();

			uint selected_port;
			bool try_next = false;
			do {
				try {
					selected_port = next_port++;
					service.add_inet_port ((uint16) selected_port, null);
					try_next = false;
				} catch (GLib.Error e) {
					if (e is IOError.ADDRESS_IN_USE)
						try_next = true;
					else
						throw new Error.TRANSPORT (e.message);
				}
			} while (try_next);

			var channel = new Channel (id, port, service);
			channel.active.connect (on_channel_active);
			channel.inactive.connect (on_channel_inactive);
			channel.receive.connect (on_channel_receive);
			channels[id] = channel;

			return channel;
		}

		private void remove_channel (uint id) {
			Channel channel;
			if (!channels.unset (id, out channel))
				return;

			channel.active.disconnect (on_channel_active);
			channel.inactive.disconnect (on_channel_inactive);
			channel.receive.disconnect (on_channel_receive);
			channel.close ();

			next_port = uint.min (channel.port, next_port);
		}

		private void on_channel_active (Channel channel) {
			post ("ATTACH %u", channel.id);
		}

		private void on_channel_inactive (Channel channel) {
			post ("DETACH %u", channel.id);
		}

		private void on_channel_receive (Channel channel, Bytes bytes) {
			post ("POST %u %s", channel.id, Base64.encode (bytes.get_data ()));
		}

		private void post (string format, ...) {
			var args = va_list ();
			var message = format.vprintf (args);
			agent_session.post_message_to_debugger.begin (message);
		}

		private class Channel : Object {
			public signal void active ();
			public signal void inactive ();
			public signal void receive (Bytes bytes);

			public uint id {
				get;
				construct;
			}

			public uint port {
				get;
				construct;
			}

			public SocketService service {
				get;
				construct;
			}

			private Gee.HashSet<Session> sessions = new Gee.HashSet<Session> ();

			public Channel (uint id, uint port, SocketService service) {
				Object (id: id, port: port, service: service);
			}

			public void open () {
				service.incoming.connect (on_incoming_connection);

				service.start ();
			}

			public void close () {
				foreach (var session in sessions)
					session.close ();

				service.stop ();

				service.incoming.disconnect (on_incoming_connection);
			}

			public void close_all_sessions () {
				foreach (var session in sessions)
					session.close ();
			}

			public void send (Bytes bytes) {
				foreach (var session in sessions)
					session.send (bytes);
			}

			private bool on_incoming_connection (SocketConnection connection, Object? source_object) {
				var session = new Session (connection);
				session.end.connect (on_session_end);
				session.receive.connect (on_session_receive);
				sessions.add (session);

				session.open ();

				if (sessions.size == 1)
					active ();

				return true;
			}

			private void on_session_end (Session session) {
				if (sessions.size == 1)
					inactive ();

				sessions.remove (session);
				session.end.disconnect (on_session_end);
				session.receive.disconnect (on_session_receive);
			}

			private void on_session_receive (Bytes bytes) {
				receive (bytes);
			}
		}

		private class Session : Object {
			public signal void end ();
			public signal void receive (Bytes bytes);

			public IOStream stream {
				get;
				construct;
			}

			private const size_t CHUNK_SIZE = 512;

			private InputStream input;
			private OutputStream output;
			private Queue<Bytes> outgoing = new Queue<Bytes> ();

			private Cancellable cancellable = new Cancellable ();

			public Session (IOStream stream) {
				Object (stream: stream);
			}

			construct {
				this.input = stream.get_input_stream ();
				this.output = stream.get_output_stream ();
			}

			~Session () {
				stream.close_async.begin ();
			}

			public void open () {
				process_incoming_data.begin ();
			}

			public void close () {
				cancellable.cancel ();
			}

			public void send (Bytes bytes) {
				bool write_now = outgoing.is_empty ();
				outgoing.push_tail (bytes);
				if (write_now)
					process_outgoing_data.begin ();
			}

			private async void process_incoming_data () {
				try {
					while (true) {
						var data = yield input.read_bytes_async (CHUNK_SIZE, Priority.DEFAULT, cancellable);
						if (data.length == 0)
							break;
						receive (data);
					}
				} catch (GLib.Error e) {
				}

				close ();

				end ();
			}

			private async void process_outgoing_data () {
				try {
					do {
						var bytes = outgoing.peek_head ();
						yield output.write_all_async (bytes.get_data (), Priority.DEFAULT, cancellable, null);
						outgoing.pop_head ();
					} while (!outgoing.is_empty ());
				} catch (GLib.Error e) {
				}
			}
		}
	}
}
