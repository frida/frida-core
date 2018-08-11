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
		public Gum.InspectorServer server {
			get;
			construct;
		}

		public AgentSession agent_session {
			get;
			construct;
		}

		public V8DebugServer (uint port, AgentSession agent_session) {
			Object (
				server: (port != 0) ? new Gum.InspectorServer.with_port (port) : new Gum.InspectorServer (),
				agent_session: agent_session
			);
		}

		public void start (string? sync_message) throws Error {
			try {
				server.start ();
			} catch (GLib.IOError e) {
				throw new Error.ADDRESS_IN_USE (e.message);
			}

			server.message.connect (on_message_from_frontend);
			agent_session.message_from_debugger.connect (on_message_from_backend);
		}

		public void stop () {
			agent_session.message_from_debugger.disconnect (on_message_from_backend);
			server.message.disconnect (on_message_from_frontend);

			server.stop ();
		}

		private void on_message_from_frontend (string message) {
			agent_session.post_message_to_debugger.begin (message);
		}

		private void on_message_from_backend (string message) {
			server.post_message (message);
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
			Object (
				port: (port != 0) ? port : 5858,
				agent_session: agent_session
			);
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
