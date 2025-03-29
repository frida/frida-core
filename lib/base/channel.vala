namespace Frida {
	public class ChannelServer : Object {
		private Gee.HashMap<ChannelId?, IOStream> channels =
			new Gee.HashMap<ChannelId?, IOStream> (ChannelId.hash, ChannelId.equal);

		public ChannelId register (IOStream stream) {
			var id = ChannelId.generate ();
			channels[id] = stream;
			return id;
		}

		public IOStream link (ChannelId id) throws Error {
			IOStream? stream = channels[id];
			if (stream == null)
				throw new Error.INVALID_ARGUMENT ("Invalid channel ID");
			return stream;
		}

		public void unlink (ChannelId id) {
			channels.unset (id);
		}
	}

	public class ChannelEndpoint : Object, Channel {
		public IOStream stream {
			get;
			construct;
		}

		private ByteArray write_queue = new ByteArray ();
		private bool writing = false;

		private Cancellable io_cancellable = new Cancellable ();

		public ChannelEndpoint (IOStream stream) {
			Object (stream: stream);
		}

		construct {
			read_loop.begin ();
		}

		public async void close (Cancellable? cancellable) throws Error, IOError {
			io_cancellable.cancel ();
		}

		public async void input (uint8[] data, Cancellable? cancellable) throws Error, IOError {
			if (io_cancellable.is_cancelled ())
				throw new Error.INVALID_OPERATION ("Channel is closed");

			write_queue.append (data);

			if (!writing) {
				writing = true;

				var source = new IdleSource ();
				source.set_callback (() => {
					process_write_queue.begin ();
					return false;
				});
				source.attach (MainContext.get_thread_default ());
			}
		}

		private async void read_loop () {
			var input = stream.get_input_stream ();
			var buffer = new uint8[64 * 1024];

			while (true) {
				ssize_t n;
				try {
					n = yield input.read_async (buffer, Priority.DEFAULT, io_cancellable);
				} catch (GLib.Error e) {
					break;
				}

				output (buffer[:n]);
			}

			stream.close_async.begin ();
		}

		private async void process_write_queue () {
			var output = stream.get_output_stream ();

			while (write_queue.len > 0) {
				uint8[] batch = write_queue.steal ();

				size_t bytes_written;
				try {
					yield output.write_all_async (batch, Priority.DEFAULT, io_cancellable, out bytes_written);
				} catch (GLib.Error e) {
					break;
				}
			}

			writing = false;
		}
	}

	public class ChannelStream : IOStream {
		public Channel channel {
			get;
			construct;
		}

		public override InputStream input_stream {
			get {
				return _input_stream;
			}
		}

		public override OutputStream output_stream {
			get {
				return _output_stream;
			}
		}

		public IOCondition pending_io {
			get {
				lock (state)
					return _pending_io;
			}
		}

		private State state = OPEN;

		private ChannelInputStream _input_stream;
		private ChannelOutputStream _output_stream;

		private IOCondition _pending_io;
		private ByteArray recv_queue = new ByteArray ();
		private ByteArray send_queue = new ByteArray ();

		private Gee.Map<unowned Source, IOCondition> sources = new Gee.HashMap<unowned Source, IOCondition> ();

		private Cancellable io_cancellable = new Cancellable ();

		private MainContext main_context;

		private enum State {
			OPEN,
			CLOSED
		}

		public ChannelStream (Channel channel) {
			Object (channel: channel);
		}

		construct {
			_input_stream = new ChannelInputStream (this);
			_output_stream = new ChannelOutputStream (this);

			_pending_io = IOCondition.OUT;

			main_context = MainContext.ref_thread_default ();

			channel.output.connect (on_output);
		}

		public void abandon () {
			io_cancellable.cancel ();
		}

		public override bool close (GLib.Cancellable? cancellable) throws IOError {
			_close ();
			return true;
		}

		public override async bool close_async (int io_priority, GLib.Cancellable? cancellable) throws IOError {
			_close ();
			return true;
		}

		private void _close () {
			if (main_context.is_owner ()) {
				do_close ();
			} else {
				var source = new IdleSource ();
				source.set_callback (() => {
					do_close ();
					return Source.REMOVE;
				});
				source.attach (main_context);
			}
		}

		private void do_close () {
			if (state == CLOSED)
				return;

			channel.close.begin (null);
		}

		public ssize_t recv (uint8[] buffer) throws IOError {
			ssize_t n;
			lock (state) {
				n = ssize_t.min (recv_queue.len, buffer.length);
				if (n > 0) {
					Memory.copy (buffer, recv_queue.data, n);
					recv_queue.remove_range (0, (uint) n);

					recompute_pending_io_unlocked ();
				} else {
					if (state == OPEN)
						n = -1;
				}

			}

			if (n == -1)
				throw new IOError.WOULD_BLOCK ("Resource temporarily unavailable");

			return n;
		}

		public ssize_t send (uint8[] buffer) {
			lock (state)
				send_queue.append (buffer);

			if (main_context.is_owner ()) {
				process_send_queue ();
			} else {
				var source = new IdleSource ();
				source.set_callback (() => {
					process_send_queue ();
					return Source.REMOVE;
				});
				source.attach (main_context);
			}

			return buffer.length;
		}

		private void process_send_queue () {
			uint8[]? chunk = null;
			lock (state) {
				size_t n = send_queue.len;
				if (n == 0)
					return;
				chunk = send_queue.data[0:n];
				send_queue.remove_range (0, (uint) n);
			}

			channel.input.begin (chunk, io_cancellable);
		}

		public void register_source (Source source, IOCondition condition) {
			lock (state)
				sources[source] = condition;
		}

		public void unregister_source (Source source) {
			lock (state)
				sources.unset (source);
		}

		private void on_output (uint8[] data) {
			lock (state) {
				if (data.length != 0)
					recv_queue.append (data);
				else
					state = CLOSED;
				recompute_pending_io_unlocked ();
			}
		}

		private void recompute_pending_io_unlocked () {
			IOCondition new_io = 0;
			if (recv_queue.len > 0 || state != OPEN)
				new_io |= IN;
			if (state == OPEN)
				new_io |= OUT;
			_pending_io = new_io;

			foreach (var entry in sources.entries) {
				unowned Source source = entry.key;
				IOCondition c = entry.value;
				if ((new_io & c) != 0)
					source.set_ready_time (0);
			}
		}
	}

	private class ChannelInputStream : InputStream, PollableInputStream {
		public weak ChannelStream connection {
			get;
			construct;
		}

		public ChannelInputStream (ChannelStream connection) {
			Object (connection: connection);
		}

		public override bool close (Cancellable? cancellable) throws IOError {
			return true;
		}

		public override async bool close_async (int io_priority, Cancellable? cancellable) throws GLib.IOError {
			return close (cancellable);
		}

		public override ssize_t read (uint8[] buffer, Cancellable? cancellable) throws IOError {
			assert_not_reached ();
		}

		public bool can_poll () {
			return true;
		}

		public bool is_readable () {
			return (connection.pending_io & IOCondition.IN) != 0;
		}

		public PollableSource create_source (Cancellable? cancellable) {
			return new PollableSource.full (this, new ChannelIOSource (connection, IOCondition.IN), cancellable);
		}

		public ssize_t read_nonblocking_fn (uint8[] buffer) throws GLib.Error {
			return connection.recv (buffer);
		}
	}

	private class ChannelOutputStream : OutputStream, PollableOutputStream {
		public weak ChannelStream connection {
			get;
			construct;
		}

		public ChannelOutputStream (ChannelStream connection) {
			Object (connection: connection);
		}

		public override bool close (Cancellable? cancellable) throws IOError {
			return true;
		}

		public override async bool close_async (int io_priority, Cancellable? cancellable) throws GLib.IOError {
			return close (cancellable);
		}

		public override bool flush (GLib.Cancellable? cancellable) throws GLib.Error {
			return true;
		}

		public override async bool flush_async (int io_priority, GLib.Cancellable? cancellable) throws GLib.Error {
			return true;
		}

		public override ssize_t write (uint8[] buffer, Cancellable? cancellable) throws IOError {
			assert_not_reached ();
		}

		public bool can_poll () {
			return true;
		}

		public bool is_writable () {
			return (connection.pending_io & IOCondition.OUT) != 0;
		}

		public PollableSource create_source (Cancellable? cancellable) {
			return new PollableSource.full (this, new ChannelIOSource (connection, IOCondition.OUT), cancellable);
		}

		public ssize_t write_nonblocking_fn (uint8[]? buffer) throws GLib.Error {
			return connection.send (buffer);
		}

		public PollableReturn writev_nonblocking_fn (OutputVector[] vectors, out size_t bytes_written) throws GLib.Error {
			assert_not_reached ();
		}
	}

	private class ChannelIOSource : Source {
		public ChannelStream connection;
		public IOCondition condition;

		public ChannelIOSource (ChannelStream connection, IOCondition condition) {
			this.connection = connection;
			this.condition = condition;

			connection.register_source (this, condition);
		}

		~ChannelIOSource () {
			connection.unregister_source (this);
		}

		protected override bool prepare (out int timeout) {
			timeout = -1;
			return (connection.pending_io & condition) != 0;
		}

		protected override bool check () {
			return (connection.pending_io & condition) != 0;
		}

		protected override bool dispatch (SourceFunc? callback) {
			set_ready_time (-1);

			if (callback == null)
				return Source.REMOVE;

			return callback ();
		}

		protected static bool closure_callback (Closure closure) {
			var return_value = Value (typeof (bool));

			closure.invoke (ref return_value, {});

			return return_value.get_boolean ();
		}
	}
}
