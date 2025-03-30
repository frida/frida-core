namespace Frida {
	public class ChannelRegistry : Object {
		public signal void channel_closed (ChannelId id);

		private Gee.Map<ChannelId?, weak IOStream> channels =
			new Gee.HashMap<ChannelId?, weak IOStream> (ChannelId.hash, ChannelId.equal);

		~ChannelRegistry () {
			clear ();
		}

		public void clear () {
			foreach (IOStream stream in channels.values.to_array ()) {
				var channel_stream = stream as ChannelStream;
				if (channel_stream != null)
					channel_stream.abandon ();
			}
			channels.clear ();
		}

		public void register (ChannelId id, IOStream stream) {
			stream.set_data ("channel-registry-entry", new Entry (this, id));
			lock (channels)
				channels[id] = stream;
		}

		public IOStream link (ChannelId id) throws Error {
			IOStream? stream;
			lock (channels)
				stream = channels[id];
			if (stream == null)
				throw new Error.INVALID_ARGUMENT ("Invalid channel ID");
			return stream;
		}

		public void unlink (ChannelId id) {
			lock (channels) {
				if (!channels.unset (id))
					return;
			}

			channel_closed (id);
		}

		private class Entry {
			public ChannelRegistry parent;
			public ChannelId id;

			public Entry (ChannelRegistry parent, ChannelId id) {
				this.parent = parent;
				this.id = id;
			}

			~Entry () {
				parent.unlink (id);
			}
		}
	}

	public class ChannelEndpoint : Object, Channel {
		private IOStream? stream;

		private ByteArray write_queue = new ByteArray ();
		private bool writing = false;

		private Cancellable io_cancellable = new Cancellable ();

		public ChannelEndpoint (IOStream stream) {
			this.stream = stream;

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
			stream = null;
		}

		private async void process_write_queue () {
			if (stream != null) {
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
					return events;
			}
		}

		private State state = OPEN;

		private ChannelInputStream _input_stream;
		private ChannelOutputStream _output_stream;

		private IOCondition events = OUT;
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

			main_context = MainContext.ref_thread_default ();

			channel.output.connect (on_output);
		}

		public override void dispose () {
			_output_stream.detach ();
			_input_stream.detach ();

			io_cancellable.cancel ();

			base.dispose ();
		}

		public void abandon () {
			lock (state) {
				state = CLOSED;
				update_events ();
			}
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

					update_events ();
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
				update_events ();
			}
		}

		private void update_events () {
			IOCondition new_events = 0;

			if (recv_queue.len != 0 || state == CLOSED)
				new_events |= IN;

			if (state == OPEN)
				new_events |= OUT;

			events = new_events;

			foreach (var entry in sources.entries) {
				unowned Source source = entry.key;
				IOCondition c = entry.value;
				if ((new_events & c) != 0)
					source.set_ready_time (0);
			}

			notify_property ("pending-io");
		}
	}

	private class ChannelInputStream : InputStream, PollableInputStream {
		private weak ChannelStream channel;

		public ChannelInputStream (ChannelStream channel) {
			Object ();
			this.channel = channel;
		}

		internal void detach () {
			channel = null;
		}

		public override bool close (Cancellable? cancellable) throws IOError {
			return true;
		}

		public override async bool close_async (int io_priority, Cancellable? cancellable) throws GLib.IOError {
			return close (cancellable);
		}

		public override ssize_t read (uint8[] buffer, Cancellable? cancellable) throws IOError {
			if (channel == null)
				return 0;

			if (!is_readable ()) {
				bool done = false;
				var mutex = Mutex ();
				var cond = Cond ();

				ulong io_handler = channel.notify["pending-io"].connect ((obj, pspec) => {
					if (is_readable ()) {
						mutex.lock ();
						done = true;
						cond.signal ();
						mutex.unlock ();
					}
				});
				ulong cancellation_handler = 0;
				if (cancellable != null) {
					cancellation_handler = cancellable.connect (() => {
						mutex.lock ();
						done = true;
						cond.signal ();
						mutex.unlock ();
					});
				}

				if (!is_readable ()) {
					mutex.lock ();
					while (!done)
						cond.wait (mutex);
					mutex.unlock ();
				}

				if (cancellation_handler != 0)
					cancellable.disconnect (cancellation_handler);
				channel.disconnect (io_handler);

				cancellable.set_error_if_cancelled ();
			}

			return channel.recv (buffer);
		}

		public bool can_poll () {
			return true;
		}

		public bool is_readable () {
			if (channel == null)
				return true;
			return (channel.pending_io & IOCondition.IN) != 0;
		}

		public PollableSource create_source (Cancellable? cancellable) {
			return new PollableSource.full (this, new ChannelIOSource (channel, IOCondition.IN), cancellable);
		}

		public ssize_t read_nonblocking_fn (uint8[] buffer) throws GLib.Error {
			if (channel == null)
				return 0;
			return channel.recv (buffer);
		}
	}

	private class ChannelOutputStream : OutputStream, PollableOutputStream {
		private weak ChannelStream? channel;

		public ChannelOutputStream (ChannelStream channel) {
			Object ();
			this.channel = channel;
		}

		internal void detach () {
			channel = null;
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
			return channel.send (buffer);
		}

		public bool can_poll () {
			return true;
		}

		public bool is_writable () {
			if (channel == null)
				return false;
			return (channel.pending_io & IOCondition.OUT) != 0;
		}

		public PollableSource create_source (Cancellable? cancellable) {
			return new PollableSource.full (this, new ChannelIOSource (channel, IOCondition.OUT), cancellable);
		}

		public ssize_t write_nonblocking_fn (uint8[]? buffer) throws GLib.Error {
			if (channel == null)
				throw new IOError.CLOSED ("Channel is closed");
			return channel.send (buffer);
		}

		public PollableReturn writev_nonblocking_fn (OutputVector[] vectors, out size_t bytes_written) throws GLib.Error {
			assert_not_reached ();
		}
	}

	private class ChannelIOSource : Source {
		public ChannelStream channel;
		public IOCondition condition;

		public ChannelIOSource (ChannelStream channel, IOCondition condition) {
			this.channel = channel;
			this.condition = condition;

			channel.register_source (this, condition);
		}

		~ChannelIOSource () {
			channel.unregister_source (this);
		}

		protected override bool prepare (out int timeout) {
			timeout = -1;
			return (channel.pending_io & condition) != 0;
		}

		protected override bool check () {
			return (channel.pending_io & condition) != 0;
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
