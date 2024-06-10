[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
	public interface NetworkStack : Object {
		public abstract async IOStream open_tcp_connection (string address, uint16 port, Cancellable? cancellable)
			throws Error, IOError;
		public abstract UdpSocket create_udp_socket () throws Error;
	}

	public interface UdpSocket : Object {
		public abstract DatagramBased datagram_based {
			get;
		}

		public abstract SocketAddress get_local_address () throws Error;
		public abstract bool connect (SocketAddress address, Cancellable? cancellable) throws Error;
	}

	public sealed class SystemNetworkStack : Object, NetworkStack {
		public async IOStream open_tcp_connection (string address, uint16 port, Cancellable? cancellable) throws Error, IOError {
		}

		public UdpSocket create_udp_socket () throws Error {
			var handle = new Socket (IPV6, DATAGRAM, UDP);
			return new SystemUdpSocket (handle);
		}

		private class SystemUdpSocket : Object, UdpSocket {
			public Socket handle {
				get;
				construct;
			}

			public DatagramBased datagram_based {
				get {
					return handle;
				}
			}

			public SystemUdpSocket (Socket handle) {
				Object (handle: handle);
			}

			public SocketAddress get_local_address () throws Error {
				return handle.get_local_address ();
			}

			public bool connect (SocketAddress address, Cancellable? cancellable) throws Error {
				return handle.connect (address, cancellable);
			}
		}
	}

	public sealed class VirtualNetworkStack : Object, NetworkStack {
		public signal void outgoing_datagram (Bytes datagram);

		public Bytes? ethernet_address {
			get;
			construct;
		}

		public string ipv6_address {
			get;
			construct;
		}

		public uint16 mtu {
			get;
			construct;
		}

		private bool netif_added = false;
		private LWIP.NetworkInterface handle;
		private Gee.Queue<Bytes> incoming_datagrams = new Gee.ArrayQueue<Bytes> ();

		private MainContext main_context;

		public class VirtualNetworkStack (Bytes? ethernet_address, string ipv6_address, uint16 mtu) {
			Object (
				ethernet_address: ethernet_address,
				ipv6_address: ipv6_address,
				mtu: mtu
			);
		}

		static construct {
			LWIP.Runtime.init (() => {});
		}

		construct {
			main_context = MainContext.ref_thread_default ();

			LWIP.Runtime.schedule (start);
			netif_added = true;
		}

		public override void dispose () {
			stop ();

			base.dispose ();
		}

		public async IOStream open_tcp_connection (string address, uint16 port, Cancellable? cancellable = null)
				throws Error, IOError {
			return yield TcpConnection.open (this, address, port, cancellable);
		}

		public void handle_incoming_datagram (Bytes datagram) {
			if (!netif_added)
				return;
			lock (incoming_datagrams)
				incoming_datagrams.offer (datagram);
			LWIP.Runtime.schedule (process_next_incoming_datagram);
		}

		private void start () {
			LWIP.NetworkInterface.add_noaddr (ref handle, this, on_netif_init);
			handle.set_up ();
		}

		private static LWIP.ErrorCode on_netif_init (LWIP.NetworkInterface handle) {
			VirtualNetworkStack * self = handle.state;
			self->configure_netif (ref handle);
			return OK;
		}

		private void configure_netif (ref LWIP.NetworkInterface handle) {
			if (ethernet_address != null) {
				handle.output_ip6 = LWIP.Ethernet.IPv6.output;
				handle.linkoutput = on_netif_link_output;
			} else {
				handle.output_ip6 = on_netif_output_ip6;
			}

			handle.mtu = mtu;

			if (ethernet_address != null) {
				assert (ethernet_address.length == LWIP.Ethernet.HWADDR_LEN);
				Memory.copy (&handle.hwaddr, ethernet_address.get_data (), LWIP.Ethernet.HWADDR_LEN);
				handle.hwaddr_len = LWIP.Ethernet.HWADDR_LEN;
			}

			handle.flags = BROADCAST | ETHARP;

			int8 chosen_index = -1;
			handle.add_ip6_address (LWIP.IP6Address.parse (ipv6_address), &chosen_index);
			handle.ip6_addr_set_state (chosen_index, PREFERRED);
		}

		private static LWIP.ErrorCode on_netif_link_output (LWIP.NetworkInterface handle, LWIP.PacketBuffer pbuf) {
			VirtualNetworkStack * self = handle.state;
			self->emit_datagram (pbuf);
			return OK;
		}

		private static LWIP.ErrorCode on_netif_output_ip6 (LWIP.NetworkInterface handle, LWIP.PacketBuffer pbuf,
				LWIP.IP6Address address) {
			VirtualNetworkStack * self = handle.state;
			self->emit_datagram (pbuf);
			return OK;
		}

		private void emit_datagram (LWIP.PacketBuffer pbuf) {
			var buffer = new uint8[pbuf.tot_len];
			unowned uint8[] packet = pbuf.get_contiguous (buffer, pbuf.tot_len);
			var datagram = new Bytes (packet[:pbuf.tot_len]);

			var source = new IdleSource ();
			source.set_callback (() => {
				outgoing_datagram (datagram);
				return Source.REMOVE;
			});
			source.attach (main_context);
		}

		private void process_next_incoming_datagram () {
			Bytes datagram;
			lock (incoming_datagrams)
				datagram = incoming_datagrams.poll ();

			var pbuf = LWIP.PacketBuffer.alloc (RAW, (uint16) datagram.get_size (), POOL);
			pbuf.take (datagram.get_data ());

			if (handle.input (pbuf, handle) == OK)
				*((void **) &pbuf) = null;
		}

		public void stop () {
			if (!netif_added)
				return;
			netif_added = false;

			ref ();
			LWIP.Runtime.schedule (do_stop);
		}

		private void do_stop () {
			handle.remove ();

			unref ();
		}

		private class TcpConnection : IOStream, AsyncInitable {
			public VirtualNetworkStack stack {
				get;
				construct;
			}

			public string address {
				get;
				construct;
			}

			public uint16 port {
				get;
				construct;
			}

			public State state {
				get {
					return _state;
				}
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

			private Promise<bool> established = new Promise<bool> ();

			private State _state = CREATED;
			private TcpInputStream _input_stream;
			private TcpOutputStream _output_stream;

			private unowned LWIP.TcpPcb? pcb;
			private IOCondition events = 0;
			private ByteArray rx_buf = new ByteArray.sized (64 * 1024);
			private ByteArray tx_buf = new ByteArray.sized (64 * 1024);
			private size_t rx_bytes_to_acknowledge = 0;
			private size_t tx_space_available = 0;

			private Gee.Map<unowned Source, IOCondition> sources = new Gee.HashMap<unowned Source, IOCondition> ();

			private MainContext main_context;

			public enum State {
				CREATED,
				OPENING,
				OPENED,
				CLOSED
			}

			public static async TcpConnection open (VirtualNetworkStack stack, string address, uint16 port,
					Cancellable? cancellable) throws Error, IOError {
				var connection = new TcpConnection (stack, address, port);

				try {
					yield connection.init_async (Priority.DEFAULT, cancellable);
				} catch (GLib.Error e) {
					throw_api_error (e);
				}

				return connection;
			}

			private TcpConnection (VirtualNetworkStack stack, string address, uint16 port) {
				Object (
					stack: stack,
					address: address,
					port: port
				);
			}

			construct {
				_input_stream = new TcpInputStream (this);
				_output_stream = new TcpOutputStream (this);

				main_context = MainContext.ref_thread_default ();
			}

			public override void dispose () {
				stop ();

				base.dispose ();
			}

			private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
				_state = OPENING;
				LWIP.Runtime.schedule (do_start);

				try {
					yield established.future.wait_async (cancellable);
				} catch (GLib.Error e) {
					stop ();
					throw_api_error (e);
				}

				return true;
			}

			private void do_start () {
				pcb = LWIP.TcpPcb.make (V6);
				pcb.set_user_data (this);
				pcb.set_recv_callback ((user_data, pcb, pbuf, err) => {
					TcpConnection * self = user_data;
					if (self != null)
						self->on_recv ((owned) pbuf, err);
					return OK;
				});
				pcb.set_sent_callback ((user_data, pcb, len) => {
					TcpConnection * self = user_data;
					if (self != null)
						self->on_sent (len);
					return OK;
				});
				pcb.set_error_callback ((user_data, err) => {
					TcpConnection * self = user_data;
					if (self != null)
						self->on_error (err);
				});
				pcb.nagle_disable ();
				pcb.bind_netif (stack.handle);

				pcb.connect (LWIP.IP6Address.parse (address), port, (user_data, pcb, err) => {
					TcpConnection * self = user_data;
					if (self != null)
						self->on_connect ();
					return OK;
				});
			}

			private void stop () {
				if (_state == CLOSED)
					return;

				if (state != CREATED) {
					ref ();
					LWIP.Runtime.schedule (do_stop);
				}

				_state = CLOSED;
			}

			private void do_stop () {
				if (pcb != null) {
					pcb.set_user_data (null);
					if (pcb.close () != OK)
						pcb.abort ();
					pcb = null;
				}

				unref ();
			}

			private void on_connect () {
				lock (state)
					tx_space_available = pcb.query_available_send_buffer_space ();
				update_events ();

				schedule_on_frida_thread (() => {
					_state = OPENED;

					if (!established.future.ready)
						established.resolve (true);

					return Source.REMOVE;
				});
			}

			private void on_recv (owned LWIP.PacketBuffer? pbuf, LWIP.ErrorCode err) {
				if (pbuf == null) {
					schedule_on_frida_thread (() => {
						_state = CLOSED;
						update_events ();
						return Source.REMOVE;
					});
					return;
				}

				var buffer = new uint8[pbuf.tot_len];
				unowned uint8[] chunk = pbuf.get_contiguous (buffer, pbuf.tot_len);
				lock (state)
					rx_buf.append (chunk[:pbuf.tot_len]);
				update_events ();
			}

			private void on_sent (uint16 len) {
				lock (state)
					tx_space_available = pcb.query_available_send_buffer_space () - tx_buf.len;
				update_events ();
			}

			private void on_error (LWIP.ErrorCode err) {
				schedule_on_frida_thread (() => {
					_state = CLOSED;
					update_events ();

					if (!established.future.ready)
						established.reject (new Error.TRANSPORT ("%s", strerror (err.to_errno ())));

					return Source.REMOVE;
				});
			}

			public override bool close (GLib.Cancellable? cancellable) throws IOError {
				stop ();
				return true;
			}

			public override async bool close_async (int io_priority, GLib.Cancellable? cancellable) throws IOError {
				stop ();
				return true;
			}

			public void shutdown_rx () throws IOError {
				LWIP.Runtime.schedule (do_shutdown_rx);
			}

			private void do_shutdown_rx () {
				if (pcb == null)
					return;
				pcb.shutdown (true, false);
			}

			public void shutdown_tx () throws IOError {
				LWIP.Runtime.schedule (do_shutdown_tx);
			}

			private void do_shutdown_tx () {
				if (pcb == null)
					return;
				pcb.shutdown (false, true);
			}

			public ssize_t recv (uint8[] buffer) throws IOError {
				ssize_t n;
				lock (state) {
					n = ssize_t.min (buffer.length, rx_buf.len);
					if (n != 0) {
						Memory.copy (buffer, rx_buf.data, n);
						rx_buf.remove_range (0, (uint) n);
						rx_bytes_to_acknowledge += n;
					}
				}
				if (n == 0) {
					if (_state == CLOSED)
						return 0;
					throw new IOError.WOULD_BLOCK ("Resource temporarily unavailable");
				}

				update_events ();

				LWIP.Runtime.schedule (do_acknowledge_rx_bytes);

				return n;
			}

			private void do_acknowledge_rx_bytes () {
				if (pcb == null)
					return;

				size_t n;
				lock (state) {
					n = rx_bytes_to_acknowledge;
					rx_bytes_to_acknowledge = 0;
				}

				size_t remainder = n;
				while (remainder != 0) {
					uint16 chunk = (uint16) size_t.min (remainder, uint16.MAX);
					pcb.notify_received (chunk);
					remainder -= chunk;
				}
			}

			public ssize_t send (uint8[] buffer) throws IOError {
				ssize_t n;
				lock (state) {
					n = ssize_t.min (buffer.length, (ssize_t) tx_space_available);
					if (n != 0) {
						tx_buf.append (buffer[:n]);
						tx_space_available -= n;
					}
				}
				if (n == 0)
					throw new IOError.WOULD_BLOCK ("Resource temporarily unavailable");

				update_events ();

				LWIP.Runtime.schedule (do_send);

				return n;
			}

			private void do_send () {
				if (pcb == null)
					return;

				size_t available_space = pcb.query_available_send_buffer_space ();

				uint8[]? data = null;
				lock (state) {
					size_t n = size_t.min (tx_buf.len, available_space);
					if (n != 0) {
						data = tx_buf.data[:n];
						tx_buf.remove_range (0, (uint) n);
					}
				}
				if (data == null)
					return;

				pcb.write (data, COPY);
				pcb.output ();

				available_space = pcb.query_available_send_buffer_space ();
				lock (state)
					tx_space_available = available_space - tx_buf.len;
				update_events ();
			}

			public void register_source (Source source, IOCondition condition) {
				lock (state)
					sources[source] = condition | IOCondition.ERR | IOCondition.HUP;
			}

			public void unregister_source (Source source) {
				lock (state)
					sources.unset (source);
			}

			private void update_events () {
				lock (state) {
					IOCondition new_events = 0;

					if (rx_buf.len != 0 || _state == CLOSED)
						new_events |= IN;

					if (tx_space_available != 0)
						new_events |= OUT;

					events = new_events;

					foreach (var entry in sources.entries) {
						unowned Source source = entry.key;
						IOCondition c = entry.value;
						if ((new_events & c) != 0)
							source.set_ready_time (0);
					}
				}

				notify_property ("pending-io");
			}

			private void schedule_on_frida_thread (owned SourceFunc function) {
				var source = new IdleSource ();
				source.set_callback ((owned) function);
				source.attach (main_context);
			}
		}

		private class TcpInputStream : InputStream, PollableInputStream {
			public weak TcpConnection connection {
				get;
				construct;
			}

			public TcpInputStream (TcpConnection connection) {
				Object (connection: connection);
			}

			public override bool close (Cancellable? cancellable) throws IOError {
				connection.shutdown_rx ();
				return true;
			}

			public override async bool close_async (int io_priority, Cancellable? cancellable) throws GLib.IOError {
				return close (cancellable);
			}

			public override ssize_t read (uint8[] buffer, Cancellable? cancellable) throws IOError {
				if (!is_readable ()) {
					bool done = false;
					var mutex = Mutex ();
					var cond = Cond ();

					ulong io_handler = connection.notify["pending-io"].connect ((obj, pspec) => {
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

					mutex.lock ();
					while (!done)
						cond.wait (mutex);
					mutex.unlock ();

					if (cancellation_handler != 0)
						cancellable.disconnect (cancellation_handler);
					connection.disconnect (io_handler);

					cancellable.set_error_if_cancelled ();
				}

				return connection.recv (buffer);
			}

			public bool can_poll () {
				return true;
			}

			public bool is_readable () {
				return (connection.pending_io & IOCondition.IN) != 0;
			}

			public PollableSource create_source (Cancellable? cancellable) {
				return new PollableSource.full (this, new TcpIOSource (connection, IOCondition.IN), cancellable);
			}

			public ssize_t read_nonblocking_fn (uint8[] buffer) throws GLib.Error {
				return connection.recv (buffer);
			}
		}

		private class TcpOutputStream : OutputStream, PollableOutputStream {
			public weak TcpConnection connection {
				get;
				construct;
			}

			public TcpOutputStream (TcpConnection connection) {
				Object (connection: connection);
			}

			public override bool close (Cancellable? cancellable) throws IOError {
				connection.shutdown_tx ();
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
				return new PollableSource.full (this, new TcpIOSource (connection, IOCondition.OUT), cancellable);
			}

			public ssize_t write_nonblocking_fn (uint8[]? buffer) throws GLib.Error {
				return connection.send (buffer);
			}

			public PollableReturn writev_nonblocking_fn (OutputVector[] vectors, out size_t bytes_written) throws GLib.Error {
				assert_not_reached ();
			}
		}

		private class TcpIOSource : Source {
			public TcpConnection connection;
			public IOCondition condition;

			public TcpIOSource (TcpConnection connection, IOCondition condition) {
				this.connection = connection;
				this.condition = condition;

				connection.register_source (this, condition);
			}

			~TcpIOSource () {
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
}
