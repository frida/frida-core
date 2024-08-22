[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
	public interface NetworkStack : Object {
		public abstract InetAddress listener_ip {
			get;
		}

		public abstract uint scope_id {
			get;
		}

		public abstract async IOStream open_tcp_connection (InetSocketAddress address, Cancellable? cancellable)
			throws Error, IOError;
		public abstract UdpSocket create_udp_socket () throws Error;
	}

	public interface UdpSocket : Object {
		public abstract DatagramBased datagram_based {
			get;
		}

		public abstract void bind (InetSocketAddress address) throws Error;
		public abstract InetSocketAddress get_local_address () throws Error;
		public abstract void socket_connect (InetSocketAddress address, Cancellable? cancellable) throws Error;
	}

	public sealed class SystemNetworkStack : Object, NetworkStack {
		public InetAddress listener_ip {
			get {
				return _listener_ip;
			}
		}

		public uint scope_id {
			get {
				return _scope_id;
			}
		}

		private InetAddress _listener_ip;
		private uint _scope_id;

		public SystemNetworkStack (InetAddress listener_ip, uint scope_id) {
			_listener_ip = listener_ip;
			_scope_id = scope_id;
		}

		public async IOStream open_tcp_connection (InetSocketAddress address, Cancellable? cancellable) throws Error, IOError {
			SocketConnection connection;
			try {
				var client = new SocketClient ();
				connection = yield client.connect_async (address, cancellable);
			} catch (GLib.Error e) {
				if (e is IOError.CONNECTION_REFUSED)
					throw new Error.SERVER_NOT_RUNNING ("%s", e.message);
				throw new Error.TRANSPORT ("%s", e.message);
			}

			Tcp.enable_nodelay (connection.socket);

			return connection;
		}

		public UdpSocket create_udp_socket () throws Error {
			try {
				var handle = new Socket (IPV6, DATAGRAM, UDP);
				return new SystemUdpSocket (handle);
			} catch (GLib.Error e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
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

			public void bind (InetSocketAddress address) throws Error {
				try {
					handle.bind (address, true);
				} catch (GLib.Error e) {
					throw new Error.NOT_SUPPORTED ("%s", e.message);
				}
			}

			public InetSocketAddress get_local_address () throws Error {
				try {
					return (InetSocketAddress) handle.get_local_address ();
				} catch (GLib.Error e) {
					throw new Error.NOT_SUPPORTED ("%s", e.message);
				}
			}

			public void socket_connect (InetSocketAddress address, Cancellable? cancellable) throws Error {
				try {
					handle.connect (address, cancellable);
				} catch (GLib.Error e) {
					throw new Error.TRANSPORT ("%s", e.message);
				}
			}
		}
	}

	public sealed class VirtualNetworkStack : Object, NetworkStack {
		public signal void outgoing_datagram (Bytes datagram);

		public Bytes? ethernet_address {
			get;
			construct;
		}

		public InetAddress? ipv6_address {
			get;
			construct;
		}

		public InetAddress listener_ip {
			get {
				if (_cached_listener_ip == null)
					_cached_listener_ip = ip6_address_to_inet_address (raw_ipv6_address);
				return _cached_listener_ip;
			}
		}

		public uint scope_id {
			get {
				return raw_ipv6_address.zone;
			}
		}

		public uint16 mtu {
			get;
			construct;
		}

		private State state = STARTED;

		private Gee.Queue<Request> requests = new Gee.ArrayQueue<Request> ();
		private unowned Thread<bool>? lwip_thread;

		private LWIP.NetworkInterface handle;
		private LWIP.IP6Address raw_ipv6_address;
		private InetAddress? _cached_listener_ip;

		private MainContext main_context;

		private enum State {
			STARTED,
			STOPPED
		}

		public class VirtualNetworkStack (Bytes? ethernet_address, InetAddress? ipv6_address, uint16 mtu) {
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

			perform_on_lwip_thread (() => {
				LWIP.NetworkInterface.add_noaddr (ref handle, this, on_netif_init);
				handle.set_link_up ();
				handle.set_up ();
				return OK;
			});
			state = STARTED;
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
			handle.flags = BROADCAST;

			if (ethernet_address != null) {
				assert (ethernet_address.length == LWIP.Ethernet.HWADDR_LEN);
				Memory.copy (&handle.hwaddr, ethernet_address.get_data (), LWIP.Ethernet.HWADDR_LEN);
				handle.hwaddr_len = LWIP.Ethernet.HWADDR_LEN;

				handle.flags |= ETHARP;
			}

			int8 chosen_index = 0;
			if (ipv6_address != null)
				handle.add_ip6_address (ip6_address_from_inet_address (ipv6_address), &chosen_index);
			else
				handle.create_ip6_linklocal_address (true);
			handle.ip6_addr_set_state (chosen_index, PREFERRED); // No need for conflict detection.
			raw_ipv6_address = handle.ip6_addr[chosen_index];
		}

		public override void dispose () {
			stop ();

			base.dispose ();
		}

		public void stop () {
			if (state == STOPPED)
				return;
			perform_on_lwip_thread (() => {
				handle.remove ();
				return OK;
			});
			state = STOPPED;
		}

		public async IOStream open_tcp_connection (InetSocketAddress address, Cancellable? cancellable = null)
				throws Error, IOError {
			check_started ();
			return yield TcpConnection.open (this, address, cancellable);
		}

		public UdpSocket create_udp_socket () throws Error {
			check_started ();
			return new Ipv6UdpSocket (this);
		}

		public void handle_incoming_datagram (Bytes datagram) throws Error {
			check_started ();

			check (perform_on_lwip_thread (() => {
				var pbuf = LWIP.PacketBuffer.alloc (RAW, (uint16) datagram.get_size (), POOL);
				pbuf.take (datagram.get_data ());

				var err = handle.input (pbuf, ref handle);
				if (err == OK)
					*((void **) &pbuf) = null;

				return err;
			}));
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

			schedule_on_frida_thread (() => {
				if (state == STARTED)
					outgoing_datagram (datagram);
				return Source.REMOVE;
			});
		}

		internal LWIP.ErrorCode perform_on_lwip_thread (owned WorkFunc work) {
			var req = new Request ((owned) work);

			lock (requests)
				requests.offer (req);

			if (Thread.self<bool> () != lwip_thread)
				LWIP.Runtime.schedule (perform_next_request);
			else
				perform_next_request ();

			return req.join ();
		}

		private void perform_next_request () {
			if (lwip_thread == null)
				lwip_thread = Thread.self ();

			Request req;
			lock (requests)
				req = requests.poll ();

			LWIP.ErrorCode err = req.work ();
			req.complete (err);
		}

		private void check_started () throws Error {
			if (state != STARTED)
				throw new Error.INVALID_OPERATION ("Networking stack has been stopped");
		}

		internal delegate LWIP.ErrorCode WorkFunc ();

		private class Request {
			public WorkFunc work;

			private bool completed = false;
			private LWIP.ErrorCode error;
			private Mutex mutex = Mutex ();
			private Cond cond = Cond ();

			public Request (owned WorkFunc work) {
				this.work = (owned) work;
			}

			public LWIP.ErrorCode join () {
				mutex.lock ();
				while (!completed)
					cond.wait (mutex);
				var err = error;
				mutex.unlock ();
				return err;
			}

			public void complete (LWIP.ErrorCode err) {
				mutex.lock ();
				completed = true;
				error = err;
				cond.signal ();
				mutex.unlock ();
			}
		}

		private void schedule_on_frida_thread (owned SourceFunc function) {
			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (main_context);
		}

		private class TcpConnection : IOStream, AsyncInitable {
			public VirtualNetworkStack netstack {
				get;
				construct;
			}

			public InetSocketAddress address {
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

			private State _state = OPENING;
			private TcpInputStream _input_stream;
			private TcpOutputStream _output_stream;

			private unowned LWIP.TcpPcb? pcb;
			private IOCondition events = 0;
			private ByteArray rx_buf = new ByteArray.sized (64 * 1024);
			private ByteArray tx_buf = new ByteArray.sized (64 * 1024);
			private size_t tx_space_available = 0;

			private Gee.Map<unowned Source, IOCondition> sources = new Gee.HashMap<unowned Source, IOCondition> ();

			private MainContext main_context;

			public enum State {
				OPENING,
				OPENED,
				CLOSED
			}

			public static async TcpConnection open (VirtualNetworkStack netstack, InetSocketAddress address,
					Cancellable? cancellable) throws Error, IOError {
				var connection = new TcpConnection (netstack, address);

				try {
					yield connection.init_async (Priority.DEFAULT, cancellable);
				} catch (GLib.Error e) {
					throw_api_error (e);
				}

				return connection;
			}

			private TcpConnection (VirtualNetworkStack netstack, InetSocketAddress address) {
				Object (netstack: netstack, address: address);
			}

			construct {
				_input_stream = new TcpInputStream (this);
				_output_stream = new TcpOutputStream (this);

				main_context = MainContext.ref_thread_default ();
			}

			public override void dispose () {
				_output_stream.detach ();
				_input_stream.detach ();

				stop ();

				base.dispose ();
			}

			private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
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
				pcb.bind_netif (&netstack.handle);

				var err = pcb.connect (ip6_address_from_inet_socket_address (address), address.get_port (), (user_data, pcb, err) => {
					TcpConnection * self = user_data;
					if (self != null)
						self->on_connect ();
					return OK;
				});
				if (err != OK) {
					schedule_on_frida_thread (() => {
						established.reject (parse_error (err));
						return Source.REMOVE;
					});
				}
			}

			private void stop () {
				netstack.perform_on_lwip_thread (() => {
					if (pcb == null)
						return OK;
					pcb.set_user_data (null);
					if (pcb.close () != OK)
						pcb.abort ();
					pcb = null;
					return OK;
				});
			}

			private void detach_from_pcb () {
				pcb.set_user_data (null);
				pcb = null;
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
					detach_from_pcb ();
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
				detach_from_pcb ();
				schedule_on_frida_thread (() => {
					_state = CLOSED;
					update_events ();

					if (!established.future.ready) {
						established.reject (parse_error (err));
					}

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
				check_io (netstack.perform_on_lwip_thread (() => {
					if (pcb == null)
						return OK;
					return pcb.shutdown (true, false);
				}));
			}

			public void shutdown_tx () throws IOError {
				check_io (netstack.perform_on_lwip_thread (() => {
					if (pcb == null)
						return OK;
					return pcb.shutdown (false, true);
				}));
			}

			public ssize_t recv (uint8[] buffer) throws IOError {
				ssize_t n = 0;

				netstack.perform_on_lwip_thread (() => {
					if (pcb == null)
						return OK;

					lock (state) {
						n = ssize_t.min (buffer.length, rx_buf.len);
						if (n == 0)
							return OK;
						Memory.copy (buffer, rx_buf.data, n);
						rx_buf.remove_range (0, (uint) n);
					}

					size_t remainder = n;
					while (remainder != 0) {
						uint16 chunk = (uint16) size_t.min (remainder, uint16.MAX);
						pcb.notify_received (chunk);
						remainder -= chunk;
					}

					return OK;
				});

				if (n == 0) {
					if (_state == CLOSED)
						return 0;
					throw new IOError.WOULD_BLOCK ("Resource temporarily unavailable");
				}

				update_events ();

				return n;
			}

			public ssize_t send (uint8[] buffer) throws IOError {
				ssize_t n = 0;

				netstack.perform_on_lwip_thread (() => {
					if (pcb == null)
						return OK;

					lock (state) {
						n = ssize_t.min (buffer.length, (ssize_t) tx_space_available);
						if (n == 0)
							return OK;
						tx_buf.append (buffer[:n]);
						tx_space_available -= n;
					}

					size_t available_space = pcb.query_available_send_buffer_space ();

					uint8[]? data = null;
					lock (state) {
						size_t num_bytes_to_write = size_t.min (tx_buf.len, available_space);
						if (num_bytes_to_write != 0) {
							data = tx_buf.data[:num_bytes_to_write];
							tx_buf.remove_range (0, (uint) num_bytes_to_write);
						}
					}
					if (data == null)
						return OK;

					pcb.write (data, COPY);
					pcb.output ();

					available_space = pcb.query_available_send_buffer_space ();
					lock (state)
						tx_space_available = available_space - tx_buf.len;

					return OK;
				});

				if (n == 0)
					throw new IOError.WOULD_BLOCK ("Resource temporarily unavailable");

				update_events ();

				return n;
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
			private weak TcpConnection connection;

			public TcpInputStream (TcpConnection connection) {
				Object ();
				this.connection = connection;
			}

			internal void detach () {
				connection = null;
			}

			public override bool close (Cancellable? cancellable) throws IOError {
				if (connection != null)
					connection.shutdown_rx ();
				return true;
			}

			public override async bool close_async (int io_priority, Cancellable? cancellable) throws GLib.IOError {
				return close (cancellable);
			}

			public override ssize_t read (uint8[] buffer, Cancellable? cancellable) throws IOError {
				if (connection == null)
					return 0;

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
				if (connection == null)
					return true;
				return (connection.pending_io & IOCondition.IN) != 0;
			}

			public PollableSource create_source (Cancellable? cancellable) {
				return new PollableSource.full (this, new TcpIOSource (connection, IOCondition.IN), cancellable);
			}

			public ssize_t read_nonblocking_fn (uint8[] buffer) throws GLib.Error {
				if (connection == null)
					return 0;
				return connection.recv (buffer);
			}
		}

		private class TcpOutputStream : OutputStream, PollableOutputStream {
			private weak TcpConnection? connection;

			public TcpOutputStream (TcpConnection connection) {
				Object ();
				this.connection = connection;
			}

			internal void detach () {
				connection = null;
			}

			public override bool close (Cancellable? cancellable) throws IOError {
				if (connection != null)
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
				if (connection == null)
					return false;
				return (connection.pending_io & IOCondition.OUT) != 0;
			}

			public PollableSource create_source (Cancellable? cancellable) {
				return new PollableSource.full (this, new TcpIOSource (connection, IOCondition.OUT), cancellable);
			}

			public ssize_t write_nonblocking_fn (uint8[]? buffer) throws GLib.Error {
				if (connection == null)
					throw new IOError.CLOSED ("Connection is closed");
				return connection.send (buffer);
			}

			public PollableReturn writev_nonblocking_fn (OutputVector[] vectors, out size_t bytes_written) throws GLib.Error {
				assert_not_reached ();
			}
		}

		private class TcpIOSource : Source {
			public TcpConnection connection;
			public IOCondition condition;

			public TcpIOSource (TcpConnection? connection, IOCondition condition) {
				this.connection = connection;
				this.condition = condition;

				if (connection != null)
					connection.register_source (this, condition);
			}

			~TcpIOSource () {
				if (connection != null)
					connection.unregister_source (this);
			}

			protected override bool prepare (out int timeout) {
				timeout = -1;
				return is_ready ();
			}

			protected override bool check () {
				return is_ready ();
			}

			private bool is_ready () {
				IOCondition pending_io = (connection != null) ? connection.pending_io : IOCondition.IN;
				return (pending_io & condition) != 0;
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

		private class Ipv6UdpSocket : Object, UdpSocket, DatagramBased {
			public VirtualNetworkStack netstack {
				get;
				construct;
			}

			public DatagramBased datagram_based {
				get {
					return this;
				}
			}

			public IOCondition pending_io {
				get {
					lock (events)
						return events;
				}
			}

			private unowned LWIP.UdpPcb? pcb;
			private IOCondition events = OUT;
			private Gee.Queue<Packet> rx_queue = new Gee.ArrayQueue<Packet> ();

			private Gee.Map<unowned Source, IOCondition> sources = new Gee.HashMap<unowned Source, IOCondition> ();

			public Ipv6UdpSocket (VirtualNetworkStack netstack) {
				Object (netstack: netstack);
			}

			construct {
				netstack.perform_on_lwip_thread (() => {
					pcb = LWIP.UdpPcb.make (V6);
					pcb.set_recv_callback (on_recv);
					pcb.bind_netif (&netstack.handle);
					return OK;
				});
			}

			public override void dispose () {
				_netstack.perform_on_lwip_thread (() => {
					pcb.remove ();
					pcb = null;
					return OK;
				});

				base.dispose ();
			}

			private void on_recv (LWIP.UdpPcb pcb, owned LWIP.PacketBuffer? pbuf, LWIP.IP6Address addr, uint16 port) {
				var buffer = new uint8[pbuf.tot_len];
				unowned uint8[] chunk = pbuf.get_contiguous (buffer, pbuf.tot_len);

				var bytes = new Bytes (chunk[:pbuf.tot_len]);
				var sender = ip6_address_to_inet_socket_address (addr, port);
				var packet = new Packet (bytes, sender);

				lock (events)
					rx_queue.offer (packet);
				update_events ();
			}

			public void bind (InetSocketAddress address) throws Error {
				check (netstack.perform_on_lwip_thread (() => {
					return pcb.bind (ip6_address_from_inet_socket_address (address), address.get_port ());
				}));
			}

			public InetSocketAddress get_local_address () throws Error {
				InetSocketAddress? result = null;
				netstack.perform_on_lwip_thread (() => {
					result = ip6_address_to_inet_socket_address (pcb.local_ip, pcb.local_port);
					return OK;
				});
				return result;
			}

			public void socket_connect (InetSocketAddress address, Cancellable? cancellable) throws Error {
				check (netstack.perform_on_lwip_thread (() => {
					return pcb.connect (ip6_address_from_inet_socket_address (address), address.get_port ());
				}));
			}

			public int datagram_receive_messages (InputMessage[] messages, int flags, int64 timeout,
					Cancellable? cancellable) throws GLib.Error {
				if (flags != 0)
					throw new IOError.NOT_SUPPORTED ("Flags not supported");
				if (timeout != 0)
					throw new IOError.NOT_SUPPORTED ("Blocking I/O not supported");

				int received;
				for (received = 0; received != messages.length; received++) {
					Packet? packet;
					lock (events)
						packet = rx_queue.poll ();
					if (packet == null) {
						if (received == 0)
							throw new IOError.WOULD_BLOCK ("Resource temporarily unavailable");
						break;
					}
					update_events ();

					if (messages[received].address != null)
						*messages[received].address = packet.address.ref ();

					messages[received].bytes_received = 0;
					messages[received].flags = 0;

					var bytes = packet.bytes;
					uint8 * data = bytes.get_data ();
					size_t remaining = bytes.get_size ();
					foreach (unowned InputVector vector in messages[received].vectors) {
						size_t n = size_t.min (remaining, vector.size);
						if (n == 0)
							break;
						Memory.copy (vector.buffer, data, n);
						data += n;
						remaining -= n;
						messages[received].bytes_received += n;
					}
				}

				return received;
			}

			public virtual int datagram_send_messages (OutputMessage[] messages, int flags, int64 timeout,
					Cancellable? cancellable) throws GLib.Error {
				if (flags != 0)
					throw new IOError.NOT_SUPPORTED ("Flags not supported");

				var packets = new Gee.ArrayList<Packet> ();
				foreach (unowned OutputMessage message in messages) {
					var bytes = new ByteArray ();
					foreach (unowned OutputVector vector in message.vectors) {
						unowned uint8[] data = (uint8[]) vector.buffer;
						bytes.append (data[:vector.size]);
					}
					packets.add (
						new Packet (ByteArray.free_to_bytes ((owned) bytes), (InetSocketAddress) message.address));
				}

				int sent = 0;
				var err = netstack.perform_on_lwip_thread (() => {
					LWIP.ErrorCode err = OK;
					foreach (var packet in packets) {
						var pbuf = LWIP.PacketBuffer.alloc (RAW, (uint16) packet.bytes.get_size (), POOL);
						pbuf.take (packet.bytes.get_data ());

						InetSocketAddress? dst_addr = packet.address;
						if (dst_addr != null)
							err = pcb.sendto (pbuf, ip6_address_from_inet_socket_address (dst_addr), dst_addr.get_port ());
						else
							err = pcb.send (pbuf);
						if (err == OK)
							sent++;
						else
							break;
					}
					return err;
				});
				if (sent == 0)
					check_io (err);
				return sent;
			}

			public virtual DatagramBasedSource datagram_create_source (IOCondition condition, Cancellable? cancellable) {
				return new Ipv6UdpSocketSource (this, condition);
			}

			public virtual IOCondition datagram_condition_check (IOCondition condition) {
				assert_not_reached ();
			}

			public virtual bool datagram_condition_wait (IOCondition condition, int64 timeout, Cancellable? cancellable)
					throws GLib.Error {
				assert_not_reached ();
			}

			public void register_source (Source source, IOCondition condition) {
				lock (events)
					sources[source] = condition | IOCondition.ERR | IOCondition.HUP;
			}

			public void unregister_source (Source source) {
				lock (events)
					sources.unset (source);
			}

			private void update_events () {
				lock (events) {
					IOCondition new_events = OUT;

					if (!rx_queue.is_empty)
						new_events |= IN;

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

			private class Packet {
				public Bytes bytes;
				public InetSocketAddress? address;

				public Packet (Bytes bytes, InetSocketAddress? address) {
					this.bytes = bytes;
					this.address = address;
				}
			}
		}

		private class Ipv6UdpSocketSource : DatagramBasedSource {
			public Ipv6UdpSocket socket;
			public IOCondition condition;

			public Ipv6UdpSocketSource (Ipv6UdpSocket socket, IOCondition condition) {
				this.socket = socket;
				this.condition = condition;

				socket.register_source (this, condition);
			}

			~Ipv6UdpSocketSource () {
				socket.unregister_source (this);
			}

			protected override bool prepare (out int timeout) {
				timeout = -1;
				return (socket.pending_io & condition) != 0;
			}

			protected override bool check () {
				return (socket.pending_io & condition) != 0;
			}

			protected override bool dispatch (SourceFunc? callback) {
				set_ready_time (-1);

				if (callback == null)
					return Source.REMOVE;

				DatagramBasedSourceFunc f = (DatagramBasedSourceFunc) callback;
				return f (socket, socket.pending_io);
			}
		}

		private static void check (LWIP.ErrorCode err) throws Error {
			if (err != OK)
				throw parse_error (err);
		}

		private static void check_io (LWIP.ErrorCode err) throws IOError {
			if (err != OK)
				throw IOError.from_errno (err.to_errno ());
		}

		private static Error parse_error (LWIP.ErrorCode err) {
			unowned string message = strerror (err.to_errno ());
			if (err == RST)
				return new Error.SERVER_NOT_RUNNING ("%s", message);
			return new Error.TRANSPORT ("%s", message);
		}

		private static LWIP.IP6Address ip6_address_from_inet_socket_address (InetSocketAddress address) {
			var addr = ip6_address_from_inet_address (address.get_address ());
			addr.zone = (uint8) address.scope_id;
			return addr;
		}

		private static LWIP.IP6Address ip6_address_from_inet_address (InetAddress address) {
			return LWIP.IP6Address.parse (address.to_string ());
		}

		private static InetSocketAddress ip6_address_to_inet_socket_address (LWIP.IP6Address address, uint16 port) {
			return (InetSocketAddress) Object.new (typeof (InetSocketAddress),
				address: ip6_address_to_inet_address (address),
				port: port,
				scope_id: address.zone
			);
		}

		private static InetAddress ip6_address_to_inet_address (LWIP.IP6Address address) {
			char buf[40];
			return new InetAddress.from_string (address.to_string (buf));
		}
	}
}
