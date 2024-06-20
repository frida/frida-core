[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
	public interface NetworkStack : Object {
		public abstract uint scope_id {
			get;
		}

		public abstract async IOStream open_tcp_connection (InetSocketAddress address, Cancellable? cancellable)
			throws Error, IOError;
		public abstract async UdpSocket create_udp_socket (Cancellable? cancellable) throws Error, IOError;
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
		public uint scope_id {
			get {
				return _scope_id;
			}
		}

		private uint _scope_id;

		public SystemNetworkStack (uint scope_id) {
			this._scope_id = scope_id;
		}

		public async IOStream open_tcp_connection (InetSocketAddress address, Cancellable? cancellable) throws Error, IOError {
			SocketConnection connection;
			try {
				var client = new SocketClient ();
				connection = yield client.connect_async (address, cancellable);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("%s", e.message);
			}

			Tcp.enable_nodelay (connection.socket);

			return connection;
		}

		public async UdpSocket create_udp_socket (Cancellable? cancellable) throws Error {
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

	public sealed class VirtualNetworkStack : Object, AsyncInitable, NetworkStack {
		public signal void outgoing_datagram (Bytes datagram);

		public Bytes? ethernet_address {
			get;
			construct;
		}

		public InetAddress ipv6_address {
			get;
			construct;
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

		private Promise<bool> allocated = new Promise<bool> ();

		private bool netif_added = false;
		private LWIP.NetworkInterface handle;
		private LWIP.IP6Address raw_ipv6_address;
		private Gee.Queue<Bytes> incoming_datagrams = new Gee.ArrayQueue<Bytes> ();

		private MainContext main_context;

		private DataOutputStream pcap;

		public static async VirtualNetworkStack create (Bytes? ethernet_address, InetAddress ipv6_address, uint16 mtu,
				Cancellable? cancellable) throws IOError {
			var netstack = new VirtualNetworkStack (ethernet_address, ipv6_address, mtu);

			try {
				yield netstack.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				assert (e is IOError.CANCELLED);
				throw (IOError) e;
			}

			return netstack;
		}

		private class VirtualNetworkStack (Bytes? ethernet_address, InetAddress ipv6_address, uint16 mtu) {
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

			try {
				var f = File.new_build_filename (Environment.get_user_special_dir (DESKTOP),
					"vns-%s.pcap".printf (ipv6_address.to_string ().replace (":", "")));
				try {
					f.delete ();
				} catch (GLib.Error e) {
				}
				pcap = new DataOutputStream (f.create (REPLACE_DESTINATION));
				pcap.set_byte_order (HOST_ENDIAN);
				pcap.put_uint32 (0xa1b2c3d4U);
				pcap.put_uint16 (2);
				pcap.put_uint16 (4);
				pcap.put_uint32 (0);
				pcap.put_uint32 (0);
				pcap.put_uint32 (16384);
				pcap.put_uint32 ((ethernet_address != null) ? 1 : 229); // Ethernet or IPv6
				pcap.flush ();
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
		}

		public override void dispose () {
			stop ();

			base.dispose ();
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws IOError {
			LWIP.Runtime.schedule (start);
			netif_added = true;

			try {
				yield allocated.future.wait_async (cancellable);
			} catch (GLib.Error e) {
				assert (e is IOError.CANCELLED);
				throw (IOError) e;
			}

			return true;
		}

		public async IOStream open_tcp_connection (InetSocketAddress address, Cancellable? cancellable = null)
				throws Error, IOError {
			return yield TcpConnection.open (this, address, cancellable);
		}

		public async UdpSocket create_udp_socket (Cancellable? cancellable) throws Error, IOError {
			return yield Ipv6UdpSocket.create (this, cancellable);
		}

		public void handle_incoming_datagram (Bytes datagram) {
			if (!netif_added)
				return;
			log_datagram (datagram);
			lock (incoming_datagrams)
				incoming_datagrams.offer (datagram);
			LWIP.Runtime.schedule (process_next_incoming_datagram);
		}

		private void start () {
			LWIP.NetworkInterface.add_noaddr (ref handle, this, on_netif_init);
			handle.set_link_up ();
			handle.set_up ();

			schedule_on_frida_thread (() => {
				allocated.resolve (true);
				return Source.REMOVE;
			});
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

			//int8 chosen_index = -1;
			//handle.add_ip6_address (ip6_address_from_inet_address (ipv6_address), &chosen_index);
			//handle.ip6_addr_set_state (chosen_index, PREFERRED);
			int8 chosen_index = 0;
			handle.create_ip6_linklocal_address (true);
			raw_ipv6_address = handle.ip6_addr[chosen_index];

			//var icmp_group = LWIP.IP6Address.parse ("ff02::1");
			//LWIP.IP6MulticastListenerDiscovery.join_group_netif (ref handle, icmp_group);
			//var mdns_group = LWIP.IP6Address.parse ("ff02::fb");
			//LWIP.IP6MulticastListenerDiscovery.join_group_netif (ref handle, mdns_group);
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
				log_datagram (datagram);
				outgoing_datagram (datagram);
				return Source.REMOVE;
			});
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

		private void schedule_on_frida_thread (owned SourceFunc function) {
			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (main_context);
		}

		private void log_datagram (Bytes datagram) {
			lock (pcap) {
				try {
					int64 timestamp = get_real_time ();
					pcap.put_uint32 ((uint32) (timestamp / 1000000));
					pcap.put_uint32 ((uint32) (timestamp % 1000000));
					pcap.put_uint32 (datagram.length);
					pcap.put_uint32 (datagram.length);
					size_t written;
					pcap.write_all (datagram.get_data (), out written);
					pcap.flush ();
				} catch (GLib.Error e) {
					printerr ("%s\n", e.message);
					assert_not_reached ();
				}
			}
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
				pcb.bind_netif (netstack.handle);

				pcb.connect (ip6_address_from_inet_socket_address (address), address.get_port (), (user_data, pcb, err) => {
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

		private class Ipv6UdpSocket : Object, AsyncInitable, UdpSocket, DatagramBased {
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
					lock (state)
						return events;
				}
			}

			private Promise<bool> allocated = new Promise<bool> ();

			private State state = CREATED;

			private unowned LWIP.UdpPcb? pcb;
			private Gee.Queue<BindRequest> bind_requests = new Gee.ArrayQueue<BindRequest> ();
			private Gee.Queue<GetLocalAddressRequest> get_local_address_requests =
				new Gee.ArrayQueue<GetLocalAddressRequest> ();
			private Gee.Queue<ConnectRequest> connect_requests = new Gee.ArrayQueue<ConnectRequest> ();
			private IOCondition events = OUT;
			private Gee.Queue<Packet> rx_queue = new Gee.ArrayQueue<Packet> ();
			private Gee.Queue<Packet> tx_queue = new Gee.ArrayQueue<Packet> ();

			private Gee.Map<unowned Source, IOCondition> sources = new Gee.HashMap<unowned Source, IOCondition> ();

			private MainContext main_context;

			public enum State {
				CREATED,
				ALLOCATING,
				ALLOCATED,
				DESTROYED
			}

			public static async Ipv6UdpSocket create (VirtualNetworkStack netstack, Cancellable? cancellable) throws IOError {
				var sock = new Ipv6UdpSocket (netstack);

				try {
					yield sock.init_async (Priority.DEFAULT, cancellable);
				} catch (GLib.Error e) {
					assert (e is IOError.CANCELLED);
					throw (IOError) e;
				}

				return sock;
			}

			private Ipv6UdpSocket (VirtualNetworkStack netstack) {
				Object (netstack: netstack);
			}

			construct {
				main_context = MainContext.ref_thread_default ();
			}

			public override void dispose () {
				destroy ();

				base.dispose ();
			}

			private async bool init_async (int io_priority, Cancellable? cancellable) throws IOError {
				state = ALLOCATING;
				LWIP.Runtime.schedule (allocate);

				try {
					yield allocated.future.wait_async (cancellable);
				} catch (GLib.Error e) {
					assert (e is IOError.CANCELLED);
					throw (IOError) e;
				}

				return true;
			}

			private void allocate () {
				pcb = LWIP.UdpPcb.make (V6);
				pcb.mcast_ttl = 1;
				pcb.set_recv_callback ((pcb, pbuf, addr, port) => {
					on_recv ((owned) pbuf, addr, port);
				});
				pcb.bind_netif (netstack.handle);

				schedule_on_frida_thread (() => {
					state = ALLOCATED;
					allocated.resolve (true);
					return Source.REMOVE;
				});
			}

			private void destroy () {
				if (state == CREATED || state == DESTROYED)
					return;

				ref ();
				LWIP.Runtime.schedule (do_destroy);

				state = DESTROYED;
			}

			private void do_destroy () {
				pcb.remove ();
				pcb = null;

				unref ();
			}

			private void on_recv (owned LWIP.PacketBuffer? pbuf, LWIP.IP6Address addr, uint16 port) {
				var buffer = new uint8[pbuf.tot_len];
				unowned uint8[] chunk = pbuf.get_contiguous (buffer, pbuf.tot_len);

				var bytes = new Bytes (chunk[:pbuf.tot_len]);
				var sender = ip6_address_to_inet_socket_address (addr, port);
				var packet = new Packet (bytes, sender);

				lock (state)
					rx_queue.offer (packet);
				update_events ();
			}

			public void bind (InetSocketAddress address) throws Error {
				var req = new BindRequest () { address = address };

				lock (state)
					bind_requests.offer (req);
				LWIP.Runtime.schedule (do_bind);

				req.join ();
			}

			private void do_bind () {
				BindRequest req;
				lock (state)
					req = bind_requests.poll ();

				var err = pcb.bind (ip6_address_from_inet_socket_address (req.address), req.address.get_port ());
				if (err == OK)
					req.resolve (true);
				else
					req.reject (err);
			}

			public InetSocketAddress get_local_address () throws Error {
				var req = new GetLocalAddressRequest ();

				lock (state)
					get_local_address_requests.offer (req);
				LWIP.Runtime.schedule (do_get_local_address);

				return req.join ();
			}

			private void do_get_local_address () {
				GetLocalAddressRequest req;
				lock (state)
					req = get_local_address_requests.poll ();

				req.resolve (ip6_address_to_inet_socket_address (pcb.local_ip, pcb.local_port));
			}

			public void socket_connect (InetSocketAddress address, Cancellable? cancellable) throws Error {
				var req = new ConnectRequest () { address = address };

				lock (state)
					connect_requests.offer (req);
				LWIP.Runtime.schedule (do_socket_connect);

				req.join ();
			}

			private void do_socket_connect () {
				ConnectRequest req;
				lock (state)
					req = connect_requests.poll ();

				var err = pcb.connect (ip6_address_from_inet_socket_address (req.address), req.address.get_port ());
				if (err == OK)
					req.resolve (true);
				else
					req.reject (err);
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
					lock (state)
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

				foreach (unowned OutputMessage message in messages) {
					foreach (unowned OutputVector vector in message.vectors) {
						unowned uint8[] data = (uint8[]) vector.buffer;
						var packet = new Packet (new Bytes (data[:vector.size]),
							(InetSocketAddress) message.address);
						lock (state)
							tx_queue.offer (packet);
					}
				}

				LWIP.Runtime.schedule (transmit_pending);

				return messages.length;
			}

			private void transmit_pending () {
				while (true) {
					Packet? packet;
					lock (state)
						packet = tx_queue.poll ();
					if (packet == null)
						return;

					var pbuf = LWIP.PacketBuffer.alloc (RAW, (uint16) packet.bytes.get_size (), POOL);
					pbuf.take (packet.bytes.get_data ());

					InetSocketAddress? dst_addr = packet.address;
					if (dst_addr != null)
						pcb.sendto (pbuf, ip6_address_from_inet_socket_address (dst_addr), dst_addr.get_port ());
					else
						pcb.send (pbuf);
				}
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
				lock (state)
					sources[source] = condition | IOCondition.ERR | IOCondition.HUP;
			}

			public void unregister_source (Source source) {
				lock (state)
					sources.unset (source);
			}

			private void update_events () {
				lock (state) {
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

			private void schedule_on_frida_thread (owned SourceFunc function) {
				var source = new IdleSource ();
				source.set_callback ((owned) function);
				source.attach (main_context);
			}

			private class Request<T> {
				public Gee.Promise<T> promise = new Gee.Promise<T> ();

				public T join () throws Error {
					var future = promise.future;
					try {
						return future.wait ();
					} catch (Gee.FutureError e) {
						assert (e is Gee.FutureError.EXCEPTION);
						throw (Error) future.exception;
					}
				}

				public void resolve (T val) {
					promise.set_value (val);
				}

				public void reject (LWIP.ErrorCode err) {
					promise.set_exception (new Error.TRANSPORT ("%s", strerror (err.to_errno ())));
				}
			}

			private class BindRequest : Request<bool> {
				public InetSocketAddress address;
			}

			private class GetLocalAddressRequest : Request<InetSocketAddress> {
				public InetSocketAddress address;
			}

			private class ConnectRequest : Request<bool> {
				public InetSocketAddress address;
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
			return new InetAddress.from_string (address.to_string ());
		}
	}
}
