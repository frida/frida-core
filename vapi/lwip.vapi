[CCode (gir_namespace = "LWIP", gir_version = "1.0")]
namespace LWIP {
	[CCode (cheader_filename = "lwip/tcpip.h", lower_case_cprefix = "tcpip_")]
	namespace Runtime {
		public void init (InitDoneFunc init_done);

		[CCode (cname = "tcpip_callback")]
		public ErrorCode schedule (WorkFunc work);

		[CCode (cname = "tcpip_init_done_fn")]
		public delegate void InitDoneFunc ();

		[CCode (cname = "tcpip_callback_fn")]
		public delegate void WorkFunc ();
	}

	[CCode (cheader_filename = "lwip/netif.h", cname = "struct netif", cprefix = "netif_")]
	public struct NetworkInterface {
		public static void add_noaddr (ref NetworkInterface netif, void * state, NetworkInterfaceInitFunc init,
			NetworkInterfaceInputFunc input = NetworkInterface.default_input_handler);

		public void remove ();

		public void set_up ();
		public void set_down ();

		public void ip6_addr_set (int8 addr_idx, IP6Address address);
		public ErrorCode add_ip6_address (IP6Address address, int8 * chosen_index = null);
		public void ip6_addr_set_state (int8 addr_index, IP6AddressState state);

		[CCode (cname = "netif_input")]
		public static ErrorCode default_input_handler (PacketBuffer pbuf, NetworkInterface netif);

		public NetworkInterfaceInputFunc input;
		public NetworkInterfaceOutputIP6Func output_ip6;

		public void * state;

		public uint16 mtu;
	}

	[CCode (cname = "netif_init_fn", has_target = false)]
	public delegate ErrorCode NetworkInterfaceInitFunc (NetworkInterface netif);

	[CCode (cname = "netif_input_fn", has_target = false)]
	public delegate ErrorCode NetworkInterfaceInputFunc (PacketBuffer pbuf, NetworkInterface netif);

	[CCode (cname = "netif_output_ip6_fn", has_target = false)]
	public delegate ErrorCode NetworkInterfaceOutputIP6Func (NetworkInterface netif, PacketBuffer pbuf, IP6Address address);

	[CCode (cheader_filename = "lwip/ip6_addr.h", cname = "ip6_addr_t", cprefix = "ip6_addr_")]
	public struct IP6Address {
		[CCode (cname = "ip6addr_aton")]
		public static IP6Address parse (string str);
	}

	[Flags]
	[CCode (cheader_filename = "lwip/ip6_addr.h", cname = "u8_t", cprefix = "IP6_ADDR_", has_type_id = false)]
	public enum IP6AddressState {
		INVALID,
		TENTATIVE,
		TENTATIVE_1,
		TENTATIVE_2,
		TENTATIVE_3,
		TENTATIVE_4,
		TENTATIVE_5,
		TENTATIVE_6,
		TENTATIVE_7,
		VALID,
		PREFERRED,
		DEPRECATED,
		DUPLICATED,
	}

	[CCode (cheader_filename = "lwip/ip_addr.h", cname = "u8_t", cprefix = "IPADDR_TYPE_", has_type_id = false)]
	public enum IPAddressType {
		V4,
		V6,
		ANY,
	}

	[Compact]
	[CCode (cheader_filename = "lwip/pbuf.h", cname = "struct pbuf", cprefix = "pbuf_")]
	public class PacketBuffer {
		public static PacketBuffer alloc (Layer layer, uint16 length, Type type);

		public PacketBuffer? next;
		[CCode (array_length_cname = "len")]
		public uint8[] payload;
		public uint16 tot_len;

		[CCode (array_length = false)]
		public unowned uint8[] get_contiguous (uint8[] buffer, uint16 len, uint16 offset = 0);

		public ErrorCode take (uint8[] data);

		[CCode (cname = "pbuf_layer", cprefix = "PBUF_", has_type_id = false)]
		public enum Layer {
			TRANSPORT,
			IP,
			LINK,
			RAW_TX,
			RAW,
		}

		[CCode (cname = "pbuf_type", cprefix = "PBUF_", has_type_id = false)]
		public enum Type {
			RAM,
			ROM,
			REF,
			POOL,
		}
	}

	[Compact]
	[CCode (cheader_filename = "lwip/tcp.h", cname = "struct tcp_pcb", cprefix = "tcp_")]
	public class TcpPcb {
		[CCode (cname = "tcp_new_ip_type")]
		public static unowned TcpPcb make (IPAddressType type);

		[CCode (cname = "tcp_arg")]
		public void set_user_data (void * user_data);

		[CCode (cname = "tcp_recv")]
		public void set_recv_callback (RecvFunc f);
		[CCode (cname = "tcp_sent")]
		public void set_sent_callback (SentFunc f);
		[CCode (cname = "tcp_err")]
		public void set_error_callback (ErrorFunc f);

		public void nagle_disable ();
		public void nagle_enable ();

		public void abort ();
		public ErrorCode close ();
		public ErrorCode shutdown (bool shut_rx, bool shut_tx);

		public void bind_netif (NetworkInterface? netif);

		public ErrorCode connect (IP6Address address, uint16 port, ConnectedFunc connected);

		[CCode (cname = "tcp_recved")]
		public void notify_received (uint16 len);

		[CCode (cname = "tcp_sndbuf")]
		public uint16 query_available_send_buffer_space ();

		public ErrorCode write (uint8[] data, WriteFlags flags = 0);
		public ErrorCode output ();

		[CCode (cname = "tcp_recv_fn", has_target = false)]
		public delegate ErrorCode RecvFunc (void * user_data, TcpPcb pcb, owned PacketBuffer? pbuf, ErrorCode err);

		[CCode (cname = "tcp_sent_fn", has_target = false)]
		public delegate ErrorCode SentFunc (void * user_data, TcpPcb pcb, uint16 len);

		[CCode (cname = "tcp_err_fn", has_target = false)]
		public delegate void ErrorFunc (void * user_data, ErrorCode err);

		[CCode (cname = "tcp_connected_fn", has_target = false)]
		public delegate ErrorCode ConnectedFunc (void * user_data, TcpPcb pcb, ErrorCode err);

		[Flags]
		[CCode (cname = "u8_t", cprefix = "TCP_WRITE_FLAG_", has_type_id = false)]
		public enum WriteFlags {
			COPY,
			MORE,
		}
	}

	[CCode (cheader_filename = "lwip/err.h", cname = "err_t", cprefix = "ERR_", lower_case_cprefix = "err_", has_type_id = false)]
	public enum ErrorCode {
		OK,
		MEM,
		BUF,
		TIMEOUT,
		RTE,
		INPROGRESS,
		VAL,
		WOULDBLOCK,
		USE,
		ALREADY,
		ISCONN,
		CONN,
		IF,
		ABRT,
		RST,
		CLSD,
		ARG;

		public int to_errno ();
	}
}
