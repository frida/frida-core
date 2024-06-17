[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
	using Darwin.GCD;
	using Darwin.IOKit;

	public class MacOSFruitFinder : Object, FruitFinder {
		public string? udid_from_iface (string ifname) throws Error {
			var matching_dict = Darwin.IOKit.service_matching (Darwin.IOKit.ETHERNET_INTERFACE_CLASS);
			if (matching_dict == null)
				return null;
			matching_dict.add (CoreFoundation.String.make (Darwin.IOKit.BSD_NAME_KEY), CoreFoundation.String.make (ifname));

			var registry = IORegistry.open ();
			foreach (var service in registry.matching_services (matching_dict)) {
				var usb_serial = find_idevice (service.parent (Darwin.IOKit.IOSERVICE_PLANE));
				if (usb_serial != null)
					return usb_serial;
			}

			return null;
		}

		private string? find_idevice (IORegistryEntry service) throws Error {
			if (service.get_string_property ("CFBundleIdentifier") == "com.apple.driver.usb.cdc.ncm")
				return find_idevice (service.parent (Darwin.IOKit.IOSERVICE_PLANE));

			var props = service.get_properties ();

			var prod = props.get_string_value ("USB Product Name");
			if (prod != "iPhone" && prod != "iPad")
				return null;

			return props.get_string_value ("USB Serial Number");
		}
	}

	namespace XNU {
		public PcbList query_active_tcp_connections () {
			size_t size = 0;
			Darwin.XNU.sysctlbyname ("net.inet.tcp.pcblist_n", null, &size);

			var pcbs = new uint8[size];
			Darwin.XNU.sysctlbyname ("net.inet.tcp.pcblist_n", pcbs, &size);

			return new PcbList (pcbs);
		}

		public class PcbList {
			private uint8[] pcbs;

			internal PcbList (owned uint8[] pcbs) {
				this.pcbs = (owned) pcbs;
			}

			public Iterator iterator () {
				return new Iterator (this);
			}

			public class Iterator {
				private PcbList list;
				private InetItem * cursor;

				internal Iterator (PcbList list) {
					this.list = list;

					var gen = (Darwin.XNU.InetPcbGeneration *) list.pcbs;
					cursor = (InetItem *) ((uint8 *) list.pcbs + gen->length);
				}

				public Item? next_value () {
					InetPcb * pcb = null;
					while (true) {
						if (cursor->length == 24)
							return null;

						switch (cursor->kind) {
							case InetItemKind.PCB:
								pcb = (InetPcb *) cursor;
								break;
							case InetItemKind.SOCKET:
								var item = new Item (*pcb, *((InetSocket *) cursor));
								advance ();
								return item;
						}

						advance ();
					}
				}

				private void advance () {
					uint32 l = cursor->length;
					if (l % 8 != 0)
						l += 8 - (l % 8);
					cursor = (InetItem *) ((uint8 *) cursor + l);
				}
			}

			public class Item {
				public SocketFamily family {
					get {
						return ((pcb.version_flag & Darwin.XNU.InetVersionFlags.IPV6) != 0)
							? SocketFamily.IPV6
							: SocketFamily.IPV4;
					}
				}

				public InetAddress local_address {
					get {
						if (cached_local_address == null)
							cached_local_address = parse_address (pcb.local_address);
						return cached_local_address;
					}
				}

				public uint16 local_port {
					get {
						return uint16.from_big_endian (pcb.local_port);
					}
				}

				public InetAddress foreign_address {
					get {
						if (cached_foreign_address == null)
							cached_foreign_address = parse_address (pcb.foreign_address);
						return cached_foreign_address;
					}
				}

				public uint16 foreign_port {
					get {
						return uint16.from_big_endian (pcb.foreign_port);
					}
				}

				public int32 effective_pid {
					get {
						return sock.effective_pid;
					}
				}

				private InetPcb pcb;
				private InetSocket sock;
				private InetAddress? cached_local_address;
				private InetAddress? cached_foreign_address;

				public Item (InetPcb pcb, InetSocket sock) {
					this.pcb = pcb;
					this.sock = sock;
				}

				private InetAddress parse_address (uint8[] bytes) {
					if ((pcb.version_flag & Darwin.XNU.InetVersionFlags.IPV6) != 0)
						return new InetAddress.from_bytes (bytes, IPV6);
					var addr = (Darwin.XNU.InetAddr4in6 *) bytes;
					return new InetAddress.from_bytes ((uint8[]) &addr->addr4.s_addr, IPV4);
				}
			}
		}

		[SimpleType]
		public struct InetItem {
			public uint32 length;
			public uint32 kind;
		}

		public enum InetItemKind {
			SOCKET	= 0x001,
			PCB	= 0x010,
		}

		[SimpleType]
		public struct InetPcb {
			public uint32 length;
			public uint32 kind;

			public uint64 inpp;
			public uint16 foreign_port;
			public uint16 local_port;
			public uint32 per_protocol_pcb_low;
			public uint32 per_protocol_pcb_high;
			public uint32 generation_count_low;
			public uint32 generation_count_high;
			public int flags;
			public uint32 flow;
			public uint8 version_flag;
			public uint8 ip_ttl;
			public uint8 ip_protocol;
			public uint8 padding;
			public uint8 foreign_address[16];
			public uint8 local_address[16];
			public InetDepend4 depend4;
			public InetDepend6 depend6;
			public uint32 flowhash;
			public uint32 flags2;
		}

		[SimpleType]
		public struct InetSocket {
			public uint32 length;
			public uint32 kind;

			public uint64 so;
			public int16 type;
			public uint16 options_low;
			public uint16 options_high;
			public int16 linger;
			public int16 state;
			public uint16 pcb[4];
			public uint16 protocol_low;
			public uint16 protocol_high;
			public uint16 family_low;
			public uint16 family_high;
			public int16 qlen;
			public int16 incqlen;
			public int16 qlimit;
			public int16 timeo;
			public uint16 error;
			public int32 pgid;
			public uint32 oobmark;
			public uint32 uid;
			public int32 last_pid;
			public int32 effective_pid;
			public uint64 gencnt;
			public uint32 flags;
			public uint32 flags1;
			public int32 usecount;
			public int32 retaincnt;
			public uint32 filter_flags;
		}

		[SimpleType]
		public struct InetDepend4 {
			public uint8 ip_tos;
		}

		[SimpleType]
		public struct InetDepend6 {
			public uint8 hlim;
			public int checksum;
			public uint16 interface_index;
			public int16 hops;
		}
	}
}
