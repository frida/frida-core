namespace Zed {
	[DBus (name = "org.boblycat.frida.HostSession")]
	public interface HostSession : Object {
		public abstract async HostProcessInfo[] enumerate_processes () throws IOError;
	}

	public struct HostProcessInfo {
		public uint pid {
			get;
			private set;
		}

		public string name {
			get;
			private set;
		}

		public HostProcessIcon small_icon {
			get;
			private set;
		}

		public HostProcessIcon large_icon {
			get;
			private set;
		}

		public HostProcessInfo (uint pid, string name, HostProcessIcon small_icon, HostProcessIcon large_icon) {
			this.pid = pid;
			this.name = name;
			this.small_icon = small_icon;
			this.large_icon = large_icon;
		}
	}

	public struct HostProcessIcon {
		public int width {
			get;
			private set;
		}

		public int height {
			get;
			private set;
		}

		public int rowstride {
			get;
			private set;
		}

		public string data {
			get;
			private set;
		}

		public HostProcessIcon (int width, int height, int rowstride, string data) {
			this.width = width;
			this.height = height;
			this.rowstride = rowstride;
			this.data = data;
		}
	}

	namespace ObjectPath {
		public const string HOST_SESSION = "/org/boblycat/frida/HostSession";
	}
}
