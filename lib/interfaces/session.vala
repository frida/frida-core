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

		public string small_icon {
			get;
			private set;
		}

		public string large_icon {
			get;
			private set;
		}

		public HostProcessInfo (uint pid, string name, string small_icon = "", string large_icon = "") {
			this.pid = pid;
			this.name = name;
			this.small_icon = small_icon;
			this.large_icon = large_icon;
		}
	}

	namespace ObjectPath {
		public const string HOST_SESSION = "/org/boblycat/frida/HostSession";
	}
}
