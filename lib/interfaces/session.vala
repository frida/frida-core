namespace Zed {
	[DBus (name = "org.boblycat.frida.HostSession")]
	public interface HostSession : Object {
		public abstract async HostProcessInfo[] enumerate_processes () throws IOError;

		public abstract async AgentSessionId attach_to (uint pid) throws IOError;
	}

	[DBus (name = "org.boblycat.frida.AgentSession")]
	public interface AgentSession : Object {
		public abstract async AgentModuleInfo[] query_modules () throws IOError;
		public abstract async AgentFunctionInfo[] query_module_functions (string module_name) throws IOError;
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

	public struct AgentSessionId {
		public uint handle {
			get;
			private set;
		}

		public AgentSessionId (uint handle) {
			this.handle = handle;
		}
	}

	public struct AgentModuleInfo {
		public string name {
			get;
			private set;
		}

		public string uid {
			get;
			private set;
		}

		public uint64 size {
			get;
			private set;
		}

		public uint64 address {
			get;
			private set;
		}

		public AgentModuleInfo (string name, string uid, uint64 size, uint64 address) {
			this.name = name;
			this.uid = uid;
			this.size = size;
			this.address = address;
		}
	}

	public struct AgentFunctionInfo {
		public string name {
			get;
			private set;
		}

		public uint64 address {
			get;
			private set;
		}

		public AgentFunctionInfo (string name, uint64 address) {
			this.name = name;
			this.address = address;
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
