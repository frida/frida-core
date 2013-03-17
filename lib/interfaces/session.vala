namespace Zed {
	[DBus (name = "org.boblycat.frida.HostSession")]
	public interface HostSession : Object {
		public abstract async HostProcessInfo[] enumerate_processes () throws IOError;

		public abstract async uint spawn (string path, string[] argv, string[] envp) throws IOError;
		public abstract async void resume (uint pid) throws IOError;
		public abstract async AgentSessionId attach_to (uint pid) throws IOError;
	}

	[DBus (name = "org.boblycat.frida.AgentSession")]
	public interface AgentSession : Object {
		public abstract async void close () throws IOError;

		public abstract async AgentScriptId create_script (string source) throws IOError;
		public abstract async void destroy_script (AgentScriptId sid) throws IOError;
		public abstract async void load_script (AgentScriptId sid) throws IOError;
		public abstract async void post_message_to_script (AgentScriptId sid, string message) throws IOError;
		public signal void message_from_script (AgentScriptId sid, string message, uint8[] data);
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

		public ImageData small_icon {
			get;
			private set;
		}

		public ImageData large_icon {
			get;
			private set;
		}

		public HostProcessInfo (uint pid, string name, ImageData small_icon, ImageData large_icon) {
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

	public struct AgentScriptId {
		public uint handle {
			get;
			private set;
		}

		public AgentScriptId (uint handle) {
			this.handle = handle;
		}
	}

	public struct ImageData {
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

		public string pixels {
			get;
			private set;
		}

		public ImageData (int width, int height, int rowstride, string pixels) {
			this.width = width;
			this.height = height;
			this.rowstride = rowstride;
			this.pixels = pixels;
		}
	}

	namespace ObjectPath {
		public const string HOST_SESSION = "/org/boblycat/frida/HostSession";
		public const string AGENT_SESSION = "/org/boblycat/frida/AgentSession";
	}
}