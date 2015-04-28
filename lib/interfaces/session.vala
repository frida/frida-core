namespace Frida {
	[DBus (name = "re.frida.HostSession")]
	public interface HostSession : Object {
		public abstract async HostProcessInfo[] enumerate_processes () throws Error;

		public abstract async uint spawn (string path, string[] argv, string[] envp) throws Error;
		public abstract async void resume (uint pid) throws Error;
		public abstract async void kill (uint pid) throws Error;
		public abstract async AgentSessionId attach_to (uint pid) throws Error;
	}

	[DBus (name = "re.frida.AgentSession")]
	public interface AgentSession : Object {
		public abstract async void close () throws Error;

		public abstract async AgentScriptId create_script (string name, string source) throws Error;
		public abstract async void destroy_script (AgentScriptId sid) throws Error;
		public abstract async void load_script (AgentScriptId sid) throws Error;
		public abstract async void post_message_to_script (AgentScriptId sid, string message) throws Error;
		public signal void message_from_script (AgentScriptId sid, string message, uint8[] data);

		public abstract async void enable_debugger () throws Error;
		public abstract async void disable_debugger () throws Error;
		public abstract async void post_message_to_debugger (string message) throws Error;
		public signal void message_from_debugger (string message);
	}

	[DBus (name = "re.frida.Error")]
	public errordomain Error {
		SERVER_NOT_RUNNING,
		EXECUTABLE_NOT_FOUND,
		EXECUTABLE_NOT_SUPPORTED,
		PROCESS_NOT_RESPONDING,
		PROCESS_GONE,
		INVALID_ARGUMENT,
		INVALID_OPERATION,
		PERMISSION_DENIED,
		ADDRESS_IN_USE,
		TIMED_OUT,
		NOT_SUPPORTED,
		PROTOCOL
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
		public const string HOST_SESSION = "/re/frida/HostSession";
		public const string AGENT_SESSION = "/re/frida/AgentSession";
	}
}
