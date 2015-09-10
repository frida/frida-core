namespace Frida {
	[DBus (name = "re.frida.HostSession1")]
	public interface HostSession : Object {
		public abstract async HostApplicationInfo get_frontmost_application () throws GLib.Error;
		public abstract async HostApplicationInfo[] enumerate_applications () throws GLib.Error;
		public abstract async HostProcessInfo[] enumerate_processes () throws GLib.Error;

		public abstract async void enable_spawn_gating () throws GLib.Error;
		public abstract async void disable_spawn_gating () throws GLib.Error;
		public abstract async HostSpawnInfo[] enumerate_pending_spawns () throws GLib.Error;
		public abstract async uint spawn (string path, string[] argv, string[] envp) throws GLib.Error;
		public abstract async void resume (uint pid) throws GLib.Error;
		public abstract async void kill (uint pid) throws GLib.Error;
		public abstract async AgentSessionId attach_to (uint pid) throws GLib.Error;

		public signal void spawned (HostSpawnInfo info);
		public signal void agent_session_destroyed (AgentSessionId id);
	}

	[DBus (name = "re.frida.AgentSession1")]
	public interface AgentSession : Object {
		public abstract async void close () throws GLib.Error;

		public abstract async void ping () throws GLib.Error;

		public abstract async AgentScriptId create_script (string name, string source) throws GLib.Error;
		public abstract async void destroy_script (AgentScriptId sid) throws GLib.Error;
		public abstract async void load_script (AgentScriptId sid) throws GLib.Error;
		public abstract async void post_message_to_script (AgentScriptId sid, string message) throws GLib.Error;
		public signal void message_from_script (AgentScriptId sid, string message, uint8[] data);

		public abstract async void enable_debugger () throws GLib.Error;
		public abstract async void disable_debugger () throws GLib.Error;
		public abstract async void post_message_to_debugger (string message) throws GLib.Error;
		public signal void message_from_debugger (string message);
	}

	[DBus (name = "re.frida.Error")]
	public errordomain Error {
		SERVER_NOT_RUNNING,
		EXECUTABLE_NOT_FOUND,
		EXECUTABLE_NOT_SUPPORTED,
		PROCESS_NOT_FOUND,
		PROCESS_NOT_RESPONDING,
		INVALID_ARGUMENT,
		INVALID_OPERATION,
		PERMISSION_DENIED,
		ADDRESS_IN_USE,
		TIMED_OUT,
		NOT_SUPPORTED,
		PROTOCOL,
		TRANSPORT
	}

	namespace Marshal {
		public static Frida.Error from_dbus (GLib.Error e) {
			DBusError.strip_remote_error (e);
			if (e is Frida.Error)
				return (Frida.Error) e;
			else
				return new Frida.Error.TRANSPORT (e.message);
		}
	}

	public struct HostApplicationInfo {
		public string identifier {
			get;
			private set;
		}

		public string name {
			get;
			private set;
		}

		public uint pid {
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

		public HostApplicationInfo (string identifier, string name, uint pid, ImageData small_icon, ImageData large_icon) {
			this.identifier = identifier;
			this.name = name;
			this.pid = pid;
			this.small_icon = small_icon;
			this.large_icon = large_icon;
		}
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

	public struct HostSpawnInfo {
		public uint pid {
			get;
			private set;
		}

		public string identifier {
			get;
			private set;
		}

		public HostSpawnInfo (uint pid, string identifier) {
			this.pid = pid;
			this.identifier = identifier;
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
		public const string HOST_SESSION = "/re/frida/HostSession1";
		public const string AGENT_SESSION = "/re/frida/AgentSession1";

		public static string from_agent_session_id (AgentSessionId id) {
			return "%s/%u".printf (AGENT_SESSION, id.handle);
		}
	}
}
