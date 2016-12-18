namespace Frida {
	[DBus (name = "re.frida.HostSession8")]
	public interface HostSession : Object {
		public abstract async HostApplicationInfo get_frontmost_application () throws GLib.Error;
		public abstract async HostApplicationInfo[] enumerate_applications () throws GLib.Error;
		public abstract async HostProcessInfo[] enumerate_processes () throws GLib.Error;

		public abstract async void enable_spawn_gating () throws GLib.Error;
		public abstract async void disable_spawn_gating () throws GLib.Error;
		public abstract async HostSpawnInfo[] enumerate_pending_spawns () throws GLib.Error;
		public abstract async uint spawn (string path, string[] argv, string[] envp) throws GLib.Error;
		public abstract async void input (uint pid, uint8[] data) throws GLib.Error;
		public abstract async void resume (uint pid) throws GLib.Error;
		public abstract async void kill (uint pid) throws GLib.Error;
		public abstract async AgentSessionId attach_to (uint pid) throws GLib.Error;
		public abstract async InjectorPayloadId inject_library_file (uint pid, string path, string entrypoint, string data) throws GLib.Error;
		public abstract async InjectorPayloadId inject_library_blob (uint pid, uint8[] blob, string entrypoint, string data) throws GLib.Error;

		public signal void spawned (HostSpawnInfo info);
		public signal void output (uint pid, int fd, uint8[] data);
		public signal void agent_session_destroyed (AgentSessionId id);
		public signal void uninjected (InjectorPayloadId id);
	}

	[DBus (name = "re.frida.AgentSessionProvider8")]
	public interface AgentSessionProvider : Object {
		public abstract async void open (AgentSessionId id) throws GLib.Error;
		public abstract async void unload () throws GLib.Error;

		public signal void opened (AgentSessionId id);
		public signal void closed (AgentSessionId id);
	}

	[DBus (name = "re.frida.AgentSession8")]
	public interface AgentSession : Object {
		public abstract async void close () throws GLib.Error;

		public abstract async AgentScriptId create_script (string name, string source) throws GLib.Error;
		public abstract async AgentScriptId create_script_from_bytes (string name, uint8[] bytes) throws GLib.Error;
		public abstract async uint8[] compile_script (string source) throws GLib.Error;
		public abstract async void destroy_script (AgentScriptId sid) throws GLib.Error;
		public abstract async void load_script (AgentScriptId sid) throws GLib.Error;
		public abstract async void post_to_script (AgentScriptId sid, string message, bool has_data, uint8[] data) throws GLib.Error;
		public signal void message_from_script (AgentScriptId sid, string message, bool has_data, uint8[] data);

		public abstract async void enable_debugger () throws GLib.Error;
		public abstract async void disable_debugger () throws GLib.Error;
		public abstract async void post_message_to_debugger (string message) throws GLib.Error;
		public signal void message_from_debugger (string message);

		public abstract async void disable_jit () throws GLib.Error;
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
			if (e is Frida.Error) {
				return (Frida.Error) e;
			} else if (e is DBusError.UNKNOWN_METHOD) {
				return new Frida.Error.PROTOCOL ("Unable to communicate with remote frida-server; " +
					"please ensure that major versions match and that the remote Frida has the feature you are trying to use");
			} else {
				return new Frida.Error.TRANSPORT (e.message);
			}
		}

		public static void throw_if_cancelled (Cancellable? cancellable) throws Error {
			if (cancellable == null)
				return;

			try {
				cancellable.set_error_if_cancelled ();
			} catch (IOError e) {
				throw new Error.INVALID_OPERATION (e.message);
			}
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

	public struct InjectorPayloadId {
		public uint handle {
			get;
			private set;
		}

		public InjectorPayloadId (uint handle) {
			this.handle = handle;
		}
	}

	public struct MappedLibraryBlob {
		public uint64 address {
			get;
			private set;
		}

		public uint size {
			get;
			private set;
		}

		public MappedLibraryBlob (uint64 address, uint size) {
			this.address = address;
			this.size = size;
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
		public const string AGENT_SESSION_PROVIDER = "/re/frida/AgentSessionProvider";
		public const string AGENT_SESSION = "/re/frida/AgentSession";

		public static string from_agent_session_id (AgentSessionId id) {
			return "%s/%u".printf (AGENT_SESSION, id.handle);
		}
	}
}
