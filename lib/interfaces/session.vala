namespace Frida {
	[DBus (name = "re.frida.HostSession12")]
	public interface HostSession : Object {
		public abstract async HostApplicationInfo get_frontmost_application () throws GLib.Error;
		public abstract async HostApplicationInfo[] enumerate_applications () throws GLib.Error;
		public abstract async HostProcessInfo[] enumerate_processes () throws GLib.Error;

		public abstract async void enable_spawn_gating () throws GLib.Error;
		public abstract async void disable_spawn_gating () throws GLib.Error;
		public abstract async HostSpawnInfo[] enumerate_pending_spawn () throws GLib.Error;
		public abstract async HostChildInfo[] enumerate_pending_children () throws GLib.Error;
		public abstract async uint spawn (string program, HostSpawnOptions options) throws GLib.Error;
		public abstract async void input (uint pid, uint8[] data) throws GLib.Error;
		public abstract async void resume (uint pid) throws GLib.Error;
		public abstract async void kill (uint pid) throws GLib.Error;
		public abstract async AgentSessionId attach_to (uint pid) throws GLib.Error;
		public abstract async InjectorPayloadId inject_library_file (uint pid, string path, string entrypoint, string data) throws GLib.Error;
		public abstract async InjectorPayloadId inject_library_blob (uint pid, uint8[] blob, string entrypoint, string data) throws GLib.Error;

		public signal void spawn_added (HostSpawnInfo info);
		public signal void spawn_removed (HostSpawnInfo info);
		public signal void child_added (HostChildInfo info);
		public signal void child_removed (HostChildInfo info);
		public signal void output (uint pid, int fd, uint8[] data);
		public signal void agent_session_destroyed (AgentSessionId id, SessionDetachReason reason);
		public signal void agent_session_crashed (AgentSessionId id, string crash_report);
		public signal void uninjected (InjectorPayloadId id);
	}

	[DBus (name = "re.frida.AgentSessionProvider12")]
	public interface AgentSessionProvider : Object {
		public abstract async void open (AgentSessionId id) throws GLib.Error;
		public abstract async void unload () throws GLib.Error;

		public signal void opened (AgentSessionId id);
		public signal void closed (AgentSessionId id);
		public signal void child_gating_changed (uint subscriber_count);
	}

	[DBus (name = "re.frida.AgentSession12")]
	public interface AgentSession : Object {
		public abstract async void close () throws GLib.Error;

		public abstract async void enable_child_gating () throws GLib.Error;
		public abstract async void disable_child_gating () throws GLib.Error;

		public abstract async AgentScriptId create_script (string name, string source) throws GLib.Error;
		public abstract async AgentScriptId create_script_from_bytes (uint8[] bytes) throws GLib.Error;
		public abstract async uint8[] compile_script (string name, string source) throws GLib.Error;
		public abstract async void destroy_script (AgentScriptId sid) throws GLib.Error;
		public abstract async void load_script (AgentScriptId sid) throws GLib.Error;
		public abstract async void eternalize_script (AgentScriptId sid) throws GLib.Error;
		public abstract async void post_to_script (AgentScriptId sid, string message, bool has_data, uint8[] data) throws GLib.Error;
		public signal void message_from_script (AgentScriptId sid, string message, bool has_data, uint8[] data);

		public abstract async void enable_debugger () throws GLib.Error;
		public abstract async void disable_debugger () throws GLib.Error;
		public abstract async void post_message_to_debugger (string message) throws GLib.Error;
		public signal void message_from_debugger (string message);

		public abstract async void enable_jit () throws GLib.Error;
	}

	[DBus (name = "re.frida.AgentController12")]
	public interface AgentController : Object {
#if !WINDOWS
		public abstract async HostChildId prepare_to_fork (uint parent_pid, out uint parent_injectee_id, out uint child_injectee_id, out GLib.Socket child_socket) throws GLib.Error;
#endif
		public abstract async void recreate_agent_thread (uint pid, uint injectee_id) throws GLib.Error;
		public abstract async void wait_for_permission_to_resume (HostChildId id, HostChildInfo info) throws GLib.Error;

		public abstract async void prepare_to_exec (HostChildInfo info) throws GLib.Error;
		public abstract async void cancel_exec (uint pid) throws GLib.Error;

		public abstract async void acknowledge_spawn (HostChildInfo info, SpawnStartState start_state) throws GLib.Error;
	}

	public enum SpawnStartState {
		RUNNING,
		SUSPENDED,
	}

	public enum UnloadPolicy {
		IMMEDIATE,
		RESIDENT,
		DEFERRED
	}

#if DARWIN
	public struct DarwinInjectorState {
		public Gum.MemoryRange? mapped_range;
	}
#endif

#if LINUX
	public struct LinuxInjectorState {
		public int fifo_fd;
	}
#endif

	public enum SessionDetachReason {
		APPLICATION_REQUESTED = 1,
		PROCESS_REPLACED,
		PROCESS_TERMINATED,
		SERVER_TERMINATED,
		DEVICE_LOST
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

	public struct HostSpawnOptions {
		public bool has_argv {
			get;
			set;
		}

		public string[] argv {
			get;
			set;
		}

		public bool has_envp {
			get;
			set;
		}

		public string[] envp {
			get;
			set;
		}

		public bool has_env {
			get;
			set;
		}

		public string[] env {
			get;
			set;
		}

		public string cwd {
			get;
			set;
		}

		public Stdio stdio {
			get;
			set;
		}

		public uint8[] aux {
			get;
			set;
		}

		public HostSpawnOptions () {
			this.argv = {};
			this.envp = {};
			this.env = {};
			this.cwd = "";
			this.stdio = INHERIT;
			this.aux = {};
		}

		public VariantDict load_aux () {
			return new VariantDict (new Variant.from_bytes (VariantType.VARDICT, new Bytes (aux), false));
		}

		public string[] compute_argv (string path) {
			return has_argv ? argv : new string[] { path };
		}

		public string[] compute_envp () {
			var base_env = has_envp ? envp : Environ.get ();
			if (!has_env)
				return base_env;

			var names = new Gee.ArrayList<string> ();
			var values = new Gee.HashMap<string, string> ();
			parse_envp (base_env, names, values);

			var overridden_names = new Gee.ArrayList<string> ();
			var overridden_values = new Gee.HashMap<string, string> ();
			parse_envp (env, overridden_names, overridden_values);

			foreach (var name in overridden_names) {
				if (!values.has_key (name))
					names.add (name);
				values[name] = overridden_values[name];
			}

			var result = new string[names.size];
			var i = 0;
			foreach (var name in names) {
				result[i] = name.concat ("=", values[name]);
				i++;
			}
			return result;
		}

		private static void parse_envp (string[] envp, Gee.ArrayList<string> names, Gee.HashMap<string, string> values) {
			foreach (var pair in envp) {
				var tokens = pair.split ("=", 2);
				if (tokens.length == 1)
					continue;
				var name = tokens[0];
				var val = tokens[1];
				names.add (name);
				values[name] = val;
			}
		}
	}

	public enum Stdio {
		INHERIT,
		PIPE
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

	public struct HostChildId {
		public uint handle {
			get;
			private set;
		}

		public HostChildId (uint handle) {
			this.handle = handle;
		}
	}

	public struct HostChildInfo {
		public uint pid {
			get;
			private set;
		}

		public uint parent_pid {
			get;
			private set;
		}

		public ChildOrigin origin {
			get;
			private set;
		}

		public string identifier {
			get;
			set;
		}

		public string path {
			get;
			set;
		}

		public bool has_argv {
			get;
			set;
		}

		public string[] argv {
			get;
			set;
		}

		public bool has_envp {
			get;
			set;
		}

		public string[] envp {
			get;
			set;
		}

		public HostChildInfo (uint pid, uint parent_pid, ChildOrigin origin) {
			this.pid = pid;
			this.parent_pid = parent_pid;
			this.origin = origin;
			this.identifier = "";
			this.path = "";
			this.argv = {};
			this.envp = {};
		}
	}

	public enum ChildOrigin {
		FORK,
		EXEC,
		SPAWN
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

		public uint allocated_size {
			get;
			private set;
		}

		public MappedLibraryBlob (uint64 address, uint size, uint allocated_size) {
			this.address = address;
			this.size = size;
			this.allocated_size = allocated_size;
		}
	}

	public class Image : Object {
		public ImageData data;

		public Image (ImageData data) {
			this.data = data;
		}

		public static Image? from_data (ImageData? data) {
			if (data == null)
				return null;
			return new Image (data);
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

	namespace ServerGuid {
		public const string HOST_SESSION_SERVICE = "6769746875622e636f6d2f6672696461";
	}

	namespace ObjectPath {
		public const string HOST_SESSION = "/re/frida/HostSession";
		public const string AGENT_SESSION_PROVIDER = "/re/frida/AgentSessionProvider";
		public const string AGENT_SESSION = "/re/frida/AgentSession";
		public const string AGENT_CONTROLLER = "/re/frida/AgentController";
		public const string CHILD_SESSION = "/re/frida/ChildSession";

		public static string from_agent_session_id (AgentSessionId id) {
			return "%s/%u".printf (AGENT_SESSION, id.handle);
		}
	}
}
