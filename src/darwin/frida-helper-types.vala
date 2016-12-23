#if DARWIN
namespace Frida {
	public interface DarwinHelper : Object {
		public signal void output (uint pid, int fd, uint8[] data);
		public signal void uninjected (uint id);

		public abstract async void close ();

		public abstract async void preload () throws Error;

		public abstract async AgentSessionProvider create_system_session_provider (string agent_filename, out DBusConnection conn) throws Error;

		public abstract async uint spawn (string path, string[] argv, string[] envp) throws Error;
		public abstract async void input (uint pid, uint8[] data) throws Error;
		public abstract async void launch (string identifier, string? url) throws Error;
		public abstract async void resume (uint pid) throws Error;
		public abstract async void kill_process (uint pid) throws Error;
		public abstract async void kill_application (string identifier) throws Error;

		public abstract async uint inject_library_file (uint pid, string path, string entrypoint, string data) throws Error;
		public abstract async uint inject_library_blob (uint pid, string name, MappedLibraryBlob blob, string entrypoint, string data) throws Error;

		public abstract async IOStream make_pipe_stream (uint remote_pid, out string remote_address) throws Error;

		public abstract async MappedLibraryBlob? try_mmap (Bytes blob) throws Error;
	}

	[DBus (name = "re.frida.Helper")]
	public interface DarwinRemoteHelper : Object {
		public signal void output (uint pid, int fd, uint8[] data);
		public signal void uninjected (uint id);

		public abstract async void stop () throws GLib.Error;

		public abstract async string create_system_session_provider (string agent_filename) throws GLib.Error;

		public abstract async uint spawn (string path, string[] argv, string[] envp) throws GLib.Error;
		public abstract async void launch (string identifier, string url) throws GLib.Error;
		public abstract async void input (uint pid, uint8[] data) throws GLib.Error;
		public abstract async void resume (uint pid) throws GLib.Error;
		public abstract async void kill_process (uint pid) throws GLib.Error;
		public abstract async void kill_application (string identifier) throws GLib.Error;

		public abstract async uint inject_library_file (uint pid, string path, string entrypoint, string data) throws GLib.Error;
		public abstract async uint inject_library_blob (uint pid, string name, MappedLibraryBlob blob, string entrypoint, string data) throws GLib.Error;

		public abstract async PipeEndpoints make_pipe_endpoints (uint local_pid, uint remote_pid) throws GLib.Error;
	}

	[DBus (name = "re.frida.Helper")]
	public interface TunneledStream : Object {
		public abstract async void close () throws GLib.Error;
		public abstract async uint8[] read () throws GLib.Error;
		public abstract async void write (uint8[] data) throws GLib.Error;
	}

	public struct PipeEndpoints {
		public string local_address {
			get;
			private set;
		}

		public string remote_address {
			get;
			private set;
		}

		public PipeEndpoints (string local_address, string remote_address) {
			this.local_address = local_address;
			this.remote_address = remote_address;
		}
	}

	namespace ObjectPath {
		public const string HELPER = "/re/frida/Helper";
		public const string SYSTEM_SESSION_PROVIDER = "/re/frida/SystemSessionProvider";
		public const string TUNNELED_STREAM = "/re/frida/TunneledStream";

		public static string from_tunneled_stream_id (uint id) {
			return "%s/%u".printf (TUNNELED_STREAM, id);
		}
	}
}
#endif
