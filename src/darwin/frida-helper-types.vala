namespace Frida {
	public interface DarwinHelper : Object {
		public signal void output (uint pid, int fd, uint8[] data);
		public signal void spawned (HostSpawnInfo info);
		public signal void uninjected (uint id);

		public abstract uint pid {
			get;
		}

		public abstract async void close ();

		public abstract async void preload () throws Error;

		public abstract async void enable_spawn_gating () throws Error;
		public abstract async void disable_spawn_gating () throws Error;
		public abstract async HostSpawnInfo[] enumerate_pending_spawn () throws Error;
		public abstract async uint spawn (string path, string[] argv, bool has_envp, string[] envp) throws Error;
		public abstract async void input (uint pid, uint8[] data) throws Error;
		public abstract async void launch (string identifier, string? url) throws Error;
		public abstract async void wait_until_suspended (uint pid) throws Error;
		public abstract async void cancel_pending_waits (uint pid) throws Error;
		public abstract async void resume (uint pid) throws Error;
		public abstract async void kill_process (uint pid) throws Error;
		public abstract async void kill_application (string identifier) throws Error;

		public abstract async uint inject_library_file (uint pid, string path, string entrypoint, string data) throws Error;
		public abstract async uint inject_library_blob (uint pid, string name, MappedLibraryBlob blob, string entrypoint, string data) throws Error;
		public abstract async uint demonitor_and_clone_injectee_state (uint id) throws Error;
		public abstract async void recreate_injectee_thread (uint pid, uint id) throws Error;

		public abstract async Gee.Promise<IOStream> open_pipe_stream (uint remote_pid, out string remote_address) throws Error;

		public abstract async MappedLibraryBlob? try_mmap (Bytes blob) throws Error;
	}

	[DBus (name = "re.frida.Helper")]
	public interface DarwinRemoteHelper : Object {
		public signal void output (uint pid, int fd, uint8[] data);
		public signal void spawned (HostSpawnInfo info);
		public signal void uninjected (uint id);

		public abstract async void stop () throws GLib.Error;

		public abstract async void enable_spawn_gating () throws GLib.Error;
		public abstract async void disable_spawn_gating () throws GLib.Error;
		public abstract async HostSpawnInfo[] enumerate_pending_spawn () throws GLib.Error;
		public abstract async uint spawn (string path, string[] argv, bool has_envp, string[] envp) throws GLib.Error;
		public abstract async void launch (string identifier, string url) throws GLib.Error;
		public abstract async void input (uint pid, uint8[] data) throws GLib.Error;
		public abstract async void wait_until_suspended (uint pid) throws GLib.Error;
		public abstract async void cancel_pending_waits (uint pid) throws GLib.Error;
		public abstract async void resume (uint pid) throws GLib.Error;
		public abstract async void kill_process (uint pid) throws GLib.Error;
		public abstract async void kill_application (string identifier) throws GLib.Error;

		public abstract async uint inject_library_file (uint pid, string path, string entrypoint, string data) throws GLib.Error;
		public abstract async uint inject_library_blob (uint pid, string name, MappedLibraryBlob blob, string entrypoint, string data) throws GLib.Error;
		public abstract async uint demonitor_and_clone_injectee_state (uint id) throws GLib.Error;
		public abstract async void recreate_injectee_thread (uint pid, uint id) throws GLib.Error;

		public abstract async PipeEndpoints make_pipe_endpoints (uint remote_pid) throws GLib.Error;
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
	}
}
