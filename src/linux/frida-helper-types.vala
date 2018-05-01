namespace Frida {
	[DBus (name = "re.frida.Helper")]
	public interface Helper : Object {
		public signal void output (uint pid, int fd, uint8[] data);
		public signal void uninjected (uint id);

		public abstract async void stop () throws GLib.Error;

		public abstract async uint spawn (string path, string[] argv, bool has_envp, string[] envp) throws GLib.Error;
		public abstract async void prepare_exec_transition (uint pid) throws GLib.Error;
		public abstract async void await_exec_transition (uint pid) throws GLib.Error;
		public abstract async void cancel_exec_transition (uint pid) throws GLib.Error;
		public abstract async void input (uint pid, uint8[] data) throws GLib.Error;
		public abstract async void resume (uint pid) throws GLib.Error;
		public abstract async void kill (uint pid) throws GLib.Error;

		public abstract async uint inject_library_file (uint pid, string path, string entrypoint, string data, string temp_path) throws GLib.Error;
		public abstract async uint demonitor_and_clone_injectee_state (uint id) throws GLib.Error;
		public abstract async void recreate_injectee_thread (uint pid, uint id) throws GLib.Error;
	}

	namespace ObjectPath {
		public const string HELPER = "/re/frida/Helper";
	}
}
