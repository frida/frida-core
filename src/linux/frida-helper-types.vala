namespace Frida {
	[DBus (name = "re.frida.Helper")]
	public interface Helper : Object {
		public signal void uninjected (uint id);
		public abstract async void stop () throws GLib.Error;
		public abstract async uint spawn (string path, string[] argv, string[] envp) throws GLib.Error;
		public abstract async void input (uint pid, uint8[] data) throws GLib.Error;
		public abstract async void resume (uint pid) throws GLib.Error;
		public abstract async void kill (uint pid) throws GLib.Error;
		public abstract async uint inject_library_file (uint pid, string path, string entrypoint, string data, string temp_path) throws GLib.Error;

		public signal void output (uint pid, int fd, uint8[] data);
	}

	namespace ObjectPath {
		public const string HELPER = "/re/frida/Helper";
	}
}
