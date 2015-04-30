#if LINUX
namespace Frida {
	[DBus (name = "re.frida.Helper")]
	public interface Helper : Object {
		public signal void uninjected (uint id);
		public abstract async void stop () throws GLib.Error;
		public abstract async uint spawn (string path, string[] argv, string[] envp) throws GLib.Error;
		public abstract async void resume (uint pid) throws GLib.Error;
		public abstract async void kill (uint pid) throws GLib.Error;
		public abstract async uint inject (uint pid, string filename, string data_string, string temp_path) throws GLib.Error;
	}

	namespace ObjectPath {
		public const string HELPER = "/re/frida/Helper";
	}
}
#endif
