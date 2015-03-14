#if LINUX
namespace Frida {
	[DBus (name = "re.frida.Helper")]
	public interface Helper : Object {
		public signal void uninjected (uint id);
		public abstract async void stop () throws IOError;
		public abstract async uint spawn (string path, string[] argv, string[] envp) throws IOError;
		public abstract async void resume (uint pid) throws IOError;
		public abstract async uint inject (uint pid, string filename, string data_string) throws IOError;
	}

	namespace ObjectPath {
		public const string HELPER = "/re/frida/Helper";
	}
}
#endif
