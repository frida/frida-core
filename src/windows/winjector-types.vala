#if WINDOWS
namespace Frida {
	[DBus (name = "re.frida.WinjectorHelper")]
	public interface WinjectorHelper : Object {
		public abstract async void stop () throws GLib.Error;
		public abstract async uint inject_library_file (uint pid, string path, string entrypoint, string data) throws GLib.Error;

		public signal void uninjected (uint id);
	}

	namespace WinjectorObjectPath {
		public const string HELPER = "/re/frida/WinjectorHelper";
	}
}
#endif
