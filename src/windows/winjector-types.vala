#if WINDOWS
namespace Frida {
	[DBus (name = "re.frida.WinjectorHelper")]
	public interface WinjectorHelper : Object {
		public abstract async void stop () throws GLib.Error;
		public abstract async void inject (uint pid, string filename_template, string data_string) throws GLib.Error;
	}

	namespace WinjectorObjectPath {
		public const string HELPER = "/re/frida/WinjectorHelper";
	}
}
#endif
