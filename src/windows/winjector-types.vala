namespace Frida {
	[DBus (name = "org.boblycat.frida.WinjectorHelper")]
	public interface WinjectorHelper : Object {
		public abstract async void stop () throws IOError;
		public abstract async void inject (uint pid, string filename_template, string data_string) throws IOError;
	}

	namespace WinjectorObjectPath {
		public const string HELPER = "/org/boblycat/frida/WinjectorHelper";
	}
}
