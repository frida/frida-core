#if DARWIN
namespace Frida {
	[DBus (name = "org.boblycat.frida.FruitjectorHelper")]
	public interface FruitjectorHelper : Object {
		public signal void uninjected (uint id);
		public abstract async void stop () throws IOError;
		public abstract async uint inject (uint pid, string filename, string data_string) throws IOError;
	}

	namespace FruitjectorObjectPath {
		public const string HELPER = "/org/boblycat/frida/FruitjectorHelper";
	}
}
#endif
