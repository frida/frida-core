#if DARWIN
namespace Frida {
	[DBus (name = "org.boblycat.frida.FruitjectorHelper")]
	public interface FruitjectorHelper : Object {
		public abstract async void stop () throws IOError;
		public abstract async void inject (uint pid, string data_string) throws IOError;
	}

	namespace FruitjectorObjectPath {
		public const string HELPER = "/org/boblycat/frida/FruitjectorHelper";
	}
}
#endif
