#if DARWIN
namespace Frida {
	[DBus (name = "org.boblycat.frida.FruitjectorHelper")]
	public interface FruitjectorHelper : Object {
		public signal void uninjected (uint id);
		public abstract async void stop () throws IOError;
		public abstract async uint inject (uint pid, string filename, string data_string) throws IOError;
		public abstract async FruitjectorPipeEndpoints make_pipe_endpoints (uint local_pid, uint remote_pid) throws IOError;
	}

	public struct FruitjectorPipeEndpoints {
		public string local_address {
			get;
			private set;
		}

		public string remote_address {
			get;
			private set;
		}

		public FruitjectorPipeEndpoints (string local_address, string remote_address) {
			this.local_address = local_address;
			this.remote_address = remote_address;
		}
	}

	namespace FruitjectorObjectPath {
		public const string HELPER = "/org/boblycat/frida/FruitjectorHelper";
	}
}
#endif
