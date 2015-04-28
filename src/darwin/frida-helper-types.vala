#if DARWIN
namespace Frida {
	[DBus (name = "re.frida.Helper")]
	public interface Helper : Object {
		public signal void uninjected (uint id);
		public abstract async void stop () throws Error;
		public abstract async uint spawn (string path, string[] argv, string[] envp) throws Error;
		public abstract async void resume (uint pid) throws Error;
		public abstract async uint inject (uint pid, string filename, string data_string) throws Error;
		public abstract async PipeEndpoints make_pipe_endpoints (uint local_pid, uint remote_pid) throws Error;
	}

	public struct PipeEndpoints {
		public string local_address {
			get;
			private set;
		}

		public string remote_address {
			get;
			private set;
		}

		public PipeEndpoints (string local_address, string remote_address) {
			this.local_address = local_address;
			this.remote_address = remote_address;
		}
	}

	namespace ObjectPath {
		public const string HELPER = "/re/frida/Helper";
	}
}
#endif
