namespace Winjector {
	public class ServiceManager : Object {
		private WinIpc.ClientProxy master;
		private string helper32_address;
		private string helper64_address;

		public ServiceManager (string master_address, string helper32_address, string helper64_address) {
			master = new WinIpc.ClientProxy (master_address);

			this.helper32_address = helper32_address;
			this.helper64_address = helper64_address;
		}

		public void run () {
		}
	}

	public class Service : Object {
		public void run () {
		}
	}
}

int main (string[] args) {
	if (args.length > 1) {
		if (args.length != 4)
			return 1;

		var master_address = args[1];
		var helper32_address = args[2];
		var helper64_address = args[3];

		var manager = new Winjector.ServiceManager (master_address, helper32_address, helper64_address);
		manager.run ();

		return 0;
	}

	var service = new Winjector.Service ();
	service.run ();

	return 0;
}
