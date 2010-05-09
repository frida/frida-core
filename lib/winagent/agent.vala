namespace Zed.Agent {
	public void main (string ipc_server_address) {
		var loop = new MainLoop ();

		var proxy = new WinIpc.ClientProxy (ipc_server_address);
		proxy.add_notify_handler ("Stop", "", (arg) => {
			loop.quit ();
		});

		Idle.add (() => {
			do_establish (proxy);
			return false;
		});

		loop.run ();
	}

	private async void do_establish (WinIpc.ClientProxy proxy) {
		try {
			yield proxy.establish ();
		} catch (WinIpc.ProxyError e) {
			error (e.message);
		}
	}
}

