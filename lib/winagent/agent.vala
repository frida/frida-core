namespace Zed.Agent {
	private static WinIpc.ClientProxy proxy;
	private static int counter = 1;

	public void main (string ipc_server_address) {
		var loop = new MainLoop ();

		proxy = new WinIpc.ClientProxy (ipc_server_address);
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

			Timeout.add (1500, on_timer_tick);
		} catch (WinIpc.ProxyError e) {
			error (e.message);
		}
	}

	private static bool on_timer_tick () {
		proxy.emit ("FunctionCall", new Variant ("s", "EncryptMessage%u".printf (counter++)));
		return true;
	}
}

