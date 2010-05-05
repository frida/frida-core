namespace Zed.Agent {
	public void main (string ipc_server_address) {
		initialize ();

		var loop = new MainLoop ();

		var proxy = new WinIpc.ClientProxy (ipc_server_address);
		proxy.add_notify_handler ("Stop", "", (arg) => {
			loop.quit ();
		});
		proxy.add_notify_handler ("ExitProcess", "u", (arg) => {
			uint exit_code;
			arg.get ("u", out exit_code);
			exit_process (exit_code);
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

	private extern void initialize ();
	private extern void exit_process (uint exit_code);
}

