public class Zed.Application : Object {
	private HostSessionService host_session_service;

	private MainLoop main_loop;
	private MainContext main_context;

	construct {
		main_context = new MainContext ();
		main_context.push_thread_default ();
		main_loop = new MainLoop (main_context);

		host_session_service = new HostSessionService.with_default_backends ();
	}

	public void run () {
		main_loop.run ();
	}

	private async void stop () {
		yield host_session_service.stop ();
		main_loop.quit ();
	}
}
