public class Zed.Application : Object {
	private HostSessionService host_session_service;

	private MainLoop main_loop;
	private unowned Thread<bool> input_thread;

	construct {
		main_loop = new MainLoop ();

		host_session_service = new HostSessionService.with_default_backends ();
	}

	public void run () {
		Idle.add (() => {
			start ();
			return false;
		});
		main_loop.run ();
	}

	private async void start () {
		yield host_session_service.start ();

		try {
			input_thread = Thread.create<bool> (input_loop, true);
		} catch (ThreadError e) {
			assert_not_reached ();
		}
	}

	private async void stop () {
		input_thread.join ();

		yield host_session_service.stop ();
		main_loop.quit ();
	}

	private bool input_loop () {
		Readline.initialize ();
		Readline.parse_and_bind ("bind \"^R\" em-inc-search-prev");

		while (true) {
			var command = Readline.readline ("> ");
			if (command == null)
				break;
			command = command.strip ();
			if (command == "")
				continue;
			stdout.printf ("OK [%s]\n", command);
			Readline.History.add (command);
		}

		Idle.add (() => {
			stop ();
			return false;
		});

		return true;
	}
}
