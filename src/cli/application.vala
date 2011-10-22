public class Zed.Application : Object {
	private HostSessionService host_session_service;

	private MainLoop main_loop;
	private unowned Thread<bool> input_thread;

	/* FIXME: anti-pattern galore */
	private Gee.HashMap<int, HostSessionProvider> provider_by_id = new Gee.HashMap<int, HostSessionProvider> ();
	private Gee.HashMap<HostSessionProvider, HostSession> host_session_by_provider = new Gee.HashMap<HostSessionProvider, HostSession> ();
	private Gee.HashMap<uint, AgentSession> agent_session_by_pid = new Gee.HashMap<uint, AgentSession> ();
	private int last_id = 1;

	construct {
		main_loop = new MainLoop ();

		host_session_service = new HostSessionService.with_default_backends ();
		host_session_service.provider_available.connect ((provider) => {
			var id = last_id++;
			provider_by_id[id] = provider;
			stdout.printf ("Provider<%d> Available: '%s'\n", id, provider.name);
		});
		host_session_service.provider_unavailable.connect ((provider) => {
			var id = -1;
			foreach (var entry in provider_by_id.entries) {
				if (entry.value == provider) {
					id = entry.key;
					break;
				}
			}
			provider_by_id.unset (id);
			host_session_by_provider.unset (provider);
			stdout.printf ("Provider<%d> Unavailable: '%s'\n", id, provider.name);
		});
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
			var line = Readline.readline ("> ");
			if (line == null)
				break;
			line = line.strip ();
			if (line == "")
				continue;
			Readline.History.add (line);

			string command;
			string[] args;
			try {
				if (!Shell.parse_argv (line, out args))
					continue;
				command = args[0];
			} catch (ShellError e) {
				stderr.printf ("ERROR: %s\n", e.message);
				continue;
			}

			if (command == "ls" && args.length == 2) {
				var id = int.parse (args[1]);
				Idle.add (() => {
					var provider = provider_by_id[id];
					if (provider != null)
						enumerate (provider);
					else
						stderr.printf ("ERROR: invalid provider!\n");
					return false;
				});
			} else if (command == "inject" && args.length == 4) {
				var id = int.parse (args[1]);
				var pid = int.parse (args[2]);
				string script;
				try {
					FileUtils.get_contents (args[3], out script);
				} catch (FileError e) {
					stderr.printf ("ERROR: %s\n", e.message);
					continue;
				}
				Idle.add (() => {
					var provider = provider_by_id[id];
					if (provider != null)
						inject (script, provider, pid);
					else
						stderr.printf ("ERROR: invalid provider!\n");
					return false;
				});
			}

		}

		Idle.add (() => {
			stop ();
			return false;
		});

		return true;
	}

	private async void enumerate (HostSessionProvider provider) {
		try {
			var session = yield obtain_host_session (provider);
			stdout.printf ("PID\tNAME\n");
			foreach (var process in yield session.enumerate_processes ()) {
				stdout.printf ("%u\t%s\n", process.pid, process.name);
			}
		} catch (IOError e) {
			stderr.printf ("ERROR: %s\n", e.message);
		}
	}

	private async void inject (string script, HostSessionProvider provider, uint pid) {
		try {
			var host_session = yield obtain_host_session (provider);
			var agent_session = yield obtain_agent_session (provider, host_session, pid);
			var id = yield agent_session.create_script (script);
			agent_session.message_from_script.connect ((sid, msg) => {
				if (sid == id)
					stdout.printf ("Message from script: %s\n", msg);
			});
			yield agent_session.load_script (id);
		} catch (IOError e) {
			stderr.printf ("ERROR: %s\n", e.message);
		}
	}

	private async HostSession obtain_host_session (HostSessionProvider provider) throws IOError {
		var session = host_session_by_provider[provider];
		if (session == null) {
			session = yield provider.create ();
			host_session_by_provider[provider] = session;
		}
		return session;
	}

	private async AgentSession obtain_agent_session (HostSessionProvider provider, HostSession host_session, uint pid) throws IOError {
		var session = agent_session_by_pid[pid];
		if (session == null) {
			var id = yield host_session.attach_to (pid);
			session = yield provider.obtain_agent_session (id);
			agent_session_by_pid[pid] = session;
		}
		return session;
	}
}
