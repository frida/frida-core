namespace Frida.WebGateway {
	private static Application application;

	private static bool output_version = false;
	private static string? gateway_address = null;
	private static string? gateway_certpath = null;
	private static string? target_address = null;
	private static string? target_certpath = null;
	private static string? root_path = null;
	private static string? origin = null;
#if !WINDOWS
	private static bool daemonize = false;
#endif

	private delegate void ReadyHandler (bool success);

	const OptionEntry[] options = {
		{ "version", 0, 0, OptionArg.NONE, ref output_version, "Output version information and exit", null },
		{ "gateway-endpoint", 0, 0, OptionArg.STRING, ref gateway_address, "Expose gateway endpoint on ADDRESS", "ADDRESS" },
		{ "gateway-certificate", 0, 0, OptionArg.FILENAME, ref gateway_certpath, "Enable TLS on gateway endpoint using CERTIFICATE",
			"CERTIFICATE" },
		{ "target-endpoint", 0, 0, OptionArg.STRING, ref target_address, "Connect to target at ADDRESS", "ADDRESS" },
		{ "target-certificate", 0, 0, OptionArg.FILENAME, ref target_certpath, "Speak TLS with target, expecting CERTIFICATE",
			"CERTIFICATE" },
		{ "root", 0, 0, OptionArg.FILENAME, ref root_path, "Serve static files inside ROOT (by default no files are served)",
			"ROOT" },
		{ "origin", 0, 0, OptionArg.STRING, ref origin, "Only accept requests with “Origin” header matching ORIGIN " +
			"(by default any origin will be accepted)", "ORIGIN" },
#if !WINDOWS
		{ "daemonize", 'D', 0, OptionArg.NONE, ref daemonize, "Detach and become a daemon", null },
#endif
		{ null }
	};

	private static int main (string[] args) {
#if HAVE_GIOOPENSSL
		GIOOpenSSL.register ();
#endif

		try {
			var ctx = new OptionContext ();
			ctx.set_help_enabled (true);
			ctx.add_main_entries (options, null);
			ctx.parse (ref args);
		} catch (OptionError e) {
			printerr ("%s\n", e.message);
			printerr ("Run '%s --help' to see a full list of available command line options.\n", args[0]);
			return 1;
		}

		if (output_version) {
			stdout.printf ("%s\n", version_string ());
			return 0;
		}

		EndpointParameters gateway_params, target_params;
		try {
			gateway_params = new EndpointParameters (gateway_address, 0, parse_certificate (gateway_certpath));
			target_params = new EndpointParameters (target_address, 0, parse_certificate (target_certpath));
		} catch (GLib.Error e) {
			printerr ("%s\n", e.message);
			return 2;
		}

		File? root = (root_path != null) ? File.new_for_path (root_path) : null;

		ReadyHandler? on_ready = null;
#if !WINDOWS
		if (daemonize) {
			var sync_fds = new int[2];

			try {
				Unix.open_pipe (sync_fds, 0);
				Unix.set_fd_nonblocking (sync_fds[0], true);
				Unix.set_fd_nonblocking (sync_fds[1], true);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			var sync_in = new UnixInputStream (sync_fds[0], true);
			var sync_out = new UnixOutputStream (sync_fds[1], true);

			var pid = Posix.fork ();
			if (pid != 0) {
				try {
					var status = new uint8[1];
					sync_in.read (status);
					return status[0];
				} catch (GLib.Error e) {
					return 3;
				}
			}

			sync_in = null;
			on_ready = (success) => {
				if (success) {
					Posix.setsid ();

					var null_in = Posix.open ("/dev/null", Posix.O_RDONLY);
					var null_out = Posix.open ("/dev/null", Posix.O_WRONLY);
					Posix.dup2 (null_in, Posix.STDIN_FILENO);
					Posix.dup2 (null_out, Posix.STDOUT_FILENO);
					Posix.dup2 (null_out, Posix.STDERR_FILENO);
					Posix.close (null_in);
					Posix.close (null_out);
				}

				var status = new uint8[1];
				status[0] = success ? 0 : 1;
				try {
					sync_out.write (status);
				} catch (GLib.Error e) {
				}
				sync_out = null;
			};
		}
#endif

		application = new Application (new WebGatewayService (gateway_params, target_params, root, origin));

		Posix.signal (Posix.Signal.INT, (sig) => {
			application.stop ();
		});
		Posix.signal (Posix.Signal.TERM, (sig) => {
			application.stop ();
		});

		if (on_ready != null) {
			application.ready.connect (() => {
				on_ready (true);
				on_ready = null;
			});
		}

		return application.run ();
	}

	private class Application : Object {
		public signal void ready ();

		public WebGatewayService service {
			get;
			construct;
		}

		private Cancellable io_cancellable = new Cancellable ();

		private MainLoop loop = new MainLoop ();
		private int exit_code;
		private bool stopping;

		public Application (WebGatewayService service) {
			Object (service: service);
		}

		public int run () {
			Idle.add (() => {
				start.begin ();
				return false;
			});

			exit_code = 0;

			loop.run ();

			return exit_code;
		}

		private async void start () {
			try {
				yield service.start (io_cancellable);
			} catch (GLib.Error e) {
				if (e is IOError.CANCELLED)
					return;
				printerr ("Unable to start: %s\n", e.message);
				exit_code = 4;
				loop.quit ();
				return;
			}

			Idle.add (() => {
				ready ();
				return false;
			});
		}

		public void stop () {
			Idle.add (() => {
				perform_stop.begin ();
				return false;
			});
		}

		private async void perform_stop () {
			if (stopping)
				return;
			stopping = true;

			io_cancellable.cancel ();

			try {
				yield service.stop ();
			} catch (IOError e) {
				assert_not_reached ();
			}

			Idle.add (() => {
				loop.quit ();
				return false;
			});
		}
	}

	private TlsCertificate? parse_certificate (string? path) throws GLib.Error {
		if (path == null)
			return null;

		return new TlsCertificate.from_file (path);
	}
}
