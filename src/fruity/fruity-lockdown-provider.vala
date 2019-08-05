namespace Frida {
	public class FruityLockdownProvider : Object, HostSessionProvider {
		public string id {
			get { return _id; }
		}
		private string _id;

		public string name {
			get { return device_name; }
		}

		public Image? icon {
			get { return device_icon; }
		}

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.USB; }
		}

		public string device_name {
			get;
			construct;
		}

		public Image? device_icon {
			get;
			construct;
		}

		public Fruity.DeviceDetails device_details {
			get;
			construct;
		}

		public FruityLockdownProvider (string name, Image? icon, Fruity.DeviceDetails details) {
			Object (
				device_name: name + " [lockdown]",
				device_icon: icon,
				device_details: details
			);
		}

		construct {
			_id = device_details.udid.raw_value + ":lockdown";
		}

		public async void close (Cancellable? cancellable) throws IOError {
		}

		public async HostSession create (string? location, Cancellable? cancellable) throws Error, IOError {
			try {
				var lockdown = yield Fruity.LockdownClient.open (device_details, cancellable);

				return new FruityLockdownSession (lockdown);
			} catch (Fruity.LockdownError e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
		}

		public async void destroy (HostSession host_session, Cancellable? cancellable) throws Error, IOError {
			var session = host_session as FruityLockdownSession;

			yield session.close (cancellable);
		}

		public async AgentSession obtain_agent_session (HostSession host_session, AgentSessionId agent_session_id,
				Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet implemented");
		}
	}

	public class FruityLockdownSession : Object, HostSession {
		public Fruity.LockdownClient lockdown {
			get;
			construct;
		}

		private Gee.HashMap<uint, SpawnEntry> spawn_entries = new Gee.HashMap<uint, SpawnEntry> ();

		public FruityLockdownSession (Fruity.LockdownClient lockdown) {
			Object (lockdown: lockdown);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			yield lockdown.close (cancellable);
		}

		public async HostApplicationInfo get_frontmost_application (Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet implemented");
		}

		public async HostApplicationInfo[] enumerate_applications (Cancellable? cancellable) throws Error, IOError {
			try {
				var installation_proxy = yield Fruity.InstallationProxyClient.open (lockdown, cancellable);

				var apps = yield installation_proxy.browse (cancellable);

				uint no_pid = 0;
				var no_icon = ImageData (0, 0, 0, "");

				var result = new HostApplicationInfo[apps.size];
				int i = 0;
				foreach (var app in apps) {
					result[i] = HostApplicationInfo (app.identifier, app.name, no_pid, no_icon, no_icon);
					i++;
				}

				return result;
			} catch (Fruity.InstallationProxyError e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
		}

		public async HostProcessInfo[] enumerate_processes (Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet implemented");
		}

		public async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet implemented");
		}

		public async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet implemented");
		}

		public async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet implemented");
		}

		public async HostChildInfo[] enumerate_pending_children (Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet implemented");
		}

		public async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError {
			if (program[0] == '/')
				throw new Error.NOT_SUPPORTED ("Only able to spawn apps");

			var launch_options = new Fruity.LaunchOptions ();

			if (options.has_envp)
				throw new Error.NOT_SUPPORTED ("The 'envp' option is not supported when spawning iOS apps");

			if (options.has_env)
				launch_options.env = options.env;

			if (options.cwd.length > 0)
				throw new Error.NOT_SUPPORTED ("The 'cwd' option is not supported when spawning iOS apps");

			var aux_options = options.load_aux ();

			if (aux_options.contains ("aslr")) {
				string? aslr = null;
				if (!aux_options.lookup ("aslr", "s", out aslr) || (aslr != "auto" && aslr != "disable")) {
					throw new Error.INVALID_ARGUMENT (
						"The 'aslr' option must be a string set to either 'auto' or 'disable'");
				}
				launch_options.aslr = (aslr == "auto") ? Fruity.Aslr.AUTO : Fruity.Aslr.DISABLE;
			}

			try {
				var installation_proxy = yield Fruity.InstallationProxyClient.open (lockdown, cancellable);

				var app = yield installation_proxy.lookup_one (program, cancellable);
				if (app == null)
					throw new Error.INVALID_ARGUMENT ("Unable to find app with bundle identifier '%s'", program);

				if (!app.debuggable)
					throw new Error.INVALID_ARGUMENT ("Application '%s' is not debuggable", program);

				var lldb = yield Fruity.LLDBClient.open (lockdown, cancellable);

				string[] argv = { app.path };
				if (options.has_argv) {
					var provided_argv = options.argv;
					var length = provided_argv.length;
					for (int i = 1; i < length; i++)
						argv += provided_argv[i];
				}

				var process = yield lldb.launch (argv, launch_options, cancellable);

				var pid = process.pid;

				var entry = new SpawnEntry (lldb, process);
				entry.closed.connect (on_spawn_entry_closed);
				entry.output.connect (on_spawn_entry_output);
				spawn_entries[pid] = entry;

				return pid;
			} catch (Fruity.InstallationProxyError e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			} catch (Fruity.LLDBError e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
		}

		public async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet implemented");
		}

		public async void resume (uint pid, Cancellable? cancellable) throws Error, IOError {
			var entry = spawn_entries[pid];
			if (entry == null)
				throw new Error.INVALID_ARGUMENT ("Invalid PID");

			yield entry.resume (cancellable);
		}

		public async void kill (uint pid, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet implemented");
		}

		public async AgentSessionId attach_to (uint pid, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet implemented");
		}

		public async InjectorPayloadId inject_library_file (uint pid, string path, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet implemented");
		}

		public async InjectorPayloadId inject_library_blob (uint pid, uint8[] blob, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet implemented");
		}

		private void on_spawn_entry_closed (SpawnEntry entry) {
			spawn_entries.unset (entry.process.pid);

			entry.closed.disconnect (on_spawn_entry_closed);
			entry.output.disconnect (on_spawn_entry_output);
		}

		private void on_spawn_entry_output (SpawnEntry entry, Bytes bytes) {
			output (entry.process.pid, 1, bytes.get_data ());
		}

		private class SpawnEntry : Object {
			public signal void closed ();
			public signal void output (Bytes bytes);

			public Fruity.LLDBClient lldb {
				get;
				construct;
			}

			public Fruity.ProcessInfo process {
				get;
				construct;
			}

			public SpawnEntry (Fruity.LLDBClient lldb, Fruity.ProcessInfo process) {
				Object (
					lldb: lldb,
					process: process
				);
			}

			construct {
				lldb.closed.connect (on_lldb_closed);
				lldb.console_output.connect (on_lldb_console_output);
			}

			~SpawnEntry () {
				lldb.closed.disconnect (on_lldb_closed);
				lldb.console_output.disconnect (on_lldb_console_output);
			}

			public async void resume (Cancellable? cancellable) throws Error, IOError {
				try {
					yield lldb.continue (cancellable);
				} catch (Fruity.LLDBError e) {
					throw new Error.NOT_SUPPORTED ("%s", e.message);
				}
			}

			private void on_lldb_closed () {
				closed ();
			}

			private void on_lldb_console_output (Bytes bytes) {
				output (bytes);
			}
		}
	}
}
