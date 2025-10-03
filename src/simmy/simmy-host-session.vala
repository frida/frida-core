namespace Frida {
	public sealed class SimmyHostSessionBackend : Object, HostSessionBackend {
		private Gee.Map<string, SimmyHostSessionProvider> providers = new Gee.HashMap<string, SimmyHostSessionProvider> ();

		private Cancellable io_cancellable = new Cancellable ();

		public async void start (Cancellable? cancellable) throws IOError {
			string output;
			try {
				output = yield simctl ({ "list", "devices", "--json" }, cancellable);
			} catch (Error e) {
				return;
			}

			Json.Reader reader;
			try {
				reader = new Json.Reader (Json.from_string (output));
			} catch (GLib.Error e) {
				return;
			}

			reader.read_member ("devices");

			foreach (string runtime in reader.list_members ()) {
				reader.read_member (runtime);

				uint n = reader.count_elements ();
				for (uint i = 0; i != n; i++) {
					reader.read_element (i);

					reader.read_member ("state");
					bool is_booted = reader.get_string_value () == "Booted";
					reader.end_member ();

					if (is_booted) {
						reader.read_member ("udid");
						string? udid = reader.get_string_value ();
						reader.end_member ();

						reader.read_member ("name");
						string? name = reader.get_string_value ();
						reader.end_member ();

						if (udid != null && name != null) {
							var prov = new SimmyHostSessionProvider (new Simmy.Device (udid, name, runtime));
							providers[udid] = prov;
							provider_available (prov);
						}
					}

					reader.end_element ();
				}

				reader.end_member ();
			}
		}

		public async void stop (Cancellable? cancellable) throws IOError {
			io_cancellable.cancel ();

			foreach (var provider in providers.values) {
				provider_unavailable (provider);
				yield provider.close (cancellable);
			}
			providers.clear ();
		}
	}

	public sealed class SimmyHostSessionProvider : Object, HostSessionProvider {
		public Simmy.Device device {
			get;
			construct;
		}

		public string id {
			get { return device.udid; }
		}

		public string name {
			get { return device.name; }
		}

		public Variant? icon {
			get { return null; }
		}

		public HostSessionProviderKind kind {
			get {
				return HostSessionProviderKind.REMOTE;
			}
		}

		private SimmyHostSession? host_session;

		public SimmyHostSessionProvider (Simmy.Device device) {
			Object (device: device);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			if (host_session == null)
				return;

			host_session.agent_session_detached.disconnect (on_agent_session_detached);

			//yield host_session.close (cancellable);
			host_session = null;
		}

		public async HostSession create (HostSessionHub hub, HostSessionOptions? options, Cancellable? cancellable)
				throws Error, IOError {
			if (host_session != null)
				throw new Error.INVALID_OPERATION ("Already created");

			HostSessionEntry local_system = yield hub.resolve_host_session ("local", cancellable);

			host_session = new SimmyHostSession (device, local_system);
			host_session.agent_session_detached.connect (on_agent_session_detached);

			return host_session;
		}

		public async void destroy (HostSession session, Cancellable? cancellable) throws Error, IOError {
			if (session != host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");

			host_session.agent_session_detached.disconnect (on_agent_session_detached);

			//yield host_session.close (cancellable);
			host_session = null;
		}

		public async AgentSession link_agent_session (HostSession host_session, AgentSessionId id, AgentMessageSink sink,
				Cancellable? cancellable) throws Error, IOError {
			if (host_session != this.host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");

			return yield this.host_session.link_agent_session (id, sink, cancellable);
		}

		public void unlink_agent_session (HostSession host_session, AgentSessionId id) {
			if (host_session != this.host_session)
				return;

			this.host_session.unlink_agent_session (id);
		}

		public async IOStream link_channel (HostSession host_session, ChannelId id, Cancellable? cancellable)
				throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Channels are not supported by this backend");
		}

		public void unlink_channel (HostSession host_session, ChannelId id) {
		}

		public async ServiceSession link_service_session (HostSession host_session, ServiceSessionId id, Cancellable? cancellable)
				throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Services are not supported by this backend");
		}

		public void unlink_service_session (HostSession host_session, ServiceSessionId id) {
		}

		private void on_agent_session_detached (AgentSessionId id, SessionDetachReason reason, CrashInfo crash) {
			agent_session_detached (id, reason, crash);
		}
	}

	public sealed class SimmyHostSession : Object, HostSession {
		public Simmy.Device device {
			get;
			construct;
		}

		public HostSessionEntry local_system {
			get;
			construct;
		}

		private Cancellable io_cancellable = new Cancellable ();

		public SimmyHostSession (Simmy.Device device, HostSessionEntry local_system) {
			Object (device: device, local_system: local_system);
		}

		construct {
			var s = local_system.session;
			s.process_crashed.connect (on_process_crashed);
			s.agent_session_detached.connect (on_agent_session_detached);
			s.uninjected.connect (on_uninjected);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			io_cancellable.cancel ();
		}

		public async void ping (uint interval_seconds, Cancellable? cancellable) throws Error, IOError {
			throw new Error.INVALID_OPERATION ("Only meant to be implemented by services");
		}

		public async HashTable<string, Variant> query_system_parameters (Cancellable? cancellable) throws Error, IOError {
			var parameters = new HashTable<string, Variant> (str_hash, str_equal);

			string[] tokens = device.runtime.split (".");
			unowned string os_and_version = tokens[tokens.length - 1];
			string[] os_tokens = os_and_version.split ("-", 2);
			string os_name = os_tokens[0];
			string os_version = os_tokens[1].replace ("-", ".");

			var os = new HashTable<string, Variant> (str_hash, str_equal);
			os["id"] = os_name.down ();
			os["name"] = os_name.replace ("iOS", "iPhone OS");
			os["version"] = os_version;
			parameters["os"] = os;

			parameters["platform"] = "darwin";

			parameters["arch"] = "arm64";

			var hardware = new HashTable<string, Variant> (str_hash, str_equal);
			hardware["product"] = device.name;
			parameters["hardware"] = hardware;

			parameters["access"] = "full";

			parameters["name"] = device.name;
			parameters["udid"] = device.udid;

			return parameters;
		}

		public async HostApplicationInfo get_frontmost_application (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async HostApplicationInfo[] enumerate_applications (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			string raw_apps = yield simctl ({ "listapps", device.udid }, cancellable);
			var parser = new TextPList.Parser (raw_apps);
			var reader = new VariantReader (parser.parse ());

			var pids = new Gee.HashMap<string, uint> ();
			string raw_processes = yield simctl ({ "spawn", device.udid, "launchctl", "list" }, cancellable);
			string[] lines = raw_processes.chomp ().split ("\n");
			foreach (string line in lines[1:]) {
				string[] tokens = line.split ("\t", 3);
				if (tokens.length != 3)
					throw new Error.PROTOCOL ("Unexpected launchctl output");

				unowned string raw_pid = tokens[0];
				if (raw_pid == "-")
					continue;

				unowned string label = tokens[2];
				if (!label.has_prefix ("UIKitApplication:"))
					continue;
				string identifier = label[17:].split ("[", 2)[0];

				pids[identifier] = uint.parse (raw_pid);
			}

			var result = new HostApplicationInfo[0];
			foreach (string identifier in reader.list_members ()) {
				reader.read_member (identifier);

				string name = reader
					.read_member ("CFBundleDisplayName")
					.get_string_value ();
				reader.end_member ();

				var info = HostApplicationInfo (identifier, name, pids[identifier], make_parameters_dict ());
				result += info;

				reader.end_member ();
			}
			return result;
		}

		public async HostProcessInfo[] enumerate_processes (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async HostChildInfo[] enumerate_pending_children (Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError {
			string result = yield simctl ({
				"launch",
				"--wait-for-debugger",
				"--terminate-running-process",
				device.udid,
				program,
			}, cancellable);

			string[] tokens = result.split (" ", 2);
			uint pid = uint.parse (tokens[1]);

			return pid;
		}

		public async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public async void resume (uint pid, Cancellable? cancellable) throws GLib.Error {
			yield local_system.session.resume (pid, cancellable);
		}

		public async void kill (uint pid, Cancellable? cancellable) throws GLib.Error {
			yield local_system.session.kill (pid, cancellable);
		}

		public async AgentSessionId attach (uint pid, HashTable<string, Variant> options,
				Cancellable? cancellable) throws GLib.Error {
			return yield local_system.session.attach (pid, options, cancellable);
		}

		public async void reattach (AgentSessionId id, Cancellable? cancellable) throws Error, IOError {
			throw new Error.INVALID_OPERATION ("Only meant to be implemented by services");
		}

		public async AgentSession link_agent_session (AgentSessionId id, AgentMessageSink sink,
				Cancellable? cancellable) throws Error, IOError {
			return yield local_system.provider.link_agent_session (local_system.session, id, sink, cancellable);
		}

		public void unlink_agent_session (AgentSessionId id) {
			local_system.provider.unlink_agent_session (local_system.session, id);
		}

		public async InjectorPayloadId inject_library_file (uint pid, string path, string entrypoint, string data,
				Cancellable? cancellable) throws GLib.Error {
			return yield local_system.session.inject_library_file (pid, path, entrypoint, data, cancellable);
		}

		public async InjectorPayloadId inject_library_blob (uint pid, uint8[] blob, string entrypoint, string data,
				Cancellable? cancellable) throws GLib.Error {
			return yield local_system.session.inject_library_blob (pid, blob, entrypoint, data, cancellable);
		}

		public async ChannelId open_channel (string address, Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public IOStream link_channel (ChannelId id) throws Error {
			throw_not_supported ();
		}

		public void unlink_channel (ChannelId id) {
			assert_not_reached ();
		}

		public async ServiceSessionId open_service (string address, Cancellable? cancellable) throws Error, IOError {
			throw_not_supported ();
		}

		public ServiceSession link_service_session (ServiceSessionId id) throws Error {
			throw_not_supported ();
		}

		public void unlink_service_session (ServiceSessionId id) {
			assert_not_reached ();
		}

		private void on_process_crashed (CrashInfo crash) {
			process_crashed (crash);
		}

		private void on_agent_session_detached (AgentSessionId id, SessionDetachReason reason, CrashInfo crash) {
			agent_session_detached (id, reason, crash);
		}

		private void on_uninjected (InjectorPayloadId id) {
			uninjected (id);
		}

		[NoReturn]
		private static void throw_not_supported () throws Error {
			throw new Error.NOT_SUPPORTED ("Not yet supported by the Simmy backend");
		}
	}

	[CCode (gir_namespace = "FridaSimmy", gir_version = "1.0")]
	namespace Simmy {
		public class Device : Object {
			public string udid {
				get;
				construct;
			}

			public string name {
				get;
				construct;
			}

			public string runtime {
				get;
				construct;
			}

			public Device (string udid, string name, string runtime) {
				Object (
					udid: udid,
					name: name,
					runtime: runtime
				);
			}
		}
	}

	private async string simctl (string[] args, Cancellable? cancellable) throws Error, IOError {
		var launcher = new SubprocessLauncher (STDIN_PIPE | STDOUT_PIPE | STDERR_SILENCE);

		Subprocess proc;
		string output;
		try {
			var argv = new Gee.ArrayList<string?> ();
			argv.add_all_array ({ "xcrun", "simctl" });
			argv.add_all_array (args);
			argv.add (null);

			proc = launcher.spawnv (argv.to_array ());

			yield proc.communicate_utf8_async (null, cancellable, out output, null);
		} catch (GLib.Error e) {
			throw new Error.NOT_SUPPORTED ("Unable to spawn simctl: %s", e.message);
		}

		var exit_status = proc.get_exit_status ();
		if (exit_status != 0)
			throw new Error.NOT_SUPPORTED ("Unable to query simctl, exit status: %d", exit_status);

		return output;
	}
}
