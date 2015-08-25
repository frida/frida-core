#if LINUX
namespace Frida {
	public class LinuxHostSessionBackend : Object, HostSessionBackend {
		private LinuxHostSessionProvider local_provider;

		public async void start () {
			assert (local_provider == null);
			local_provider = new LinuxHostSessionProvider ();
			provider_available (local_provider);
		}

		public async void stop () {
			assert (local_provider != null);
			provider_unavailable (local_provider);
			yield local_provider.close ();
			local_provider = null;
		}
	}

	public class LinuxHostSessionProvider : Object, HostSessionProvider {
		public string name {
			get { return "Local System"; }
		}

		public ImageData? icon {
			get { return null; }
		}

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.LOCAL_SYSTEM; }
		}

		private LinuxHostSession host_session;

		public async void close () {
			if (host_session != null)
				yield host_session.close ();
			host_session = null;
		}

		public async HostSession create (string? location = null) throws Error {
			assert (location == null);
			if (host_session != null)
				throw new Error.INVALID_ARGUMENT ("Invalid location: already created");
			host_session = new LinuxHostSession ();
			host_session.agent_session_closed.connect (on_agent_session_closed);
			return host_session;
		}

		public async void destroy (HostSession session) throws Error {
			if (session != host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");
			host_session.agent_session_closed.disconnect (on_agent_session_closed);
			yield host_session.close ();
			host_session = null;
		}

		public async AgentSession obtain_agent_session (HostSession host_session, AgentSessionId agent_session_id) throws Error {
			if (host_session != this.host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");
			return yield this.host_session.obtain_agent_session (agent_session_id);
		}

		private void on_agent_session_closed (AgentSessionId id, AgentSession session) {
			agent_session_closed (id);
		}
	}

	public class LinuxHostSession : BaseDBusHostSession {
		private HelperProcess helper;
		private Linjector injector;
		private AgentDescriptor agent_desc;

#if ANDROID
		private RoboAgent robo_agent;
#endif

		construct {
			helper = new HelperProcess ();
			injector = new Linjector.with_helper (helper);

			var blob32 = Frida.Data.Agent.get_frida_agent_32_so_blob ();
			var blob64 = Frida.Data.Agent.get_frida_agent_64_so_blob ();
			agent_desc = new AgentDescriptor ("frida-agent-%u.so",
				new MemoryInputStream.from_data (blob32.data, null),
				new MemoryInputStream.from_data (blob64.data, null));

#if ANDROID
			robo_agent = new RoboAgent (this);
#endif
		}

		public override async void close () {
			yield base.close ();

			var uninjected_handler = injector.uninjected.connect ((id) => close.callback ());
			while (injector.any_still_injected ())
				yield;
			injector.disconnect (uninjected_handler);
			yield injector.close ();
			injector = null;

			yield helper.close ();
			helper = null;

#if ANDROID
			yield robo_agent.close ();
			robo_agent = null;
#endif
		}

		public override async HostApplicationInfo get_frontmost_application () throws Error {
			return System.get_frontmost_application ();
		}

		public override async HostApplicationInfo[] enumerate_applications () throws Error {
#if ANDROID
			return yield robo_agent.enumerate_applications ();
#else
			return System.enumerate_applications ();
#endif
		}

		public override async HostProcessInfo[] enumerate_processes () throws Error {
			return System.enumerate_processes ();
		}

		public override async uint spawn (string path, string[] argv, string[] envp) throws Error {
#if ANDROID
			if (!path.has_prefix ("/")) {
				string package_name = path;
				if (argv.length > 1)
					throw new Error.INVALID_ARGUMENT ("Too many arguments: expected package name only");
				return yield robo_agent.spawn (package_name);
			} else {
				return yield helper.spawn (path, argv, envp);
			}
#else
			return yield helper.spawn (path, argv, envp);
#endif
		}

		public override async void resume (uint pid) throws Error {
#if ANDROID
			if (yield robo_agent.resume (pid))
				return;
#endif
			yield helper.resume (pid);
		}

		public override async void kill (uint pid) throws Error {
			yield helper.kill (pid);
		}

		protected override async IOStream perform_attach_to (uint pid, out Object? transport) throws Error {
			PipeTransport.set_temp_directory (helper.tempdir.path);
			PipeTransport t;
			Pipe stream;
			try {
				t = new PipeTransport ();
				stream = new Pipe (t.local_address);
			} catch (IOError stream_error) {
				throw new Error.NOT_SUPPORTED (stream_error.message);
			}
			yield injector.inject (pid, agent_desc, t.remote_address);
			transport = t;
			return stream;
		}
	}

#if ANDROID
	private class RoboAgent : ParasiteService {
		private Gee.HashMap<uint, SpawnedApp> spawned_app_by_pid = new Gee.HashMap<uint, SpawnedApp> ();

		public RoboAgent (LinuxHostSession host_session) {
			string * source = Frida.Data.Android.get_robo_agent_js_blob ().data;
			base (host_session, "system_server", source);
		}

		public async HostApplicationInfo[] enumerate_applications () throws Error {
			var apps = yield call ("enumerateApplications", new Json.Node[] {});
			var items = apps.get_array ();
			var length = items.get_length ();
			var result = new HostApplicationInfo[length];
			var no_icon = ImageData (0, 0, 0, "");
			for (var i = 0; i != length; i++) {
				var item = items.get_array_element (i);
				var identifier = item.get_string_element (0);
				var name = item.get_string_element (1);
				var pid = (uint) item.get_int_element (2);
				result[i] = HostApplicationInfo (identifier, name, pid, no_icon, no_icon);
			}
			return result;
		}

		public async uint spawn (string package_name) throws Error {
			bool existing_app_killed = false;
			do {
				existing_app_killed = false;
				var installed_apps = yield enumerate_applications ();
				foreach (var installed_app in installed_apps) {
					if (installed_app.identifier == package_name) {
						var running_pid = installed_app.pid;
						if (running_pid != 0) {
							System.kill (running_pid);

							existing_app_killed = true;

							var source = new TimeoutSource (250);
							source.set_callback (() => {
								spawn.callback ();
								return false;
							});
							source.attach (MainContext.get_thread_default ());
							yield;
						}
						break;
					}
				}
			} while (existing_app_killed);

			var result = yield call ("spawn", new Json.Node[] { new Json.Node.alloc ().init_string (package_name) });
			var pid = (uint) result.get_int ();

			var app = new SpawnedApp (package_name);
			spawned_app_by_pid[pid] = app;

			return pid;
		}

		public async bool resume (uint pid) throws Error {
			SpawnedApp app;
			if (!spawned_app_by_pid.unset (pid, out app))
				return false;
			return true;
		}

		private class SpawnedApp : Object {
			public string package_name {
				get;
				construct;
			}

			public SpawnedApp (string package_name) {
				Object (package_name: package_name);
			}
		}
	}

	private class ParasiteService : Object {
		private LinuxHostSession host_session;
		private string target_process;
		private string script_source;
		private AgentSession cached_session;
		private AgentScriptId cached_script;

		private Gee.HashMap<string, PendingResponse> pending = new Gee.HashMap<string, PendingResponse> ();
		private int64 next_request_id = 1;

		protected ParasiteService (LinuxHostSession host_session, string target_process, string script_source) {
			this.host_session = host_session;
			this.target_process = target_process;
			this.script_source = script_source;
		}

		public async void close () {
			if (cached_script.handle != 0) {
				try {
					yield cached_session.destroy_script (cached_script);
				} catch (GLib.Error e) {
				}
				cached_script = AgentScriptId (0);
			}

			if (cached_session != null) {
				try {
					yield cached_session.close ();
				} catch (GLib.Error e) {
				}
				cached_session = null;
			}

			host_session = null;
		}

		protected async Json.Node call (string method, Json.Node[] args) throws Error {
			AgentSession session;
			AgentScriptId script;
			yield get_agent (out session, out script);

			var request_id = next_request_id++;

			var builder = new Json.Builder ();
			builder
			.begin_array ()
			.add_string_value ("frida:rpc")
			.add_int_value (request_id)
			.add_string_value ("call")
			.add_string_value (method)
			.begin_array ();
			foreach (var arg in args)
				builder.add_value (arg);
			builder
			.end_array ()
			.end_array ();

			var generator = new Json.Generator ();
			generator.set_root (builder.get_root ());
			size_t length;
			var request = generator.to_data (out length);

			var response = new PendingResponse (() => call.callback ());
			pending[request_id.to_string ()] = response;

			post_call_request.begin (request, response, session, script);

			yield;

			if (response.error != null)
				throw response.error;

			return response.result;
		}


		private async void post_call_request (string request, PendingResponse response, AgentSession session, AgentScriptId script) {
			try {
				yield session.post_message_to_script (script, request);
			} catch (GLib.Error e) {
				response.complete_with_error (Marshal.from_dbus (e));
			}
		}

		private async void get_agent (out AgentSession session, out AgentScriptId script) throws Error {
			try {
				if (cached_session == null) {
					var pid = get_pid (target_process);
					var id = yield host_session.attach_to (pid);
					cached_session = yield host_session.obtain_agent_session (id);
				}

				if (cached_script.handle == 0) {
					cached_script = yield cached_session.create_script ("parasite-service", script_source);
					cached_session.message_from_script.connect (on_message_from_script);
					yield cached_session.load_script (cached_script);
				}
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}

			session = cached_session;
			script = cached_script;
		}

		private void on_message_from_script (AgentScriptId sid, string raw_message, uint8[] data) {
			if (sid != cached_script)
				return;

			var parser = new Json.Parser ();
			try {
				parser.load_from_data (raw_message);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
			var message = parser.get_root ().get_object ();
			var type = message.get_string_member ("type");
			if (type == "send") {
				var rpc_message = message.get_array_member ("payload");
				var request_id = rpc_message.get_int_element (1);
				PendingResponse response;
				pending.unset (request_id.to_string (), out response);
				var status = rpc_message.get_string_element (2);
				if (status == "ok")
					response.complete_with_result (rpc_message.get_element (3));
				else
					response.complete_with_error (new Error.NOT_SUPPORTED (rpc_message.get_string_element (3)));
			} else {
				stderr.printf ("%s\n", raw_message);
			}
		}

		private uint get_pid (string name) throws Error {
			foreach (HostProcessInfo info in System.enumerate_processes ()) {
				if (info.name == name)
					return info.pid;
			}
			throw new Error.PROCESS_NOT_FOUND ("Unable to find process with name '%s'".printf (name));
		}

		private class PendingResponse {
			public delegate void CompletionHandler ();
			private CompletionHandler handler;

			public Json.Node? result {
				get;
				private set;
			}

			public Error? error {
				get;
				private set;
			}

			public PendingResponse (owned CompletionHandler handler) {
				this.handler = (owned) handler;
			}

			public void complete_with_result (Json.Node r) {
				result = r;
				handler ();
			}

			public void complete_with_error (Error e) {
				error = e;
				handler ();
			}
		}
	}
#endif
}
#endif
