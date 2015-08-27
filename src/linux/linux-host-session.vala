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
		private AgentResource agent;

#if ANDROID
		private RoboLauncher robo_launcher;
		private RoboAgent robo_agent;
#endif

		construct {
			helper = new HelperProcess ();
			injector = new Linjector.with_helper (helper);

			var blob32 = Frida.Data.Agent.get_frida_agent_32_so_blob ();
			var blob64 = Frida.Data.Agent.get_frida_agent_64_so_blob ();
			agent = new AgentResource ("frida-agent-%u.so",
				new MemoryInputStream.from_data (blob32.data, null),
				new MemoryInputStream.from_data (blob64.data, null),
				AgentMode.INSTANCED,
				helper.tempdir);

#if ANDROID
			robo_agent = new RoboAgent (this);
#endif
		}

		public override async void close () {
			yield base.close ();

#if ANDROID
			if (robo_launcher != null) {
				yield robo_launcher.close ();
				robo_launcher = null;
			}

			yield robo_agent.close ();
			robo_agent = null;
#endif

			var uninjected_handler = injector.uninjected.connect ((id) => close.callback ());
			while (injector.any_still_injected ())
				yield;
			injector.disconnect (uninjected_handler);
			yield injector.close ();
			injector = null;

			yield helper.close ();
			helper = null;
		}

		public override async HostApplicationInfo get_frontmost_application () throws Error {
#if ANDROID
			return yield robo_agent.get_frontmost_application ();
#else
			return System.get_frontmost_application ();
#endif
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
				if (robo_launcher == null)
					robo_launcher = new RoboLauncher (robo_agent, helper, injector, agent);
				return yield robo_launcher.spawn (package_name);
			} else {
				return yield helper.spawn (path, argv, envp);
			}
#else
			return yield helper.spawn (path, argv, envp);
#endif
		}

		public override async void resume (uint pid) throws Error {
#if ANDROID
			if (robo_launcher != null) {
				if (yield robo_launcher.try_resume (pid))
					return;
			}
#endif
			yield helper.resume (pid);
		}

		public override async void kill (uint pid) throws Error {
			yield helper.kill (pid);
		}

		protected override async IOStream perform_attach_to (uint pid, out Object? transport) throws Error {
			PipeTransport t;
			Pipe pipe;

#if ANDROID
			if (robo_launcher != null) {
				if (robo_launcher.try_get_pipe (pid, out pipe, out t)) {
					transport = t;
					return pipe;
				}
			}
#endif

			PipeTransport.set_temp_directory (helper.tempdir.path);
			try {
				t = new PipeTransport ();
				pipe = new Pipe (t.local_address);
			} catch (IOError stream_error) {
				throw new Error.NOT_SUPPORTED (stream_error.message);
			}
			yield injector.inject (pid, agent, t.remote_address);
			transport = t;
			return pipe;
		}
	}

#if ANDROID
	private class RoboLauncher {
		private RoboAgent robo_agent;
		private HelperProcess helper;
		private Linjector injector;
		private AgentResource agent;
		private AgentResource loader;
		private uint loader32;
		private uint loader64;
		private UnixSocketAddress service_address;
		private SocketService service;

		private Gee.HashMap<string, SpawnRequest> spawn_request_by_package_name = new Gee.HashMap<string, SpawnRequest> ();
		private Gee.HashMap<uint, Loader> loader_by_pid = new Gee.HashMap<uint, Loader> ();

		internal RoboLauncher (RoboAgent robo_agent, HelperProcess helper, Linjector injector, AgentResource agent) {
			this.robo_agent = robo_agent;
			this.helper = helper;
			this.injector = injector;
			this.agent = agent;

			var blob32 = Frida.Data.Loader.get_frida_loader_32_so_blob ();
			var blob64 = Frida.Data.Loader.get_frida_loader_64_so_blob ();
			this.loader = new AgentResource ("frida-loader-%u.so",
				new MemoryInputStream.from_data (blob32.data, null),
				new MemoryInputStream.from_data (blob64.data, null),
				AgentMode.SINGLETON,
				helper.tempdir);

			this.service = new SocketService ();
			var address = new UnixSocketAddress (Path.build_filename (agent.tempdir.path, "callback"));
			SocketAddress effective_address;
			try {
				this.service.add_address (address, SocketType.STREAM, SocketProtocol.DEFAULT, null, out effective_address);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
			assert (effective_address is UnixSocketAddress);
			this.service_address = effective_address as UnixSocketAddress;
			FileUtils.chmod (this.service_address.path, 0777);
			this.service.incoming.connect (this.on_incoming_connection);
			this.service.start ();
		}

		public async void close () {
			service.stop ();
			service = null;

			FileUtils.unlink (service_address.path);

			agent = null;
		}

		public async uint spawn (string package_name) throws Error {
			yield ensure_loader_injected ();

			PipeTransport.set_temp_directory (helper.tempdir.path);
			PipeTransport transport;
			Pipe pipe;
			try {
				transport = new PipeTransport ();
				pipe = new Pipe (transport.local_address);
			} catch (IOError stream_error) {
				throw new Error.NOT_SUPPORTED (stream_error.message);
			}

			agent.ensure_written_to_disk ();

			var waiting = false;
			var timed_out = false;
			var request = new SpawnRequest (package_name, () => {
				if (waiting)
					spawn.callback ();
			});
			spawn_request_by_package_name[package_name] = request;

			yield robo_agent.stop_activity (package_name);
			uint pid = yield robo_agent.start_activity (package_name);
			if (request.result == null) {
				var timeout = Timeout.add_seconds (10, () => {
					timed_out = true;
					spawn.callback ();
					return false;
				});
				waiting = true;
				yield;
				waiting = false;
				if (timed_out) {
					spawn_request_by_package_name.unset (package_name);
					throw new Error.TIMED_OUT ("Unexpectedly timed out while waiting for app to launch");
				} else {
					Source.remove (timeout);
				}
			}

			var loader = request.result;
			loader.transport = transport;
			loader.pipe = pipe;

			yield loader.send_string (transport.remote_address);

			loader_by_pid[pid] = loader;

			return pid;
		}

		public bool try_get_pipe (uint pid, out Pipe? pipe, out PipeTransport? transport) {
			Loader loader = loader_by_pid[pid];
			if (loader == null) {
				pipe = null;
				transport = null;
				return false;
			}
			pipe = loader.pipe;
			transport = loader.transport;
			return true;
		}

		public async bool try_resume (uint pid) throws Error {
			Loader loader;
			if (!loader_by_pid.unset (pid, out loader))
				return false;
			yield loader.send_string ("go");
			return true;
		}

		private async void ensure_loader_injected () throws Error {
			var should_inject_32bit_loader = loader32 == 0 && loader.so32 != null;
			var should_inject_64bit_loader = loader64 == 0 && loader.so64 != null;
			if (!should_inject_32bit_loader && !should_inject_64bit_loader)
				return;

			var passes = new string[] { "", agent.tempdir.path };
			foreach (var data_dir in passes) {
				var pending = new Gee.HashSet<uint> ();
				var waiting = false;
				var timed_out = false;

				var on_uninjected = injector.uninjected.connect ((id) => {
					pending.remove (id);
					if (waiting)
						ensure_loader_injected.callback ();
				});

				try {
					if (should_inject_32bit_loader) {
						loader32 = yield injector.inject (LocalProcesses.get_pid ("zygote"), loader, data_dir);
						pending.add (loader32);
					}

					if (should_inject_64bit_loader) {
						var zygote64_pid = LocalProcesses.find_pid ("zygote64");
						if (zygote64_pid != 0) {
							loader64 = yield injector.inject (zygote64_pid, loader, data_dir);
							pending.add (loader64);
						} else {
							loader64 = 1;
						}
					}

					var timeout = Timeout.add_seconds (10, () => {
						timed_out = true;
						ensure_loader_injected.callback ();
						return false;
					});
					while (!pending.is_empty) {
						waiting = true;
						yield;
						waiting = false;
					}
					if (!timed_out)
						Source.remove (timeout);
				} finally {
					injector.disconnect (on_uninjected);
				}

				if (timed_out)
					throw new Error.PROCESS_NOT_RESPONDING ("Unexpectedly timed out while injecting loader into zygote");
			}
		}

		private bool on_incoming_connection (SocketConnection connection, Object? source_object) {
			perform_handshake.begin (new Loader (connection));
			return true;
		}

		private async void perform_handshake (Loader loader) {
			try {
				var package_name = yield loader.recv_string ();
				SpawnRequest request;
				if (!spawn_request_by_package_name.unset (package_name, out request)) {
					loader.close ();
					return;
				}
				request.complete (loader);
			} catch (Error e) {
			}
		}

		private class SpawnRequest : Object {
			public delegate void CompletionHandler ();

			public string package_name {
				get;
				construct;
			}

			private CompletionHandler handler;

			public Loader? result {
				get;
				private set;
			}

			public SpawnRequest (string package_name, owned CompletionHandler handler) {
				Object (package_name: package_name);

				this.handler = (owned) handler;
			}

			public void complete (Loader r) {
				result = r;
				handler ();
			}
		}

		private class Loader {
			private SocketConnection connection;
			private InputStream input;
			private OutputStream output;

			public PipeTransport? transport {
				get;
				set;
			}

			public Pipe? pipe {
				get;
				set;
			}

			public Loader (SocketConnection connection) {
				this.connection = connection;
				this.input = connection.input_stream;
				this.output = connection.output_stream;
			}

			public void close () {
				connection.close_async.begin ();
			}

			public async string recv_string () throws Error {
				try {
					var size_buf = new uint8[1];
					var n = yield input.read_async (size_buf);
					if (n == 0)
						throw new Error.TRANSPORT ("Unable to communicate with loader");
					var size = size_buf[0];

					var data_buf = new uint8[size];
					size_t bytes_read;
					yield input.read_all_async (data_buf, Priority.DEFAULT, null, out bytes_read);
					if (bytes_read != size)
						throw new Error.TRANSPORT ("Unable to communicate with loader");

					char * v = data_buf;
					return (string) v;
				} catch (GLib.Error e) {
					throw new Error.TRANSPORT ("Unable to communicate with loader");
				}
			}

			public async void send_string (string v) throws Error {
				var data_buf = new uint8[1 + v.length];
				data_buf[0] = (uint8) v.length;
				Memory.copy (data_buf + 1, v, v.length);
				size_t bytes_written;
				try {
					yield output.write_all_async (data_buf, Priority.DEFAULT, null, out bytes_written);
				} catch (GLib.Error e) {
					throw new Error.TRANSPORT ("Unable to communicate with loader");
				}
				if (bytes_written != data_buf.length)
					throw new Error.TRANSPORT ("Unable to communicate with loader");
			}
		}
	}

	private class RoboAgent : ParasiteService {
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

		public async HostApplicationInfo get_frontmost_application () throws Error {
			var app = yield call ("getFrontmostApplication", new Json.Node[] {});
			var item = app.get_array ();
			var no_icon = ImageData (0, 0, 0, "");
			if (app != null) {
				var identifier = item.get_string_element (0);
				var name = item.get_string_element (1);
				var pid = (uint) item.get_int_element (2);
				return HostApplicationInfo (identifier, name, pid, no_icon, no_icon);
			} else {
				return HostApplicationInfo ("", "", 0, no_icon, no_icon);
			}
		}

		public async uint start_activity (string package_name) throws Error {
			var result = yield call ("startActivity", new Json.Node[] { new Json.Node.alloc ().init_string (package_name) });
			var pid = (uint) result.get_int ();
			return pid;
		}

		public async void stop_activity (string package_name) throws Error {
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

							var source = new TimeoutSource (100);
							source.set_callback (() => {
								stop_activity.callback ();
								return false;
							});
							source.attach (MainContext.get_thread_default ());
							yield;
						}
						break;
					}
				}
			} while (existing_app_killed);
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
					var pid = LocalProcesses.get_pid (target_process);
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

	namespace LocalProcesses {
		internal uint find_pid (string name) {
			foreach (HostProcessInfo info in System.enumerate_processes ()) {
				if (info.name == name)
					return info.pid;
			}
			return 0;
		}

		internal uint get_pid (string name) throws Error {
			var pid = find_pid (name);
			if (pid == 0)
				throw new Error.PROCESS_NOT_FOUND ("Unable to find process with name '%s'".printf (name));
			return pid;
		}
	}
#endif
}
#endif
