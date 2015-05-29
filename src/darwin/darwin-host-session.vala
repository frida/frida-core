#if DARWIN
namespace Frida {
	public class DarwinHostSessionBackend : Object, HostSessionBackend {
		private DarwinHostSessionProvider local_provider;

		public async void start () {
			assert (local_provider == null);
			local_provider = new DarwinHostSessionProvider ();
			provider_available (local_provider);
		}

		public async void stop () {
			assert (local_provider != null);
			provider_unavailable (local_provider);
			yield local_provider.close ();
			local_provider = null;
		}
	}

	public class DarwinHostSessionProvider : Object, HostSessionProvider {
		public string name {
			get { return "Local System"; }
		}

		public ImageData? icon {
			get { return _icon; }
		}
		private ImageData? _icon;

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.LOCAL_SYSTEM; }
		}

		private DarwinHostSession host_session;

		construct {
			_icon = _extract_icon ();
		}

		public async void close () {
			if (host_session != null)
				yield host_session.close ();
			host_session = null;
		}

		public async HostSession create (string? location = null) throws Error {
			assert (location == null);
			if (host_session != null)
				throw new Error.INVALID_ARGUMENT ("Invalid location: already created");
			host_session = new DarwinHostSession ();
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

		public static extern ImageData? _extract_icon ();
	}

	public class DarwinHostSession : BaseDBusHostSession {
		private HelperProcess helper;
		private Fruitjector injector;
		private AgentResource agent;
		private FruitLauncher fruit_launcher;

		construct {
			helper = new HelperProcess ();
			injector = new Fruitjector.with_helper (helper);

			var blob = Frida.Data.Agent.get_frida_agent_dylib_blob ();
			agent = new AgentResource (blob.name, new MemoryInputStream.from_data (blob.data, null), helper.tempdir);
		}

		public override async void close () {
			yield base.close ();

			if (fruit_launcher != null) {
				yield fruit_launcher.close ();
				fruit_launcher = null;
			}

			var uninjected_handler = injector.uninjected.connect ((id) => close.callback ());
			while (injector.any_still_injected ())
				yield;
			injector.disconnect (uninjected_handler);
			yield injector.close ();
			injector = null;

			agent = null;

			yield helper.close ();
			helper = null;
		}

		public override async Frida.HostProcessInfo[] enumerate_processes () throws Error {
			return System.enumerate_processes ();
		}

		public override async uint spawn (string path, string[] argv, string[] envp) throws Error {
			if (_is_running_on_ios () && !path.has_prefix ("/")) {
				if (fruit_launcher == null)
					fruit_launcher = new FruitLauncher (this, agent);
				return yield fruit_launcher.launch (path);
			} else {
				return yield helper.spawn (path, argv, envp);
			}
		}

		public override async void resume (uint pid) throws Error {
			yield helper.resume (pid);
		}

		public override async void kill (uint pid) throws Error {
			System.kill (pid);
		}

		protected override async IOStream perform_attach_to (uint pid, out Object? transport) throws Error {
			string local_address, remote_address;
			yield injector.make_pipe_endpoints (pid, out local_address, out remote_address);
			Pipe stream;
			try {
				stream = new Pipe (local_address);
			} catch (IOError stream_error) {
				throw new Error.NOT_SUPPORTED (stream_error.message);
			}
			yield injector.inject (pid, agent, remote_address);
			transport = null;
			return stream;
		}

		// TODO: use Vala's preprocessor when the build system has been fixed
		public static extern bool _is_running_on_ios ();
	}

	private class FruitLauncher {
		private DarwinHostSession host_session;
		private AgentResource agent;
		private UnixSocketAddress service_address;
		private SocketService service;
		private AgentSession springboard_session;
		private AgentScriptId springboard_script;

		internal FruitLauncher (DarwinHostSession host_session, AgentResource agent) {
			this.host_session = host_session;
			this.agent = agent;

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
			this.service.incoming.connect (on_incoming_connection);
			this.service.start ();
		}

		public async void close () {
			if (springboard_script.handle != 0) {
				try {
					yield springboard_session.destroy_script (springboard_script);
				} catch (GLib.Error e) {
				}
				springboard_script = AgentScriptId (0);
			}

			if (springboard_session != null) {
				try {
					yield springboard_session.close ();
				} catch (GLib.Error e) {
				}
				springboard_session = null;
			}

			service.stop ();
			service = null;

			agent = null;

			host_session = null;
		}

		public async uint launch (string name) throws Error {
			AgentSession session;
			AgentScriptId script;
			yield get_springboard_agent (out session, out script);

			stderr.printf ("posting to script: %u\n", script.handle);
			try {
				yield session.post_message_to_script (script, "[\"%s\",\"%s\"]".printf (agent.file.path, service_address.path));
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}

			// TODO: ask SpringBoard to launch this app

			throw new Error.NOT_SUPPORTED ("DERPRRRR");
		}

		private async void get_springboard_agent (out AgentSession session, out AgentScriptId script) throws Error {
			try {
				if (springboard_session == null) {
					var pid = get_pid ("SpringBoard");
					var id = yield host_session.attach_to (pid);
					springboard_session = yield host_session.obtain_agent_session (id);
				}

				if (springboard_script.handle == 0) {
					springboard_script = yield springboard_session.create_script ("fruit-launcher",
						"'use strict';\n"																+
						"\n"																		+
						"function onMessage(m) {\n"															+
						"    if (m !== null)\n"																+
						"        enable(m[0], m[1]);\n"															+
						"    else\n"																	+
						"        disable();\n"																+
						"    send('synchronized');\n"															+
						"\n"																		+
						"    recv(onMessage);\n"															+
						"}\n"																		+
						"recv(onMessage);\n"																+
						"\n"																		+
						"function enable(dylib, socket) {\n"														+
						"    let libraries = getDyldInsertLibraries();\n"												+
						"    libraries = libraries.filter(isForeignLibraryPath);\n"											+
						"    libraries.unshift(dylib);\n"														+
						"    setDyldInsertLibraries(libraries);\n"													+
						"\n"																		+
						"    setenv('FRIDA_CALLBACK_SOCKET', socket, true);\n"												+
						"}\n"																		+
						"\n"																		+
						"function disable() {\n"															+
						"    unsetenv('FRIDA_CALLBACK_SOCKET');\n"													+
						"\n"																		+
						"    let libraries = getDyldInsertLibraries();\n"												+
						"    libraries = libraries.filter(isForeignLibraryPath);\n"											+
						"    setDyldInsertLibraries(libraries);\n"													+
						"\n"																		+
						"    currentDylib = null;\n"															+
						"}\n"																		+
						"\n"																		+
						"function getDyldInsertLibraries() {\n"														+
						"    return (getenv('DYLD_INSERT_LIBRARIES') || '').split(':').map(normalizedLibraryPath).filter(isValidLibraryPath);\n"			+
						"}\n"																		+
						"\n"																		+
						"function setDyldInsertLibraries(libraries) {\n"												+
						"    if (libraries.length > 0)\n"														+
						"        setenv('DYLD_INSERT_LIBRARIES', libraries.join(':'), true);\n"										+
						"    else\n"																	+
						"        unsetenv('DYLD_INSERT_LIBRARIES');\n"													+
						"}\n"																		+
						"\n"																		+
						"function normalizedLibraryPath(p) {\n"														+
						"    return p.trim();\n"															+
						"}\n"																		+
						"\n"																		+
						"function isValidLibraryPath(p) {\n"														+
						"    return p.length > 0;\n"															+
						"}\n"																		+
						"\n"																		+
						"function isForeignLibraryPath(p) {\n"														+
						"    return p.indexOf('/frida-agent.dylib') === -1;\n"												+
						"}\n"																		+
						"\n"																		+
						"const getenvImpl = new NativeFunction(Module.findExportByName('libsystem_c.dylib', 'getenv'), 'pointer', ['pointer']);\n"			+
						"function getenv(name) {\n"															+
						"    return Memory.readUtf8String(getenvImpl(Memory.allocUtf8String(name)));\n"									+
						"}\n"																		+
						"\n"																		+
						"const setenvImpl = new NativeFunction(Module.findExportByName('libsystem_c.dylib', 'setenv'), 'int', ['pointer', 'pointer', 'int']);\n"	+
						"function setenv(name, value, overwrite) {\n"													+
						"    return setenvImpl(Memory.allocUtf8String(name), Memory.allocUtf8String(value), overwrite ? 1 : 0);\n"					+
						"}\n"																		+
						"\n"																		+
						"const unsetenvImpl = new NativeFunction(Module.findExportByName('libsystem_c.dylib', 'unsetenv'), 'int', ['pointer']);\n"			+
						"function unsetenv(name) {\n"															+
						"    return unsetenvImpl(Memory.allocUtf8String(name));\n"											+
						"}"
					);
					springboard_session.message_from_script.connect (on_message_from_script);
					yield springboard_session.load_script (springboard_script);
				}
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}

			session = springboard_session;
			script = springboard_script;
		}

		private void on_message_from_script (AgentScriptId sid, string message, uint8[] data) {
			if (sid != springboard_script)
				return;
			stderr.printf ("Got message: '%s'\n", message);
		}

		private bool on_incoming_connection (SocketConnection connection, Object? source_object) {
			stderr.printf ("Incoming connection! %p\n", connection);
			return false;
		}

		private uint get_pid (string name) throws Error {
			foreach (HostProcessInfo info in System.enumerate_processes ()) {
				if (info.name == name)
					return info.pid;
			}
			throw new Error.PROCESS_NOT_FOUND ("Unable to find process with name '%s'".printf (name));
		}

	}
}
#endif
