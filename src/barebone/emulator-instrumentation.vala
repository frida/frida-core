namespace Frida {
	private sealed class EmulatorInstrumentation : InternalAgent {
		private LocalConnection local_connection;
		private uint pid;
		private GDB.Client? client;

		private EmulatorInstrumentation (LocalConnection connection, uint pid) {
			Object (connection: connection);
			local_connection = connection;
			this.pid = pid;
		}

		public static async EmulatorInstrumentation apply (HostSessionHub hub, BareboneConfig config,
				Cancellable? cancellable) throws Error, IOError {
			HostSessionEntry local_system = yield hub.resolve_host_session ("local", cancellable);
			var connection = new LocalConnection (local_system);

			var instrumentation = new EmulatorInstrumentation (connection, config.connection.pid);
			try {
				yield instrumentation.start (config, cancellable);
			} catch (GLib.Error e) {
				try {
					yield instrumentation.close (cancellable);
				} catch (IOError ignored) {
				}
				throw_api_error (e);
			}
			return instrumentation;
		}

		private async void start (BareboneConfig config, Cancellable? cancellable) throws Error, IOError {
			yield ensure_loaded (cancellable);

#if MACOS || LINUX
			string? pipe_path = pipe_socket_path (config);
			if (pipe_path != null) {
				var path = new Json.Node.alloc ().init_string (pipe_path);
				yield call ("allowPipePath", new Json.Node[] { path }, null, cancellable);
			}
#endif
		}

		public void adopt_breakpoints (GDB.Client client) {
			this.client = client;

			client.breakpoints_provided_externally = true;
			client.breakpoints_changed.connect (on_breakpoints_changed);
		}

		private void on_breakpoints_changed (uint64[] addresses) {
			var values = new Json.Array ();
			foreach (uint64 address in addresses)
				values.add_string_element (("0x%" + uint64.FORMAT_MODIFIER + "x").printf (address));
			var arg = new Json.Node.alloc ().init_array (values);
			call.begin ("setBreakpoints", new Json.Node[] { arg }, null, null);
		}

		protected override void on_event (string type, Json.Array event) {
			if (type != "breakpoint")
				return;

			var hit = event.get_object_element (1);
			uint64 address = uint64.parse (hit.get_string_member ("address").substring (2), 16);
			uint vp = (uint) hit.get_int_member ("vp");
			uint64 stack = uint64.parse (hit.get_string_member ("rsp").substring (2), 16);
			client.report_breakpoint_hit.begin (address, vp, stack, null);
		}

		public async void tear_down (Cancellable? cancellable) throws IOError {
			yield close (cancellable);
		}

		protected override async uint get_target_pid (Cancellable? cancellable) throws Error, IOError {
			return pid;
		}

		protected override async string? load_source (Cancellable? cancellable) throws Error, IOError {
			return (string) shim_blob ().data;
		}

		private static Frida.Data.Barebone.Blob shim_blob () {
#if WINDOWS
			return Frida.Data.Barebone.get_android_emulator_windows_js_blob ();
#elif MACOS
			return Frida.Data.Barebone.get_android_emulator_macos_js_blob ();
#else
			return Frida.Data.Barebone.get_android_emulator_linux_js_blob ();
#endif
		}

#if MACOS || LINUX
		private static string? pipe_socket_path (BareboneConfig config) {
			var injected = config.agent as BareboneInjectedAgentConfig;
			if (injected == null)
				return null;

			var pipe_vsock = injected.transport as BareboneVsockPipeTransportConfig;
			if (pipe_vsock != null)
				return pipe_vsock.socket_path;

			var vsock = injected.transport as BareboneVsockTransportConfig;
			if (vsock != null)
				return vsock.socket_path;

			return null;
		}
#endif
	}

	private sealed class LocalConnection : Object, HostSessionConnection {
		public HostSessionEntry local_system {
			get;
			construct;
		}

		public HostSession host_session {
			get {
				return local_system.session;
			}
		}

		public LocalConnection (HostSessionEntry local_system) {
			Object (local_system: local_system);
		}

		public async AgentSession link_agent_session (AgentSessionId id, AgentMessageSink sink,
				Cancellable? cancellable) throws Error, IOError {
			return yield local_system.provider.link_agent_session (local_system.session, id, sink, cancellable);
		}

		public void unlink_agent_session (AgentSessionId id) {
			local_system.provider.unlink_agent_session (local_system.session, id);
		}
	}
}
