namespace Frida {
	private sealed class EmulatorInstrumentation : Object {
		private DeviceManager manager;
		private Script script;
		private GDB.Client? client;

		private EmulatorInstrumentation (DeviceManager manager, Script script) {
			this.manager = manager;
			this.script = script;
		}

		public static async EmulatorInstrumentation apply (BareboneConfig config, Cancellable? cancellable)
				throws Error, IOError {
			var manager = new DeviceManager ();
			bool adopted = false;
			try {
				var device = yield manager.get_device_by_type (DeviceType.LOCAL, 0, cancellable);
				var session = yield device.attach (config.connection.pid, null, cancellable);

				unowned string source = (string) shim_blob ().data;
				var script = yield session.create_script (source, null, cancellable);

				yield script.load (cancellable);

#if MACOS || LINUX
				string? pipe_path = pipe_socket_path (config);
				if (pipe_path != null) {
					var builder = new Json.Builder ();
					builder.begin_object ();
					builder.set_member_name ("type");
					builder.add_string_value ("allow-pipe-path");
					builder.set_member_name ("path");
					builder.add_string_value (pipe_path);
					builder.end_object ();
					script.post (Json.to_string (builder.get_root (), false));
				}

#endif
				var instrumentation = new EmulatorInstrumentation (manager, script);
				adopted = true;
				return instrumentation;
			} finally {
				if (!adopted) {
					try {
						yield manager.close (cancellable);
					} catch (IOError e) {
					}
				}
			}
		}

		public void adopt_breakpoints (GDB.Client client) {
			this.client = client;

			client.breakpoints_provided_externally = true;
			client.breakpoints_changed.connect (on_breakpoints_changed);
			script.message.connect (on_message);
		}

		private void on_breakpoints_changed (uint64[] addresses) {
			var builder = new Json.Builder ();
			builder.begin_object ();
			builder.set_member_name ("type");
			builder.add_string_value ("breakpoints");
			builder.set_member_name ("addresses");
			builder.begin_array ();
			foreach (uint64 address in addresses)
				builder.add_string_value (("0x%" + uint64.FORMAT_MODIFIER + "x").printf (address));
			builder.end_array ();
			builder.end_object ();
			script.post (Json.to_string (builder.get_root (), false));
		}

		private void on_message (string json, Bytes? data) {
			try {
				var root = Json.from_string (json).get_object ();
				if (!root.has_member ("payload"))
					return;
				var payload = root.get_object_member ("payload");
				if (payload.get_string_member ("type") != "breakpoint")
					return;

				uint64 address = uint64.parse (payload.get_string_member ("address").substring (2), 16);
				uint vp = (uint) payload.get_int_member ("vp");
				uint64 stack = uint64.parse (payload.get_string_member ("rsp").substring (2), 16);
				client.report_breakpoint_hit.begin (address, vp, stack, null);
			} catch (GLib.Error e) {
			}
		}

		public async void tear_down (Cancellable? cancellable) throws IOError {
			try {
				yield script.unload (cancellable);
			} catch (GLib.Error e) {
			}
			yield manager.close (cancellable);
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
}
