namespace Frida {
	private sealed class EmulatorInstrumentation : Object {
		private DeviceManager manager;
		private Script script;

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

#if MACOS
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
#else
			return Frida.Data.Barebone.get_android_emulator_macos_js_blob ();
#endif
		}

#if MACOS
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
