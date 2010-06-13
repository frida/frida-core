namespace Zed {
	namespace Agent {
		private static WinIpc.ClientProxy proxy;

		private static Zed.FuncTracer func_tracer;
		private static Zed.GstTracer gst_tracer;

		public void main (string ipc_server_address) {
			var loop = new MainLoop ();

			proxy = new WinIpc.ClientProxy (ipc_server_address);
			proxy.add_notify_handler ("Stop", "", (arg) => {
				loop.quit ();
			});
			proxy.register_query_sync_handler ("QueryModules", "", (arg) => {
				var builder = new VariantBuilder (new VariantType ("a(stt)"));
				foreach (var module in query_modules ())
					builder.add ("(stt)", module.name, module.base_address, module.size);
				return builder.end ();
			});
			proxy.register_query_sync_handler ("QueryModuleFunctions", "s", (arg) => {
				var module_name = arg.get_string ();
				var builder = new VariantBuilder (new VariantType ("a(st)"));
				foreach (var func in query_module_functions (module_name))
					builder.add ("(st)", func.name, func.base_address);
				return builder.end ();
			});

			Idle.add (() => {
				do_establish (proxy);
				return false;
			});

			loop.run ();

			if (gst_tracer != null) {
				gst_tracer.detach ();
				gst_tracer = null;
			}

			if (func_tracer != null) {
				func_tracer.detach ();
				func_tracer = null;
			}
		}

		private async void do_establish (WinIpc.ClientProxy proxy) {
			try {
				yield proxy.establish ();
			} catch (WinIpc.ProxyError e) {
				error (e.message);
				return;
			}

			func_tracer = new Zed.FuncTracer (proxy);
			func_tracer.attach ();

			gst_tracer = new Zed.GstTracer (proxy);
			gst_tracer.attach ();
		}

		public extern ModuleInfo[] query_modules ();
		public extern FunctionInfo[] query_module_functions (string module_name);

		public class ModuleInfo {
			public string name {
				get;
				private set;
			}

			public uint64 base_address {
				get;
				private set;
			}

			public uint64 size {
				get;
				private set;
			}

			public ModuleInfo (string name, uint64 base_address, uint64 size) {
				this.name = name;
				this.base_address = base_address;
				this.size = size;
			}
		}

		public class FunctionInfo {
			public string name {
				get;
				private set;
			}

			public uint64 base_address {
				get;
				private set;
			}

			public FunctionInfo (string name, uint64 base_address) {
				this.name = name;
				this.base_address = base_address;
			}
		}
	}
}

