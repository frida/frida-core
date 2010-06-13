namespace Zed {
	namespace Agent {
		private static WinIpc.ClientProxy proxy;

		private static Zed.Investigator investigator;
		private static Zed.GstTracer gst_tracer;

		public void main (string ipc_server_address) {
			var loop = new MainLoop ();

			proxy = new WinIpc.ClientProxy (ipc_server_address);
			proxy.add_notify_handler ("Stop", "", (arg) => {
				loop.quit ();
			});
			proxy.register_query_sync_handler ("StartInvestigation", "(ssss)", (arg) => {
				if (investigator != null)
					return new Variant.boolean (false);

				investigator = new Investigator (proxy);

				string start_module_name, start_function_name;
				string stop_module_name, stop_function_name;
				arg.get ("(ssss)", out start_module_name, out start_function_name, out stop_module_name, out stop_function_name);
				var start_trigger = new TriggerInfo (start_module_name, start_function_name);
				var stop_trigger = new TriggerInfo (stop_module_name, stop_function_name);
				bool is_attached = investigator.attach (start_trigger, stop_trigger);
				if (!is_attached)
					investigator = null;

				return new Variant.boolean (is_attached);
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

			if (investigator != null) {
				investigator.detach ();
				investigator = null;
			}
		}

		private async void do_establish (WinIpc.ClientProxy proxy) {
			try {
				yield proxy.establish ();
			} catch (WinIpc.ProxyError e) {
				error (e.message);
				return;
			}

			/*
			gst_tracer = new Zed.GstTracer (proxy);
			gst_tracer.attach ();
			*/
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

