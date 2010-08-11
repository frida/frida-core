namespace Zed {
	namespace Agent {
		private static WinIpc.ClientProxy proxy;

		private static Zed.ScriptEngine script_engine;
		private static Zed.Investigator investigator;
		private static Zed.MemoryTracker memory_tracker;
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
			proxy.register_query_sync_handler ("StopInvestigation", "", (arg) => {
				if (investigator != null) {
					investigator.detach ();
					investigator = null;
				}

				return null;
			});
			proxy.add_notify_handler ("Stop", "", (arg) => {
				loop.quit ();
			});
			proxy.register_query_sync_handler ("QueryModules", "", (arg) => {
				return query_modules ();
			});
			proxy.register_query_sync_handler ("QueryModuleFunctions", "s", (arg) => {
				var module_name = arg.get_string ();
				return query_module_functions (module_name);
			});
			proxy.register_query_sync_handler ("DumpMemory", "(tt)", (arg) => {
				uint64 address, size;
				arg.@get ("(tt)", out address, out size);
				return dump_memory (address, size);
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

			memory_tracker = null;

			script_engine.shutdown ();
			script_engine = null;
		}

		private async void do_establish (WinIpc.ClientProxy proxy) {
			try {
				yield proxy.establish ();
			} catch (WinIpc.ProxyError e) {
				error (e.message);
			}

			script_engine = new Zed.ScriptEngine (proxy);

			memory_tracker = new Zed.MemoryTracker (proxy);

			/*
			gst_tracer = new Zed.GstTracer (proxy);
			gst_tracer.attach ();
			*/
		}

		public extern Variant query_modules ();
		public extern Variant query_module_functions (string module_name);
		public extern Variant dump_memory (uint64 address, uint64 size);
	}
}

