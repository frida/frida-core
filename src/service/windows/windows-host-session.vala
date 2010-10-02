namespace Zed.Service {
	public class WindowsHostSessionBackend : Object, HostSessionBackend {
		public Winjector winjector {
			get;
			private set;
		}

		public Service.AgentDescriptor agent_desc {
			get;
			private set;
		}

		private WindowsHostSessionProvider local_provider;

		private Gee.HashMap<uint, WindowsAgentSession> agent_session_by_id = new Gee.HashMap<uint, WindowsAgentSession> ();
		private uint last_session_id = 1;

		public async void start () {
			assert (winjector == null);
			winjector = new Winjector ();

			var blob32 = Zed.Data.WinAgent.get_zed_winagent_32_dll_blob ();
			var blob64 = Zed.Data.WinAgent.get_zed_winagent_64_dll_blob ();
			agent_desc = new Service.AgentDescriptor ("zed-winagent-%u.dll",
				new MemoryInputStream.from_data (blob32.data, blob32.size, null),
				new MemoryInputStream.from_data (blob64.data, blob64.size, null));

			assert (local_provider == null);
			local_provider = new WindowsHostSessionProvider (this);
			provider_available (local_provider);
		}

		public async void stop () {
			foreach (var agent_session in agent_session_by_id.values) {
				try {
					yield agent_session.close ();
				} catch (IOError e) {
				}
			}
			agent_session_by_id.clear ();

			provider_unavailable (local_provider);
			assert (local_provider != null);
			local_provider = null;

			// HACK: give processes 50 ms to unload DLLs
			var source = new TimeoutSource (50);
			source.set_callback (() => {
				stop.callback ();
				return false;
			});
			source.attach (MainContext.get_thread_default ());
			yield;

			agent_desc = null;

			yield winjector.close ();
			winjector = null;
		}

		public AgentSessionId register_agent_session (WindowsAgentSession session) {
			var id = last_session_id++;
			agent_session_by_id[id] = session;
			return AgentSessionId (id);
		}

		public WindowsAgentSession? lookup_agent_session_by_id (AgentSessionId id) {
			return agent_session_by_id[id.handle];
		}
	}

	public class WindowsHostSessionProvider : Object, HostSessionProvider {
		public WindowsHostSessionBackend session_backend {
			get;
			construct;
		}

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

		public WindowsHostSessionProvider (WindowsHostSessionBackend session_backend) {
			Object (session_backend: session_backend);
		}

		construct {
			try {
				_icon = _extract_icon ();
			} catch (IOError e) {
			}
		}

		public async HostSession create () throws IOError {
			return new WindowsHostSession (session_backend);
		}

		public async AgentSession obtain_agent_session (AgentSessionId id) throws IOError {
			var agent_session = session_backend.lookup_agent_session_by_id (id);
			if (agent_session == null)
				throw new IOError.FAILED ("invalid session id");
			return agent_session;
		}

		public static extern ImageData? _extract_icon () throws IOError;
	}

	public class WindowsHostSession : Object, HostSession {
		public WindowsHostSessionBackend session_backend {
			get;
			construct;
		}

		private WindowsProcessBackend process_backend = new WindowsProcessBackend ();

		public WindowsHostSession (WindowsHostSessionBackend session_backend) {
			Object (session_backend: session_backend);
		}

		public async HostProcessInfo[] enumerate_processes () throws IOError {
			var processes = yield process_backend.enumerate_processes ();
			return processes;
		}

		public async AgentSessionId attach_to (uint pid) throws IOError {
			try {
				var proxy = yield session_backend.winjector.inject (pid, session_backend.agent_desc, null);
				var session = new WindowsAgentSession (proxy);
				return session_backend.register_agent_session (session);
			} catch (WinjectorError e) {
				throw new IOError.FAILED (e.message);
			}
		}
	}

	public class WindowsAgentSession : Object, AgentSession {
		public WinIpc.Proxy proxy {
			get;
			construct;
		}

		private const string SIMPLE_RESULT_SIGNATURE = "(bs)";

		public WindowsAgentSession (WinIpc.Proxy proxy) {
			Object (proxy: proxy);
		}

		construct {
			proxy.add_notify_handler ("NewBatchOfClues", "a(itt)", (arg) => {
				AgentClue[] clues = new AgentClue[arg.n_children ()];

				uint i = 0;
				foreach (var entry in arg) {
					int depth;
					uint64 location;
					uint64 target;
					entry.@get ("(itt)", out depth, out location, out target);

					clues[i++] = AgentClue (depth, location, target);
				}

				new_batch_of_clues (clues);
			});
			proxy.add_notify_handler ("InvestigationComplete", "", (arg) => investigation_complete ());

			proxy.add_notify_handler ("MessageFromScript", "(uv)", (arg) => {
				uint script_id;
				Variant msg;
				arg.@get ("(uv)", out script_id, out msg);

				message_from_script (script_id, msg.get_variant ());
			});
		}

		public async void close () throws IOError {
			try {
				yield proxy.emit ("Stop");
			} catch (WinIpc.ProxyError e) {
				throw new IOError.FAILED (e.message);
			}
		}

		public async AgentModuleInfo[] query_modules () throws IOError {
			try {
				var module_values = yield proxy.query ("QueryModules", null, "a(sstt)");

				var result = new AgentModuleInfo[module_values.n_children ()];
				uint i = 0;

				foreach (var module_value in module_values) {
					string mod_name;
					string mod_uid;
					uint64 mod_size;
					uint64 mod_base;
					module_value.@get ("(sstt)", out mod_name, out mod_uid, out mod_size, out mod_base);

					result[i++] = AgentModuleInfo (mod_name, mod_uid, mod_size, mod_base);
				}

				return result;
			} catch (WinIpc.ProxyError e) {
				throw new IOError.FAILED (e.message);
			}
		}

		public async AgentFunctionInfo[] query_module_functions (string module_name) throws IOError {
			try {
				var function_values = yield proxy.query ("QueryModuleFunctions", new Variant.string (module_name), "a(st)");

				var result = new AgentFunctionInfo[function_values.n_children ()];
				uint i = 0;

				foreach (var function_value in function_values) {
					string func_name;
					uint64 func_address;
					function_value.@get ("(st)", out func_name, out func_address);

					result[i++] = AgentFunctionInfo (func_name, func_address);
				}

				return result;
			} catch (WinIpc.ProxyError e) {
				throw new IOError.FAILED (e.message);
			}
		}

		public async uint8[] read_memory (uint64 address, uint size) throws IOError {
			try {
				var result_variant = yield proxy.query ("DumpMemory", new Variant ("(tu)", address, size), "(bsay)");

				bool succeeded;
				string error_message;
				VariantIter bytes;
				result_variant.@get ("(bsay)", out succeeded, out error_message, out bytes);

				if (succeeded) {
					uint8[] result = new uint8[bytes.n_children ()];

					Variant byte_wrapper;
					for (uint i = 0; (byte_wrapper = bytes.next_value ()) != null; i++)
						result[i] = byte_wrapper.get_byte ();

					return result;
				} else {
					throw new IOError.FAILED (error_message);
				}
			} catch (WinIpc.ProxyError e) {
				throw new IOError.FAILED (e.message);
			}
		}

		public async void start_investigation (AgentTriggerInfo start_trigger, AgentTriggerInfo stop_trigger) throws IOError {
			try {
				var arg = new Variant ("(ssss)",
					start_trigger.module_name, start_trigger.function_name,
					stop_trigger.module_name, stop_trigger.function_name);
				var result = yield proxy.query ("StartInvestigation", arg, "b");
				if (!result.get_boolean ())
					throw new IOError.FAILED ("failed to start investigation");
			} catch (WinIpc.ProxyError e) {
				throw new IOError.FAILED (e.message);
			}
		}

		public async void stop_investigation () throws IOError {
			try {
				yield proxy.query ("StopInvestigation");
			} catch (WinIpc.ProxyError e) {
				throw new IOError.FAILED (e.message);
			}
		}

		public async AgentScriptInfo attach_script_to (string script_text, uint64 address) throws IOError {
			try {
				var argument_variant = new Variant ("(st)", script_text, address);
				var result_variant = yield proxy.query ("AttachScriptTo", argument_variant, "(ustu)");

				uint id;
				string error_message;
				uint64 code_address;
				uint32 code_size;
				result_variant.@get ("(ustu)", out id, out error_message, out code_address, out code_size);

				if (id != 0)
					return AgentScriptInfo (id, code_address, code_size);
				else
					throw new IOError.FAILED (error_message);
			} catch (WinIpc.ProxyError e) {
				throw new IOError.FAILED (e.message);
			}
		}

		public async void detach_script (uint script_id) throws IOError {
			try {
				var argument_variant = new Variant ("u", script_id);
				var result_variant = yield proxy.query ("DetachScript", argument_variant, SIMPLE_RESULT_SIGNATURE);
				check_simple_result (result_variant);
			} catch (WinIpc.ProxyError e) {
				throw new IOError.FAILED (e.message);
			}
		}

		public async void begin_instance_trace () throws IOError {
			try {
				var result_variant = yield proxy.query ("BeginInstanceTrace", null, SIMPLE_RESULT_SIGNATURE);
				check_simple_result (result_variant);
			} catch (WinIpc.ProxyError e) {
				throw new IOError.FAILED (e.message);
			}
		}

		public async void end_instance_trace () throws IOError {
			try {
				var result_variant = yield proxy.query ("EndInstanceTrace", null, SIMPLE_RESULT_SIGNATURE);
				check_simple_result (result_variant);
			} catch (WinIpc.ProxyError e) {
				throw new IOError.FAILED (e.message);
			}
		}

		public async AgentInstanceInfo[] peek_instances () throws IOError {
			try {
				var result_variant = yield proxy.query ("PeekInstances", null, "(ba(tus))");

				bool success;
				VariantIter entries_iter;
				result_variant.@get ("(ba(tus))", out success, out entries_iter);

				if (!success)
					throw new IOError.FAILED ("no trace in progress?");

				var entries = new AgentInstanceInfo[entries_iter.n_children ()];
				uint i = 0;

				Variant entry;
				while ((entry = entries_iter.next_value ()) != null) {
					uint64 address;
					uint ref_count;
					string type_name;
					entry.@get ("(tus)", out address, out ref_count, out type_name);
					entries[i++] = AgentInstanceInfo (address, ref_count, type_name);
				}

				return entries;
			} catch (WinIpc.ProxyError e) {
				throw new IOError.NOT_SUPPORTED (e.message);
			}
		}

		private void check_simple_result (Variant result_variant) throws IOError {
			bool succeeded;
			string error_message;
			result_variant.@get (SIMPLE_RESULT_SIGNATURE, out succeeded, out error_message);

			if (!succeeded)
				throw new IOError.FAILED (error_message);
		}
	}

	public class WindowsProcessBackend {
		private MainContext current_main_context;
		private Gee.ArrayList<EnumerateRequest> pending_requests = new Gee.ArrayList<EnumerateRequest> ();

		public async HostProcessInfo[] enumerate_processes () {
			bool is_first_request = pending_requests.is_empty;

			var request = new EnumerateRequest (() => enumerate_processes.callback ());
			if (is_first_request) {
				current_main_context = MainContext.get_thread_default ();

				try {
					Thread.create (enumerate_processes_worker, false);
				} catch (ThreadError e) {
					error (e.message);
				}
			}
			pending_requests.add (request);
			yield;

			return request.result;
		}

		public static extern HostProcessInfo[] enumerate_processes_sync ();

		private void * enumerate_processes_worker () {
			var processes = enumerate_processes_sync ();

			var source = new IdleSource ();
			source.set_callback (() => {
				current_main_context = null;
				var requests = pending_requests;
				pending_requests = new Gee.ArrayList<EnumerateRequest> ();

				foreach (var request in requests)
					request.complete (processes);

				return false;
			});
			source.attach (current_main_context);

			return null;
		}

		private class EnumerateRequest {
			public delegate void CompletionHandler ();
			private CompletionHandler handler;

			public HostProcessInfo[] result {
				get;
				private set;
			}

			public EnumerateRequest (CompletionHandler handler) {
				this.handler = handler;
			}

			public void complete (HostProcessInfo[] processes) {
				this.result = processes;
				handler ();
			}
		}
	}
}

