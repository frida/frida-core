using Gee;

namespace Zed {
	public class View.AgentSession : Object {
		public Gtk.Widget widget {
			get {
				return root_vbox;
			}
		}

		public Gtk.Frame control_frame {
			get;
			private set;
		}

		public ProcessInfoLabel process_info_label {
			get;
			private set;
		}

		public Gtk.Button go_button {
			get;
			private set;
		}

		public FunctionSelector start_selector {
			get;
			private set;
		}

		public FunctionSelector stop_selector {
			get;
			private set;
		}

		public Gtk.TreeView event_view {
			get;
			private set;
		}

		private Gtk.VBox root_vbox;

		public AgentSession () {
			try {
				var builder = new Gtk.Builder ();
				builder.add_from_string (Zed.Data.Ui.AGENT_SESSION_XML, -1);

				root_vbox = builder.get_object ("root_vbox") as Gtk.VBox;

				control_frame = builder.get_object ("control_frame") as Gtk.Frame;
				go_button = builder.get_object ("go_button") as Gtk.Button;
				event_view = builder.get_object ("event_view") as Gtk.TreeView;

				process_info_label = new ProcessInfoLabel ();
				var process_info_alignment = builder.get_object ("process_info_alignment") as Gtk.Alignment;
				process_info_alignment.add (process_info_label);

				start_selector = new FunctionSelector ();
				var start_alignment = builder.get_object ("start_alignment") as Gtk.Alignment;
				start_alignment.add (start_selector);

				stop_selector = new FunctionSelector ();
				var stop_alignment = builder.get_object ("stop_alignment") as Gtk.Alignment;
				stop_alignment.add (stop_selector);
			} catch (Error e) {
				error (e.message);
			}
		}
	}

	public class Presenter.AgentSession : Object {
		public View.AgentSession view {
			get;
			construct;
		}

		public ProcessInfo process_info {
			get;
			construct;
		}

		public Service.CodeService code_service {
			get;
			construct;
		}

		public enum State {
			UNINITIALIZED,
			INJECTING,
			INJECTED,
			ERROR,
			TERMINATED
		}

		public State state {
			get;
			private set;
		}

		private string error_message;

		private Service.Winjector winjector;
		private Service.AgentDescriptor agent_desc;

		private ProcessInfoLabel process_info_label;
		private FunctionSelector start_selector;
		private FunctionSelector stop_selector;

		private Gtk.ListStore function_call_store = new Gtk.ListStore (1, typeof (FunctionCall));

		private Investigation investigation;

		public WinIpc.Proxy proxy {
			get;
			private set;
		}

		public AgentSession (View.AgentSession view, ProcessInfo process_info, Service.CodeService code_service, Service.Winjector winjector, Service.AgentDescriptor agent_desc) {
			Object (view: view, process_info: process_info, code_service: code_service);

			update_state (State.UNINITIALIZED);
			this.winjector = winjector;
			this.agent_desc = agent_desc;

			process_info_label = new ProcessInfoLabel (view.process_info_label, process_info);
			start_selector = new FunctionSelector (view.start_selector);
			stop_selector = new FunctionSelector (view.stop_selector);

			configure_selectors ();
			configure_go_button ();
			configure_event_view ();
		}

		public async void inject () {
			try {
				update_state (State.INJECTING);
				proxy = yield winjector.inject (process_info.pid, agent_desc, null);
				update_state (State.INJECTED);

				start_selector.set_proxy (proxy);
				stop_selector.set_proxy (proxy);
			} catch (Service.WinjectorError e) {
				this.error (e.message);
			}
		}

		public async void terminate () {
			if (state == State.TERMINATED)
				return;

			if (state == State.INJECTED) {
				try {
					yield proxy.emit ("Stop");
				} catch (WinIpc.ProxyError e) {
					this.error (e.message);
					return;
				}
			}

			update_state (State.TERMINATED);
		}

		private async void start_investigation () {
			function_call_store.clear ();

			investigation = new Investigation (proxy, code_service);
			investigation.new_function_call.connect (on_new_function_call);
			investigation.finished.connect (end_investigation);

			update_view ();

			var start_trigger = new TriggerInfo (start_selector.selected_module_name, start_selector.selected_function_name);
			var stop_trigger = new TriggerInfo (stop_selector.selected_module_name, stop_selector.selected_function_name);
			bool success = yield investigation.start (start_trigger, stop_trigger);
			if (!success)
				investigation = null;

			update_view ();
		}

		private void on_new_function_call (FunctionCall function_call) {
			Gtk.TreeIter iter;
			function_call_store.append (out iter);
			function_call_store.set (iter, 0, function_call);
		}

		private void end_investigation () {
			investigation = null;
			update_view ();
		}

		private void error (string message) {
			this.error_message = message;
			update_state (State.ERROR);
		}

		private void configure_selectors () {
			start_selector.notify["selection-is-set"].connect (update_view);
			stop_selector.notify["selection-is-set"].connect (update_view);
		}

		private void configure_go_button () {
			view.go_button.clicked.connect (() => start_investigation ());
		}

		private void configure_event_view () {
			var ev = view.event_view;

			ev.set_model (function_call_store);

			ev.insert_column_with_data_func (-1, "From", new Gtk.CellRendererText (), event_view_from_column_data_callback);

			var target_renderer = new Gtk.CellRendererText ();
			target_renderer.editable = true;
			target_renderer.edited.connect ((path_str, new_text) => {
				var path = new Gtk.TreePath.from_string (path_str);
				Gtk.TreeIter iter;
				function_call_store.get_iter (out iter, path);

				FunctionCall call;
				function_call_store.@get (iter, 0, out call);
				code_service.rename_function (call.target, new_text);
			});
			ev.insert_column_with_data_func (-1, "To", target_renderer, event_view_to_column_data_callback);
		}

		private void event_view_from_column_data_callback (Gtk.TreeViewColumn col, Gtk.CellRenderer renderer, Gtk.TreeModel model, Gtk.TreeIter iter) {
			FunctionCall call;
			model.get (iter, 0, out call);

			var text_renderer = renderer as Gtk.CellRendererText;
			var module = call.module;
			if (module != null) {
				text_renderer.text = "%s+0x%08llx".printf (module.spec.name, call.offset);
			} else {
				text_renderer.text = "0x%08llx".printf (call.offset);
			}
		}

		private void event_view_to_column_data_callback (Gtk.TreeViewColumn col, Gtk.CellRenderer renderer, Gtk.TreeModel model, Gtk.TreeIter iter) {
			FunctionCall call;
			model.get (iter, 0, out call);

			(renderer as Gtk.CellRendererText).text = call.target.spec.name;
		}

		private void update_view () {
			view.control_frame.sensitive = (state == State.INJECTED);

			if (state == State.INJECTED) {
				view.start_selector.sensitive = (investigation == null);
				view.stop_selector.sensitive = (investigation == null);
				view.go_button.sensitive = (start_selector.selection_is_set && stop_selector.selection_is_set && investigation == null);
			}
		}

		private void update_state (State new_state) {
			if (new_state == this.state)
				return;

			this.state = new_state;

			update_view ();
		}

		public string state_to_string () {
			switch (state) {
				case State.UNINITIALIZED:
					return "Uninitialized";
				case State.INJECTING:
					return "Injecting";
				case State.INJECTED:
					return "Injected";
				case State.ERROR:
					return "Error: %s".printf (error_message);
				case State.TERMINATED:
					return "Terminated";
				default:
					assert_not_reached ();
			}
		}
	}

	public class Investigation : Object {
		public signal void new_function_call (FunctionCall function_call);
		public signal void finished ();

		private WinIpc.Proxy proxy;
		private Service.CodeService code_service;

		private uint new_batch_handler_id;
		private uint complete_handler_id;

		private LinkedList<Variant> pending_clue_batches = new LinkedList<Variant> ();
		private bool is_processing_clues;

		public Investigation (WinIpc.Proxy proxy, Service.CodeService code_service) {
			this.proxy = proxy;
			this.code_service = code_service;

			new_batch_handler_id = proxy.add_notify_handler ("NewBatchOfClues", "a(itt)", on_new_batch_of_clues);
			complete_handler_id = proxy.add_notify_handler ("InvestigationComplete", "", (arg) => stop ());
		}

		~Investigation () {
			proxy.remove_notify_handler (complete_handler_id);
			proxy.remove_notify_handler (new_batch_handler_id);
		}

		public async bool start (TriggerInfo start_trigger, TriggerInfo stop_trigger) {
			bool success = yield update_module_specs ();
			if (!success)
				return false;

			try {
				var arg = new Variant ("(ssss)",
					start_trigger.module_name, start_trigger.function_name,
					stop_trigger.module_name, stop_trigger.function_name);
				var result = yield proxy.query ("StartInvestigation", arg, "b");
				return result.get_boolean ();
			} catch (WinIpc.ProxyError e) {
				return false;
			}
		}

		private async void stop () {
			try {
				yield proxy.query ("StopInvestigation");
			} catch (WinIpc.ProxyError e) {
			}

			finished ();
		}

		private async bool update_module_specs () {
			try {
				var module_values = yield proxy.query ("QueryModules", null, "a(sstt)");
				foreach (var module_value in module_values) {
					string mod_name;
					string mod_uid;
					uint64 mod_size;
					uint64 mod_base;
					module_value.@get ("(sstt)", out mod_name, out mod_uid, out mod_size, out mod_base);

					Service.ModuleSpec module_spec = yield code_service.find_module_spec_by_uid (mod_uid);
					if (module_spec == null) {
						module_spec = new Service.ModuleSpec (mod_name, mod_uid, mod_size);
						code_service.add_module_spec (module_spec);

						var function_values = yield proxy.query ("QueryModuleFunctions", new Variant.string (mod_name), "a(st)");
						foreach (var function_value in function_values) {
							string func_name;
							uint64 func_address;
							function_value.@get ("(st)", out func_name, out func_address);

							var func_spec = new Service.FunctionSpec (func_name, func_address - mod_base);
							yield code_service.add_function_spec_to_module (func_spec, module_spec);
						}
					}

					Service.Module module = yield code_service.find_module_by_address (mod_base);
					if (module == null) {
						module = new Service.Module (module_spec, mod_base);
						code_service.add_module (module);
					}
				}
			} catch (WinIpc.ProxyError e) {
				return false;
			}

			return true;
		}

		private void on_new_batch_of_clues (Variant? arg) {
			pending_clue_batches.add (arg);

			if (!is_processing_clues) {
				is_processing_clues = true;

				Idle.add (() => {
					process_clues ();
					return false;
				});
			}
		}

		private async void process_clues () {
			while (true) {
				var clue_batch = pending_clue_batches.poll ();
				if (clue_batch == null)
					break;

				foreach (var clue in clue_batch) {
					int depth;
					uint64 location;
					uint64 target;
					clue.@get ("(itt)", out depth, out location, out target);

					var location_module = yield code_service.find_module_by_address (location);
					uint64 location_offset = (location_module != null) ? location - location_module.address : location;

					var target_func = yield code_service.find_function_by_address (target);
					if (target_func == null) {
						var target_func_module = yield code_service.find_module_by_address (target);
						if (target_func_module != null) {
							var target_func_offset = target - target_func_module.address;
							var target_func_name = "%s_%08llx".printf (target_func_module.spec.bare_name, target_func_offset);
							var target_func_spec = new Service.FunctionSpec (target_func_name, target_func_offset);
							target_func = new Service.Function (target_func_spec, target);
							yield code_service.add_function_to_module (target_func, target_func_module);
						} else {
							var dynamic_func_name = "dynamic_%08llx".printf (target);
							var dynamic_func_spec = new Service.FunctionSpec (dynamic_func_name, target);
							target_func = new Service.Function (dynamic_func_spec, target);
							yield code_service.add_function (target_func);
						}
					}

					var func_call = new FunctionCall (depth, location_module, location_offset, target_func);
					new_function_call (func_call);
				}
			}

			is_processing_clues = false;
		}
	}

	public class TriggerInfo {
		public string module_name {
			get;
			private set;
		}

		public string function_name {
			get;
			private set;
		}

		public TriggerInfo (string module_name, string function_name) {
			this.module_name = module_name;
			this.function_name = function_name;
		}
	}

	public class FunctionCall : Object {
		public int depth {
			get;
			construct;
		}

		public Service.Module? module {
			get;
			construct;
		}

		public uint64 offset {
			get;
			construct;
		}

		public Service.Function target {
			get;
			construct;
		}

		public FunctionCall (int depth, Service.Module? module, uint64 offset, Service.Function target) {
			Object (depth: depth, module: module, offset: offset, target: target);
		}
	}
}

