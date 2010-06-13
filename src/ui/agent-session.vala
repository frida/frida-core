namespace Zed {
	public class View.AgentSession : Object {
		public Gtk.Widget widget {
			get {
				return root_vbox;
			}
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

		private Gtk.VBox root_vbox;
		private Gtk.Alignment start_alignment;
		private Gtk.Alignment stop_alignment;

		public AgentSession () {
			try {
				var builder = new Gtk.Builder ();
				builder.add_from_string (Zed.Data.Ui.AGENT_SESSION_XML, -1);

				root_vbox = builder.get_object ("root_vbox") as Gtk.VBox;

				start_alignment = builder.get_object ("start_alignment") as Gtk.Alignment;
				stop_alignment = builder.get_object ("stop_alignment") as Gtk.Alignment;
				go_button = builder.get_object ("go_button") as Gtk.Button;

				start_selector = new FunctionSelector ();
				start_alignment.add (start_selector);

				stop_selector = new FunctionSelector ();
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

		public ProcessInfo process_info {
			get;
			private set;
		}

		private string error_message;

		private Service.Winjector winjector;
		private Service.AgentDescriptor agent_desc;

		private FunctionSelector start_selector;
		private FunctionSelector stop_selector;

		public WinIpc.Proxy proxy {
			get;
			private set;
		}

		public AgentSession (View.AgentSession view, ProcessInfo process_info, Service.Winjector winjector, Service.AgentDescriptor agent_desc) {
			Object (view: view);

			this.state = State.UNINITIALIZED;
			this.process_info = process_info;
			this.winjector = winjector;
			this.agent_desc = agent_desc;

			start_selector = new FunctionSelector (view.start_selector);
			stop_selector = new FunctionSelector (view.stop_selector);
		}

		public async void inject () {
			try {
				this.state = State.INJECTING;
				proxy = yield winjector.inject (process_info.pid, agent_desc, null);
				proxy.add_notify_handler ("FuncEvent", "(i(ssu)(ssu))", on_func_event);
				this.state = State.INJECTED;

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

			state = State.TERMINATED;
		}

		private void error (string message) {
			this.error_message = message;
			this.state = State.ERROR;
		}

		private void on_func_event (Variant? arg) {
			/*
			Gtk.TreeIter iter;
			event_store.append (out iter);
			event_store.set (iter, 0, arg.print (false));
			*/
			print ("on_func_event\n");
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

	public class View.FunctionSelector : Gtk.HBox {
		public Gtk.ComboBoxEntry module_entry {
			get;
			private set;
		}

		public Gtk.ComboBoxEntry function_entry {
			get;
			private set;
		}

		public FunctionSelector () {
		}

		public void set_models (Gtk.TreeModel module_model, Gtk.TreeModel function_model) {
			assert (module_entry == null && function_entry == null);

			module_entry = new Gtk.ComboBoxEntry.with_model (module_model, 0);
			pack_start (module_entry, false, false, 0);

			function_entry = new Gtk.ComboBoxEntry.with_model (function_model, 0);
			pack_start (function_entry, false, true, 5);

			show_all ();
		}
	}

	public class Presenter.FunctionSelector : Object {
		public View.FunctionSelector view {
			get;
			construct;
		}

		private WinIpc.Proxy proxy;

		private Gtk.ListStore module_store = new Gtk.ListStore (1, typeof (string));
		private Gtk.ListStore function_store = new Gtk.ListStore (1, typeof (string));

		public FunctionSelector (View.FunctionSelector view) {
			Object (view: view);

			module_store.set_sort_column_id (0, Gtk.SortType.ASCENDING);
			function_store.set_sort_column_id (0, Gtk.SortType.ASCENDING);

			view.set_models (module_store, function_store);

			configure_module_entry ();
		}

		public void set_proxy (WinIpc.Proxy proxy) {
			assert (this.proxy == null);
			this.proxy = proxy;

			fetch_modules ();
		}

		private void configure_module_entry () {
			view.module_entry.changed.connect (() => fetch_functions_in_selected_module ());
		}

		private async void fetch_modules () {
			module_store.clear ();

			try {
				var modules = yield proxy.query ("QueryModules", null, "a(stt)");
				foreach (var module in modules) {
					string name;
					uint64 base_address;
					uint64 size;
					module.get ("(stt)", out name, out base_address, out size);

					Gtk.TreeIter iter;
					module_store.append (out iter);
					module_store.set (iter, 0, name);
				}
			} catch (WinIpc.ProxyError e) {
			}
		}

		private async void fetch_functions_in_selected_module () {
			function_store.clear ();

			var module_name = view.module_entry.get_active_text ();

			try {
				var functions = yield proxy.query ("QueryModuleFunctions", new Variant.string (module_name), "a(st)");
				foreach (var function in functions) {
					string name;
					uint64 base_address;
					function.get ("(st)", out name, out base_address);

					Gtk.TreeIter iter;
					function_store.append (out iter);
					function_store.set (iter, 0, name);
				}
			} catch (WinIpc.ProxyError e) {
			}
		}
	}
}

