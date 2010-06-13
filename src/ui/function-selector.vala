namespace Zed {
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

		public bool selection_is_set {
			get;
			private set;
		}

		public string selected_module_name {
			get { return view.module_entry.get_active_text (); }
		}

		public string selected_function_name {
			get { return view.function_entry.get_active_text (); }
		}

		private WinIpc.Proxy proxy;

		private Gtk.ListStore module_store = new Gtk.ListStore (1, typeof (string));
		private Gtk.ListStore function_store = new Gtk.ListStore (1, typeof (string));

		public FunctionSelector (View.FunctionSelector view) {
			Object (view: view);

			module_store.set_sort_column_id (0, Gtk.SortType.ASCENDING);
			function_store.set_sort_column_id (0, Gtk.SortType.ASCENDING);

			view.set_models (module_store, function_store);

			configure_entries ();
		}

		public void set_proxy (WinIpc.Proxy proxy) {
			assert (this.proxy == null);
			this.proxy = proxy;

			fetch_modules ();
		}

		private void configure_entries () {
			view.module_entry.changed.connect (() => {
				fetch_functions_in_selected_module ();
				update_selection_is_set ();
			});

			view.function_entry.changed.connect (() => update_selection_is_set ());
		}

		private void update_selection_is_set () {
			var module_text = view.module_entry.get_active_text ();
			var function_text = view.function_entry.get_active_text ();
			selection_is_set = (module_text != null && module_text.strip ().length != 0 &&
				function_text != null && function_text.strip ().length != 0);
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
