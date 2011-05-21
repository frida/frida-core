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

		private Gtk.ListStore module_store = new Gtk.ListStore (1, typeof (string));
		private Gtk.ListStore function_store = new Gtk.ListStore (1, typeof (string));

		private Zed.AgentSession session;

		public FunctionSelector (View.FunctionSelector view) {
			Object (view: view);
		}

		construct {
			module_store.set_sort_column_id (0, Gtk.SortType.ASCENDING);
			function_store.set_sort_column_id (0, Gtk.SortType.ASCENDING);

			view.set_models (module_store, function_store);

			configure_entries ();
		}

		public void set_session (Zed.AgentSession session) {
			assert (this.session == null);
			this.session = session;

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

			bool seen_winsock_module = false;

			try {
				var module_info_list = yield session.query_modules ();
				foreach (var mi in module_info_list) {
					Gtk.TreeIter iter;
					module_store.append (out iter);
					module_store.set (iter, 0, mi.name);

					if (mi.name == "WS2_32.dll")
						seen_winsock_module = true;
				}
			} catch (IOError e) {
			}

			if (seen_winsock_module) {
				(view.module_entry.child as Gtk.Entry).set_text ("WS2_32.dll");
				(view.function_entry.child as Gtk.Entry).set_text ("WSARecv");
			}
		}

		private async void fetch_functions_in_selected_module () {
			function_store.clear ();

			var module_name = view.module_entry.get_active_text ();

			try {
				var function_info_list = yield session.query_module_functions (module_name);
				foreach (var fi in function_info_list) {
					Gtk.TreeIter iter;
					function_store.append (out iter);
					function_store.set (iter, 0, fi.name);
				}
			} catch (IOError e) {
			}
		}
	}
}
