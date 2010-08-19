using Gee;

namespace Zed {
	public class View.HostSession : Object {
		public Gtk.Widget widget {
			get {
				return hpaned;
			}
		}

		public Gtk.ComboBox provider_combo {
			get;
			private set;
		}

		public Gtk.HBox top_hbox {
			get;
			private set;
		}

		public ProcessSelector process_selector {
			get;
			private set;
		}

		public Gtk.Button add_button {
			get;
			private set;
		}

		public Gtk.ScrolledWindow session_scrollwin {
			get;
			private set;
		}

		public Gtk.TreeView session_treeview {
			get;
			private set;
		}

		public Gtk.Notebook session_notebook {
			get;
			private set;
		}

		private Gtk.HPaned hpaned;

		public HostSession () {
			try {
				var builder = new Gtk.Builder ();
				var blob = Zed.Data.Ui.get_host_session_ui_blob ();
				builder.add_from_string ((string) blob.data, blob.size);

				hpaned = builder.get_object ("root_hpaned") as Gtk.HPaned;

				provider_combo = builder.get_object ("provider_combo") as Gtk.ComboBox;

				top_hbox = builder.get_object ("top_hbox") as Gtk.HBox;

				process_selector = new ProcessSelector ();
				var alignment = builder.get_object ("process_selector_alignment") as Gtk.Alignment;
				alignment.add (process_selector);

				add_button = builder.get_object ("add_button") as Gtk.Button;

				session_scrollwin = builder.get_object ("session_scrollwin") as Gtk.ScrolledWindow;
				session_treeview = builder.get_object ("session_treeview") as Gtk.TreeView;
				session_notebook = builder.get_object ("session_notebook") as Gtk.Notebook;
			} catch (Error e) {
				error (e.message);
			}
		}

		public void show_error_message (string message) {
			var dialog = new Gtk.MessageDialog (find_parent_window (), Gtk.DialogFlags.DESTROY_WITH_PARENT, Gtk.MessageType.ERROR, Gtk.ButtonsType.OK, "Error: %s", message);
			dialog.response.connect ((response_id) => dialog.destroy ());
			dialog.run ();
		}

		private Gtk.Window? find_parent_window () {
			Gtk.Widget cur = this.widget;

			do {
				cur = cur.parent;
				if (cur is Gtk.Window)
					return cur as Gtk.Window;
			} while (cur != null);

			return null;
		}

	}

	public class Presenter.HostSession : Object {
		public View.HostSession view {
			get;
			construct;
		}

		public Service.HostSessionService service {
			get;
			construct;
		}

		public Service.StorageBackend storage_backend {
			get;
			construct;
		}

		public Service.Winjector winjector {
			get;
			construct;
		}

		private Gtk.ListStore provider_store = new Gtk.ListStore (1, typeof (Service.HostSessionProvider));
		private Gee.HashMap<Service.HostSessionProvider, SessionEntry> session_by_provider = new Gee.HashMap<Service.HostSessionProvider, SessionEntry> ();
		private SessionEntry active_session;

		private ProcessSelector process_selector;

		private uint sync_handler_id;

		private HashMap<string, Service.ModuleSpec> module_spec_by_uid = new HashMap<string, Service.ModuleSpec> ();

		private Gtk.ListStore session_store = new Gtk.ListStore (1, typeof (AgentSession));
		private AgentSession current_session;

		private Service.AgentDescriptor agent_desc;

		private const double PROCESS_LIST_MIN_UPDATE_INTERVAL = 5.0;

		private const int STORAGE_BACKEND_SYNC_TIMEOUT_MSEC = 5000;

		private const int KEYVAL_DELETE = 65535;

		public HostSession (View.HostSession view, Service.HostSessionService service, Service.StorageBackend storage_backend) {
			Object (view: view, service: service, storage_backend: storage_backend, winjector: new Service.Winjector () /* here for now */);
		}

		construct {
			process_selector = new ProcessSelector (view.process_selector);

			configure_service ();

			configure_provider_combo ();
			configure_add_button ();
			configure_session_treeview ();

			var blob32 = Zed.Data.WinAgent.get_zed_winagent_32_dll_blob ();
			var blob64 = Zed.Data.WinAgent.get_zed_winagent_64_dll_blob ();
			agent_desc = new Service.AgentDescriptor ("zed-winagent-%u.dll",
				new MemoryInputStream.from_data (blob32.data, blob32.size, null),
				new MemoryInputStream.from_data (blob64.data, blob64.size, null));

			load_data_from_storage_backend ();
		}

		private async void activate_provider (Service.HostSessionProvider provider) {
			var entry = session_by_provider.get (provider);
			if (entry == null) {
				try {
					var session = yield provider.create ();

					entry = new SessionEntry (provider, session);
					session_by_provider[provider] = entry;
				} catch (IOError e) {
					view.provider_combo.sensitive = true;

					if (active_session != null)
						select_provider (active_session.provider);
					update_session_control_ui ();

					view.show_error_message (e.message);

					return;
				}
			}

			view.provider_combo.sensitive = true;
			select_provider (provider);
			active_session = entry;

			update_session_control_ui ();
		}

		private void select_provider (Service.HostSessionProvider provider) {
			var path = provider_store_path_of_provider (provider);
			Gtk.TreeIter iter;
			provider_store.get_iter (out iter, path);
			view.provider_combo.set_active_iter (iter);
		}

		private void update_session_control_ui () {
			bool have_active_session = active_session != null;
			if (have_active_session) {
				process_selector.session = active_session.session;
				view.top_hbox.show ();
				view.session_scrollwin.show ();
			} else {
				process_selector.session = null;
				view.top_hbox.hide ();
				view.session_scrollwin.hide ();
			}
		}

		/*
		private async void start_session (uint pid) {
			var process_info = yield process_list.info_from_pid (pid);

			var code_service = create_code_service ();

			var session = new AgentSession (new View.AgentSession (), process_info, code_service, winjector, agent_desc);
			session.notify["state"].connect (() => on_session_state_changed (session));

			Gtk.TreeIter iter;
			session_store.append (out iter);
			session_store.set (iter, 0, session);

			view.session_notebook.append_page (session.view.widget, null);

			session.inject ();
		}
		*/

		private void switch_to_session (AgentSession session) {
			var previous_session = current_session;
			current_session = session;
			if (previous_session != null)
				refresh_row_for (previous_session);
			refresh_row_for (current_session);

			view.session_notebook.set_current_page (notebook_page_index_of (session));
		}

		private void remove_session_at (Gtk.TreePath path) {
			var session = get_session_at (path);

			view.session_notebook.remove_page (notebook_page_index_of (session));

			Gtk.TreeIter iter;
			session_store.get_iter (out iter, path);
			session_store.remove (iter);

			if (current_session == session) {
				current_session = null;

				if (session_store.get_iter_first (out iter)) {
					AgentSession first_session;
					session_store.get (iter, 0, out first_session);
					switch_to_session (first_session);
				}
			}
		}

		private Service.CodeService create_code_service () {
			var service = new Service.CodeService ();

			foreach (var entry in module_spec_by_uid)
				service.add_module_spec (entry.@value);

			service.module_spec_added.connect ((module_spec) => {
				var uid = module_spec.uid;
				if (!module_spec_by_uid.has_key (uid)) {
					module_spec_by_uid[uid] = module_spec;
					schedule_storage_backend_sync ();
				}
			});
			service.module_spec_modified.connect ((module_spec) => {
				assert (module_spec_by_uid.has_key (module_spec.uid));
				schedule_storage_backend_sync ();
			});

			return service;
		}

		private void schedule_storage_backend_sync () {
			if (sync_handler_id != 0)
				Source.remove (sync_handler_id);
			sync_handler_id = Timeout.add (STORAGE_BACKEND_SYNC_TIMEOUT_MSEC, () => {
				save_data_to_storage_backend ();
				sync_handler_id = 0;
				return false;
			});
		}

		private void load_data_from_storage_backend () {
			var values = storage_backend.read ("module-specs");
			if (values != null) {
				foreach (var val in values) {
					var module_spec = Service.ModuleSpec.from_variant (val.get_variant ());
					module_spec_by_uid[module_spec.uid] = module_spec;
				}
			}
		}

		private void save_data_to_storage_backend () {
			var builder = new VariantBuilder (new VariantType ("av"));
			foreach (var entry in module_spec_by_uid)
				builder.add ("v", entry.@value.to_variant ());
			storage_backend.write ("module-specs", builder.end ());
		}

		private void refresh_row_for (AgentSession session) {
			var path = session_store_path_of (session);

			Gtk.TreeIter iter;
			session_store.get_iter (out iter, path);
			session_store.row_changed (path, iter);
		}

		private void on_session_state_changed (AgentSession session) {
			refresh_row_for (session);

			switch (session.state) {
				case AgentSession.State.INJECTED:
					switch_to_session (session);
					break;
				default:
					break;
			}
		}

		public async void close () {
			Gtk.TreeIter iter;
			if (session_store.get_iter_first (out iter)) {
				do {
					AgentSession session;
					session_store.get (iter, 0, out session);
					yield session.terminate ();
				} while (session_store.iter_next (ref iter));
			}

			Thread.usleep (50000); /* HACK: give processes 50 ms to unload DLLs */

			yield winjector.close ();
		}

		private void configure_service () {
			service.provider_available.connect ((provider) => {
				Gtk.TreeIter iter;
				provider_store.append (out iter);
				provider_store.set (iter, 0, provider);

				if (active_session == null && provider.kind == Service.HostSessionProviderKind.LOCAL_SYSTEM && (view.provider_combo.get_flags () & Gtk.WidgetFlags.SENSITIVE) != 0) {
					view.provider_combo.sensitive = false;

					activate_provider (provider);
				}
			});
			service.provider_unavailable.connect ((provider) => {
				session_by_provider.unset (provider);

				Gtk.TreeIter iter;
				var path = provider_store_path_of_provider (provider);
				provider_store.get_iter (out iter, path);
				provider_store.remove (iter);

				if (active_session != null && active_session.provider == provider) {
					process_selector.session = null;
					active_session = null;
					update_session_control_ui ();
				}
			});

			service.start ();
		}

		private void configure_provider_combo () {
			var combo = view.provider_combo;
			combo.changed.connect (() => {
				Gtk.TreeIter iter;
				if (view.provider_combo.get_active_iter (out iter)) {
					Service.HostSessionProvider provider;
					provider_store.get (iter, 0, out provider);
					activate_provider (provider);
				}
			});

			combo.set_model (provider_store);

			var name_renderer = new Gtk.CellRendererText ();
			combo.pack_end (name_renderer, true);
			combo.set_cell_data_func (name_renderer, provider_combo_data_callback);
		}

		private void configure_add_button () {
			/*
			view.add_button.clicked.connect (() => {
				var pid = view.pid_entry.text.to_int ();
				if (pid != 0) {
					view.pid_entry.text = "";
					start_session (pid);
				}
			});
			*/
		}

		private void configure_session_treeview () {
			var sv = view.session_treeview;

			sv.set_model (session_store);

			var col = new Gtk.TreeViewColumn ();
			col.title = "Process";
			col.set_min_width (92);
			var icon_renderer = new Gtk.CellRendererPixbuf ();
			col.pack_start (icon_renderer, false);
			col.set_cell_data_func (icon_renderer, session_process_column_data_callback);
			var name_renderer = new Gtk.CellRendererText ();
			col.pack_start (name_renderer, true);
			col.set_cell_data_func (name_renderer, session_process_column_data_callback);
			sv.append_column (col);

			int col_count = sv.insert_column_with_data_func (-1, "ID", new Gtk.CellRendererText (), session_pid_column_data_callback);
			col = sv.get_column (col_count - 1);
			col.set_min_width (31);

			sv.insert_column_with_data_func (-1, "Status", new Gtk.CellRendererText (), session_status_column_data_callback);

			sv.row_activated.connect ((path, col) => {
				var session = get_session_at (path);
				switch_to_session (session);
			});
			sv.key_press_event.connect ((event) => {
				if (event.keyval == KEYVAL_DELETE) {
					var selection = sv.get_selection ();

					Gtk.TreeModel model;
					Gtk.TreeIter iter;
					if (selection.get_selected (out model, out iter)) {
						AgentSession session;
						model.get (iter, 0, out session);

						if (session.state != AgentSession.State.TERMINATED)
							session.terminate ();
						else
							remove_session_at (model.get_path (iter));
					}
				}

				return false;
			});
		}

		private AgentSession get_session_at (Gtk.TreePath path) {
			Gtk.TreeIter iter;
			session_store.get_iter (out iter, path);
			AgentSession session;
			session_store.get (iter, 0, out session);
			return session;
		}

		private Gtk.TreePath provider_store_path_of_provider (Service.HostSessionProvider provider) {
			Gtk.TreeIter iter;
			if (provider_store.get_iter_first (out iter)) {
				do {
					Service.HostSessionProvider p;
					provider_store.get (iter, 0, out p);
					if (p == provider)
						return provider_store.get_path (iter);
				} while (provider_store.iter_next (ref iter));
			}

			assert_not_reached ();
		}

		private Gtk.TreePath session_store_path_of (AgentSession session) {
			Gtk.TreeIter iter;
			if (session_store.get_iter_first (out iter)) {
				do {
					AgentSession s;
					session_store.get (iter, 0, out s);
					if (s == session)
						return session_store.get_path (iter);
				} while (session_store.iter_next (ref iter));
			}

			assert_not_reached ();
		}

		private int notebook_page_index_of (AgentSession session) {
			var notebook = view.session_notebook;
			var session_view = session.view;
			for (int i = notebook.get_n_pages () - 1; i >= 0; i--) {
				var current_view = notebook.get_nth_page (i);
				if (current_view == session_view.widget)
					return i;
			}

			assert_not_reached ();
		}

		private void provider_combo_data_callback (Gtk.CellLayout layout, Gtk.CellRenderer renderer, Gtk.TreeModel model, Gtk.TreeIter iter) {
			Service.HostSessionProvider p;
			model.get (iter, 0, out p);

			(renderer as Gtk.CellRendererText).text = p.name;
		}

		private void session_process_column_data_callback (Gtk.CellLayout layout, Gtk.CellRenderer renderer, Gtk.TreeModel model, Gtk.TreeIter iter) {
			AgentSession session;
			model.get (iter, 0, out session);
			if (renderer is Gtk.CellRendererPixbuf) {
				(renderer as Gtk.CellRendererPixbuf).pixbuf = session.process_info.small_icon;
			} else {
				var text_renderer = renderer as Gtk.CellRendererText;
				if (session == current_session)
					text_renderer.markup = "<b>%s</b>".printf (session.process_info.name.to_string ());
				else
					text_renderer.text = session.process_info.name.to_string ();
			}
		}

		private void session_pid_column_data_callback (Gtk.TreeViewColumn col, Gtk.CellRenderer renderer, Gtk.TreeModel model, Gtk.TreeIter iter) {
			AgentSession session;
			model.get (iter, 0, out session);
			(renderer as Gtk.CellRendererText).text = session.process_info.pid.to_string ();
		}

		private void session_status_column_data_callback (Gtk.TreeViewColumn col, Gtk.CellRenderer renderer, Gtk.TreeModel model, Gtk.TreeIter iter) {
			AgentSession session;
			model.get (iter, 0, out session);
			(renderer as Gtk.CellRendererText).text = session.state_to_string ();
		}

		private class SessionEntry {
			public Service.HostSessionProvider provider {
				get;
				private set;
			}

			public Zed.HostSession session {
				get;
				private set;
			}

			public SessionEntry (Service.HostSessionProvider provider, Zed.HostSession session) {
				this.provider = provider;
				this.session = session;
			}
		}
	}
}

