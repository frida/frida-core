namespace Zed {
	public class View.ProcessSelector : Gtk.HBox {
		public Gtk.ComboBoxEntry combo {
			get;
			private set;
		}

		public Gtk.Entry entry {
			get {
				return combo.get_child () as Gtk.Entry;
			}
		}

		public void set_model (Gtk.TreeModel process_model) {
			assert (combo == null);

			combo = new Gtk.ComboBoxEntry.with_model (process_model, 0);
			pack_start (combo, true, true, 0);

			show_all ();
		}
	}

	public class Presenter.ProcessSelector : Object {
		public View.ProcessSelector view {
			get;
			construct;
		}

		public Zed.HostSession session {
			get { return _session; }
			set { switch_session (value); }
		}
		private Zed.HostSession _session;

		private Gtk.ListStore process_store = new Gtk.ListStore (2, typeof (string), typeof (ProcessInfo));
		private Gee.HashMap<void *, IconData> icon_data_by_pointer = new Gee.HashMap<void *, IconData> ();

		public ProcessSelector (View.ProcessSelector view) {
			Object (view: view);

			process_store.set_sort_column_id (0, Gtk.SortType.ASCENDING);

			view.set_model (process_store);

			configure_combo_entry ();
		}

		private void switch_session (Zed.HostSession new_session) {
			if (new_session == this._session)
				return;

			process_store.clear ();

			this._session = new_session;

			if (new_session != null)
				fetch_processes_from (new_session);
		}

		private async void fetch_processes_from (Zed.HostSession session) {
			try {
				var processes = yield session.enumerate_processes ();
				if (this.session != session)
					return;

				foreach (var p in processes) {
					var info = new ProcessInfo (p.pid, p.name, pixbuf_from_icon (p.small_icon), pixbuf_from_icon (p.large_icon));

					Gtk.TreeIter iter;
					process_store.append (out iter);
					process_store.set (iter, 0, p.name, 1, info);
				}
			} catch (IOError e) {
			}
		}

		private void update_entry_with (Gtk.TreeModel model, Gtk.TreeIter iter) {
			ProcessInfo pi;
			model.get (iter, 1, out pi);
			var entry = view.entry;
			entry.set_text (pi.pid.to_string ());
			entry.move_cursor (Gtk.MovementStep.BUFFER_ENDS, 1, false);
		}

		private void configure_combo_entry () {
			var combo = view.combo;
			configure_cell_layout (combo);

			var entry = view.entry;
			entry.changed.connect (() => {
				Gtk.TreeIter iter;
				if (view.combo.get_active_iter (out iter))
					update_entry_with (process_store, iter);
			});

			var completion = new Gtk.EntryCompletion ();

			completion.set_model (process_store);
			completion.set_popup_completion (true);

			configure_cell_layout (completion);
			completion.set_text_column (0);

			completion.match_selected.connect ((model, iter) => {
				update_entry_with (model, iter);
				return true;
			});

			entry.set_completion (completion);
		}

		private void configure_cell_layout (Gtk.CellLayout layout) {
			bool had_existing_renderer = layout.get_cells ().length () != 0;
			layout.clear ();

			var icon_renderer = new Gtk.CellRendererPixbuf ();
			layout.pack_start (icon_renderer, false);
			layout.set_cell_data_func (icon_renderer, icon_cell_data_callback);

			if (had_existing_renderer) {
				var name_renderer = new Gtk.CellRendererText ();
				layout.pack_start (name_renderer, true);
				layout.set_cell_data_func (name_renderer, name_cell_data_callback);
			}

			var pid_renderer = new Gtk.CellRendererText ();
			layout.pack_end (pid_renderer, false);
			layout.set_cell_data_func (pid_renderer, pid_cell_data_callback);
		}

		private void icon_cell_data_callback (Gtk.CellLayout layout, Gtk.CellRenderer renderer, Gtk.TreeModel model, Gtk.TreeIter iter) {
			ProcessInfo pi;
			model.get (iter, 1, out pi);
			(renderer as Gtk.CellRendererPixbuf).pixbuf = pi.small_icon;
		}

		private void name_cell_data_callback (Gtk.CellLayout layout, Gtk.CellRenderer renderer, Gtk.TreeModel model, Gtk.TreeIter iter) {
			ProcessInfo pi;
			model.get (iter, 1, out pi);
			(renderer as Gtk.CellRendererText).text = pi.name;
		}

		private void pid_cell_data_callback (Gtk.CellLayout layout, Gtk.CellRenderer renderer, Gtk.TreeModel model, Gtk.TreeIter iter) {
			ProcessInfo pi;
			model.get (iter, 1, out pi);
			(renderer as Gtk.CellRendererText).text = pi.pid.to_string ();
		}

		private Gdk.Pixbuf? pixbuf_from_icon (HostProcessIcon icon) {
			if (icon.width == 0)
				return null;

			var icon_data = new IconData.from_icon (icon);
			icon_data_by_pointer[icon_data.pixels] = icon_data;

			return new Gdk.Pixbuf.from_data (icon_data.pixels, Gdk.Colorspace.RGB, true, 8, icon.width, icon.height, icon.rowstride, (pixels) => {
				icon_data_by_pointer.unset (pixels);
			});
		}

		private class IconData {
			public uchar[] pixels {
				get;
				private set;
			}

			public IconData.from_icon (HostProcessIcon icon) {
				pixels = Base64.decode (icon.data);
			}
		}
	}

	// FIXME: move ProcessInfo here

	/*
			pe.focus_in_event.connect ((event) => {
				if (process_list.time_since_last_update () >= PROCESS_LIST_MIN_UPDATE_INTERVAL)
					process_list.update ();
				return false;
			});
	*/
}
