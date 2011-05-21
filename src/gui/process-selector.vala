namespace Zed {
	public class View.ProcessSelector : Gtk.HBox {
		public Gtk.ComboBoxEntry combo {
			get;
			private set;
		}

		public Gtk.Entry? entry {
			get {
				return combo.get_child () as Gtk.Entry;
			}
		}

		public signal void activated ();

		public void set_model (Gtk.TreeModel process_model) {
			assert (combo == null);

			combo = new Gtk.ComboBoxEntry.with_model (process_model, 0);
			pack_start (combo, true, true, 0);

			entry.activate.connect (() => this.activated ());

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

		public ProcessInfo? selected_process {
			owned get {
				Gtk.TreeIter iter;
				if (view.combo.get_active_iter (out iter)) {
					ProcessInfo pi;
					process_store.get (iter, 1, out pi);

					return pi;
				} else {
					int pid = view.entry.text.to_int ();
					if (pid <= 0)
						return null;

					var pi = process_info_by_pid[pid];
					if (pi != null)
						return pi;

					return new ProcessInfo (pid, "[Unknown Process]");
				}
			}
		}

		private Gtk.ListStore process_store = new Gtk.ListStore (2, typeof (string), typeof (ProcessInfo));
		private Gee.HashMap<uint, ProcessInfo> process_info_by_pid = new Gee.HashMap<uint, ProcessInfo> ();
		private ImageFactory image_factory = new ImageFactory ();

		private Timer last_refresh = new Timer ();
		private bool refresh_in_progress = false;
		private const double MIN_REFRESH_INTERVAL = 5.0;

		public ProcessSelector (View.ProcessSelector view) {
			Object (view: view);

			process_store.set_sort_func (1, compare_process_info_by_icon_name_and_pid);
			process_store.set_sort_column_id (1, Gtk.SortType.ASCENDING);

			view.set_model (process_store);

			configure_combo_entry ();
		}

		public void clear_selection () {
			view.entry.text = "";
		}

		private void switch_session (Zed.HostSession? new_session) {
			if (new_session == this._session)
				return;

			var entry = view.entry;
			if (entry != null)
				entry.text = "";

			this._session = new_session;

			refresh ();
		}

		private void consider_refresh () {
			if (last_refresh.elapsed () < MIN_REFRESH_INTERVAL)
				return;

			refresh ();
		}

		private async void refresh () {
			if (refresh_in_progress)
				return;

			refresh_in_progress = true;

			process_store.clear ();
			process_info_by_pid.clear ();

			last_refresh.reset ();

			if (_session != null) {
				yield fetch_processes_from (_session);

				last_refresh.reset ();
			}

			refresh_in_progress = false;
		}

		private async void fetch_processes_from (Zed.HostSession session) {
			try {
				var processes = yield session.enumerate_processes ();
				if (this.session != session)
					return;

				foreach (var p in processes) {
					var info = new ProcessInfo (p.pid, p.name,
						image_factory.create_pixbuf_from_image_data (p.small_icon),
						image_factory.create_pixbuf_from_image_data (p.large_icon));

					Gtk.TreeIter iter;
					process_store.append (out iter);
					process_store.set (iter, 0, p.name, 1, info);

					process_info_by_pid[p.pid] = info;
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
			combo.popup.connect (() => consider_refresh ());
			configure_cell_layout (combo);

			var entry = view.entry;
			entry.focus_in_event.connect ((event) => {
				consider_refresh ();
				return false;
			});
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

		private int compare_process_info_by_icon_name_and_pid (Gtk.TreeModel model, Gtk.TreeIter iter_a, Gtk.TreeIter iter_b) {
			ProcessInfo a, b;
			model.get (iter_a, 1, out a);
			model.get (iter_b, 1, out b);

			var a_has_icon = a.small_icon != null;
			var b_has_icon = b.small_icon != null;
			if (a_has_icon == b_has_icon) {
				var name_equality = a.name.ascii_casecmp (b.name);
				if (name_equality != 0)
					return name_equality;

				if (a.pid < b.pid)
					return -1;
				else
					return 1;
			} else if (a_has_icon) {
				return -1;
			} else {
				return 1;
			}
		}

	}

	public class ProcessInfo : Object {
		public uint pid {
			get;
			private set;
		}

		public string name {
			get;
			private set;
		}

		public Gdk.Pixbuf? small_icon {
			get;
			private set;
		}

		public Gdk.Pixbuf? large_icon {
			get;
			private set;
		}

		public ProcessInfo (uint pid, string name, Gdk.Pixbuf? small_icon = null, Gdk.Pixbuf? large_icon = null) {
			this.pid = pid;
			this.name = name;
			this.small_icon = small_icon;
			this.large_icon = large_icon;
		}
	}
}

