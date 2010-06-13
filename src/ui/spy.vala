namespace Zed {
	public class View.Spy : Object {
		public Gtk.Widget widget {
			get {
				return hpaned;
			}
		}

		public Gtk.Entry pid_entry {
			get;
			private set;
		}

		public Gtk.Button add_button {
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

		public Spy () {
			try {
				var builder = new Gtk.Builder ();
				builder.add_from_string (Zed.Data.Ui.SPY_XML, -1);

				hpaned = builder.get_object ("root_hpaned") as Gtk.HPaned;

				pid_entry = builder.get_object ("pid_entry") as Gtk.Entry;
				add_button = builder.get_object ("add_button") as Gtk.Button;
				session_treeview = builder.get_object ("session_treeview") as Gtk.TreeView;
				session_notebook = builder.get_object ("session_notebook") as Gtk.Notebook;
			} catch (Error e) {
				error (e.message);
			}
		}
	}

	public class Presenter.Spy : Object {
		public View.Spy view {
			get;
			construct;
		}

		public Service.Winjector winjector {
			get;
			construct;
		}

		private Gtk.ListStore session_store = new Gtk.ListStore (1, typeof (AgentSession));

		private Service.AgentDescriptor agent_desc;

		private Service.ProcessList process_list = new Service.ProcessList ();
		private const double PROCESS_LIST_MIN_UPDATE_INTERVAL = 5.0;

		private const int KEYVAL_DELETE = 65535;

		public Spy (View.Spy view) {
			Object (view: view, winjector: new Service.Winjector () /* here for now */);

			configure_pid_entry ();
			configure_add_button ();
			configure_session_treeview ();

			agent_desc = new Service.AgentDescriptor ("zed-winagent-%u.dll",
				new MemoryInputStream.from_data (get_winagent_32_data (), get_winagent_32_size (), null),
				new MemoryInputStream.from_data (get_winagent_64_data (), get_winagent_64_size (), null));
		}

		private async void start_session (uint pid) {
			var process_info = yield process_list.info_from_pid (pid);

			var view = new View.AgentSession ();
			var session = new AgentSession (view, process_info, winjector, agent_desc);
			session.notify["state"].connect (() => on_session_state_changed (session));

			Gtk.TreeIter iter;
			session_store.append (out iter);
			session_store.set (iter, 0, session);

			session.inject ();
		}

		private void on_session_state_changed (AgentSession session) {
			var path = find_session_store_path_of (session);
			assert (path != null);

			Gtk.TreeIter iter;
			session_store.get_iter (out iter, path);
			session_store.row_changed (path, iter);

			switch (session.state) {
				case AgentSession.State.INJECTED:
					view.session_notebook.append_page (session.view.widget, null);
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
					session.terminate ();
				} while (session_store.iter_next (ref iter));
			}

			Thread.usleep (50000); /* HACK: give processes 50 ms to unload DLLs */

			yield winjector.close ();
		}

		private void configure_pid_entry () {
			var pe = view.pid_entry;

			pe.activate.connect (() => {
				view.add_button.clicked ();
			});
			pe.focus_in_event.connect ((event) => {
				if (process_list.time_since_last_update () >= PROCESS_LIST_MIN_UPDATE_INTERVAL)
					process_list.update ();
				return false;
			});

			var completion = new Gtk.EntryCompletion ();

			completion.set_model (process_list.model);
			completion.set_popup_completion (true);

			var icon_renderer = new Gtk.CellRendererPixbuf ();
			completion.pack_start (icon_renderer, false);
			completion.set_cell_data_func (icon_renderer, pid_entry_completion_data_callback);

			completion.set_text_column (0);

			var pid_renderer = new Gtk.CellRendererText ();
			completion.pack_end (pid_renderer, false);
			completion.set_cell_data_func (pid_renderer, pid_entry_completion_data_callback);

			completion.match_selected.connect ((model, iter) => {
				ProcessInfo pi;
				model.get (iter, 1, out pi);
				pe.set_text (pi.pid.to_string ());
				pe.move_cursor (Gtk.MovementStep.BUFFER_ENDS, 1, false);
				return true;
			});

			pe.set_completion (completion);
		}

		private void configure_add_button () {
			view.add_button.clicked.connect (() => {
				var pid = view.pid_entry.text.to_int ();
				if (pid != 0) {
					view.pid_entry.text = "";
					start_session (pid);
				}
			});
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

		private void remove_session_at (Gtk.TreePath path) {
			Gtk.TreeIter iter;
			session_store.get_iter (out iter, path);

			AgentSession session;
			session_store.get (iter, 0, out session);

			var notebook = view.session_notebook;
			var session_view = session.view;
			for (int i = notebook.get_n_pages () - 1; i >= 0; i--) {
				var current_view = notebook.get_nth_page (i);
				if (current_view == session_view.widget) {
					notebook.remove_page (i);
					break;
				}
			}

			session_store.remove (iter);
		}

		private Gtk.TreePath? find_session_store_path_of (AgentSession session) {
			Gtk.TreeIter iter;
			if (!session_store.get_iter_first (out iter))
				return null;

			do {
				AgentSession s;
				session_store.get (iter, 0, out s);
				if (s == session)
					return session_store.get_path (iter);
			} while (session_store.iter_next (ref iter));

			return null;
		}

		private void pid_entry_completion_data_callback (Gtk.CellLayout layout, Gtk.CellRenderer renderer, Gtk.TreeModel model, Gtk.TreeIter iter) {
			ProcessInfo pi;
			model.get (iter, 1, out pi);

			if (renderer is Gtk.CellRendererPixbuf)
				(renderer as Gtk.CellRendererPixbuf).pixbuf = pi.small_icon;
			else
				(renderer as Gtk.CellRendererText).text = pi.pid.to_string ();
		}

		private void session_process_column_data_callback (Gtk.CellLayout layout, Gtk.CellRenderer renderer, Gtk.TreeModel model, Gtk.TreeIter iter) {
			AgentSession session;
			model.get (iter, 0, out session);
			if (renderer is Gtk.CellRendererPixbuf)
				(renderer as Gtk.CellRendererPixbuf).pixbuf = session.process_info.small_icon;
			else
				(renderer as Gtk.CellRendererText).text = session.process_info.name.to_string ();
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

		private static extern void * get_winagent_32_data ();
		private static extern uint get_winagent_32_size ();

		private static extern void * get_winagent_64_data ();
		private static extern uint get_winagent_64_size ();
	}
}

