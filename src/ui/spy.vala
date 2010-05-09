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

		public Gtk.TreeView process_view {
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
				process_view = builder.get_object ("process_treeview") as Gtk.TreeView;
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

		private Gtk.ListStore process_store;

		private Service.AgentDescriptor agent_desc;

		public Spy (View.Spy view) {
			Object (view: view, winjector: new Service.Winjector () /* here for now */);

			process_store = new Gtk.ListStore (3, typeof (uint), typeof (string), typeof (WinIpc.Proxy));
			process_store.set_sort_column_id (0, Gtk.SortType.ASCENDING);
			view.process_view.set_model (process_store);
			view.process_view.insert_column_with_attributes (-1, "PID", new Gtk.CellRendererText (), "text", 0);
			view.process_view.insert_column_with_attributes (-1, "Status", new Gtk.CellRendererText (), "text", 1);

			agent_desc = new Service.AgentDescriptor ("zed-winagent-%u.dll",
				new MemoryInputStream.from_data (get_winagent_32_data (), get_winagent_32_size (), null),
				new MemoryInputStream.from_data (get_winagent_64_data (), get_winagent_64_size (), null));

			connect_signals ();
		}

		public async void close () {
			Gtk.TreeIter iter;
			if (process_store.get_iter_first (out iter)) {
				do {
					var val = Value (typeof (WinIpc.Proxy));
					process_store.get_value (iter, 2, out val);
					WinIpc.Proxy proxy = (WinIpc.Proxy) val.get_object ();
					if (proxy != null)
						proxy.emit ("Stop");
				} while (process_store.iter_next (ref iter));
			}

			Thread.usleep (50000); /* HACK: give processes 50 ms to unload DLLs */

			yield winjector.close ();
		}

		private void connect_signals () {
			view.add_button.clicked.connect (() => {
				var pid = view.pid_entry.text.to_int ();
				if (pid != 0) {
					view.pid_entry.text = "";
					inject_into (pid);
				}
			});
		}

		private async void inject_into (uint pid) {
			Gtk.TreeIter iter;
			process_store.append (out iter);

			try {
				process_store.set (iter, 0, pid, 1, "Injecting...");
				var proxy = yield winjector.inject (pid, agent_desc, null);
				process_store.set (iter, 1, "Injected!", 2, proxy);
			} catch (Service.WinjectorError e) {
				process_store.set (iter, 1, "Error: %s".printf (e.message));
			}
		}

		private static extern void * get_winagent_32_data ();
		private static extern uint get_winagent_32_size ();

		private static extern void * get_winagent_64_data ();
		private static extern uint get_winagent_64_size ();
	}
}

